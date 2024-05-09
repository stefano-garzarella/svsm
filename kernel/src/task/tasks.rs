// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::address::{Address, VirtAddr};
use crate::cpu::idt::svsm::default_return;
use crate::cpu::msr::read_flags;
use crate::cpu::percpu::PerCpu;
use crate::cpu::X86ExceptionContext;
use crate::cpu::X86GeneralRegs;
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::locking::{RWLock, SpinLock};
use crate::mm::pagetable::{PTEntryFlags, PageTableRef};
use crate::mm::vm::{Mapping, VMFileMappingFlags, VMKernelStack, VMR};
use crate::mm::{
    mappings::create_anon_mapping, mappings::create_file_mapping, VMMappingGuard,
    SVSM_PERTASK_BASE, SVSM_PERTASK_END, SVSM_PERTASK_STACK_BASE, USER_MEM_END, USER_MEM_START,
};
use crate::types::{SVSM_USER_CS, SVSM_USER_DS};
use crate::utils::MemoryRegion;
use intrusive_collections::{intrusive_adapter, LinkedListAtomicLink};

use super::schedule::{current_task_terminated, schedule};

pub const INITIAL_TASK_ID: u32 = 1;

#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum TaskState {
    RUNNING,
    BLOCKED,
    #[default]
    TERMINATED,
}

#[derive(Clone, Copy, Debug)]
pub enum TaskError {
    // Attempt to close a non-terminated task
    NotTerminated,
    // A closed task could not be removed from the task list
    CloseFailed,
}

impl From<TaskError> for SvsmError {
    fn from(e: TaskError) -> Self {
        Self::Task(e)
    }
}

pub const TASK_FLAG_SHARE_PT: u16 = 0x01;

#[derive(Debug, Default)]
struct TaskIDAllocator {
    next_id: AtomicU32,
}

impl TaskIDAllocator {
    const fn new() -> Self {
        Self {
            next_id: AtomicU32::new(INITIAL_TASK_ID + 1),
        }
    }

    fn next_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reserve IDs of 0 and 1
        while (id == 0_u32) || (id == INITIAL_TASK_ID) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }
}

static TASK_ID_ALLOCATOR: TaskIDAllocator = TaskIDAllocator::new();

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct TaskContext {
    pub rsp: u64,
    pub regs: X86GeneralRegs,
    pub flags: u64,
    pub ret_addr: u64,
}

#[repr(C)]
struct TaskSchedState {
    /// Whether this is an idle task
    idle_task: bool,

    /// Current state of the task
    state: TaskState,

    /// CPU this task is currently assigned to
    cpu: u32,
}

impl TaskSchedState {
    pub fn panic_on_idle(&mut self, msg: &str) -> &mut Self {
        if self.idle_task {
            panic!("{}", msg);
        }
        self
    }
}

#[repr(C)]
pub struct Task {
    pub rsp: u64,

    pub stack_bounds: MemoryRegion<VirtAddr>,

    /// Page table that is loaded when the task is scheduled
    pub page_table: SpinLock<PageTableRef>,

    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: VMR,

    /// Task virtual memory range for use at CPL 3 - None for kernel tasks
    vm_user_range: Option<VMR>,

    /// State relevant for scheduler
    sched_state: RWLock<TaskSchedState>,

    /// ID of the task
    id: u32,

    /// Link to global task list
    list_link: LinkedListAtomicLink,

    /// Link to scheduler run queue
    runlist_link: LinkedListAtomicLink,
}

// SAFETY: Send + Sync is required for Arc<Task> to implement Send. All members
// of  `Task` are Send + Sync except for the intrusive_collection links, which
// are only Send. The only access to these is via the intrusive_adapter!
// generated code which does not use them concurrently across threads.
unsafe impl Sync for Task {}

pub type TaskPointer = Arc<Task>;

intrusive_adapter!(pub TaskRunListAdapter = TaskPointer: Task { runlist_link: LinkedListAtomicLink });
intrusive_adapter!(pub TaskListAdapter = TaskPointer: Task { list_link: LinkedListAtomicLink });

impl PartialEq for Task {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("rsp", &self.rsp)
            .field("state", &self.sched_state.lock_read().state)
            .field("id", &self.id)
            .finish()
    }
}

impl Task {
    pub fn create(cpu: &mut PerCpu, entry: extern "C" fn()) -> Result<TaskPointer, SvsmError> {
        let mut pgtable = cpu.get_pgtable().clone_shared()?;

        cpu.populate_page_table(&mut pgtable);

        let vm_kernel_range = VMR::new(SVSM_PERTASK_BASE, SVSM_PERTASK_END, PTEntryFlags::empty());
        vm_kernel_range.initialize()?;

        let (stack, raw_bounds, rsp_offset) = Self::allocate_ktask_stack(cpu, entry)?;
        vm_kernel_range.insert_at(SVSM_PERTASK_STACK_BASE, stack)?;

        vm_kernel_range.populate(&mut pgtable);

        // Remap at the per-task offset
        let bounds = MemoryRegion::new(
            SVSM_PERTASK_STACK_BASE + raw_bounds.start().into(),
            raw_bounds.len(),
        );

        Ok(Arc::new(Task {
            rsp: bounds
                .end()
                .checked_sub(rsp_offset)
                .expect("Invalid stack offset from task::allocate_ktask_stack()")
                .bits() as u64,
            stack_bounds: bounds,
            page_table: SpinLock::new(pgtable),
            vm_kernel_range,
            vm_user_range: None,
            sched_state: RWLock::new(TaskSchedState {
                idle_task: false,
                state: TaskState::RUNNING,
                cpu: cpu.get_apic_id(),
            }),
            id: TASK_ID_ALLOCATOR.next_id(),
            list_link: LinkedListAtomicLink::default(),
            runlist_link: LinkedListAtomicLink::default(),
        }))
    }

    pub fn create_user(cpu: &mut PerCpu, user_entry: usize) -> Result<TaskPointer, SvsmError> {
        let mut pgtable = cpu.get_pgtable().clone_shared()?;

        cpu.populate_page_table(&mut pgtable);

        let vm_kernel_range = VMR::new(SVSM_PERTASK_BASE, SVSM_PERTASK_END, PTEntryFlags::empty());
        vm_kernel_range.initialize()?;

        let (stack, raw_bounds, stack_offset) = Self::allocate_utask_stack(cpu, user_entry)?;
        vm_kernel_range.insert_at(SVSM_PERTASK_STACK_BASE, stack)?;

        vm_kernel_range.populate(&mut pgtable);

        let vm_user_range = VMR::new(USER_MEM_START, USER_MEM_END, PTEntryFlags::USER);
        vm_user_range.initialize_lazy()?;

        // Remap at the per-task offset
        let bounds = MemoryRegion::new(
            SVSM_PERTASK_STACK_BASE + raw_bounds.start().into(),
            raw_bounds.len(),
        );

        Ok(Arc::new(Task {
            rsp: bounds
                .end()
                .checked_sub(stack_offset)
                .expect("Invalid stack offset from task::allocate_utask_stack()")
                .bits() as u64,
            stack_bounds: bounds,
            page_table: SpinLock::new(pgtable),
            vm_kernel_range,
            vm_user_range: Some(vm_user_range),
            sched_state: RWLock::new(TaskSchedState {
                idle_task: false,
                state: TaskState::RUNNING,
                cpu: cpu.get_apic_id(),
            }),
            id: TASK_ID_ALLOCATOR.next_id(),
            list_link: LinkedListAtomicLink::default(),
            runlist_link: LinkedListAtomicLink::default(),
        }))
    }

    pub fn stack_bounds(&self) -> MemoryRegion<VirtAddr> {
        self.stack_bounds
    }

    pub fn get_task_id(&self) -> u32 {
        self.id
    }

    pub fn set_task_running(&self) {
        self.sched_state.lock_write().state = TaskState::RUNNING;
    }

    pub fn set_task_terminated(&self) {
        self.sched_state
            .lock_write()
            .panic_on_idle("Trying to terminate idle task")
            .state = TaskState::TERMINATED;
    }

    pub fn set_task_blocked(&self) {
        self.sched_state
            .lock_write()
            .panic_on_idle("Trying to block idle task")
            .state = TaskState::BLOCKED;
    }

    pub fn is_running(&self) -> bool {
        self.sched_state.lock_read().state == TaskState::RUNNING
    }

    pub fn is_terminated(&self) -> bool {
        self.sched_state.lock_read().state == TaskState::TERMINATED
    }

    pub fn set_idle_task(&self) {
        self.sched_state.lock_write().idle_task = true;
    }

    pub fn is_idle_task(&self) -> bool {
        self.sched_state.lock_read().idle_task
    }

    pub fn update_cpu(&self, new_cpu: u32) -> u32 {
        let mut state = self.sched_state.lock_write();
        let old_cpu = state.cpu;
        state.cpu = new_cpu;
        old_cpu
    }

    pub fn handle_pf(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        self.vm_kernel_range.handle_page_fault(vaddr, write)
    }

    pub fn fault(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        if vaddr >= USER_MEM_START && vaddr < USER_MEM_END && self.vm_user_range.is_some() {
            let vmr = self.vm_user_range.as_ref().unwrap();
            let mut pgtbl = self.page_table.lock();
            vmr.populate_addr(&mut pgtbl, vaddr);
            vmr.handle_page_fault(vaddr, write)?;
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    fn allocate_stack_common() -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>), SvsmError> {
        let stack = VMKernelStack::new()?;
        let bounds = stack.bounds(VirtAddr::from(0u64));

        let mapping = Arc::new(Mapping::new(stack));

        Ok((mapping, bounds))
    }

    fn allocate_ktask_stack(
        cpu: &mut PerCpu,
        entry: extern "C" fn(),
    ) -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>, usize), SvsmError> {
        let (mapping, bounds) = Task::allocate_stack_common()?;

        let percpu_mapping = cpu.new_mapping(mapping.clone())?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_ptr = (percpu_mapping.virt_addr() + bounds.end().bits()).as_mut_ptr::<u64>();

        // 'Push' the task frame onto the stack
        unsafe {
            // flags
            stack_ptr.offset(-3).write(read_flags());
            // ret_addr
            stack_ptr.offset(-2).write(entry as *const () as u64);
            // Task termination handler for when entry point returns
            stack_ptr.offset(-1).write(task_exit as *const () as u64);
        }

        Ok((mapping, bounds, size_of::<TaskContext>() + size_of::<u64>()))
    }

    fn allocate_utask_stack(
        cpu: &mut PerCpu,
        user_entry: usize,
    ) -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>, usize), SvsmError> {
        let (mapping, bounds) = Task::allocate_stack_common()?;

        let percpu_mapping = cpu.new_mapping(mapping.clone())?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_ptr = (percpu_mapping.virt_addr() + bounds.end().bits()).as_mut_ptr::<u8>();

        let mut stack_offset = size_of::<X86ExceptionContext>();

        // 'Push' the task frame onto the stack
        unsafe {
            // Setup IRQ return frame
            let mut iret_frame = X86ExceptionContext::default();
            iret_frame.frame.rip = user_entry;
            iret_frame.frame.cs = (SVSM_USER_CS | 3).into();
            iret_frame.frame.flags = 0;
            iret_frame.frame.rsp = (USER_MEM_END - 8).into();
            iret_frame.frame.ss = (SVSM_USER_DS | 3).into();

            // Copy IRET frame to stack
            let stack_iret_frame = stack_ptr.sub(stack_offset).cast::<X86ExceptionContext>();
            *stack_iret_frame = iret_frame;

            stack_offset += size_of::<TaskContext>();

            let task_context = TaskContext {
                ret_addr: VirtAddr::from(default_return as *const ())
                    .bits()
                    .try_into()
                    .unwrap(),
                ..Default::default()
            };
            let stack_task_context = stack_ptr.sub(stack_offset).cast::<TaskContext>();
            *stack_task_context = task_context;
        }

        Ok((mapping, bounds, stack_offset))
    }

    pub fn mmap_common(
        vmr: &VMR,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        let mapping = if let Some(f) = file {
            create_file_mapping(f, offset, size, flags)?
        } else {
            create_anon_mapping(size, flags)?
        };

        if flags.contains(VMFileMappingFlags::Fixed) {
            Ok(vmr.insert_at(addr, mapping)?)
        } else {
            Ok(vmr.insert_hint(addr, mapping)?)
        }
    }

    pub fn mmap_kernel(
        &self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        Self::mmap_common(&self.vm_kernel_range, addr, file, offset, size, flags)
    }

    pub fn mmap_kernel_guard<'a>(
        &'a self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VMMappingGuard<'a>, SvsmError> {
        let vaddr = Self::mmap_common(&self.vm_kernel_range, addr, file, offset, size, flags)?;
        Ok(VMMappingGuard::new(&self.vm_kernel_range, vaddr))
    }

    pub fn mmap_user(
        &self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        if self.vm_user_range.is_none() {
            return Err(SvsmError::Mem);
        }

        let vmr = self.vm_user_range.as_ref().unwrap();

        Self::mmap_common(vmr, addr, file, offset, size, flags)
    }

    pub fn munmap_kernel(&self, addr: VirtAddr) -> Result<(), SvsmError> {
        self.vm_kernel_range.remove(addr)?;
        Ok(())
    }

    pub fn munmap_user(&self, addr: VirtAddr) -> Result<(), SvsmError> {
        if self.vm_user_range.is_none() {
            return Err(SvsmError::Mem);
        }

        self.vm_user_range.as_ref().unwrap().remove(addr)?;
        Ok(())
    }
}

pub fn is_task_fault(vaddr: VirtAddr) -> bool {
    (vaddr >= USER_MEM_START && vaddr < USER_MEM_END)
        || (vaddr >= SVSM_PERTASK_BASE && vaddr < SVSM_PERTASK_END)
}

extern "C" fn task_exit() {
    unsafe {
        current_task_terminated();
    }
    schedule();
}

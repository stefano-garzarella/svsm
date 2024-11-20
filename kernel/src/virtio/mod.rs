// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>

extern crate alloc;
use crate::locking::SpinLock;
use alloc::vec::Vec;
use core::{
    cell::OnceCell,
    ptr::{addr_of, NonNull},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use virtio_drivers::{
    device::blk::{VirtIOBlk, SECTOR_SIZE},
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        DeviceType, Transport,
    },
};

use crate::{
    address::{PhysAddr, VirtAddr},
    cpu::{self, percpu::this_cpu},
    mm::{page_visibility::*, *},
};

struct PageStore {
    pages: Vec<(PhysAddr, SharedBox<[u8; PAGE_SIZE]>)>,
}

impl PageStore {
    pub fn new() -> Self {
        PageStore { pages: Vec::new() }
    }

    pub fn push(&mut self, pa: PhysAddr, shared_page: SharedBox<[u8; PAGE_SIZE]>) {
        self.pages.push((pa, shared_page));
    }

    pub fn pop(&mut self, pa: PhysAddr) -> Option<SharedBox<[u8; PAGE_SIZE]>> {
        if let Some(p) = self.pages.iter().position(|e| e.0 == pa) {
            Some(self.pages.remove(p).1)
        } else {
            None
        }
    }
}

static SHARED_MEM: SpinLock<OnceCell<PageStore>> = SpinLock::new(OnceCell::new());

pub fn virtio_init() {
    SHARED_MEM.lock().get_or_init(|| PageStore::new());
}

struct SvsmHal;

/// Implementation of virtio-drivers MMIO hardware abstraction for AMD SEV-SNP
/// in the Coconut-SVSM context. Due to missing #VC handler for MMIO, use ghcb exits
/// instead.
unsafe impl virtio_drivers::Hal for SvsmHal {
    fn dma_alloc(
        pages: usize,
        _direction: virtio_drivers::BufferDirection,
    ) -> (virtio_drivers::PhysAddr, NonNull<u8>) {
        // TODO: allow more than one page.
        //       This currently works, becasue in "modern" virtio mode the crate only allocates
        //       one page at a time.
        assert!(pages == 1);

        let shared_page = SharedBox::<[u8; PAGE_SIZE]>::try_new_zeroed().unwrap();
        let pa = virt_to_phys(shared_page.addr());
        let p = unsafe { NonNull::<u8>::new_unchecked(shared_page.addr().as_mut_ptr()) };

        SHARED_MEM.lock().get_mut().unwrap().push(pa, shared_page);

        (pa.into(), p)
    }

    unsafe fn dma_dealloc(
        paddr: virtio_drivers::PhysAddr,
        _vaddr: NonNull<u8>,
        pages: usize,
    ) -> i32 {
        //TODO: allow more than one page
        assert!(pages == 1);

        SHARED_MEM
            .lock()
            .get_mut()
            .unwrap()
            .pop(paddr.into())
            .unwrap();

        0
    }

    unsafe fn mmio_phys_to_virt(paddr: virtio_drivers::PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(phys_to_virt(paddr.into()).as_mut_ptr())
            .expect("Error getting VirtAddr from PhysAddr")
    }

    unsafe fn share(
        buffer: NonNull<[u8]>,
        direction: virtio_drivers::BufferDirection,
    ) -> virtio_drivers::PhysAddr {
        // TODO: allow more than one page
        assert!(buffer.len() <= PAGE_SIZE);

        let shared_page = SharedBox::<[u8; PAGE_SIZE]>::try_new_zeroed().unwrap();

        if direction == virtio_drivers::BufferDirection::DriverToDevice {
            unsafe {
                // copy from buffer to shared page
                let src = buffer.as_ptr().cast::<u8>();
                let dst = shared_page.addr().as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(src, dst, buffer.len());
            }
        }

        let pa = virt_to_phys(shared_page.addr());
        SHARED_MEM.lock().get_mut().unwrap().push(pa, shared_page);

        // return pa of shared page
        pa.into()
    }

    unsafe fn unshare(
        paddr: virtio_drivers::PhysAddr,
        buffer: NonNull<[u8]>,
        direction: virtio_drivers::BufferDirection,
    ) {
        assert!(buffer.len() <= PAGE_SIZE);

        if let Some(shared_page) = SHARED_MEM.lock().get_mut().unwrap().pop(paddr.into()) {
            let vaddr = phys_to_virt(paddr.into());
            let va_from_shared = shared_page.addr();
            assert!(vaddr == va_from_shared);

            if direction == virtio_drivers::BufferDirection::DeviceToDriver {
                unsafe {
                    let dst = buffer.as_ptr().cast::<u8>();
                    let src = vaddr.as_mut_ptr::<u8>();
                    core::ptr::copy_nonoverlapping(src, dst, buffer.len());
                }
            }
        } else {
            panic!("unshare: No shared page found at given pa");
        }
        // implicit drop of share_page here.
    }

    unsafe fn mmio_read<T: FromBytes + Immutable>(src: &T) -> T {
        let paddr = this_cpu()
            .get_pgtable()
            .phys_addr(VirtAddr::from(addr_of!(*src)))
            .unwrap();

        cpu::percpu::current_ghcb()
            .mmio_read::<T>(paddr)
            .expect("GHCB MMIO Read failed")
    }

    unsafe fn mmio_write<T: IntoBytes + Immutable>(dst: &mut T, v: T) {
        let paddr = this_cpu()
            .get_pgtable()
            .phys_addr(VirtAddr::from(addr_of!(*dst)))
            .unwrap();

        cpu::percpu::current_ghcb()
            .mmio_write::<T>(paddr, &v)
            .expect("GHCB MMIO Write failed");
    }
}

/// virtio-blk via mmio demo.
pub fn test_mmio() {
    static MMIO_BASE: u64 = 0xfef03000; // Hard-coded in Qemu

    let paddr = PhysAddr::from(MMIO_BASE);
    let mem = PerCPUPageMappingGuard::create_4k(paddr).expect("Error mapping MMIO region");

    log::info!(
        "mapped MMIO range {:016x} to vaddr {:016x}",
        MMIO_BASE,
        mem.virt_addr()
    );
    // Test code below taken from virtio-drivers aarch64 example.
    let header = NonNull::new(mem.virt_addr().as_mut_ptr() as *mut VirtIOHeader).unwrap();
    match unsafe { MmioTransport::<SvsmHal>::new(header) } {
        Err(e) => log::warn!(
            "Error creating VirtIO MMIO transport at {:016x}: {}",
            MMIO_BASE,
            e
        ),
        Ok(transport) => {
            log::info!(
                target: "virtio",
                "Detected virtio MMIO device with vendor id {:#X}, device type {:?}, version {:?}",
                transport.vendor_id(),
                transport.device_type(),
                transport.version(),
            );
            match transport.device_type() {
                DeviceType::Block => virtio_blk(transport),
                t => log::warn!(target: "virtio", "Unrecognized virtio device: {:?}", t),
            }
        }
    }

    log::info!(target: "virtio", "Virtio test end");
}

/// Run some basic smoke tests on the virtio-blk device
fn virtio_blk<T: Transport>(transport: T) {
    let mut blk = VirtIOBlk::<SvsmHal, T>::new(transport).expect("Failed to create blk driver");
    assert!(!blk.readonly());

    // IO Tests copied from virtio-drivers example
    {
        log::info!("Write+Read Test Start");
        let mut input = [0xffu8; 512];
        let mut output = [0; 512];
        for i in 0..32 {
            for x in input.iter_mut() {
                *x = i as u8;
            }
            blk.write_blocks(i, &input).expect("failed to write");
            blk.read_blocks(i, &mut output).expect("failed to read");
            assert_eq!(input, output);
        }
        log::info!("Write+Read Test End");
    }

    // Write Speed Benchmark. Requires external time measurement.
    {
        log::info!("Write Benchmark Start");
        const MAX_SIZE: usize = 4096;
        let input = [0xffu8; MAX_SIZE];
        let capacity = blk.capacity() as usize * SECTOR_SIZE;
        const REWRITES: usize = 1;

        for write_size in [512, 4096] {
            assert!(write_size <= MAX_SIZE);
            let n_blocks = capacity / write_size;

            log::info!("virtio-blk start write. Block size = {}", write_size);
            for _ in 0..REWRITES {
                for block in 0..n_blocks {
                    blk.write_blocks(block * write_size / SECTOR_SIZE, &input[0..write_size])
                        .expect("Write Error");
                }
            }
            log::info!(
                "virtio-blk end write. Block size = {}, Total bytes = {}",
                write_size,
                write_size * n_blocks * REWRITES
            );
        }
        log::info!("Write Benchmark End");
    }
}

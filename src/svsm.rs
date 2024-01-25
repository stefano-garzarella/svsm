// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use svsm::fw_meta::{print_fw_meta, validate_fw_memory, SevFWMetaData};

use bootlib::kernel_launch::KernelLaunchInfo;
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use svsm::address::{PhysAddr, VirtAddr};
use svsm::config::SvsmConfig;
use svsm::console::{init_console, install_console_logger, WRITER};
use svsm::cpu::control_regs::{cr0_init, cr4_init};
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::efer::efer_init;
use svsm::cpu::gdt::load_gdt;
use svsm::cpu::idt::svsm::{early_idt_init, idt_init};
use svsm::cpu::percpu::PerCpu;
use svsm::cpu::percpu::{this_cpu, this_cpu_mut};
use svsm::cpu::smp::start_secondary_cpus;
use svsm::debug::gdbstub::svsm_gdbstub::{debug_break, gdbstub_start};
use svsm::debug::stacktrace::print_stack;
use svsm::elf;
use svsm::error::SvsmError;
use svsm::fs::{initialize_fs, populate_ram_fs};
use svsm::fw_cfg::FwCfg;
use svsm::greq::driver::guest_request_driver_init;
use svsm::igvm_params::IgvmParams;
use svsm::kbc;
use svsm::kernel_region::new_kernel_region;
use svsm::mm::alloc::{memory_info, print_memory_info, root_mem_init};
use svsm::mm::memory::init_memory_map;
use svsm::mm::pagetable::paging_init;
use svsm::mm::virtualrange::virt_log_usage;
use svsm::mm::{init_kernel_mapping_info, PerCPUPageMappingGuard};
use svsm::requests::{request_loop, update_mappings};
use svsm::serial::SerialPort;
use svsm::sev::secrets_page::{copy_secrets_page, disable_vmpck0, SecretsPage};
use svsm::sev::utils::{rmp_adjust, RMPFlags};
use svsm::sev::{init_hypervisor_ghcb_features, sev_status_init};
use svsm::svsm_console::SVSMIOPort;
use svsm::svsm_paging::{init_page_table, invalidate_early_boot_memory};
use svsm::task::{create_task, TASK_FLAG_SHARE_PT};
use svsm::types::{PageSize, GUEST_VMPL, PAGE_SIZE};
use svsm::utils::{halt, immut_after_init::ImmutAfterInitCell, zero_mem_region};

use svsm::mm::validate::{init_valid_bitmap_ptr, migrate_valid_bitmap};

use alloc::format;
use core::ptr;

extern "C" {
    pub static mut SECRETS_PAGE: SecretsPage;
    pub static bsp_stack_end: u8;
}

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %r8  Pointer to the KernelLaunchInfo structure
 * %r9  Pointer to the valid-bitmap from stage2
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code64

        .globl  startup_64
    startup_64:
        /* Setup stack */
        leaq bsp_stack_end(%rip), %rsp

        /* Jump to rust code */
        movq    %r8, %rdi
        movq    %r9, %rsi
        jmp svsm_start

        .bss

        .align 4096
    bsp_stack:
        .fill 4*4096, 1, 0
    bsp_stack_end:

        .align 4096
        .globl SECRETS_PAGE
    SECRETS_PAGE:
        .fill 4096, 1, 0
        "#,
    options(att_syntax)
);

static CPUID_PAGE: ImmutAfterInitCell<SnpCpuidTable> = ImmutAfterInitCell::uninit();
static LAUNCH_INFO: ImmutAfterInitCell<KernelLaunchInfo> = ImmutAfterInitCell::uninit();

fn copy_cpuid_table_to_fw(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let start = guard.virt_addr();
    let end = start + PAGE_SIZE;

    let target = ptr::NonNull::new(start.as_mut_ptr::<SnpCpuidTable>()).unwrap();

    // Zero target
    zero_mem_region(start, end);

    // Copy data
    unsafe {
        let dst = target.as_ptr();
        *dst = *CPUID_PAGE;
    }

    Ok(())
}

fn copy_secrets_page_to_fw(fw_addr: PhysAddr, caa_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let start = guard.virt_addr();

    let mut target = ptr::NonNull::new(start.as_mut_ptr::<SecretsPage>()).unwrap();

    // Zero target
    unsafe {
        let mut page_ptr = target.cast::<u8>();
        ptr::write_bytes(page_ptr.as_mut(), 0, PAGE_SIZE);
    }

    // Copy and initialize data
    unsafe {
        let dst = target.as_ptr();
        *dst = SECRETS_PAGE;

        // Copy Table
        let fw_sp = target.as_mut();

        // Zero VMPCK key for VMPLs with more privileges than the guest
        for vmpck in fw_sp.vmpck.iter_mut().take(GUEST_VMPL) {
            vmpck.fill(0);
        }

        let &li = &*LAUNCH_INFO;

        fw_sp.svsm_base = li.kernel_region_phys_start;
        fw_sp.svsm_size = li.kernel_region_phys_end - li.kernel_region_phys_start;
        fw_sp.svsm_caa = u64::from(caa_addr);
        fw_sp.svsm_max_version = 1;
        fw_sp.svsm_guest_vmpl = GUEST_VMPL as u8;
    }

    Ok(())
}

fn zero_caa_page(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let vaddr = guard.virt_addr();

    zero_mem_region(vaddr, vaddr + PAGE_SIZE);

    Ok(())
}

pub fn copy_tables_to_fw(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
    if let Some(addr) = fw_meta.cpuid_page {
        copy_cpuid_table_to_fw(addr)?;
    }

    let secrets_page = match fw_meta.secrets_page {
        Some(addr) => addr,
        None => panic!("FW does not specify SECRETS_PAGE location"),
    };

    let caa_page = match fw_meta.caa_page {
        Some(addr) => addr,
        None => panic!("FW does not specify CAA_PAGE location"),
    };

    copy_secrets_page_to_fw(secrets_page, caa_page)?;

    zero_caa_page(caa_page)?;

    Ok(())
}

fn prepare_fw_launch(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
    let cpu = this_cpu_mut();

    if let Some(caa) = fw_meta.caa_page {
        cpu.shared.update_guest_caa(caa);
    }

    cpu.alloc_guest_vmsa()?;
    update_mappings()?;

    Ok(())
}

fn launch_fw(config: &SvsmConfig) -> Result<(), SvsmError> {
    let vmsa_pa = this_cpu_mut().guest_vmsa_ref().vmsa_phys().unwrap();
    let vmsa = this_cpu_mut().guest_vmsa();

    config.initialize_guest_vmsa(vmsa);

    log::info!("VMSA PA: {:#x}", vmsa_pa);

    let sev_features = vmsa.sev_features;

    log::info!("Launching Firmware");
    this_cpu_mut()
        .ghcb()
        .register_guest_vmsa(vmsa_pa, 0, GUEST_VMPL as u64, sev_features)?;

    Ok(())
}

fn validate_fw(config: &SvsmConfig, launch_info: &KernelLaunchInfo) -> Result<(), SvsmError> {
    let kernel_region = new_kernel_region(launch_info);
    let flash_regions = config.get_fw_regions(&kernel_region);

    for (i, region) in flash_regions.into_iter().enumerate() {
        log::info!(
            "Flash region {} at {:#018x} size {:018x}",
            i,
            region.start(),
            region.len(),
        );

        for paddr in region.iter_pages(PageSize::Regular) {
            let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
            let vaddr = guard.virt_addr();
            if let Err(e) = rmp_adjust(
                vaddr,
                RMPFlags::GUEST_VMPL | RMPFlags::RWX,
                PageSize::Regular,
            ) {
                log::info!("rmpadjust failed for addr {:#018x}", vaddr);
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn memory_init(launch_info: &KernelLaunchInfo) {
    root_mem_init(
        PhysAddr::from(launch_info.heap_area_phys_start),
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_size() as usize / PAGE_SIZE,
    );
}

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();
static CONSOLE_SERIAL: ImmutAfterInitCell<SerialPort> = ImmutAfterInitCell::uninit();

pub fn boot_stack_info() {
    unsafe {
        let vaddr = VirtAddr::from(&bsp_stack_end as *const u8);
        log::info!("Boot stack starts        @ {:#018x}", vaddr);
    }
}

fn mapping_info_init(launch_info: &KernelLaunchInfo) {
    init_kernel_mapping_info(
        VirtAddr::from(launch_info.heap_area_virt_start),
        VirtAddr::from(launch_info.heap_area_virt_end()),
        PhysAddr::from(launch_info.heap_area_phys_start),
    );
}

#[no_mangle]
pub extern "C" fn svsm_start(li: &KernelLaunchInfo, vb_addr: usize) {
    let launch_info: KernelLaunchInfo = *li;
    let vb_ptr = VirtAddr::new(vb_addr).as_mut_ptr::<u64>();

    mapping_info_init(&launch_info);

    init_valid_bitmap_ptr(new_kernel_region(&launch_info), vb_ptr);

    load_gdt();
    early_idt_init();

    // Capture the debug serial port before the launch info disappears from
    // the address space.
    let debug_serial_port = li.debug_serial_port;

    LAUNCH_INFO
        .init(li)
        .expect("Already initialized launch info");

    let cpuid_table_virt = VirtAddr::from(launch_info.cpuid_page);
    unsafe {
        CPUID_PAGE
            .init(&*(cpuid_table_virt.as_ptr::<SnpCpuidTable>()))
            .expect("Already initialized CPUID page")
    };
    register_cpuid_table(&CPUID_PAGE);
    dump_cpuid_table();

    unsafe {
        let secrets_page_virt = VirtAddr::from(launch_info.secrets_page);
        copy_secrets_page(&mut SECRETS_PAGE, secrets_page_virt);
        zero_mem_region(secrets_page_virt, secrets_page_virt + PAGE_SIZE);
    }

    cr0_init();
    cr4_init();
    efer_init();
    sev_status_init();

    memory_init(&launch_info);
    migrate_valid_bitmap().expect("Failed to migrate valid-bitmap");

    let kernel_elf_len = (launch_info.kernel_elf_stage2_virt_end
        - launch_info.kernel_elf_stage2_virt_start) as usize;
    let kernel_elf_buf_ptr = launch_info.kernel_elf_stage2_virt_start as *const u8;
    let kernel_elf_buf = unsafe { slice::from_raw_parts(kernel_elf_buf_ptr, kernel_elf_len) };
    let kernel_elf = match elf::Elf64File::read(kernel_elf_buf) {
        Ok(kernel_elf) => kernel_elf,
        Err(e) => panic!("error reading kernel ELF: {}", e),
    };

    paging_init();
    init_page_table(&launch_info, &kernel_elf);

    unsafe {
        let bsp_percpu = PerCpu::alloc(0)
            .expect("Failed to allocate BSP per-cpu data")
            .as_mut()
            .unwrap();

        bsp_percpu
            .setup()
            .expect("Failed to setup BSP per-cpu area");
        bsp_percpu
            .setup_on_cpu()
            .expect("Failed to run percpu.setup_on_cpu()");
        bsp_percpu.load();
    }
    idt_init();

    CONSOLE_SERIAL
        .init(&SerialPort {
            driver: &CONSOLE_IO,
            port: debug_serial_port,
        })
        .expect("console serial output already configured");

    WRITER.lock().set(&*CONSOLE_SERIAL);
    init_console();
    install_console_logger("SVSM");

    log::info!("COCONUT Secure Virtual Machine Service Module (SVSM)");

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    boot_stack_info();

    let bp = this_cpu().get_top_of_stack();

    log::info!("BSP Runtime stack starts @ {:#018x}", bp);

    // Create the root task that runs the entry point then handles the request loop
    create_task(
        svsm_main,
        TASK_FLAG_SHARE_PT,
        Some(this_cpu().get_apic_id()),
    )
    .expect("Failed to create initial task");

    panic!("SVSM entry point terminated unexpectedly");
}

#[no_mangle]
pub extern "C" fn svsm_main() {
    // If required, the GDB stub can be started earlier, just after the console
    // is initialised in svsm_start() above.
    gdbstub_start().expect("Could not start GDB stub");
    // Uncomment the line below if you want to wait for
    // a remote GDB connection
    //debug_break();

    init_hypervisor_ghcb_features().expect("Failed to obtain hypervisor GHCB features");

    let launch_info = &*LAUNCH_INFO;
    let config = if launch_info.igvm_params_virt_addr != 0 {
        let igvm_params = IgvmParams::new(VirtAddr::from(launch_info.igvm_params_virt_addr));
        SvsmConfig::IgvmConfig(igvm_params)
    } else {
        SvsmConfig::FirmwareConfig(FwCfg::new(&CONSOLE_IO))
    };

    init_memory_map(&config, &LAUNCH_INFO).expect("Failed to init guest memory map");

    initialize_fs();

    populate_ram_fs(LAUNCH_INFO.kernel_fs_start, LAUNCH_INFO.kernel_fs_end)
        .expect("Failed to unpack FS archive");

    invalidate_early_boot_memory(&config, launch_info)
        .expect("Failed to invalidate early boot memory");

    let cpus = config.load_cpu_info().expect("Failed to load ACPI tables");
    let mut nr_cpus = 0;

    for cpu in cpus.iter() {
        if cpu.enabled {
            nr_cpus += 1;
        }
    }

    log::info!("{} CPU(s) present", nr_cpus);

    start_secondary_cpus(&cpus);

    let fw_metadata = config.get_fw_metadata();
    if let Some(ref fw_meta) = fw_metadata {
        print_fw_meta(fw_meta);

        if let Err(e) = validate_fw_memory(&config, fw_meta, &LAUNCH_INFO) {
            panic!("Failed to validate firmware memory: {:#?}", e);
        }

        if let Err(e) = copy_tables_to_fw(fw_meta) {
            panic!("Failed to copy firmware tables: {:#?}", e);
        }

        if let Err(e) = validate_fw(&config, &LAUNCH_INFO) {
            panic!("Failed to validate flash memory: {:#?}", e);
        }
    }

    guest_request_driver_init();

    use svsm::greq::services::get_report_ex;

    log::info!("Getting report");
    let res = get_report_ex(&[0u8; 64]);
    match res {
        Ok((report, certs)) => {
            log::info!("Got a report: {:02x?}", &report);
            log::info!("Got Certs {:02x?}", &certs[..64]);

            let measurement_string = report.measurement.map(|v| format!("{v:02x}")).join("");
            log::info!("SNP Launch Measurement: {measurement_string}");
        }
        Err(e) => log::info!("Error getting attestation report: {e:?}"),
    }

    match kbc::get_secret("svsm") {
        Ok(secret) => log::info!("Got the secret: {secret}"),
        Err(e) => log::error!("Error doing remote attestation: {e:?}"),
    }

    if let Some(ref fw_meta) = fw_metadata {
        prepare_fw_launch(fw_meta).expect("Failed to setup guest VMSA/CAA");
    }

    virt_log_usage();

    if config.should_launch_fw() {
        if let Err(e) = launch_fw(&config) {
            panic!("Failed to launch FW: {:#?}", e);
        }
    }

    #[cfg(test)]
    crate::test_main();

    request_loop();

    panic!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    disable_vmpck0();

    log::error!("Panic: CPU[{}] {}", this_cpu().get_apic_id(), info);

    print_stack(3);

    loop {
        debug_break();
        halt();
    }
}

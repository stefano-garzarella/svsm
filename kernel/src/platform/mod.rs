// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::io::IOPort;
use crate::platform::native::NativePlatform;
use crate::platform::snp::SnpPlatform;
use crate::platform::tdp::TdpPlatform;
use crate::types::PageSize;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;

use bootlib::platform::SvsmPlatformType;

pub mod guest_cpu;
pub mod native;
pub mod snp;
pub mod tdp;

pub static SVSM_PLATFORM: ImmutAfterInitCell<SvsmPlatformCell> = ImmutAfterInitCell::uninit();

#[derive(Clone, Copy, Debug)]
pub struct PageEncryptionMasks {
    pub private_pte_mask: usize,
    pub shared_pte_mask: usize,
    pub addr_mask_width: u32,
    pub phys_addr_sizes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PageStateChangeOp {
    Private,
    Shared,
    Psmash,
    Unsmash,
}

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform {
    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self, debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError>;

    /// Performs initialization of the platform runtime environment after
    /// the core system environment has been initialized.
    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError>;

    /// Performs initialiation of the environment specfic to the SVSM kernel
    /// (for services not used by stage2).
    fn env_setup_svsm(&self) -> Result<(), SvsmError>;

    /// Completes initialization of a per-CPU object during construction.
    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Completes initialization of a per-CPU object on the target CPU.
    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Determines the paging encryption masks for the current architecture.
    fn get_page_encryption_masks(&self) -> PageEncryptionMasks;

    /// Obtain CPUID using platform-specific tables.
    fn cpuid(&self, eax: u32) -> Option<CpuidResult>;

    /// Establishes state required for guest/host communication.
    fn setup_guest_host_comm(&mut self, cpu: &PerCpu, is_bsp: bool);

    /// Obtains a reference to an I/O port implemetation appropriate to the
    /// platform.
    fn get_io_port(&self) -> &'static dyn IOPort;

    /// Performs a page state change between private and shared states.
    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError>;

    /// Marks a range of pages as valid for use as private pages.
    fn validate_page_range(&self, region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError>;

    /// Marks a range of pages as invalid for use as private pages.
    fn invalidate_page_range(&self, region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError>;

    /// Configures the use of alternate injection as requested.
    fn configure_alternate_injection(&mut self, alt_inj_requested: bool) -> Result<(), SvsmError>;

    /// Changes the state of APIC registration on this system, returning either
    /// the current registration state or an error.
    fn change_apic_registration_state(&self, incr: bool) -> Result<bool, SvsmError>;

    /// Queries the state of APIC registration on this system.
    fn query_apic_registration_state(&self) -> bool;

    /// Signal an IRQ on one or more CPUs.
    fn post_irq(&self, icr: u64) -> Result<(), SvsmError>;

    /// Perform an EOI of the current interrupt.
    fn eoi(&self);
}

//FIXME - remove Copy trait
#[derive(Clone, Copy, Debug)]
pub enum SvsmPlatformCell {
    Snp(SnpPlatform),
    Tdp(TdpPlatform),
    Native(NativePlatform),
}

impl SvsmPlatformCell {
    pub fn new(platform_type: SvsmPlatformType) -> Self {
        match platform_type {
            SvsmPlatformType::Native => SvsmPlatformCell::Native(NativePlatform::new()),
            SvsmPlatformType::Snp => SvsmPlatformCell::Snp(SnpPlatform::new()),
            SvsmPlatformType::Tdp => SvsmPlatformCell::Tdp(TdpPlatform::new()),
        }
    }

    pub fn as_dyn_ref(&self) -> &dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }

    pub fn as_mut_dyn_ref(&mut self) -> &mut dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }
}

extern crate alloc;

use alloc::{format, string::String};

use core::{slice::from_raw_parts_mut};

use crate::address::{Address, PhysAddr};
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::{valid_phys_address,GuestPtr};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::types::{PAGE_SIZE};

fn custom_call(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);

    if paddr.is_null() {
        return Err(SvsmReqError::invalid_parameter());
    }
    if !valid_phys_address(paddr) {
        return Err(SvsmReqError::invalid_address());
    }

    // The buffer size is one page, but it not required to be page aligned.
    let start = paddr.page_align();
    let offset = paddr.page_offset();
    let end = (paddr + PAGE_SIZE).page_align_up();

    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr_count = guard.virt_addr() + offset;
    let vaddr_buffer = vaddr_count + 8;

    // SAFETY: vaddr comes from a new mapped region.
    let count = unsafe { GuestPtr::<u64>::new(vaddr_count).read() ? };

    // SAFETY: vaddr comes from a new mapped region.
    let buffer = unsafe { from_raw_parts_mut(vaddr_buffer.as_mut_ptr::<u8>(), count as usize) };

    let buf_string: String = buffer.iter().map(|v| format!("{v:02x}")).collect();
    log::info!("Custom call - size {} buffer {}", count, buf_string);

    Ok(())
}

pub fn custom_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        0 => custom_call(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}


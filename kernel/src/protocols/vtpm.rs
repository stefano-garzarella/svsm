// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM Corp
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! vTPM protocol implementation (SVSM spec, chapter 8).

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    address::{Address, PhysAddr, VirtAddr},
    mm::{valid_phys_address, GuestPtr, PerCPUPageMappingGuard},
    protocols::{errors::SvsmReqError, RequestParams},
    types::PAGE_SIZE,
    vtpm::{vtpm_get_locked, MsTpmSimulatorInterface, VtpmProtocolInterface},
};

/// vTPM platform commands (SVSM spec, section 8.1 - SVSM_VTPM_QUERY)
///
/// The platform commmand values follow the values used by the
/// Official TPM 2.0 Reference Implementation by Microsoft.
///
/// `ms-tpm-20-ref/TPMCmd/Simulator/include/TpmTcpProtocol.h`
#[repr(u32)]
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum TpmPlatformCommand {
    SendCommand = 8,
}

impl TryFrom<u32> for TpmPlatformCommand {
    type Error = SvsmReqError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let cmd = match value {
            x if x == TpmPlatformCommand::SendCommand as u32 => TpmPlatformCommand::SendCommand,
            other => {
                log::warn!("Failed to convert {} to a TPM platform command", other);
                return Err(SvsmReqError::invalid_parameter());
            }
        };

        Ok(cmd)
    }
}

fn vtpm_platform_commands_supported_bitmap() -> u64 {
    let mut bitmap: u64 = 0;
    let vtpm = vtpm_get_locked();

    for cmd in vtpm.get_supported_commands() {
        bitmap |= 1u64 << *cmd as u32;
    }

    bitmap
}

fn is_vtpm_platform_command_supported(cmd: TpmPlatformCommand) -> bool {
    let vtpm = vtpm_get_locked();
    vtpm.get_supported_commands().iter().any(|x| *x == cmd)
}

const SEND_COMMAND_REQ_INBUF_SIZE: usize = PAGE_SIZE - 9;

// vTPM protocol services (SVSM spec, table 14)
const SVSM_VTPM_QUERY: u32 = 0;
const SVSM_VTPM_COMMAND: u32 = 1;

/// TPM_SEND_COMMAND request structure (SVSM spec, table 16)
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct TpmSendCommandRequest {
    /// MSSIM platform command ID
    command: u32,
    /// Locality usage for the vTPM is not defined yet (must be zero)
    locality: u8,
    /// Size of the input buffer
    inbuf_size: u32,
    /// Input buffer that contains the TPM command
    inbuf: [u8; SEND_COMMAND_REQ_INBUF_SIZE],
}

impl TpmSendCommandRequest {
    pub fn send(&self) -> Result<Vec<u8>, SvsmReqError> {
        // TODO: Before implementing locality, we need to agree what it means
        // to the platform
        if self.locality != 0 {
            return Err(SvsmReqError::invalid_parameter());
        }

        let mut length = self.inbuf_size as usize;

        let tpm_cmd = self
            .inbuf
            .get(..length)
            .ok_or_else(SvsmReqError::invalid_parameter)?;
        let mut buffer: Vec<u8> = Vec::with_capacity(SEND_COMMAND_RESP_OUTBUF_SIZE);
        buffer.extend_from_slice(tpm_cmd);

        // The buffer slice must be large enough to hold the TPM command response
        unsafe { buffer.set_len(buffer.capacity()) };

        let vtpm = vtpm_get_locked();
        vtpm.send_tpm_command(buffer.as_mut_slice(), &mut length, self.locality)?;

        unsafe {
            if length > buffer.capacity() {
                return Err(SvsmReqError::invalid_request());
            }
            buffer.set_len(length);
        }

        Ok(buffer)
    }
}

const SEND_COMMAND_RESP_OUTBUF_SIZE: usize = PAGE_SIZE - 4;

/// TPM_SEND_COMMAND response structure (SVSM spec, table 17)
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct TpmSendCommandResponse {
    /// Size of the output buffer
    outbuf_size: u32,
    /// Output buffer that will hold the command response
    outbuf: [u8; SEND_COMMAND_RESP_OUTBUF_SIZE],
}

impl TpmSendCommandResponse {
    /// Write the response to the outbuf
    ///
    /// # Arguments
    ///
    /// * `response`: TPM_SEND_COMMAND response slice
    pub fn set_outbuf(&mut self, response: &[u8]) -> Result<(), SvsmReqError> {
        self.outbuf
            .get_mut(..response.len())
            .ok_or_else(SvsmReqError::invalid_request)?
            .copy_from_slice(response);
        self.outbuf_size = response.len() as u32;

        Ok(())
    }
}

fn vtpm_query_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Bitmap of the supported vTPM commands
    params.rcx = vtpm_platform_commands_supported_bitmap();
    // Supported vTPM features. Must-be-zero
    params.rdx = 0;

    Ok(())
}

fn tpm_send_command_request(iobuf: VirtAddr) -> Result<u32, SvsmReqError> {
    let outbuf: Vec<u8> = {
        let request = unsafe { &*iobuf.as_mut_ptr::<TpmSendCommandRequest>() };
        request.send()?
    };
    let response = unsafe { &mut *iobuf.as_mut_ptr::<TpmSendCommandResponse>() };
    let _ = response.set_outbuf(outbuf.as_slice());

    Ok(outbuf.len() as u32)
}

fn vtpm_command_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);

    if paddr.is_null() {
        return Ok(());
        // FIXME: Return Invalid Parameter when TPM drivers are
        //        able to probe the SVSM vTPM using the
        //        SVSM_VTPM_QUERY runtime protocol
        //
        // return Err(SvsmReqError::invalid_parameter());
    }
    if !valid_phys_address(paddr) {
        return Err(SvsmReqError::invalid_address());
    }

    // The vTPM buffer size is one page, but it not required to be page aligned.
    let start = paddr.page_align();
    let offset = paddr.page_offset();
    let end = (paddr + PAGE_SIZE).page_align_up();

    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr = guard.virt_addr() + offset;

    // vTPM common request/response structure (SVSM spec, table 15)
    //
    // First 4 bytes are used as input and output.
    //     IN: platform command
    //    OUT: platform command response size

    let guest_page = GuestPtr::<u32>::new(vaddr);
    let command = guest_page.read()?;
    let cmd = TpmPlatformCommand::try_from(command)?;

    if !is_vtpm_platform_command_supported(cmd) {
        return Err(SvsmReqError::unsupported_call());
    }

    let response_size = match cmd {
        TpmPlatformCommand::SendCommand => tpm_send_command_request(vaddr)?,
    };

    guest_page.write(response_size)?;

    Ok(())
}

pub fn vtpm_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_VTPM_QUERY => vtpm_query_request(params),
        SVSM_VTPM_COMMAND => vtpm_command_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}

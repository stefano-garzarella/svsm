// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! API to send `SNP_GUEST_REQUEST` commands to the PSP

extern crate alloc;

use alloc::boxed::Box;

use crate::{
    greq::{
        driver::{send_extended_guest_request, send_regular_guest_request},
        msg::SnpGuestRequestMsgType,
        pld_report::{SnpReportRequest, SnpReportResponse},
    },
    mm::page_memory::PageMemory,
    protocols::errors::SvsmReqError,
};
use core::mem::size_of;

use super::pld_report::AttestationReport;

const REPORT_REQUEST_SIZE: usize = size_of::<SnpReportRequest>();
const REPORT_RESPONSE_SIZE: usize = size_of::<SnpReportResponse>();

fn get_report(buffer: &mut [u8], certs: Option<&mut [u8]>) -> Result<usize, SvsmReqError> {
    let request: &SnpReportRequest = SnpReportRequest::try_from_as_ref(buffer)?;
    // Non-VMPL0 attestation reports can be requested by the guest kernel
    // directly to the PSP.
    if !request.is_vmpl0() {
        return Err(SvsmReqError::invalid_parameter());
    }
    let response_len = if certs.is_none() {
        send_regular_guest_request(
            SnpGuestRequestMsgType::ReportRequest,
            buffer,
            REPORT_REQUEST_SIZE,
        )?
    } else {
        send_extended_guest_request(
            SnpGuestRequestMsgType::ReportRequest,
            buffer,
            REPORT_REQUEST_SIZE,
            certs.unwrap(),
        )?
    };
    if REPORT_RESPONSE_SIZE > response_len {
        return Err(SvsmReqError::invalid_request());
    }
    let response: &SnpReportResponse = SnpReportResponse::try_from_as_ref(buffer)?;
    response.validate()?;

    Ok(response_len)
}

/// Request a regular VMPL0 attestation report to the PSP.
///
/// Use the `SNP_GUEST_REQUEST` driver to send the provided `MSG_REPORT_REQ` command to
/// the PSP. The VPML field of the command must be set to zero.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `buffer`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///             sent to the PSP. It must be large enough to hold the
///             [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
///
/// # Returns
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match the
///        [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
pub fn get_regular_report(buffer: &mut [u8]) -> Result<usize, SvsmReqError> {
    get_report(buffer, None)
}

/// Request an extended VMPL0 attestation report to the PSP.
///
/// We say that it is extended because it requests a VMPL0 attestation report
/// to the PSP (as in [`get_regular_report()`]) and also requests to the hypervisor
/// the certificates required to verify the attestation report.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `buffer`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///             sent to the PSP. It must be large enough to hold the
///             [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
/// * `certs`:  Buffer to store the SEV-SNP certificates received from the hypervisor.
///
/// # Return codes
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match
///                the [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
///     * `SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(certs_buffer_size, psp_rc)))`:
///         * `certs` is not large enough to hold the certificates.
///             * `certs_buffer_size`: number of bytes required.
///             * `psp_rc`: PSP return code
pub fn get_extended_report(buffer: &mut [u8], certs: &mut [u8]) -> Result<usize, SvsmReqError> {
    get_report(buffer, Some(certs))
}

#[derive(Debug, Clone, Copy)]
pub enum ReportError {
    RequestError(SvsmReqError),
    InvalidResponseSize(usize),
    NotImpl,
}

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

pub type ReportUserData = [u8; 64];

pub fn get_report_ex(
    user_data: &ReportUserData,
) -> Result<(Box<AttestationReport>, PageMemory), ReportError> {
    let mut request_buffer =
        PageMemory::new_zeroed(max(user_data.len(), size_of::<SnpReportResponse>()));
    request_buffer[..user_data.len()].clone_from_slice(user_data);

    let mut cert_buffer = PageMemory::new_zeroed(3 * crate::mm::PAGE_SIZE);

    match get_report(&mut request_buffer, Some(&mut cert_buffer)) {
        Ok(REPORT_RESPONSE_SIZE) => {
            let response = SnpReportResponse::try_from_as_ref(&request_buffer).unwrap();
            Ok((Box::new(response.report), cert_buffer))
        }
        Ok(wrong_size) => Err(ReportError::InvalidResponseSize(wrong_size)),
        Err(e) => Err(ReportError::RequestError(e)),
    }
}

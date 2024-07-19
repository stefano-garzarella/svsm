// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Red Hat, Inc. All rights reserved.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>

extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec};
use log::{error, info};
use raclients::{
    client_proxy::{Connection, Error as CPError, Proxy, Read, Write},
    in_proxy::client_session::ClientSessionGuest,
};

use crate::{
    greq::{
        pld_report::{AttestationReport, SnpReportResponse, USER_DATA_SIZE},
        services::get_regular_report,
    },
    serial::{SerialPort, Terminal},
    svsm_console::SVSMIOPort,
};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AutenticationFailed,
}

pub fn get_secret() -> Result<String, Error> {
    info!("KBC: Starting remote attestation protocol");

    static PROXY_IO: SVSMIOPort = SVSMIOPort::new();
    let sp: SerialPort<'_> = SerialPort::new(&PROXY_IO, 0x3e8 /*COM3*/);

    sp.init();

    let mut proxy = Proxy::new(Box::new(sp));

    let mut cs = ClientSessionGuest::new();

    let mut snp_report = vec![0; core::mem::size_of::<SnpReportResponse>()];
    // HACK: extend SnpReportRequest to get user_data slice
    let user_data = &mut snp_report[..USER_DATA_SIZE];

    info!("KBC: Negotiation");

    if let Err(e) = cs.negotiation(&mut proxy, user_data) {
        error!("KBC: Negotiation failed - {e}");
        return Err(Error::AutenticationFailed);
    }

    info!("KBC: Negotiation done");

    let user_data_string: String = user_data.iter().map(|v| format!("{v:02x}")).collect();
    info!("KBC: SNP Report Request - user_data: {user_data_string}");

    info!("KBC: Generating attestation report...");
    let size = get_regular_report(&mut snp_report).unwrap();
    info!("KBC: Generating attestation report... Done");

    assert_eq!(size, snp_report.len());

    let response = SnpReportResponse::try_from_as_ref(&snp_report).unwrap();
    let attestation = response.validate().unwrap();

    let measurement_string = attestation.measurement.map(|v| format!("{v:02x}")).join("");
    info!("KBC: SNP Launch Measurement: {measurement_string}");

    let report = unsafe {
        core::slice::from_raw_parts(
            (attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    };

    info!("KBC: Attestation");

    let secret = match cs.attestation(&mut proxy, report) {
        Ok(secret) => secret,
        Err(e) => {
            error!("KBC: Attestation failed - {e}");
            return Err(Error::AutenticationFailed);
        }
    };

    info!("KBC: Attestation done");

    Ok(secret)
}

impl Write for SerialPort<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, CPError> {
        let mut count = 0usize;

        for byte in buf {
            self.put_byte(*byte);
            count += 1;
        }

        Ok(count)
    }

    fn flush(&mut self) -> Result<(), CPError> {
        Ok(())
    }
}

impl Read for SerialPort<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError> {
        let mut count = 0usize;

        for byte in buf {
            *byte = self.get_byte();
            count += 1;
        }

        Ok(count)
    }
}

impl Connection for SerialPort<'_> {}

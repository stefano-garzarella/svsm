// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Red Hat, Inc. All rights reserved.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>

extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use log::{debug, error, info};
use rand_chacha::rand_core::SeedableRng;
use reference_kbc::{
    client_proxy::{
        Connection, Error as CPError, HttpMethod, Proxy, Read, Request, Response, Write,
    },
    client_session::{ClientSession, ClientTeeSnp, SnpGeneration},
};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha2::{Digest, Sha512};

use crate::{
    greq::{pld_report::AttestationReport, services::get_report_ex},
    serial::{SerialPort, Terminal},
    svsm_console::SVSMIOPort,
};

#[derive(Debug)]
pub enum Error {
    AutenticationFailed,
}

pub fn get_secret(workload_id: &str) -> Result<String, Error> {
    static PROXY_IO: SVSMIOPort = SVSMIOPort::new();
    let sp: SerialPort = SerialPort {
        driver: &PROXY_IO,
        port: 0x3e8, //COM3)
    };

    sp.init();

    let mut proxy = Proxy::new(Box::new(sp));

    // TODO: get entrophy for the seed
    let mut rng = rand_chacha::ChaChaRng::from_seed([0; 32]);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mut snp = ClientTeeSnp::new(SnpGeneration::Milan, workload_id.to_string());
    let mut cs = ClientSession::new();

    let request = cs.request(&snp).unwrap();

    let req = Request {
        endpoint: "/kbs/v0/auth".to_string(),
        method: HttpMethod::POST,
        body: json!(&request),
    };
    proxy.write_json(&json!(req)).unwrap();
    let data = proxy.read_json().unwrap();
    let resp: Response = serde_json::from_value(data).unwrap();

    let challenge = if resp.is_success() {
        let challenge = resp.body;
        info!("Authentication success - {}", challenge);
        challenge
    } else {
        error!("Authentication error({0}) - {1}", resp.status, resp.body);
        return Err(Error::AutenticationFailed);
    };

    debug!("Challenge: {:#?}", challenge);
    let nonce = cs
        .challenge(serde_json::from_str(&challenge).unwrap())
        .unwrap();

    info!("Nonce: {}", nonce);

    let mut hasher = Sha512::new();
    hasher.update(nonce.as_bytes());
    hasher.update(pub_key.n().to_string().as_bytes());
    hasher.update(pub_key.e().to_string().as_bytes());

    let res = get_report_ex(&hasher.finalize().into()).unwrap();
    let attestation = res.0;

    snp.update_report(unsafe {
        core::slice::from_raw_parts(
            (&*attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    });

    let attestation = cs.attestation(pub_key.n(), pub_key.e(), &snp).unwrap();

    let req = Request {
        endpoint: "/kbs/v0/attest".to_string(),
        method: HttpMethod::POST,
        body: json!(&attestation),
    };
    proxy.write_json(&json!(req)).unwrap();
    let data = proxy.read_json().unwrap();
    let resp: Response = serde_json::from_value(data).unwrap();
    if resp.is_success() {
        info!("Attestation success - {}", resp.body)
    } else {
        error!("Attestation error({0}) - {1}", resp.status, resp.body)
    }

    Ok("".to_string())
}

impl<'a> Write for SerialPort<'a> {
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

impl<'a> Read for SerialPort<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, CPError> {
        let mut count = 0usize;

        for byte in buf {
            *byte = self.get_byte();
            count += 1;
        }

        Ok(count)
    }
}

impl<'a> Connection for SerialPort<'a> {}

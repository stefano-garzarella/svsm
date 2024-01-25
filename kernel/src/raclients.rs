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
use raclients::{
    client_proxy::{Connection, Error as CPError, Proxy, ProxyRequest, Read, RequestType, Write},
    client_session::ClientSession,
    clients::{reference_kbs::ReferenceKBSClientSnp, SnpGeneration},
};
use rand_chacha::rand_core::SeedableRng;
use rdrand::RdSeed;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha512};

use crate::{
    greq::{pld_report::AttestationReport, services::get_report_ex},
    serial::{SerialPort, Terminal},
    svsm_console::SVSMIOPort,
};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AutenticationFailed,
}

pub fn get_secret(workload_id: &str) -> Result<String, Error> {
    static PROXY_IO: SVSMIOPort = SVSMIOPort::new();
    let sp: SerialPort<'_> = SerialPort {
        driver: &PROXY_IO,
        port: 0x3e8, //COM3
    };

    sp.init();

    let mut proxy = Proxy::new(Box::new(sp));

    let rdrand = unsafe { RdSeed::new_unchecked() };
    let mut rng = rand_chacha::ChaChaRng::from_rng(rdrand).unwrap();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mut snp = ReferenceKBSClientSnp::new(SnpGeneration::Milan, workload_id.to_string());
    let mut cs = ClientSession::new();

    let request = cs.request(&snp).unwrap();

    let challenge = match snp.make(&mut proxy, RequestType::Auth, Some(&request)) {
        Ok(challenge) => challenge.unwrap(),
        Err(e) => {
            error!("KBC: Authentication failed - {e}");
            return Err(Error::AutenticationFailed);
        }
    };

    let nonce = cs
        .challenge(serde_json::from_str(&challenge).unwrap())
        .unwrap();

    info!("KBC: Authentication done");
    debug!("    nonce: {}", nonce);

    let key_n_encoded = ClientSession::encode_key(pub_key.n()).unwrap();
    let key_e_encoded = ClientSession::encode_key(pub_key.e()).unwrap();

    let mut hasher = Sha512::new();
    hasher.update(nonce.as_bytes());
    hasher.update(key_n_encoded.as_bytes());
    hasher.update(key_e_encoded.as_bytes());

    let res = get_report_ex(&hasher.finalize().into()).unwrap();
    let attestation = res.0;

    snp.update_report(unsafe {
        core::slice::from_raw_parts(
            (&*attestation as *const AttestationReport) as *const u8,
            core::mem::size_of::<AttestationReport>(),
        )
    });

    let attestation = cs.attestation(key_n_encoded, key_e_encoded, &snp).unwrap();

    if let Err(e) = snp.make(&mut proxy, RequestType::Attest, Some(&attestation)) {
        error!("KBC: Attestation failed - {e}");
        return Err(Error::AutenticationFailed);
    }

    info!("KBC: Attestation done");

    let ciphertext_encoded = match snp.make(&mut proxy, RequestType::Key, None) {
        Ok(ce) => ce.unwrap(),
        Err(e) => {
            error!("Key request failed - {e}");
            return Err(Error::AutenticationFailed);
        }
    };

    info!("KBC: Key successfully received");

    let ciphertext = cs.secret(ciphertext_encoded, &snp).unwrap();
    let secret = priv_key.decrypt(rsa::Pkcs1v15Encrypt, &ciphertext).unwrap();

    info!("KBC: Key successfully decrypted");

    Ok(String::from_utf8(secret).unwrap())
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

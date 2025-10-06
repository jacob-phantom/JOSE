// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! P-521 (secp521r1) ECDSA signing tests

#![cfg(feature = "p521")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _};
use jose_jws::{Protected, Unprotected};
use p521::ecdsa::SigningKey;
use signature::rand_core::OsRng;

#[test]
fn test_p521_basic_signing() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es512),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");

    signer.update(payload).expect("failed to update payload");

    let signature = signer.finish(OsRng).expect("failed to finish signing");

    assert!(signature.protected.is_some());
    assert!(!signature.signature.is_empty());

    // P-521 signatures are 132 bytes (r || s)
    assert_eq!(signature.signature.len(), 132);
}

#[test]
fn test_p521_payload_variations() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es512),
            ..Default::default()
        },
        ..Default::default()
    };

    // Test various payload sizes including boundary conditions
    for size in [0, 1, 65, 66, 67, 131, 132, 133, 10 * 1024 * 1024] {
        let payload = vec![0xFFu8; size];

        let mut signer = signing_key
            .sign(Some(protected.clone()), None::<Unprotected>)
            .expect("failed to start signing");

        signer.update(&payload).expect("failed to update payload");

        let signature = signer
            .finish(OsRng)
            .unwrap_or_else(|_| panic!("failed to sign payload of size {size}"));

        assert_eq!(signature.signature.len(), 132);
    }

    // Test different payloads produce different signatures
    let mut signer1 = signing_key
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(b"payload1").expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    let mut signer2 = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer2.update(b"payload2").expect("failed to update");
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    assert_ne!(sig1.signature, sig2.signature);
}

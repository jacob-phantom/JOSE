// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! P-384 (secp384r1) ECDSA signing tests

#![cfg(feature = "p384")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _};
use jose_jws::{Protected, Unprotected};
use p384::ecdsa::SigningKey;
use signature::rand_core::OsRng;

#[test]
fn test_p384_basic_signing() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es384),
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

    // P-384 signatures are 96 bytes (r || s)
    assert_eq!(signature.signature.len(), 96);
}

#[test]
fn test_p384_different_keys_different_signatures() {
    let signing_key1 = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let signing_key2 = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es384),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer1 = signing_key1
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(payload).expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    let mut signer2 = signing_key2
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer2.update(payload).expect("failed to update");
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    // Different keys should produce different signatures
    assert_ne!(sig1.signature, sig2.signature);
}

#[test]
fn test_p384_payload_variations() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es384),
            ..Default::default()
        },
        ..Default::default()
    };

    // Test various payload sizes including boundary conditions
    for size in [0, 1, 47, 48, 49, 95, 96, 97, 1024 * 1024] {
        let payload = vec![0x42u8; size];

        let mut signer = signing_key
            .sign(Some(protected.clone()), None::<Unprotected>)
            .expect("failed to start signing");

        signer.update(&payload).expect("failed to update payload");

        let signature = signer
            .finish(OsRng)
            .unwrap_or_else(|_| panic!("failed to sign payload of size {size}"));

        assert_eq!(signature.signature.len(), 96);
    }
}

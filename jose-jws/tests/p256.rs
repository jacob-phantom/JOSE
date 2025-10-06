// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! P-256 (secp256r1) ECDSA signing tests

#![cfg(feature = "p256")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _};
use jose_jws::{Protected, Unprotected};
use p256::ecdsa::SigningKey;
use signature::rand_core::OsRng;

#[test]
fn test_p256_basic_signing() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");

    signer.update(payload).expect("failed to update payload");

    let signature = signer.finish(OsRng).expect("failed to finish signing");

    // Verify signature structure
    assert!(signature.protected.is_some());
    assert!(signature.header.is_none());
    assert!(!signature.signature.is_empty());

    // P-256 signatures are 64 bytes (r || s)
    assert_eq!(signature.signature.len(), 64);
}

#[test]
fn test_p256_deterministic_signing() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            ..Default::default()
        },
        ..Default::default()
    };

    // Create two signatures with the same key and payload
    let mut signer1 = signing_key
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(payload).expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    let mut signer2 = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer2.update(payload).expect("failed to update");
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    // P-256 uses deterministic ECDSA (RFC 6979)
    assert_eq!(sig1.signature, sig2.signature);
    assert_eq!(
        sig1.protected.as_ref().unwrap().as_ref(),
        sig2.protected.as_ref().unwrap().as_ref()
    );
}

#[test]
fn test_p256_different_keys_different_signatures() {
    let signing_key1 = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let signing_key2 = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
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
fn test_p256_payload_variations() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            ..Default::default()
        },
        ..Default::default()
    };

    // Test various payload types and sizes
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("binary", (0..=255).collect()),
        ("large", vec![0x42u8; 1024 * 1024]),
    ];

    for (name, payload) in payloads {
        let mut signer = signing_key
            .sign(Some(protected.clone()), None::<Unprotected>)
            .expect("failed to start signing");

        signer.update(&payload).expect("failed to update payload");
        let signature = signer.finish(OsRng).expect("failed to finish signing");

        assert_eq!(signature.signature.len(), 64, "Failed for {name} payload");
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

#[test]
fn test_p256_chunked_updates() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let data = b"The quick brown fox jumps over the lazy dog";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            ..Default::default()
        },
        ..Default::default()
    };

    // Single update
    let mut signer1 = signing_key
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(data).expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    // Chunked updates should produce identical signature
    let mut signer2 = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    for chunk in data.chunks(5) {
        signer2.update(chunk).expect("failed to update");
    }
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    assert_eq!(sig1.signature, sig2.signature);
}

#[test]
fn test_p256_header_with_special_characters() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            kid: Some("key-世界-🔐".to_string()),
            typ: Some("JWT".to_string()),
            cty: Some("application/json".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");

    signer.update(b"test").expect("failed to update");
    let signature = signer.finish(OsRng).expect("failed to finish");

    assert_eq!(signature.signature.len(), 64);
    assert!(signature.protected.is_some());
}

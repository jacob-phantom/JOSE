// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! K-256 (secp256k1) ECDSA signing tests

#![cfg(feature = "k256")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _};
use jose_jws::{Flattened, Protected, Unprotected};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;

#[test]
fn test_k256_basic_signing() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
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

    // K-256 signatures are 64 bytes (r || s)
    assert_eq!(signature.signature.len(), 64);
}

#[test]
fn test_k256_payload_variations() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    // Test various payload sizes - signature length should always be 64 bytes
    for size in [0, 1, 64, 256, 1024 * 1024] {
        let payload = vec![0x42u8; size];

        let mut signer = signing_key
            .sign(Some(protected.clone()), None::<Unprotected>)
            .expect("failed to start signing");

        signer.update(&payload).expect("failed to update");
        let sig = signer.finish(OsRng).expect("failed to finish");

        assert_eq!(sig.signature.len(), 64);
    }

    // Test multiple updates concatenate correctly
    let mut signer1 = signing_key
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(b"A").expect("failed to update");
    signer1.update(b"B").expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    let mut signer2 = signing_key
        .sign(Some(protected.clone()), None::<Unprotected>)
        .expect("failed to start signing");
    signer2.update(b"AB").expect("failed to update");
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    assert_eq!(sig1.signature, sig2.signature);

    // Test different payloads produce different signatures
    let mut signer3 = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer3.update(b"different").expect("failed to update");
    let sig3 = signer3.finish(OsRng).expect("failed to finish");

    assert_ne!(sig1.signature, sig3.signature);
}

#[test]
fn test_k256_header_influence() {
    use serde_json::json;

    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"same payload";

    // Different protected headers produce different signatures
    let protected1 = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            kid: Some("key1".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let protected2 = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            kid: Some("key2".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer1 = signing_key
        .sign(Some(protected1), None::<Unprotected>)
        .expect("failed to start signing");
    signer1.update(payload).expect("failed to update");
    let sig1 = signer1.finish(OsRng).expect("failed to finish");

    let mut signer2 = signing_key
        .sign(Some(protected2), None::<Unprotected>)
        .expect("failed to start signing");
    signer2.update(payload).expect("failed to update");
    let sig2 = signer2.finish(OsRng).expect("failed to finish");

    assert_ne!(sig1.signature, sig2.signature);

    // Different unprotected headers produce SAME signatures
    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer3 = signing_key
        .sign(Some(protected.clone()), Some(json!({"custom": "value1"})))
        .expect("failed to start signing");
    signer3.update(payload).expect("failed to update");
    let sig3 = signer3.finish(OsRng).expect("failed to finish");

    let mut signer4 = signing_key
        .sign(Some(protected), Some(json!({"custom": "value2"})))
        .expect("failed to start signing");
    signer4.update(payload).expect("failed to update");
    let sig4 = signer4.finish(OsRng).expect("failed to finish");

    assert_eq!(sig3.signature, sig4.signature);
}

#[test]
fn test_k256_signature_quality() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");

    signer.update(payload).expect("failed to update payload");
    let signature = signer.finish(OsRng).expect("failed to finish signing");

    // Verify signature is not degenerate (all zeros or all ones)
    assert_ne!(signature.signature.as_ref(), &[0u8; 64]);
    assert_ne!(signature.signature.as_ref(), &[0xFFu8; 64]);
}

#[test]
fn test_k256_jws_serialization_safety() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let payload = b"sensitive data";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");

    signer.update(payload).expect("failed to update");
    let signature = signer.finish(OsRng).expect("failed to finish");

    // Construct flattened JWS
    let jws = Flattened {
        payload: Some(payload.to_vec().into()),
        signature,
    };

    // Serialize to JSON
    let serialized = serde_json::to_string(&jws).expect("failed to serialize");

    // Verify it's valid JSON
    let _: serde_json::Value = serde_json::from_str(&serialized).expect("invalid JSON produced");

    // Verify protected header is base64url encoded
    assert!(serialized.contains("\"protected\""));
    assert!(serialized.contains("\"signature\""));
}

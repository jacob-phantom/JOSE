// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! K-256 (secp256k1) ECDSA signing and verification tests

#![cfg(feature = "k256")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _, Verifier as _, VerifyingKey as _};
use jose_jws::{Protected, Unprotected};
use k256::ecdsa::{SigningKey, VerifyingKey};
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

// Verification tests

#[test]
fn test_k256_basic_verification() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let verifying_key = VerifyingKey::from(&signing_key);
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    // Create signature
    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer.update(payload).expect("failed to update payload");
    let signature = signer.finish(OsRng).expect("failed to finish signing");

    // Verify signature
    let mut verifier = verifying_key
        .verify(&signature)
        .expect("failed to start verification");
    verifier.update(payload).expect("failed to update payload");
    verifier.finish().expect("verification failed");
}

#[test]
fn test_k256_verification_wrong_payload() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let verifying_key = VerifyingKey::from(&signing_key);

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    // Create signature with one payload
    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer
        .update(b"original payload")
        .expect("failed to update");
    let signature = signer.finish(OsRng).expect("failed to finish");

    // Try to verify with different payload
    let mut verifier = verifying_key
        .verify(&signature)
        .expect("failed to start verification");
    verifier
        .update(b"modified payload")
        .expect("failed to update");

    assert!(
        verifier.finish().is_err(),
        "verification should fail with wrong payload"
    );
}

#[test]
fn test_k256_verification_wrong_key() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let wrong_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let wrong_verifying_key = VerifyingKey::from(&wrong_key);
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256K),
            ..Default::default()
        },
        ..Default::default()
    };

    // Create signature with original key
    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer.update(payload).expect("failed to update");
    let signature = signer.finish(OsRng).expect("failed to finish");

    // Try to verify with wrong key
    let mut verifier = wrong_verifying_key
        .verify(&signature)
        .expect("failed to start verification");
    verifier.update(payload).expect("failed to update");

    assert!(
        verifier.finish().is_err(),
        "verification should fail with wrong key"
    );
}

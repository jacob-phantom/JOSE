// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! P-256 (secp256r1) ECDSA signing and verification tests

#![cfg(feature = "p256")]

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _, Verifier as _, VerifyingKey as _};
use jose_jws::{Protected, Unprotected};
use p256::ecdsa::{SigningKey, VerifyingKey};
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

    // P-256 uses deterministic ECDSA (RFC 6979) - same key and payload produce same signature
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

    assert_eq!(sig1.signature, sig2.signature);
}

// Verification tests

#[test]
fn test_p256_basic_verification() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let verifying_key = VerifyingKey::from(&signing_key);
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
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
fn test_p256_verification_wrong_payload() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let verifying_key = VerifyingKey::from(&signing_key);

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
            ..Default::default()
        },
        ..Default::default()
    };

    // Create signature with one payload
    let mut signer = signing_key
        .sign(Some(protected), None::<Unprotected>)
        .expect("failed to start signing");
    signer.update(b"original payload").expect("failed to update");
    let signature = signer.finish(OsRng).expect("failed to finish");

    // Try to verify with different payload
    let mut verifier = verifying_key
        .verify(&signature)
        .expect("failed to start verification");
    verifier.update(b"modified payload").expect("failed to update");

    assert!(verifier.finish().is_err(), "verification should fail with wrong payload");
}

#[test]
fn test_p256_verification_wrong_key() {
    let signing_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let wrong_key = SigningKey::try_from_rng(&mut OsRng).expect("failed to generate key");
    let wrong_verifying_key = VerifyingKey::from(&wrong_key);
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Es256),
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

    assert!(verifier.finish().is_err(), "verification should fail with wrong key");
}


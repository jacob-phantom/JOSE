// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PSS signing and verification tests (PS256, PS384, PS512)

use jose_b64::stream::Update as _;
use jose_jws::crypto::{Signer as _, SigningKey as _, Verifier as _, VerifyingKey as _};
use jose_jws::{Protected, Unprotected};
use rand_core::{OsRng, TryRngCore};
use rsa::pss;
use sha2::{Sha256, Sha384, Sha512};
use signature::Keypair;

#[test]
fn test_ps256_basic_signing() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha256>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps256),
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

    // RSA-2048 signatures are 256 bytes
    assert_eq!(signature.signature.len(), 256);
}

#[test]
fn test_ps256_randomized_signing() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha256>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps256),
            ..Default::default()
        },
        ..Default::default()
    };

    // PSS is randomized - same key and payload produce different signatures
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

    // Signatures should be different due to randomization
    assert_ne!(sig1.signature, sig2.signature);
}

#[test]
fn test_ps256_verification() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha256>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let verifying_key = signing_key.verifying_key();
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps256),
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
fn test_ps256_verification_wrong_payload() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha256>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let verifying_key = signing_key.verifying_key();

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps256),
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
fn test_ps384_basic_signing() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha384>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps384),
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
    assert_eq!(signature.signature.len(), 256);
}

#[test]
fn test_ps512_basic_signing() {
    let mut rng = OsRng;
    let signing_key = pss::SigningKey::<Sha512>::random(&mut rng.unwrap_mut(), 2048)
        .expect("failed to generate key");
    let payload = b"test payload";

    let protected = Protected {
        oth: Unprotected {
            alg: Some(jose_jwa::Signing::Ps512),
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
    assert_eq!(signature.signature.len(), 256);
}

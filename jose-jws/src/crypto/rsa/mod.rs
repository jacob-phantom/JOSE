// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RSA signing support
//!
//! This module provides support for RSA signing algorithms as defined in RFC 7518:
//! - PKCS#1 v1.5: RS256, RS384, RS512
//! - PSS: PS256, PS384, PS512

#![cfg(feature = "rsa")]

pub mod pkcs1v15;
pub mod pss;

use crate::{Protected, Unprotected};

// Re-export the state structs
pub use self::pkcs1v15::{RsaPkcs1v15SignerState, RsaPkcs1v15VerifierState};
pub use self::pss::{RsaPssSignerState, RsaPssVerifierState};

// Type aliases for PKCS#1 v1.5 (RS256, RS384, RS512)

/// RS256 signer state (RSASSA-PKCS1-v1_5 with SHA-256)
pub type Rs256SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15SignerState<'a, sha2::Sha256, U, P>;

/// RS256 verifier state (RSASSA-PKCS1-v1_5 with SHA-256)
pub type Rs256VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15VerifierState<'a, sha2::Sha256, U, P>;

/// RS384 signer state (RSASSA-PKCS1-v1_5 with SHA-384)
pub type Rs384SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15SignerState<'a, sha2::Sha384, U, P>;

/// RS384 verifier state (RSASSA-PKCS1-v1_5 with SHA-384)
pub type Rs384VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15VerifierState<'a, sha2::Sha384, U, P>;

/// RS512 signer state (RSASSA-PKCS1-v1_5 with SHA-512)
pub type Rs512SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15SignerState<'a, sha2::Sha512, U, P>;

/// RS512 verifier state (RSASSA-PKCS1-v1_5 with SHA-512)
pub type Rs512VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPkcs1v15VerifierState<'a, sha2::Sha512, U, P>;

// Type aliases for PSS (PS256, PS384, PS512)

/// PS256 signer state (RSASSA-PSS with SHA-256)
pub type Ps256SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssSignerState<'a, sha2::Sha256, U, P>;

/// PS256 verifier state (RSASSA-PSS with SHA-256)
pub type Ps256VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssVerifierState<'a, sha2::Sha256, U, P>;

/// PS384 signer state (RSASSA-PSS with SHA-384)
pub type Ps384SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssSignerState<'a, sha2::Sha384, U, P>;

/// PS384 verifier state (RSASSA-PSS with SHA-384)
pub type Ps384VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssVerifierState<'a, sha2::Sha384, U, P>;

/// PS512 signer state (RSASSA-PSS with SHA-512)
pub type Ps512SignerState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssSignerState<'a, sha2::Sha512, U, P>;

/// PS512 verifier state (RSASSA-PSS with SHA-512)
pub type Ps512VerifierState<'a, U = Unprotected, P = Protected<U>> =
    RsaPssVerifierState<'a, sha2::Sha512, U, P>;

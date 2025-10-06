// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! ECDSA signing support

#![cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]

use core::ops::Add;

use ::ecdsa::{EcdsaCurve, hazmat::DigestAlgorithm};
use elliptic_curve::{Curve, CurveArithmetic, array::ArraySize};
use jose_b64::serde::Json;
use rand_core::TryRngCore;
use serde::Serialize;
use signature::{digest::Digest, hazmat::PrehashSigner};

use super::*;

/// P-256 signer state
#[cfg(feature = "p256")]
pub type P256SignerState<'a, U = Unprotected, P = Protected<U>> =
    EcdsaSignerState<'a, p256::NistP256, U, P>;

/// P-384 signer state
#[cfg(feature = "p384")]
pub type P384SignerState<'a, U = Unprotected, P = Protected<U>> =
    EcdsaSignerState<'a, p384::NistP384, U, P>;

/// P-521 signer state
#[cfg(feature = "p521")]
pub type P521SignerState<'a, U = Unprotected, P = Protected<U>> =
    EcdsaSignerState<'a, p521::NistP521, U, P>;

/// K-256 signer state
#[cfg(feature = "k256")]
pub type K256SignerState<'a, U = Unprotected, P = Protected<U>> =
    EcdsaSignerState<'a, k256::Secp256k1, U, P>;

/// ECDSA signer state
pub struct EcdsaSignerState<'a, C, U, P>
where
    C: CurveArithmetic + DigestAlgorithm + EcdsaCurve,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
{
    /// Unprotected header
    header: Option<U>,
    /// Protected header
    protected: Option<Json<P>>,
    /// Signing key reference
    signer: &'a ::ecdsa::SigningKey<C>,
    /// Digest accumulator
    digest: <C as DigestAlgorithm>::Digest,
}

impl<'a, C, U, P> SigningKey<'a, U, P> for ::ecdsa::SigningKey<C>
where
    C: CurveArithmetic + DigestAlgorithm + EcdsaCurve,
    ::ecdsa::SigningKey<C>: PrehashSigner<::ecdsa::Signature<C>>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
    U: Serialize,
    P: Serialize,
{
    type StartError = signature::Error;
    type Signer = EcdsaSignerState<'a, C, U, P>;

    fn sign(
        &'a self,
        protected: Option<P>,
        header: Option<U>,
    ) -> Result<Self::Signer, Self::StartError> {
        let mut digest = <C as DigestAlgorithm>::Digest::new();

        let protected = if let Some(protected) = protected {
            let protected = Json::new(protected).map_err(|_| signature::Error::new())?;
            digest.update(protected.as_ref());
            Some(protected)
        } else {
            None
        };

        digest.update(b".");

        Ok(EcdsaSignerState {
            header,
            protected,
            signer: self,
            digest,
        })
    }
}

impl<C, U, P> Update for EcdsaSignerState<'_, C, U, P>
where
    C: CurveArithmetic + DigestAlgorithm + EcdsaCurve,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
    U: Serialize,
    P: Serialize,
{
    type Error = signature::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(chunk.as_ref());
        Ok(())
    }
}

impl<C, U, P> Signer<U, P> for EcdsaSignerState<'_, C, U, P>
where
    C: CurveArithmetic + DigestAlgorithm + EcdsaCurve,
    ::ecdsa::SigningKey<C>: PrehashSigner<::ecdsa::Signature<C>>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
    U: Serialize,
    P: Serialize,
{
    type FinishError = signature::Error;

    fn finish(self, _rng: impl 'static + TryRngCore) -> Result<Signature<U, P>, Self::FinishError> {
        let prehash = self.digest.finalize();
        let signature_bytes = self
            .signer
            .sign_prehash(&prehash)
            .map_err(|_| signature::Error::new())?;

        Ok(Signature {
            header: self.header,
            protected: self.protected,
            signature: signature_bytes.to_bytes().to_vec().into(),
        })
    }
}

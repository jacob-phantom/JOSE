// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RSA PKCS#1 v1.5 signing support (RS256, RS384, RS512)

use jose_b64::serde::Json;
use rand_core::TryRngCore;
use serde::Serialize;
use signature::{
    SignatureEncoding,
    digest::Digest,
    hazmat::{PrehashSigner, PrehashVerifier},
};

use super::super::*;

// Type aliases to avoid ambiguity with module name
type RsaSignature = ::rsa::pkcs1v15::Signature;
type RsaPkcs1v15SigningKey<D> = ::rsa::pkcs1v15::SigningKey<D>;
type RsaPkcs1v15VerifyingKey<D> = ::rsa::pkcs1v15::VerifyingKey<D>;

/// RSA PKCS#1 v1.5 signer state
pub struct RsaPkcs1v15SignerState<'a, D, U, P>
where
    D: Digest + 'static,
{
    /// Unprotected header
    header: Option<U>,
    /// Protected header
    protected: Option<Json<P>>,
    /// Signing key reference
    signer: &'a RsaPkcs1v15SigningKey<D>,
    /// Digest accumulator
    digest: D,
}

/// RSA PKCS#1 v1.5 verifier state
pub struct RsaPkcs1v15VerifierState<'a, D, U, P>
where
    D: Digest + 'static,
{
    /// Verifying key reference
    verifier: &'a RsaPkcs1v15VerifyingKey<D>,
    /// Expected signature bytes
    signature: &'a [u8],
    /// Digest accumulator
    digest: D,
    /// Marker for U and P types
    _phantom: core::marker::PhantomData<(U, P)>,
}

impl<'a, D, U, P> SigningKey<'a, U, P> for RsaPkcs1v15SigningKey<D>
where
    D: Digest + 'static,
    RsaPkcs1v15SigningKey<D>: PrehashSigner<RsaSignature>,
    U: Serialize,
    P: Serialize,
{
    type StartError = signature::Error;
    type Signer = RsaPkcs1v15SignerState<'a, D, U, P>;

    fn sign(
        &'a self,
        protected: Option<P>,
        header: Option<U>,
    ) -> Result<Self::Signer, Self::StartError> {
        let mut digest = D::new();

        let protected = if let Some(protected) = protected {
            let protected = Json::new(protected).map_err(|_| signature::Error::new())?;
            digest.update(protected.as_ref());
            Some(protected)
        } else {
            None
        };

        digest.update(b".");

        Ok(RsaPkcs1v15SignerState {
            header,
            protected,
            signer: self,
            digest,
        })
    }
}

impl<'a, D, U, P> VerifyingKey<'a, &'a Signature<U, P>> for RsaPkcs1v15VerifyingKey<D>
where
    D: Digest + 'static,
    RsaPkcs1v15VerifyingKey<D>: PrehashVerifier<RsaSignature>,
{
    type StartError = signature::Error;
    type Verifier = RsaPkcs1v15VerifierState<'a, D, U, P>;

    fn verify(
        &'a self,
        signature: &'a Signature<U, P>,
    ) -> Result<Self::Verifier, Self::StartError> {
        let mut digest = D::new();

        if let Some(ref protected) = signature.protected {
            digest.update(protected.as_ref());
        }

        digest.update(b".");

        Ok(RsaPkcs1v15VerifierState {
            verifier: self,
            signature: signature.signature.as_ref(),
            digest,
            _phantom: core::marker::PhantomData,
        })
    }
}

impl<D, U, P> Update for RsaPkcs1v15SignerState<'_, D, U, P>
where
    D: Digest + 'static,
    U: Serialize,
    P: Serialize,
{
    type Error = signature::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(chunk.as_ref());
        Ok(())
    }
}

impl<D, U, P> Update for RsaPkcs1v15VerifierState<'_, D, U, P>
where
    D: Digest + 'static,
{
    type Error = signature::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(chunk.as_ref());
        Ok(())
    }
}

impl<D, U, P> Signer<U, P> for RsaPkcs1v15SignerState<'_, D, U, P>
where
    D: Digest + 'static,
    RsaPkcs1v15SigningKey<D>: PrehashSigner<RsaSignature>,
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

impl<'a, D, U, P> Verifier<'a> for RsaPkcs1v15VerifierState<'a, D, U, P>
where
    D: Digest + 'static,
    RsaPkcs1v15VerifyingKey<D>: PrehashVerifier<RsaSignature>,
{
    type FinishError = signature::Error;

    fn finish(self) -> Result<(), Self::FinishError> {
        let prehash = self.digest.finalize();

        let signature =
            RsaSignature::try_from(self.signature).map_err(|_| signature::Error::new())?;

        self.verifier
            .verify_prehash(&prehash, &signature)
            .map_err(|_| signature::Error::new())?;

        Ok(())
    }
}

// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK Thumbprint implementation as defined in RFC 7638.
//!
//! This module provides methods for computing JWK Thumbprints, which are
//! cryptographic hash values computed over the required members of a JWK.

use alloc::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::key::{Ec, EcCurves, Oct, Okp, OkpCurves, Rsa};
use crate::{Jwk, Key};

/// Trait for computing JWK thumbprints.
///
/// This trait is implemented for each key type to compute the thumbprint
/// according to RFC 7638 requirements.
pub trait JwkThumbprint {
    /// Compute the JWK thumbprint using SHA-256.
    ///
    /// Returns the base64url-encoded thumbprint string.
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError>;

    /// Compute the JWK thumbprint using a custom hash function.
    ///
    /// Returns the base64url-encoded thumbprint string.
    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest;
}

/// Errors that can occur during thumbprint computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThumbprintError {
    /// Failed to format the JSON representation.
    JsonFormatError,
}

impl core::fmt::Display for ThumbprintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ThumbprintError::JsonFormatError => write!(f, "failed to format JSON for thumbprint"),
        }
    }
}

/// Helper function to build the canonical JSON representation for thumbprint computation.
fn build_canonical_json(
    kty: &str,
    required_fields: &[(&str, &str)],
) -> Result<String, ThumbprintError> {
    let mut json = String::with_capacity(256);

    // Start with opening brace
    json.push('{');

    // Create a vector of all fields including kty, then sort lexicographically
    let mut all_fields = Vec::with_capacity(required_fields.len() + 1);
    all_fields.push(("kty", kty));
    all_fields.extend_from_slice(required_fields);
    all_fields.sort_by_key(|(key, _)| *key);

    // Write each field
    for (i, (key, value)) in all_fields.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(json, "\"{key}\":\"{value}\"").map_err(|_| ThumbprintError::JsonFormatError)?;
    }

    // Close with closing brace
    json.push('}');

    Ok(json)
}

/// Compute thumbprint from canonical JSON.
fn compute_thumbprint_from_json<D>(json: &str) -> String
where
    D: Digest,
{
    let hash = D::digest(json.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}

impl JwkThumbprint for Ec {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        let crv = match self.crv {
            EcCurves::P256 => "P-256",
            EcCurves::P384 => "P-384",
            EcCurves::P521 => "P-521",
            EcCurves::P256K => "secp256k1",
        };

        let x = Base64UrlUnpadded::encode_string(&self.x);
        let y = Base64UrlUnpadded::encode_string(&self.y);

        let required_fields = &[("crv", crv), ("x", x.as_str()), ("y", y.as_str())];

        let json = build_canonical_json("EC", required_fields)?;
        Ok(compute_thumbprint_from_json::<D>(&json))
    }
}

impl JwkThumbprint for Jwk {
    /// Compute the JWK thumbprint using SHA-256 as defined in RFC 7638.
    ///
    /// This method computes a cryptographic hash over the required members
    /// of the JWK and returns the base64url-encoded result.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jose_jwk::{Jwk, JwkThumbprint, Key, Rsa};
    /// let jwk = Jwk {
    ///     key: Key::Rsa(Rsa {
    ///         e: vec![1, 0, 1].into(),
    ///         n: vec![0xAB, 0xCD, 0xEF].into(),
    ///         prv: None,
    ///     }),
    ///     prm: Default::default(),
    /// };
    ///
    /// let thumbprint = jwk.jwk_thumbprint().unwrap();
    /// assert!(!thumbprint.is_empty());
    /// ```
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.key.jwk_thumbprint()
    }

    /// Compute the JWK thumbprint using a custom hash function as defined in RFC 7638.
    ///
    /// This method allows using a different hash function than the default SHA-256.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jose_jwk::{Jwk, JwkThumbprint, Key, Rsa};
    /// # use sha2::Sha512;
    /// let jwk = Jwk {
    ///     key: Key::Rsa(Rsa {
    ///         e: vec![1, 0, 1].into(),
    ///         n: vec![0xAB, 0xCD, 0xEF].into(),
    ///         prv: None,
    ///     }),
    ///     prm: Default::default(),
    /// };
    ///
    /// let thumbprint = jwk.jwk_thumbprint_with_hash::<Sha512>().unwrap();
    /// assert!(!thumbprint.is_empty());
    /// ```
    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        self.key.jwk_thumbprint_with_hash::<D>()
    }
}

impl JwkThumbprint for Rsa {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        let e = Base64UrlUnpadded::encode_string(&self.e);
        let n = Base64UrlUnpadded::encode_string(&self.n);

        let required_fields = &[("e", e.as_str()), ("n", n.as_str())];

        let json = build_canonical_json("RSA", required_fields)?;
        Ok(compute_thumbprint_from_json::<D>(&json))
    }
}

impl JwkThumbprint for Oct {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        let k = Base64UrlUnpadded::encode_string(&self.k);

        let required_fields = &[("k", k.as_str())];

        let json = build_canonical_json("oct", required_fields)?;
        Ok(compute_thumbprint_from_json::<D>(&json))
    }
}

impl JwkThumbprint for Okp {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        let crv = match self.crv {
            OkpCurves::Ed25519 => "Ed25519",
            OkpCurves::Ed448 => "Ed448",
            OkpCurves::X25519 => "X25519",
            OkpCurves::X448 => "X448",
        };

        let x = Base64UrlUnpadded::encode_string(&self.x);

        let required_fields = &[("crv", crv), ("x", x.as_str())];

        let json = build_canonical_json("OKP", required_fields)?;
        Ok(compute_thumbprint_from_json::<D>(&json))
    }
}

impl JwkThumbprint for Key {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        match self {
            Key::Ec(ec) => ec.jwk_thumbprint(),
            Key::Rsa(rsa) => rsa.jwk_thumbprint(),
            Key::Oct(oct) => oct.jwk_thumbprint(),
            Key::Okp(okp) => okp.jwk_thumbprint(),
        }
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        match self {
            Key::Ec(ec) => ec.jwk_thumbprint_with_hash::<D>(),
            Key::Rsa(rsa) => rsa.jwk_thumbprint_with_hash::<D>(),
            Key::Oct(oct) => oct.jwk_thumbprint_with_hash::<D>(),
            Key::Okp(okp) => okp.jwk_thumbprint_with_hash::<D>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Rsa;
    use alloc::vec;

    #[test]
    fn test_build_canonical_json() {
        let result =
            build_canonical_json("RSA", &[("e", "AQAB"), ("n", "test")]).expect("canonical JSON");
        assert_eq!(result, r#"{"e":"AQAB","kty":"RSA","n":"test"}"#);
    }

    #[test]
    fn test_rsa_thumbprint_json_format() {
        let rsa = Rsa {
            e: vec![1, 0, 1].into(),
            n: vec![0xAB, 0xCD, 0xEF].into(),
            prv: None,
        };

        let result = rsa.jwk_thumbprint().expect("canonical JSON");

        // Should be base64url encoded
        assert!(!result.is_empty());
        assert!(!result.contains('='));
        assert!(!result.contains('/'));
        assert!(!result.contains('+'));
    }
}

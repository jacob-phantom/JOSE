// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK CFRG-curve key material.

use serde::{Deserialize, Serialize};

use jose_b64::serde::{Bytes, Secret};

/// A octet key pair CFRG-curve key, as defined in [RFC 8037]
///
/// [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okp {
    /// The CFRG curve.
    pub crv: OkpCurves,

    /// The public key.
    pub x: Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

/// The CFRG Curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OkpCurves {
    /// Ed25519
    Ed25519,

    /// Ed448
    Ed448,

    /// X25519
    X25519,

    /// X448
    X448,
}

impl core::fmt::Display for OkpCurves {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OkpCurves::Ed25519 => write!(f, "Ed25519"),
            OkpCurves::Ed448 => write!(f, "Ed448"),
            OkpCurves::X25519 => write!(f, "X25519"),
            OkpCurves::X448 => write!(f, "X448"),
        }
    }
}

impl core::str::FromStr for OkpCurves {
    type Err = ParseOkpCurveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519" => Ok(OkpCurves::Ed25519),
            "Ed448" => Ok(OkpCurves::Ed448),
            "X25519" => Ok(OkpCurves::X25519),
            "X448" => Ok(OkpCurves::X448),
            _ => Err(ParseOkpCurveError),
        }
    }
}

/// Error returned when parsing an OKP curve name fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOkpCurveError;

impl core::fmt::Display for ParseOkpCurveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid OKP curve name")
    }
}

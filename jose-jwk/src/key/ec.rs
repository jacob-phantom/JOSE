// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK elliptic-curve key material.

use serde::{Deserialize, Serialize};

use jose_b64::serde::{Bytes, Secret};

/// An elliptic-curve key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec {
    /// The elliptic curve identifier.
    pub crv: EcCurves,

    /// The public x coordinate.
    pub x: Bytes,

    /// The public y coordinate.
    pub y: Bytes,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

/// The elliptic curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EcCurves {
    /// P-256
    #[serde(rename = "P-256")]
    P256,

    /// P-384
    #[serde(rename = "P-384")]
    P384,

    /// P-521
    #[serde(rename = "P-521")]
    P521,

    /// P-256K
    #[serde(rename = "secp256k1")]
    P256K,
}

impl core::fmt::Display for EcCurves {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EcCurves::P256 => write!(f, "P-256"),
            EcCurves::P384 => write!(f, "P-384"),
            EcCurves::P521 => write!(f, "P-521"),
            EcCurves::P256K => write!(f, "secp256k1"),
        }
    }
}

impl core::str::FromStr for EcCurves {
    type Err = ParseEcCurveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P-256" => Ok(EcCurves::P256),
            "P-384" => Ok(EcCurves::P384),
            "P-521" => Ok(EcCurves::P521),
            "secp256k1" => Ok(EcCurves::P256K),
            _ => Err(ParseEcCurveError),
        }
    }
}

/// Error returned when parsing an EC curve name fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseEcCurveError;

impl core::fmt::Display for ParseEcCurveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid EC curve name")
    }
}

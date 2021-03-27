use crate::constants::*;
use crate::error;
use crate::rng::copy_randombytes;

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::b64::{as_base64, mac_from_base64, vec_from_base64};

use std::convert::TryFrom;
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A generic byte array for working with data, with optional [Serde](https://serde.rs) features.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, Clone, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, PartialEq, Clone))]
#[zeroize(drop)]
pub struct ByteArray<const LENGTH: usize>(pub [u8; LENGTH]);

impl<const LENGTH: usize> ByteArray<LENGTH> {
    /// Returns a zero-initialized byte array.
    pub fn new() -> Self {
        Self([0u8; LENGTH])
    }
    /// Returns a byte array filled with random data.
    pub fn gen() -> Self {
        let mut res = Self::new();
        copy_randombytes(&mut res.0);
        res
    }
    /// Fills `self` with `value`.
    pub fn fill(&mut self, value: u8) {
        self.0.fill(value);
    }
}

impl<const LENGTH: usize> Default for ByteArray<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> From<&[u8; LENGTH]> for ByteArray<LENGTH> {
    fn from(src: &[u8; LENGTH]) -> Self {
        let mut arr = Self([0u8; LENGTH]);
        arr.0.copy_from_slice(src);
        arr
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for ByteArray<LENGTH> {
    fn from(src: [u8; LENGTH]) -> Self {
        Self(src)
    }
}

impl<const LENGTH: usize> TryFrom<&[u8]> for ByteArray<LENGTH> {
    type Error = error::Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != LENGTH {
            Err(dryoc_error!(format!(
                "Invalid size: expected {} found {}",
                LENGTH,
                src.len()
            )))
        } else {
            let mut arr = Self([0u8; LENGTH]);
            arr.0.copy_from_slice(src);
            Ok(arr)
        }
    }
}

/// A type alias used for generic byte array outputs.
pub type OutputBase = Vec<u8>;
/// A type alias used for generic byte array inputs.
pub type InputBase = [u8];

/// Container for crypto box message authentication code.
pub type BoxMac = ByteArray<CRYPTO_BOX_MACBYTES>;
/// Container for crypto secret box message authentication code.
pub type SecretBoxMac = ByteArray<CRYPTO_SECRETBOX_MACBYTES>;

/// A nonce for crypto boxes.
pub type BoxNonce = ByteArray<CRYPTO_BOX_NONCEBYTES>;
/// A public key for public key authenticated crypto boxes.
pub type PublicKey = ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
/// A secret key for public key authenticated crypto boxes.
pub type SecretKey = ByteArray<CRYPTO_BOX_SECRETKEYBYTES>;

/// A nonce for secret key authenticated boxes.
pub type SecretBoxNonce = ByteArray<CRYPTO_BOX_NONCEBYTES>;
/// A secret for secret key authenticated boxes.
pub type SecretBoxKey = ByteArray<CRYPTO_SECRETBOX_KEYBYTES>;

/// A secret for authenticated secret streams.
pub type SecretStreamKey = ByteArray<CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES>;
/// A nonce for authenticated secret streams.
pub type SecretstreamNonce = ByteArray<CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES>;

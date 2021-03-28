use crate::constants::*;
use crate::error;
use crate::rng::copy_randombytes;

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::b64::{as_base64, slice_from_base64};

use std::convert::TryFrom;
use zeroize::Zeroize;

#[cfg(all(feature = "serde", not(feature = "base64")))]
use serde::{
    de::{SeqAccess, Visitor},
    Deserializer, Serializer,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A generic byte array for working with data, with optional [Serde](https://serde.rs) features.
#[cfg_attr(
    all(feature = "serde", feature = "base64"),
    derive(Zeroize, Debug, PartialEq, Clone, Serialize, Deserialize)
)]
#[cfg_attr(
    not(all(feature = "serde", feature = "base64")),
    derive(Zeroize, Debug, PartialEq, Clone)
)]
#[zeroize(drop)]
pub struct ByteArray<const LENGTH: usize>(
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(serialize_with = "as_base64", deserialize_with = "slice_from_base64")
    )]
    [u8; LENGTH],
);

#[cfg(all(feature = "serde", not(feature = "base64")))]
impl<'de, const LENGTH: usize> Deserialize<'de> for ByteArray<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArrayVisitor<const LENGTH: usize>;

        impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
            type Value = ByteArray<LENGTH>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ByteArray<LENGTH>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytearray = ByteArray::<LENGTH>::new();
                let mut idx: usize = 0;

                while let Some(elem) = seq.next_element()? {
                    if idx < LENGTH {
                        bytearray[idx] = elem;
                        idx += 1;
                    } else {
                        break;
                    }
                }

                Ok(bytearray)
            }
        }

        deserializer.deserialize_seq(ByteArrayVisitor::<LENGTH>)
    }
}

#[cfg(all(feature = "serde", not(feature = "base64")))]
impl<const LENGTH: usize> Serialize for ByteArray<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

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
    /// Copies all elements from src into self, using a memcpy.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }
    /// Returns a reference to the underlying data as a slice.
    pub fn as_slice(&self) -> &[u8; LENGTH] {
        &self.0
    }
    /// Returns a mutable reference to the underlying data as a slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8; LENGTH] {
        &mut self.0
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8]> for ByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8]> for ByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const LENGTH: usize> std::ops::Deref for ByteArray<LENGTH> {
    type Target = [u8; LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> std::ops::Index<usize> for ByteArray<LENGTH> {
    type Output = u8;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl<const LENGTH: usize> std::ops::IndexMut<usize> for ByteArray<LENGTH> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

macro_rules! impl_index {
    ($range:ty) => {
        impl<const LENGTH: usize> std::ops::Index<$range> for ByteArray<LENGTH> {
            type Output = [u8];
            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.0[..][index]
            }
        }
        impl<const LENGTH: usize> std::ops::IndexMut<$range> for ByteArray<LENGTH> {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                &mut self.0[..][index]
            }
        }
    };
}

impl_index!(std::ops::Range<usize>);
impl_index!(std::ops::RangeFull);
impl_index!(std::ops::RangeFrom<usize>);
impl_index!(std::ops::RangeInclusive<usize>);
impl_index!(std::ops::RangeTo<usize>);
impl_index!(std::ops::RangeToInclusive<usize>);

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

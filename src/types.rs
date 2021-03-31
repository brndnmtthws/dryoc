use crate::error;
use crate::rng::copy_randombytes;

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::b64::*;

use std::convert::TryFrom;
use zeroize::Zeroize;

#[cfg(all(feature = "serde", not(feature = "base64")))]
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserializer, Serializer,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A generic stack-allocated byte array for working with data, with optional
/// [Serde](https://serde.rs) features.
#[cfg_attr(
    all(feature = "serde", feature = "base64"),
    derive(Zeroize, Debug, PartialEq, Clone, Serialize, Deserialize)
)]
#[cfg_attr(
    not(all(feature = "serde", feature = "base64")),
    derive(Zeroize, Debug, PartialEq, Clone)
)]
#[zeroize(drop)]
pub struct StackByteArray<const LENGTH: usize>(
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(
            serialize_with = "as_base64",
            deserialize_with = "stackbytearray_from_base64"
        )
    )]
    [u8; LENGTH],
);

pub trait NewByteArray<const LENGTH: usize> {
    fn gen() -> Self;
    fn from_slice(other: &[u8]) -> Self;
}

pub trait ByteArray<const LENGTH: usize> {
    fn as_array(&self) -> &[u8; LENGTH];
}

pub trait Bytes: AsRef<[u8]> {
    fn as_slice(&self) -> &[u8];
}

pub trait MutByteArray<const LENGTH: usize>:
    NewByteArray<LENGTH> + ByteArray<LENGTH> + AsMut<[u8; LENGTH]>
{
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH];
}

pub trait MutBytes: Bytes + AsMut<[u8]> {
    fn as_mut_slice(&mut self) -> &mut [u8];
}

pub trait ResizeableBytes {
    fn resize(&mut self, length: usize, value: u8);
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for StackByteArray<LENGTH> {
    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = Self::default();
        copy_randombytes(&mut res.0);
        res
    }
    /// Returns a new byte array from `other`. Panics if sizes do not match.
    fn from_slice(other: &[u8]) -> Self {
        let mut res = Self::default();
        res.copy_from_slice(other);
        res
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for StackByteArray<LENGTH> {
    fn as_array(&self) -> &[u8; LENGTH] {
        &self.0
    }
}

impl<const LENGTH: usize> Bytes for StackByteArray<LENGTH> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for StackByteArray<LENGTH> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        &mut self.0
    }
}

impl Bytes for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }
}

impl MutBytes for Vec<u8> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl ResizeableBytes for Vec<u8> {
    fn resize(&mut self, length: usize, value: u8) {
        self.resize(length, value);
    }
}

impl Bytes for [u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl<const LENGTH: usize> Bytes for [u8; LENGTH] {
    fn as_slice(&self) -> &[u8] {
        self
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Returns a new fixed-length stack-allocated array
    pub fn new() -> Self {
        Self::default()
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8; LENGTH]> for StackByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8; LENGTH] {
        let arr = self.0.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8; LENGTH]> for StackByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8]> for StackByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8]> for StackByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const LENGTH: usize> std::ops::Deref for StackByteArray<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> std::ops::DerefMut for StackByteArray<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> std::ops::Index<usize> for StackByteArray<LENGTH> {
    type Output = u8;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl<const LENGTH: usize> std::ops::IndexMut<usize> for StackByteArray<LENGTH> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

macro_rules! impl_index {
    ($range:ty) => {
        impl<const LENGTH: usize> std::ops::Index<$range> for StackByteArray<LENGTH> {
            type Output = [u8];
            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.0[index]
            }
        }
        impl<const LENGTH: usize> std::ops::IndexMut<$range> for StackByteArray<LENGTH> {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                &mut self.0[index]
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

impl<const LENGTH: usize> Default for StackByteArray<LENGTH> {
    fn default() -> Self {
        Self([0u8; LENGTH])
    }
}

impl<const LENGTH: usize> From<&[u8; LENGTH]> for StackByteArray<LENGTH> {
    fn from(src: &[u8; LENGTH]) -> Self {
        let mut arr = Self::default();
        arr.0.copy_from_slice(src);
        arr
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for StackByteArray<LENGTH> {
    fn from(src: [u8; LENGTH]) -> Self {
        Self::from(&src)
    }
}

impl<const LENGTH: usize> TryFrom<&[u8]> for StackByteArray<LENGTH> {
    type Error = error::Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != LENGTH {
            Err(dryoc_error!(format!(
                "Invalid size: expected {} found {}",
                LENGTH,
                src.len()
            )))
        } else {
            let mut arr = Self::default();
            arr.0.copy_from_slice(src);
            Ok(arr)
        }
    }
}

#[cfg(all(feature = "serde", not(feature = "base64")))]
impl<const LENGTH: usize> Serialize for StackByteArray<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

#[cfg(all(feature = "serde", not(feature = "base64")))]
impl<'de, const LENGTH: usize> Deserialize<'de> for StackByteArray<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArrayVisitor<const LENGTH: usize>;

        impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
            type Value = StackByteArray<LENGTH>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = StackByteArray::<LENGTH>::new();
                let mut idx: usize = 0;

                while let Some(elem) = seq.next_element()? {
                    if idx < LENGTH {
                        arr[idx] = elem;
                        idx += 1;
                    } else {
                        break;
                    }
                }

                Ok(arr)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != LENGTH {
                    return Err(de::Error::invalid_length(v.len(), &stringify!(LENGTH)));
                }
                let mut arr = StackByteArray::<LENGTH>::new();
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(ByteArrayVisitor::<LENGTH>)
    }
}

/// A type alias used for generic byte array outputs.
pub type OutputBase = Vec<u8>;
/// A type alias used for generic byte slice inputs.
pub type InputBase = [u8];

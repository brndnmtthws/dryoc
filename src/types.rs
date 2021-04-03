use std::convert::TryFrom;

use zeroize::Zeroize;

#[cfg(any(feature = "serde", feature = "base64"))]
pub use crate::bytes_serde::*;
use crate::error::{self, Error};
#[cfg(feature = "nightly")]
pub use crate::protected::*;
use crate::rng::copy_randombytes;

/// A stack-allocated fixed-length byte array for working with data, with
/// optional [Serde](https://serde.rs) features.
#[derive(Zeroize, Debug, PartialEq, Clone)]
#[zeroize(drop)]
pub struct StackByteArray<const LENGTH: usize>([u8; LENGTH]);

pub trait ByteArray<const LENGTH: usize>: Bytes {
    fn as_array(&self) -> &[u8; LENGTH];
}

pub trait Bytes: AsRef<[u8]> {
    fn as_slice(&self) -> &[u8];
    fn len(&self) -> usize;
}

pub trait MutByteArray<const LENGTH: usize>: ByteArray<LENGTH> + MutBytes {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH];
}

pub trait NewByteArray<const LENGTH: usize>: MutByteArray<LENGTH> {
    fn new() -> Self;
    fn gen() -> Self;
    fn from_slice(other: &[u8]) -> Self;
}

pub trait MutBytes: Bytes {
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn copy_from_slice(&mut self, other: &[u8]);
}

pub trait NewBytes: MutBytes + ResizableBytes {
    fn new() -> Self;
    fn from_slice(other: &[u8]) -> Self;
}

pub trait ResizableBytes {
    fn resize(&mut self, new_len: usize, value: u8);
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

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for StackByteArray<LENGTH> {
    /// Returns a new empty (but allocated) byte array.
    fn new() -> Self {
        Self::default()
    }

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

impl<const LENGTH: usize> MutByteArray<LENGTH> for StackByteArray<LENGTH> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        &mut self.0
    }
}

impl<const LENGTH: usize> MutBytes for StackByteArray<LENGTH> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.0.copy_from_slice(other)
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for Vec<u8> {
    /// Returns a new empty (but allocated) byte array as a [Vec].
    fn new() -> Self {
        vec![0u8; LENGTH]
    }

    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = <Self as NewByteArray<LENGTH>>::new();
        copy_randombytes(&mut res);
        res
    }

    /// Returns a new byte array from `other`. Panics if sizes do not match.
    fn from_slice(other: &[u8]) -> Self {
        let mut res = <Self as NewByteArray<LENGTH>>::new();
        res.copy_from_slice(other);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for Vec<u8> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.as_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}
impl<const LENGTH: usize> ByteArray<LENGTH> for Vec<u8> {
    fn as_array(&self) -> &[u8; LENGTH] {
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for [u8; LENGTH] {
    /// Returns a new empty (but allocated) byte array as a [Vec].
    fn new() -> Self {
        [0u8; LENGTH]
    }

    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = <Self as NewByteArray<LENGTH>>::new();
        copy_randombytes(&mut res);
        res
    }

    /// Returns a new byte array from `other`. Panics if sizes do not match.
    fn from_slice(other: &[u8]) -> Self {
        let mut res = <Self as NewByteArray<LENGTH>>::new();
        res.copy_from_slice(other);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for [u8; LENGTH] {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self
    }
}

impl<const LENGTH: usize> MutBytes for [u8; LENGTH] {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        <[u8]>::copy_from_slice(self, other)
    }
}

impl Bytes for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl NewBytes for Vec<u8> {
    fn new() -> Self {
        Self::default()
    }

    fn from_slice(other: &[u8]) -> Self {
        let mut r = Self::default();
        r.extend_from_slice(other);
        r
    }
}

impl MutBytes for Vec<u8> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        <[u8]>::copy_from_slice(self, other)
    }
}

impl ResizableBytes for Vec<u8> {
    fn resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }
}

impl Bytes for [u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl Bytes for &[u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl Bytes for &mut [u8] {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl<const LENGTH: usize> Bytes for [u8; LENGTH] {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl<const LENGTH: usize> Bytes for &[u8; LENGTH] {
    fn as_slice(&self) -> &[u8] {
        *self
    }

    fn len(&self) -> usize {
        <[u8]>::len(*self)
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for [u8; LENGTH] {
    fn as_array(&self) -> &[u8; LENGTH] {
        &self
    }
}

/// Provided for convenience. Panics if the input array size doesn't match
/// `LENGTH`.
impl<const LENGTH: usize> ByteArray<LENGTH> for &[u8] {
    fn as_array(&self) -> &[u8; LENGTH] {
        if self.len() < LENGTH {
            panic!(
                "invalid slice length {}, expecting at least {}",
                self.len(),
                LENGTH
            );
        }
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for [u8] {
    fn as_array(&self) -> &[u8; LENGTH] {
        if self.len() < LENGTH {
            panic!(
                "invalid slice length {}, expecting at least {}",
                self.len(),
                LENGTH
            );
        }
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for [u8] {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        if self.len() < LENGTH {
            panic!(
                "invalid slice length {}, expecting at least {}",
                self.len(),
                LENGTH
            );
        }
        let arr = self.as_mut_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}

impl MutBytes for [u8] {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.copy_from_slice(other)
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

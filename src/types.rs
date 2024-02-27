use lazy_static::__Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng::copy_randombytes;

/// A stack-allocated fixed-length byte array for working with data, with
/// optional [Serde](https://serde.rs) features.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone)]
pub struct StackByteArray<const LENGTH: usize>([u8; LENGTH]);

/// Fixed-length byte array.
pub trait ByteArray<const LENGTH: usize>: Bytes {
    /// Returns a reference to the underlying fixed-length byte array.
    fn as_array(&self) -> &[u8; LENGTH];
}

/// Arbitrary-length array of bytes.
pub trait Bytes {
    /// Returns a slice of the underlying bytes.
    fn as_slice(&self) -> &[u8];
    /// Shorthand to retrieve the underlying length of the byte array.
    fn len(&self) -> usize;
    /// Returns true if the array is empty.
    fn is_empty(&self) -> bool;
}

/// Fixed-length mutable byte array.
pub trait MutByteArray<const LENGTH: usize>: ByteArray<LENGTH> + MutBytes {
    /// Returns a mutable reference to the underlying fixed-length byte array.
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH];
}

/// Fixed-length byte array that can be created and initialized.
pub trait NewByteArray<const LENGTH: usize>: MutByteArray<LENGTH> + NewBytes {
    /// Returns a new fixed-length byte array, initialized with zeroes.
    fn new_byte_array() -> Self;
    /// Returns a new fixed-length byte array, filled with random values.
    fn gen() -> Self;
}

/// Arbitrary-length array of mutable bytes.
pub trait MutBytes: Bytes {
    /// Returns a mutable slice to the underlying bytes.
    fn as_mut_slice(&mut self) -> &mut [u8];
    /// Copies into the underlying slice from `other`. Panics if lengths do not
    /// match.
    fn copy_from_slice(&mut self, other: &[u8]);
}

/// Arbitrary-length byte array that can be created and initialized.
pub trait NewBytes: MutBytes {
    /// Returns an empty, unallocated, arbitrary-length byte array.
    fn new_bytes() -> Self;
}

/// A byte array which can be resized.
pub trait ResizableBytes {
    /// Resizes `self` with `new_len` elements, populating new values with
    /// `value`.
    fn resize(&mut self, new_len: usize, value: u8);
}

impl<const LENGTH: usize> ByteArray<LENGTH> for StackByteArray<LENGTH> {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        &self.0
    }
}

impl<const LENGTH: usize> Bytes for StackByteArray<LENGTH> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const LENGTH: usize> NewBytes for StackByteArray<LENGTH> {
    fn new_bytes() -> Self {
        Self::default()
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for StackByteArray<LENGTH> {
    fn new_byte_array() -> Self {
        Self::default()
    }

    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = Self::default();
        copy_randombytes(&mut res.0);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for StackByteArray<LENGTH> {
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        &mut self.0
    }
}

impl<const LENGTH: usize> MutBytes for StackByteArray<LENGTH> {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.0.copy_from_slice(other)
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for Vec<u8> {
    fn new_byte_array() -> Self {
        vec![0u8; LENGTH]
    }

    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = vec![0u8; LENGTH];
        copy_randombytes(&mut res);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for Vec<u8> {
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        assert!(
            self.len() >= LENGTH,
            "invalid vec length {}, expecting at least {}",
            self.len(),
            LENGTH
        );
        let arr = self.as_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for Vec<u8> {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        assert!(
            self.len() >= LENGTH,
            "invalid vec length {}, expecting at least {}",
            self.len(),
            LENGTH
        );
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> NewBytes for [u8; LENGTH] {
    fn new_bytes() -> Self {
        [0u8; LENGTH]
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for [u8; LENGTH] {
    fn new_byte_array() -> Self {
        [0u8; LENGTH]
    }

    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = Self::new_byte_array();
        copy_randombytes(&mut res);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for [u8; LENGTH] {
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self
    }
}

impl<const LENGTH: usize> MutBytes for [u8; LENGTH] {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        <[u8]>::copy_from_slice(self, other)
    }
}

impl Bytes for Vec<u8> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl NewBytes for Vec<u8> {
    fn new_bytes() -> Self {
        vec![]
    }
}

impl MutBytes for Vec<u8> {
    #[inline]
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
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl Bytes for &[u8] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl Bytes for &mut [u8] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl<const LENGTH: usize> Bytes for [u8; LENGTH] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

#[allow(suspicious_double_ref_op)]
impl<const LENGTH: usize> Bytes for &[u8; LENGTH] {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.deref()
    }

    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self.deref())
    }

    #[inline]
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self.deref())
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for [u8; LENGTH] {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        self
    }
}

/// Provided for convenience. Panics if the input array size doesn't match
/// `LENGTH`.
impl<const LENGTH: usize> ByteArray<LENGTH> for &[u8] {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        assert!(
            self.len() >= LENGTH,
            "invalid slice length {}, expecting at least {}",
            self.len(),
            LENGTH
        );
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for [u8] {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        assert!(
            self.len() >= LENGTH,
            "invalid slice length {}, expecting at least {}",
            self.len(),
            LENGTH
        );
        let arr = self.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for [u8] {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        assert!(
            self.len() >= LENGTH,
            "invalid slice length {}, expecting at least {}",
            self.len(),
            LENGTH
        );
        let arr = self.as_mut_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}

impl MutBytes for [u8] {
    #[inline]
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

impl<'a, const LENGTH: usize> TryFrom<&'a [u8]> for StackByteArray<LENGTH> {
    type Error = crate::error::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "invalid vec length 2, expecting at least 3")]
    fn test_vec_as_array_out_of_bounds_panic() {
        let vec = vec![1, 2];
        let _ = <Vec<u8> as ByteArray<3>>::as_array(&vec)[2];
    }

    #[test]
    fn test_vec_as_array_out_of_bounds_ok() {
        let vec = vec![1, 2];
        let _ = <Vec<u8> as ByteArray<2>>::as_array(&vec)[1];
    }

    #[test]
    #[should_panic(expected = "invalid vec length 2, expecting at least 3")]
    fn test_vec_as_mut_array_out_of_bounds_panic() {
        let mut vec = vec![1, 2];
        let _ = <Vec<u8> as MutByteArray<3>>::as_mut_array(&mut vec)[2];
    }

    #[test]
    fn test_vec_as_mut_array_out_of_bounds_ok() {
        let mut vec = vec![1, 2];
        let _ = <Vec<u8> as MutByteArray<2>>::as_mut_array(&mut vec)[1];
    }
}

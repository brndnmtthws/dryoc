use std::fmt;
use std::ops::{Deref, DerefMut};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng::copy_randombytes;
use crate::utils::zeroize_bytes;

/// A stack-allocated fixed-length byte array for working with data, with
/// optional [Serde](https://serde.rs) features.
#[derive(Clone)]
pub struct StackByteArray<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Zeroize for StackByteArray<LENGTH> {
    fn zeroize(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

impl<const LENGTH: usize> Drop for StackByteArray<LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for StackByteArray<LENGTH> {}

impl<const LENGTH: usize> fmt::Debug for StackByteArray<LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackByteArray")
            .field("len", &LENGTH)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl<const LENGTH: usize> PartialEq for StackByteArray<LENGTH> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const LENGTH: usize> Eq for StackByteArray<LENGTH> {}

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
    #[allow(deprecated)]
    fn generate() -> Self
    where
        Self: Sized,
    {
        Self::r#gen()
    }
    /// Returns a new fixed-length byte array, filled with random values.
    ///
    /// Prefer [`generate`](Self::generate). `gen` is retained for compatibility
    /// with older Rust editions.
    #[deprecated(note = "use generate() instead")]
    fn r#gen() -> Self;
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

/// Returns a new byte buffer filled with random data.
pub(crate) fn gen_bytes<B: NewBytes + MutBytes>() -> B {
    let mut res = B::new_bytes();
    copy_randombytes(res.as_mut_slice());
    res
}

/// Returns a new `Output` holding `prefix || data`.
pub(crate) fn concat_bytes<Output: NewBytes + ResizableBytes>(
    prefix: &[u8],
    data: &[u8],
) -> Output {
    let mut out = Output::new_bytes();
    out.resize(prefix.len() + data.len(), 0);
    let s = out.as_mut_slice();
    s[..prefix.len()].copy_from_slice(prefix);
    s[prefix.len()..].copy_from_slice(data);
    out
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
    fn r#gen() -> Self {
        gen_bytes()
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
    fn r#gen() -> Self {
        gen_bytes()
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
    fn r#gen() -> Self {
        gen_bytes()
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

/// Implements [`Bytes`] for a slice-like type by delegating to `[u8]`.
///
/// Shared by `[u8]`, `&[u8]`, and `&mut [u8]`, whose bodies are identical:
/// each derefs to a byte slice for every method.
macro_rules! impl_bytes_for_slice {
    ($($t:ty),*) => {
        $(
            impl Bytes for $t {
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
        )*
    };
}

impl_bytes_for_slice!([u8], &[u8], &mut [u8]);

/// Implements [`Bytes`] for a fixed-size byte array (or reference to one),
/// delegating to `$this` (e.g. `a` or `a.deref()`).
macro_rules! impl_bytes_for_array {
    ($($(#[$meta:meta])* $t:ty, |$a:ident| $this:expr;)*) => {$(
        $(#[$meta])*
        impl<const LENGTH: usize> Bytes for $t {
            #[inline]
            fn as_slice(&self) -> &[u8] {
                let $a = self;
                $this
            }

            #[inline]
            fn len(&self) -> usize {
                let $a = self;
                <[u8]>::len($this)
            }

            #[inline]
            fn is_empty(&self) -> bool {
                let $a = self;
                <[u8]>::is_empty($this)
            }
        }
    )*};
}

impl_bytes_for_array! {
    [u8; LENGTH], |a| a;
    #[allow(suspicious_double_ref_op)] &[u8; LENGTH], |a| a.deref();
}

/// Implements the checked fixed-size array view of a runtime-sized byte
/// buffer, panicking with an "invalid `$noun` length" message when the buffer
/// is shorter than `LENGTH`.
macro_rules! impl_checked_bytearray {
    (immutable: $($(#[$meta:meta])* $t:ty, $noun:literal;)*) => {$(
        $(#[$meta])*
        impl<const LENGTH: usize> ByteArray<LENGTH> for $t {
            #[inline]
            fn as_array(&self) -> &[u8; LENGTH] {
                assert!(
                    self.len() >= LENGTH,
                    concat!("invalid ", $noun, " length {}, expecting at least {}"),
                    self.len(),
                    LENGTH
                );
                let arr = self.as_ptr() as *const [u8; LENGTH];
                // SAFETY: The assertion above guarantees the buffer has at
                // least `LENGTH` initialized bytes. `[u8; LENGTH]` has
                // alignment 1, so the first `LENGTH` bytes can be viewed as a
                // fixed-size byte array.
                unsafe { &*arr }
            }
        }
    )*};
    (mutable: $($t:ty, $noun:literal;)*) => {$(
        impl<const LENGTH: usize> MutByteArray<LENGTH> for $t {
            #[inline]
            fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
                assert!(
                    self.len() >= LENGTH,
                    concat!("invalid ", $noun, " length {}, expecting at least {}"),
                    self.len(),
                    LENGTH
                );
                let arr = self.as_mut_ptr() as *mut [u8; LENGTH];
                // SAFETY: The assertion above guarantees the buffer has at
                // least `LENGTH` initialized bytes. `[u8; LENGTH]` has
                // alignment 1, and the exclusive `&mut self` borrow prevents
                // aliasing the returned prefix.
                unsafe { &mut *arr }
            }
        }
    )*};
}

impl_checked_bytearray!(immutable:
    /// Provided for convenience. Panics if the input array size doesn't match
    /// `LENGTH`.
    &[u8], "slice";
    [u8], "slice";
    Vec<u8>, "vec";
);
impl_checked_bytearray!(mutable:
    Vec<u8>, "vec";
    [u8], "slice";
);

impl<const LENGTH: usize> ByteArray<LENGTH> for [u8; LENGTH] {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        self
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
        // SAFETY: `StackByteArray<LENGTH>` stores exactly `[u8; LENGTH]` in
        // `self.0`, so this cast preserves size, alignment, and initialization.
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8; LENGTH]> for StackByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
        // SAFETY: `StackByteArray<LENGTH>` stores exactly `[u8; LENGTH]` in
        // `self.0`, and `&mut self` provides exclusive access to it.
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

impl<const LENGTH: usize> Deref for StackByteArray<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for StackByteArray<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Implements `Index`/`IndexMut` for a byte container: the `usize` impls
/// yielding `u8` and the six range impls yielding `[u8]`, delegating to the
/// `$get`/`$get_mut` expressions for the backing bytes (e.g. `s.0` or
/// `s.as_slice()`).
macro_rules! impl_slice_index {
    (impl[$($generics:tt)*] $ty:ty, |$s:ident| $get:expr, |$sm:ident| $get_mut:expr) => {
        impl<$($generics)*> std::ops::Index<usize> for $ty {
            type Output = u8;

            #[inline]
            fn index(&self, index: usize) -> &Self::Output {
                let $s = self;
                &$get[index]
            }
        }
        impl<$($generics)*> std::ops::IndexMut<usize> for $ty {
            #[inline]
            fn index_mut(&mut self, index: usize) -> &mut Self::Output {
                let $sm = self;
                &mut $get_mut[index]
            }
        }
        impl_slice_index!(@ranges impl[$($generics)*] $ty, |$s| $get, |$sm| $get_mut);
    };
    (@ranges impl[$($generics:tt)*] $ty:ty, |$s:ident| $get:expr, |$sm:ident| $get_mut:expr) => {
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::Range<usize>, |$s| $get, |$sm| $get_mut);
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::RangeFull, |$s| $get, |$sm| $get_mut);
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::RangeFrom<usize>, |$s| $get, |$sm| $get_mut);
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::RangeInclusive<usize>, |$s| $get, |$sm| $get_mut);
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::RangeTo<usize>, |$s| $get, |$sm| $get_mut);
        impl_slice_index!(@range impl[$($generics)*] $ty, std::ops::RangeToInclusive<usize>, |$s| $get, |$sm| $get_mut);
    };
    (@range impl[$($generics:tt)*] $ty:ty, $range:ty, |$s:ident| $get:expr, |$sm:ident| $get_mut:expr) => {
        impl<$($generics)*> std::ops::Index<$range> for $ty {
            type Output = [u8];

            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                let $s = self;
                &$get[index]
            }
        }
        impl<$($generics)*> std::ops::IndexMut<$range> for $ty {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                let $sm = self;
                &mut $get_mut[index]
            }
        }
    };
}

// Only `protected.rs` imports this macro; it is compiled out on targets
// without the protected feature.
#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
pub(crate) use impl_slice_index;

impl_slice_index!(impl[const LENGTH: usize] StackByteArray<LENGTH>, |s| s.0, |s| s.0);

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
    type Error = crate::error::Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        validate_length!(exact LENGTH, src.len(), crate::ErrorContext::Slice);
        let mut arr = Self::default();
        arr.0.copy_from_slice(src);
        Ok(arr)
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

    #[test]
    fn stack_byte_array_debug_redacts_contents() {
        let bytes = StackByteArray::from([0xabu8; 4]);
        let debug = format!("{bytes:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("171"));
    }
}

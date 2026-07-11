//! # HKDF key derivation
//!
//! [`HkdfSha256`] and [`HkdfSha512`] provide Rustaceous wrappers around
//! libsodium's HKDF-SHA-256 and HKDF-SHA-512 functions.
//!
//! HKDF turns input keying material into one or more independent keys. It has
//! two steps:
//!
//! * extract: mix the input keying material with an optional salt to produce a
//!   pseudorandom key (PRK)
//! * expand: derive output bytes from that PRK and a context string
//!
//! Use HKDF when you already have keying material, such as a shared secret from
//! key exchange, and need separate keys for different purposes. The context is
//! public domain-separation data; changing it changes the derived output.
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::hkdf::{HkdfSha256, HkdfSha256Prk};
//!
//! let hkdf: HkdfSha256 =
//!     HkdfSha256::extract(Some(b"Act IV salt"), b"Now is the winter of our discontent");
//! let output: Vec<u8> = hkdf
//!     .expand_to_vec(42, b"session key")
//!     .expect("expand failed");
//! assert_eq!(output.len(), 42);
//! ```
//!
//! # One-shot extract and expand
//!
//! ```
//! use dryoc::hkdf::HkdfSha512;
//!
//! let output = HkdfSha512::extract_and_expand_to_vec(
//!     64,
//!     Some(b"optional deployment salt"),
//!     b"Our remedies oft in ourselves do lie",
//!     b"application secret",
//! )
//! .expect("expand failed");
//! assert_eq!(output.len(), 64);
//! ```
//!
//! # Reusing an extracted PRK
//!
//! ```
//! use dryoc::hkdf::{HkdfSha256, HkdfSha256Prk};
//!
//! let hkdf = HkdfSha256::extract(Some(b"deployment salt"), b"We know what we are");
//! let encryption_key: HkdfSha256Prk = hkdf.expand(b"encryption key").expect("expand failed");
//! let authentication_key: HkdfSha256Prk =
//!     hkdf.expand(b"authentication key").expect("expand failed");
//! assert_ne!(encryption_key, authentication_key);
//! ```
//!
//! The concrete expanders are type aliases over [`Hkdf`] and can also be used
//! through [`HkdfVariant`] in generic code.

use std::marker::PhantomData;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_kdf::{
    crypto_kdf_hkdf_sha256_expand, crypto_kdf_hkdf_sha256_extract, crypto_kdf_hkdf_sha512_expand,
    crypto_kdf_hkdf_sha512_extract,
};
use crate::constants::{
    CRYPTO_KDF_HKDF_SHA256_BYTES_MAX, CRYPTO_KDF_HKDF_SHA256_BYTES_MIN,
    CRYPTO_KDF_HKDF_SHA256_KEYBYTES, CRYPTO_KDF_HKDF_SHA512_BYTES_MAX,
    CRYPTO_KDF_HKDF_SHA512_BYTES_MIN, CRYPTO_KDF_HKDF_SHA512_KEYBYTES,
};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated pseudorandom key for HKDF-SHA-256.
pub type HkdfSha256Prk = StackByteArray<CRYPTO_KDF_HKDF_SHA256_KEYBYTES>;
/// Stack-allocated pseudorandom key for HKDF-SHA-512.
pub type HkdfSha512Prk = StackByteArray<CRYPTO_KDF_HKDF_SHA512_KEYBYTES>;
/// Stack-allocated HKDF-SHA-256 expander.
pub type HkdfSha256 = Hkdf<HkdfSha256Variant, HkdfSha256Prk, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>;
/// Stack-allocated HKDF-SHA-512 expander.
pub type HkdfSha512 = Hkdf<HkdfSha512Variant, HkdfSha512Prk, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// HKDF expander for a specific [`HkdfVariant`].
pub struct Hkdf<Variant, Prk, const PRK_LENGTH: usize>
where
    Variant: HkdfVariant<PRK_LENGTH>,
    Prk: ByteArray<PRK_LENGTH> + Zeroize + ZeroizeOnDrop,
{
    prk: Prk,
    _variant: PhantomData<Variant>,
}

/// HKDF-SHA-256 expander.
pub type HkdfSha256Expander<Prk> = Hkdf<HkdfSha256Variant, Prk, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>;
/// HKDF-SHA-512 expander.
pub type HkdfSha512Expander<Prk> = Hkdf<HkdfSha512Variant, Prk, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>;

/// HKDF-SHA-256 algorithm marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct HkdfSha256Variant;
/// HKDF-SHA-512 algorithm marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct HkdfSha512Variant;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for HKDF
    //!
    //! This mod provides protected-memory PRK aliases and locked HKDF aliases.
    //! Use these aliases when the extracted PRK or expanded output should stay
    //! in locked memory.
    //!
    //! ```
    //! use dryoc::hkdf::HkdfSha512Expander;
    //! use dryoc::hkdf::protected::*;
    //!
    //! let ikm = HeapBytes::from_slice_into_readonly_locked(b"Truth will come to light.")
    //!     .expect("ikm failed");
    //! let hkdf: LockedHkdfSha512 = HkdfSha512Expander::extract(None::<&[u8]>, &ikm);
    //! let output: Locked<HeapBytes> = hkdf.expand_to_bytes(64, b"context").expect("expand failed");
    //! assert_eq!(output.len(), 64);
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned pseudorandom key for HKDF-SHA-256.
    pub type HkdfSha256Prk = HeapByteArray<CRYPTO_KDF_HKDF_SHA256_KEYBYTES>;
    /// Heap-allocated, page-aligned pseudorandom key for HKDF-SHA-512.
    pub type HkdfSha512Prk = HeapByteArray<CRYPTO_KDF_HKDF_SHA512_KEYBYTES>;

    /// Locked HKDF-SHA-256 expander.
    pub type LockedHkdfSha256 = HkdfSha256Expander<Locked<HkdfSha256Prk>>;
    /// Locked HKDF-SHA-512 expander.
    pub type LockedHkdfSha512 = HkdfSha512Expander<Locked<HkdfSha512Prk>>;
}

/// HKDF algorithm variant used by [`Hkdf`].
pub trait HkdfVariant<const PRK_LENGTH: usize> {
    /// Default stack-allocated PRK type for this variant.
    type Prk: NewByteArray<PRK_LENGTH> + Zeroize + ZeroizeOnDrop;
    /// Minimum output length accepted by this variant.
    const OUTPUT_BYTES_MIN: usize;
    /// Maximum output length accepted by this variant.
    const OUTPUT_BYTES_MAX: usize;

    /// Creates a PRK from input keying material and optional salt.
    fn extract(prk: &mut [u8; PRK_LENGTH], salt: Option<&[u8]>, ikm: &[u8]);
    /// Expands a PRK into output keying material.
    ///
    /// # Errors
    ///
    /// Returns an error if `output.len()` is outside the range supported by
    /// this variant.
    fn expand(output: &mut [u8], context: &[u8], prk: &[u8; PRK_LENGTH]) -> Result<(), Error>;

    /// Validates an output length before allocating output storage.
    ///
    /// # Errors
    ///
    /// Returns an error if `output_len` is smaller than
    /// [`Self::OUTPUT_BYTES_MIN`] or larger than [`Self::OUTPUT_BYTES_MAX`].
    fn validate_output_len(output_len: usize) -> Result<(), Error> {
        if output_len < Self::OUTPUT_BYTES_MIN || output_len > Self::OUTPUT_BYTES_MAX {
            Err(dryoc_error!(format!(
                "invalid output length {}, should be at least {} and no more than {}",
                output_len,
                Self::OUTPUT_BYTES_MIN,
                Self::OUTPUT_BYTES_MAX
            )))
        } else {
            Ok(())
        }
    }
}

macro_rules! impl_hkdf_variant {
    (
        $variant:ty,
        $prk_len:expr,
        $prk:ty,
        $bytes_min:expr,
        $bytes_max:expr,
        $extract:path,
        $expand:path
    ) => {
        impl HkdfVariant<$prk_len> for $variant {
            type Prk = $prk;

            const OUTPUT_BYTES_MAX: usize = $bytes_max;
            const OUTPUT_BYTES_MIN: usize = $bytes_min;

            fn extract(prk: &mut [u8; $prk_len], salt: Option<&[u8]>, ikm: &[u8]) {
                $extract(prk, salt, ikm);
            }

            fn expand(
                output: &mut [u8],
                context: &[u8],
                prk: &[u8; $prk_len],
            ) -> Result<(), Error> {
                $expand(output, context, prk)
            }
        }
    };
}

impl_hkdf_variant!(
    HkdfSha256Variant,
    CRYPTO_KDF_HKDF_SHA256_KEYBYTES,
    HkdfSha256Prk,
    CRYPTO_KDF_HKDF_SHA256_BYTES_MIN,
    CRYPTO_KDF_HKDF_SHA256_BYTES_MAX,
    crypto_kdf_hkdf_sha256_extract,
    crypto_kdf_hkdf_sha256_expand
);

impl_hkdf_variant!(
    HkdfSha512Variant,
    CRYPTO_KDF_HKDF_SHA512_KEYBYTES,
    HkdfSha512Prk,
    CRYPTO_KDF_HKDF_SHA512_BYTES_MIN,
    CRYPTO_KDF_HKDF_SHA512_BYTES_MAX,
    crypto_kdf_hkdf_sha512_extract,
    crypto_kdf_hkdf_sha512_expand
);

impl<Variant, Prk, const PRK_LENGTH: usize> Hkdf<Variant, Prk, PRK_LENGTH>
where
    Variant: HkdfVariant<PRK_LENGTH>,
    Prk: NewByteArray<PRK_LENGTH> + Zeroize + ZeroizeOnDrop,
{
    /// Randomly generates a new PRK for HKDF expand.
    pub fn generate() -> Self {
        Self {
            prk: Prk::generate(),
            _variant: PhantomData,
        }
    }

    /// Randomly generates a new PRK for HKDF expand.
    ///
    /// Prefer [`generate`](Self::generate). `gen` is retained for compatibility
    /// with older Rust editions.
    #[deprecated(note = "use generate() instead")]
    pub fn r#gen() -> Self {
        Self::generate()
    }

    /// Extracts a PRK from input keying material and optional salt.
    pub fn extract<Salt: Bytes + ?Sized, Ikm: Bytes + ?Sized>(
        salt: Option<&Salt>,
        ikm: &Ikm,
    ) -> Self {
        let mut prk = Prk::new_byte_array();
        Variant::extract(
            prk.as_mut_array(),
            salt.map(|s| s.as_slice()),
            ikm.as_slice(),
        );
        Self {
            prk,
            _variant: PhantomData,
        }
    }

    /// One-shot HKDF extract-and-expand into a fixed-size output type.
    ///
    /// # Errors
    ///
    /// Returns an error if `OUTPUT_LENGTH` is outside the range supported by
    /// the selected HKDF variant.
    pub fn extract_and_expand<
        const OUTPUT_LENGTH: usize,
        Salt: Bytes + ?Sized,
        Ikm: Bytes + ?Sized,
        Context: Bytes + ?Sized,
        Output: NewByteArray<OUTPUT_LENGTH>,
    >(
        salt: Option<&Salt>,
        ikm: &Ikm,
        context: &Context,
    ) -> Result<Output, Error> {
        Self::extract(salt, ikm).expand(context)
    }

    /// One-shot HKDF extract-and-expand into a [`Vec`].
    ///
    /// # Errors
    ///
    /// Returns an error if `output_len` is outside the range supported by the
    /// selected HKDF variant.
    pub fn extract_and_expand_to_vec<
        Salt: Bytes + ?Sized,
        Ikm: Bytes + ?Sized,
        Context: Bytes + ?Sized,
    >(
        output_len: usize,
        salt: Option<&Salt>,
        ikm: &Ikm,
        context: &Context,
    ) -> Result<Vec<u8>, Error> {
        Self::extract(salt, ikm).expand_to_vec(output_len, context)
    }

    /// One-shot HKDF extract-and-expand into a runtime-sized byte container.
    ///
    /// # Errors
    ///
    /// Returns an error if `output_len` is outside the range supported by the
    /// selected HKDF variant.
    pub fn extract_and_expand_to_bytes<
        Salt: Bytes + ?Sized,
        Ikm: Bytes + ?Sized,
        Context: Bytes + ?Sized,
        Output: NewBytes + ResizableBytes,
    >(
        output_len: usize,
        salt: Option<&Salt>,
        ikm: &Ikm,
        context: &Context,
    ) -> Result<Output, Error> {
        Self::extract(salt, ikm).expand_to_bytes(output_len, context)
    }
}

impl<Variant, Prk, const PRK_LENGTH: usize> Hkdf<Variant, Prk, PRK_LENGTH>
where
    Variant: HkdfVariant<PRK_LENGTH>,
    Prk: ByteArray<PRK_LENGTH> + Zeroize + ZeroizeOnDrop,
{
    /// Constructs an HKDF expander from a PRK, consuming it.
    pub fn from_prk(prk: Prk) -> Self {
        Self {
            prk,
            _variant: PhantomData,
        }
    }

    /// Moves the PRK out of this expander.
    pub fn into_prk(self) -> Prk {
        self.prk
    }

    /// Expands this PRK into a fixed-size output type.
    ///
    /// # Errors
    ///
    /// Returns an error if `OUTPUT_LENGTH` is outside the range supported by
    /// the selected HKDF variant.
    pub fn expand<const OUTPUT_LENGTH: usize, Context: Bytes + ?Sized, Output>(
        &self,
        context: &Context,
    ) -> Result<Output, Error>
    where
        Output: NewByteArray<OUTPUT_LENGTH>,
    {
        Variant::validate_output_len(OUTPUT_LENGTH)?;
        let mut output = Output::new_byte_array();
        Variant::expand(
            output.as_mut_slice(),
            context.as_slice(),
            self.prk.as_array(),
        )?;
        Ok(output)
    }

    /// Expands this PRK into a [`Vec`] of `output_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `output_len` is outside the range supported by the
    /// selected HKDF variant.
    pub fn expand_to_vec<Context: Bytes + ?Sized>(
        &self,
        output_len: usize,
        context: &Context,
    ) -> Result<Vec<u8>, Error> {
        self.expand_to_bytes(output_len, context)
    }

    /// Expands this PRK into a runtime-sized byte container.
    ///
    /// # Errors
    ///
    /// Returns an error if `output_len` is outside the range supported by the
    /// selected HKDF variant.
    pub fn expand_to_bytes<Context: Bytes + ?Sized, Output: NewBytes + ResizableBytes>(
        &self,
        output_len: usize,
        context: &Context,
    ) -> Result<Output, Error> {
        Variant::validate_output_len(output_len)?;
        let mut output = Output::new_bytes();
        output.resize(output_len, 0);
        Variant::expand(
            output.as_mut_slice(),
            context.as_slice(),
            self.prk.as_array(),
        )?;
        Ok(output)
    }
}

impl<Variant, const PRK_LENGTH: usize> Hkdf<Variant, Variant::Prk, PRK_LENGTH>
where
    Variant: HkdfVariant<PRK_LENGTH>,
{
    /// Randomly generates a new PRK using the default stack-allocated type.
    pub fn generate_with_defaults() -> Self {
        Self::generate()
    }

    /// Randomly generates a new PRK using the default stack-allocated type.
    ///
    /// Prefer [`generate_with_defaults`](Self::generate_with_defaults). This
    /// method is retained for compatibility.
    #[deprecated(note = "use generate_with_defaults() instead")]
    pub fn gen_with_defaults() -> Self {
        Self::generate_with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256() {
        let hkdf = HkdfSha256::extract(Some(b"salt"), b"input keying material");
        let output: HkdfSha256Prk = hkdf.expand(b"context").expect("expand failed");
        assert_eq!(output.len(), CRYPTO_KDF_HKDF_SHA256_KEYBYTES);

        let output = hkdf.expand_to_vec(42, b"context").expect("expand failed");
        assert_eq!(output.len(), 42);
    }

    #[test]
    fn test_hkdf_sha512() {
        let output: Vec<u8> =
            HkdfSha512::extract_and_expand_to_vec(64, Some(b"salt"), b"ikm", b"context")
                .expect("expand failed");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_hkdf_rejects_invalid_length() {
        let hkdf = HkdfSha256::extract(None::<&[u8]>, b"ikm");
        hkdf.expand_to_vec(
            crate::constants::CRYPTO_KDF_HKDF_SHA256_BYTES_MAX + 1,
            b"context",
        )
        .expect_err("oversized output should fail");
    }

    #[test]
    fn test_hkdf_rejects_huge_length_before_allocation() {
        let hkdf = HkdfSha256::extract(None::<&[u8]>, b"ikm");
        hkdf.expand_to_vec(usize::MAX, b"context")
            .expect_err("huge output should fail before allocation");
    }

    #[test]
    fn test_hkdf_variant_generic_api() {
        fn extract_and_expand_with_variant<Variant, const PRK_LENGTH: usize>(
            salt: Option<&[u8]>,
            ikm: &[u8],
            context: &[u8],
        ) -> Vec<u8>
        where
            Variant: HkdfVariant<PRK_LENGTH>,
        {
            Hkdf::<Variant, Variant::Prk, PRK_LENGTH>::extract_and_expand_to_vec(
                42, salt, ikm, context,
            )
            .expect("expand failed")
        }

        let generic_output = extract_and_expand_with_variant::<
            HkdfSha256Variant,
            CRYPTO_KDF_HKDF_SHA256_KEYBYTES,
        >(Some(b"salt"), b"input keying material", b"context");
        let concrete_output = HkdfSha256::extract_and_expand_to_vec(
            42,
            Some(b"salt"),
            b"input keying material",
            b"context",
        )
        .expect("expand failed");

        assert_eq!(generic_output, concrete_output);
    }
}

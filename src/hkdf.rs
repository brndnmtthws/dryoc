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
            Err(length_error!(
                crate::ErrorContext::Output,
                output_len,
                range Self::OUTPUT_BYTES_MIN,
                Self::OUTPUT_BYTES_MAX
            ))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 appendix A: `(salt, ikm, info, PRK, OKM)`.
    struct Case {
        salt: Option<Vec<u8>>,
        ikm: Vec<u8>,
        info: Vec<u8>,
        prk: Vec<u8>,
        okm: Vec<u8>,
    }

    fn decode(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("hex")
    }

    /// A.1 (basic) and A.3 (no salt, no info) for SHA-256.
    fn sha256_cases() -> [Case; 2] {
        [
            Case {
                salt: Some(decode("000102030405060708090a0b0c")),
                ikm: vec![0x0b; 22],
                info: decode("f0f1f2f3f4f5f6f7f8f9"),
                prk: decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                okm: decode(concat!(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                    "34007208d5b887185865",
                )),
            },
            Case {
                salt: None,
                ikm: vec![0x0b; 22],
                info: Vec::new(),
                prk: decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                okm: decode(concat!(
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
                    "9d201395faa4b61a96c8",
                )),
            },
        ]
    }

    /// A.1 inputs with HKDF-SHA-512 (the RFC 5869 authors' published
    /// extension vectors, also used by libsodium's tests).
    fn sha512_case() -> Case {
        Case {
            salt: Some(decode("000102030405060708090a0b0c")),
            ikm: vec![0x0b; 22],
            info: decode("f0f1f2f3f4f5f6f7f8f9"),
            prk: decode(concat!(
                "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26",
                "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            )),
            okm: decode(concat!(
                "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793",
                "38da362cb8d9f925d7cb",
            )),
        }
    }

    fn assert_case<Variant, const PRK_LENGTH: usize>(case: &Case)
    where
        Variant: HkdfVariant<PRK_LENGTH>,
        Variant::Prk: Clone + PartialEq + std::fmt::Debug,
    {
        type H<V, const P: usize> = Hkdf<V, <V as HkdfVariant<P>>::Prk, P>;

        let salt = case.salt.as_deref();
        let hkdf = H::<Variant, PRK_LENGTH>::extract(salt, case.ikm.as_slice());
        assert_eq!(hkdf.prk.as_slice(), case.prk.as_slice());

        let okm_len = case.okm.len();
        assert_eq!(
            hkdf.expand_to_vec(okm_len, case.info.as_slice())
                .expect("expand"),
            case.okm
        );
        let fixed: StackByteArray<42> = hkdf.expand(case.info.as_slice()).expect("expand");
        assert_eq!(fixed.as_slice(), case.okm.as_slice());
        let bytes: Vec<u8> = hkdf
            .expand_to_bytes(okm_len, case.info.as_slice())
            .expect("expand");
        assert_eq!(bytes, case.okm);

        assert_eq!(
            H::<Variant, PRK_LENGTH>::extract_and_expand_to_vec(
                okm_len,
                salt,
                case.ikm.as_slice(),
                case.info.as_slice()
            )
            .expect("expand"),
            case.okm
        );
        let fixed: StackByteArray<42> = H::<Variant, PRK_LENGTH>::extract_and_expand(
            salt,
            case.ikm.as_slice(),
            case.info.as_slice(),
        )
        .expect("expand");
        assert_eq!(fixed.as_slice(), case.okm.as_slice());
        let bytes: Vec<u8> = H::<Variant, PRK_LENGTH>::extract_and_expand_to_bytes(
            okm_len,
            salt,
            case.ikm.as_slice(),
            case.info.as_slice(),
        )
        .expect("expand");
        assert_eq!(bytes, case.okm);

        // The PRK round-trips through `into_prk`/`from_prk`.
        let prk = hkdf.into_prk();
        assert_eq!(prk.as_slice(), case.prk.as_slice());
        assert_eq!(
            H::<Variant, PRK_LENGTH>::from_prk(prk)
                .expand_to_vec(okm_len, case.info.as_slice())
                .expect("expand"),
            case.okm
        );

        // A missing salt is the all-zero salt of one hash length.
        if case.salt.is_none() {
            let empty_salt = H::<Variant, PRK_LENGTH>::extract(Some(&[][..]), case.ikm.as_slice());
            assert_eq!(empty_salt.prk.as_slice(), case.prk.as_slice());
            let zero_salt = H::<Variant, PRK_LENGTH>::extract(
                Some(&[0u8; PRK_LENGTH][..]),
                case.ikm.as_slice(),
            );
            assert_eq!(zero_salt.prk.as_slice(), case.prk.as_slice());
        }

        // Shorter outputs are prefixes; a different context is a different key.
        let short = H::<Variant, PRK_LENGTH>::extract(salt, case.ikm.as_slice())
            .expand_to_vec(okm_len - 1, case.info.as_slice())
            .expect("expand");
        assert_eq!(short, &case.okm[..okm_len - 1]);
        let mut other_info = case.info.clone();
        other_info.push(0);
        assert_ne!(
            H::<Variant, PRK_LENGTH>::extract(salt, case.ikm.as_slice())
                .expand_to_vec(okm_len, other_info.as_slice())
                .expect("expand"),
            case.okm
        );
    }

    #[test]
    fn rfc5869_sha256_vectors() {
        for case in &sha256_cases() {
            assert_case::<HkdfSha256Variant, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>(case);
        }
    }

    #[test]
    fn rfc5869_sha512_vector() {
        assert_case::<HkdfSha512Variant, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>(&sha512_case());
    }

    #[test]
    fn output_length_limits_match_the_variant() {
        let case = &sha256_cases()[0];
        let hkdf = HkdfSha256::extract(case.salt.as_deref(), case.ikm.as_slice());
        assert!(
            hkdf.expand_to_vec(CRYPTO_KDF_HKDF_SHA256_BYTES_MIN, case.info.as_slice())
                .expect("min length")
                .is_empty()
        );
        let empty: StackByteArray<0> = hkdf.expand(case.info.as_slice()).expect("min length");
        assert!(empty.is_empty());

        let max = hkdf
            .expand_to_vec(CRYPTO_KDF_HKDF_SHA256_BYTES_MAX, case.info.as_slice())
            .expect("max length");
        assert_eq!(max.len(), CRYPTO_KDF_HKDF_SHA256_BYTES_MAX);
        assert_eq!(&max[..case.okm.len()], case.okm.as_slice());
        let mut classic = vec![0u8; CRYPTO_KDF_HKDF_SHA256_BYTES_MAX];
        crypto_kdf_hkdf_sha256_expand(&mut classic, case.info.as_slice(), hkdf.prk.as_array())
            .expect("classic expand");
        assert_eq!(max, classic);

        for length in [CRYPTO_KDF_HKDF_SHA256_BYTES_MAX + 1, usize::MAX] {
            assert!(matches!(
                hkdf.expand_to_vec(length, case.info.as_slice()),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::Output,
                    actual,
                    ..
                }) if actual == length
            ));
        }
        let too_long: Result<StackByteArray<{ CRYPTO_KDF_HKDF_SHA256_BYTES_MAX + 1 }>, Error> =
            hkdf.expand(case.info.as_slice());
        assert!(matches!(
            too_long,
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Output,
                ..
            })
        ));

        // SHA-512 allows twice as much output; the SHA-256 maximum is valid
        // there.
        let hkdf512 = HkdfSha512::extract(case.salt.as_deref(), case.ikm.as_slice());
        assert_eq!(
            hkdf512
                .expand_to_vec(CRYPTO_KDF_HKDF_SHA512_BYTES_MAX, case.info.as_slice())
                .expect("max length")
                .len(),
            CRYPTO_KDF_HKDF_SHA512_BYTES_MAX
        );
        assert!(
            hkdf512
                .expand_to_vec(CRYPTO_KDF_HKDF_SHA512_BYTES_MAX + 1, case.info.as_slice())
                .is_err()
        );
    }

    #[test]
    fn matches_classic_extract_and_expand() {
        use crate::utils::test_util::XorShift64;

        let mut rng = XorShift64::new(0x686b_6466_5f74_6573);
        for round in 0..6 {
            let ikm: Vec<u8> = (0..round * 13).map(|_| rng.next_u64() as u8).collect();
            let salt: Vec<u8> = (0..round * 7).map(|_| rng.next_u64() as u8).collect();
            let info: Vec<u8> = (0..round * 5).map(|_| rng.next_u64() as u8).collect();
            let salt = (round % 2 == 0).then_some(salt.as_slice());

            let mut prk256 = [0u8; CRYPTO_KDF_HKDF_SHA256_KEYBYTES];
            crypto_kdf_hkdf_sha256_extract(&mut prk256, salt, &ikm);
            let hkdf256 = HkdfSha256::extract(salt, ikm.as_slice());
            assert_eq!(hkdf256.prk.as_array(), &prk256);

            let mut prk512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
            crypto_kdf_hkdf_sha512_extract(&mut prk512, salt, &ikm);
            let hkdf512 = HkdfSha512::extract(salt, ikm.as_slice());
            assert_eq!(hkdf512.prk.as_array(), &prk512);

            for length in [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129] {
                let mut classic = vec![0u8; length];
                crypto_kdf_hkdf_sha256_expand(&mut classic, &info, &prk256).expect("expand");
                assert_eq!(
                    hkdf256
                        .expand_to_vec(length, info.as_slice())
                        .expect("expand"),
                    classic
                );
                crypto_kdf_hkdf_sha512_expand(&mut classic, &info, &prk512).expect("expand");
                assert_eq!(
                    hkdf512
                        .expand_to_vec(length, info.as_slice())
                        .expect("expand"),
                    classic
                );
            }
        }
    }

    #[test]
    fn generic_variant_api_reproduces_rfc5869() {
        fn extract_and_expand_with_variant<Variant, const PRK_LENGTH: usize>(case: &Case) -> Vec<u8>
        where
            Variant: HkdfVariant<PRK_LENGTH>,
        {
            Hkdf::<Variant, Variant::Prk, PRK_LENGTH>::extract_and_expand_to_vec(
                case.okm.len(),
                case.salt.as_deref(),
                case.ikm.as_slice(),
                case.info.as_slice(),
            )
            .expect("expand failed")
        }

        let case256 = &sha256_cases()[0];
        let case512 = sha512_case();
        assert_eq!(
            extract_and_expand_with_variant::<HkdfSha256Variant, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>(
                case256
            ),
            case256.okm
        );
        assert_eq!(
            extract_and_expand_with_variant::<HkdfSha512Variant, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>(
                &case512
            ),
            case512.okm
        );
        // Same inputs, different hash: the variants must not collapse.
        assert_ne!(case256.okm, case512.okm);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_expands_to_the_rfc5869_output() {
        let case = &sha256_cases()[0];
        let hkdf = HkdfSha256::extract(case.salt.as_deref(), case.ikm.as_slice());
        let json = serde_json::to_string(&hkdf).expect("serialize");
        let decoded: HkdfSha256 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            decoded
                .expand_to_vec(case.okm.len(), case.info.as_slice())
                .expect("expand"),
            case.okm
        );

        let case = sha512_case();
        let hkdf = HkdfSha512::extract(case.salt.as_deref(), case.ikm.as_slice());
        let json = serde_json::to_string(&hkdf).expect("serialize");
        let decoded: HkdfSha512 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.into_prk().as_slice(), case.prk.as_slice());
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_expanders_reproduce_rfc5869() {
        use crate::hkdf::protected::*;

        let case = &sha256_cases()[0];
        let ikm = HeapBytes::from_slice_into_readonly_locked(&case.ikm).expect("lock ikm");
        let salt = case
            .salt
            .as_ref()
            .map(|salt| HeapBytes::from_slice_into_readonly_locked(salt).expect("lock salt"));
        let hkdf: LockedHkdfSha256 = HkdfSha256Expander::extract(salt.as_ref(), &ikm);
        assert_eq!(hkdf.prk.as_slice(), case.prk.as_slice());
        let okm: Locked<HeapBytes> = hkdf
            .expand_to_bytes(case.okm.len(), case.info.as_slice())
            .expect("expand");
        assert_eq!(okm.as_slice(), case.okm.as_slice());
        let fixed: Locked<HeapByteArray<42>> = hkdf.expand(case.info.as_slice()).expect("expand");
        assert_eq!(fixed.as_slice(), case.okm.as_slice());

        let case = sha512_case();
        let ikm = HeapBytes::from_slice_into_readonly_locked(&case.ikm).expect("lock ikm");
        let hkdf: LockedHkdfSha512 = HkdfSha512Expander::extract(case.salt.as_deref(), &ikm);
        assert_eq!(
            hkdf.expand_to_vec(case.okm.len(), case.info.as_slice())
                .expect("expand"),
            case.okm
        );
    }
}

//! # Authenticated encryption with additional data
//!
//! [`DryocAead`] provides libsodium-compatible XChaCha20-Poly1305-IETF
//! authenticated encryption. The [`chacha20poly1305_ietf`] module provides the
//! RFC 8439 variant with shorter, 96-bit nonces. Both encrypt a message and can
//! authenticate unencrypted metadata, called _additional data_. If the
//! ciphertext or additional data changes, decryption fails.
//!
//! Use [`DryocAead`] when your application manages nonces and needs libsodium's
//! `ciphertext || tag` wire format. Use [`DryocAeadEnvelope`] to have dryoc
//! generate a random XChaCha20 nonce and store it as
//! `nonce || ciphertext || tag`.
//!
//! Nonces are public, but a nonce must never repeat with the same key.
//! [`DryocAeadEnvelope`] generates and stores a nonce for each message. Callers
//! using [`DryocAead`] must enforce nonce uniqueness themselves.
//!
//! If the `serde` feature is enabled,
//! [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) and
//! [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) are implemented
//! for [`AeadBox`] and [`AeadEnvelope`].
//! If the `wincode` feature is enabled,
//! [`wincode::SchemaRead`](https://docs.rs/wincode/latest/wincode/trait.SchemaRead.html) and
//! [`wincode::SchemaWrite`](https://docs.rs/wincode/latest/wincode/trait.SchemaWrite.html) are
//! implemented for [`VecBox`] and [`VecEnvelope`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::dryocaead::*;
//!
//! let key = Key::generate();
//! let nonce = Nonce::generate();
//! let message = b"Arbitrary data to encrypt";
//! let aad = b"metadata";
//!
//! let dryocaead =
//!     DryocAead::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("encrypt failed");
//! let bytes = dryocaead.to_vec();
//! let dryocaead = VecBox::from_bytes(&bytes).expect("from bytes");
//! let decrypted = dryocaead
//!     .decrypt_to_vec(Some(aad), &nonce, &key)
//!     .expect("decrypt failed");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```
//!
//! ## Generated nonce envelope example
//!
//! ```
//! use dryoc::dryocaead::*;
//!
//! let key = Key::generate();
//! let message = b"Arbitrary data to encrypt";
//! let aad = b"metadata";
//!
//! let envelope = DryocAeadEnvelope::seal_to_vec(message, Some(aad), &key).expect("seal failed");
//! let bytes = envelope.to_vec();
//! let envelope = VecEnvelope::from_bytes(&bytes).expect("from bytes");
//! let decrypted = envelope.open_to_vec(Some(aad), &key).expect("open failed");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```

use std::marker::PhantomData;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
};
use crate::error::{Error, ErrorContext};
pub use crate::types::*;
use crate::utils::{ct_eq_bytes, split_suffix};

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for AEAD algorithms supported by dryoc.
///
/// This trait is sealed so applications cannot plug in custom cryptographic
/// algorithms while still allowing dryoc to add future AEAD constructions
/// without changing the container types.
pub trait AeadAlgorithm:
    sealed::Sealed + Clone + Copy + std::fmt::Debug + Default + Eq + PartialEq
{
}

/// XChaCha20-Poly1305-IETF AEAD algorithm marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XChaCha20Poly1305Ietf;

impl sealed::Sealed for XChaCha20Poly1305Ietf {}
impl AeadAlgorithm for XChaCha20Poly1305Ietf {}

/// ChaCha20-Poly1305-IETF AEAD algorithm marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChaCha20Poly1305Ietf;

impl sealed::Sealed for ChaCha20Poly1305Ietf {}
impl AeadAlgorithm for ChaCha20Poly1305Ietf {}

/// Stack-allocated secret key for XChaCha20-Poly1305-IETF AEAD.
pub type Key = StackByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>;
/// Stack-allocated public nonce for XChaCha20-Poly1305-IETF AEAD.
pub type Nonce = StackByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>;
/// Stack-allocated authentication tag for XChaCha20-Poly1305-IETF AEAD.
pub type Mac = StackByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>;

/// XChaCha20-Poly1305-IETF AEAD box.
pub type DryocAead<Mac, Data> = AeadBox<XChaCha20Poly1305Ietf, Mac, Data>;
/// XChaCha20-Poly1305-IETF AEAD envelope with stored nonce.
pub type DryocAeadEnvelope<Nonce, Mac, Data> =
    AeadEnvelope<XChaCha20Poly1305Ietf, Nonce, Mac, Data>;
/// [`Vec`]-based XChaCha20-Poly1305-IETF AEAD box.
pub type VecBox = DryocAead<Mac, Vec<u8>>;
/// [`Vec`]-based XChaCha20-Poly1305-IETF AEAD envelope.
pub type VecEnvelope = DryocAeadEnvelope<Nonce, Mac, Vec<u8>>;

/// Algorithm-specific aliases for XChaCha20-Poly1305-IETF.
pub mod xchacha20poly1305_ietf {
    #[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
    pub use super::protected;
    pub use super::{AeadAlgorithm, AeadBox, AeadEnvelope, XChaCha20Poly1305Ietf};

    /// Stack-allocated secret key.
    pub type Key = super::Key;
    /// Stack-allocated public nonce.
    pub type Nonce = super::Nonce;
    /// Stack-allocated authentication tag.
    pub type Mac = super::Mac;
    /// XChaCha20-Poly1305-IETF AEAD box.
    pub type DryocAead<Mac, Data> = super::DryocAead<Mac, Data>;
    /// XChaCha20-Poly1305-IETF AEAD envelope with stored nonce.
    pub type DryocAeadEnvelope<Nonce, Mac, Data> = super::DryocAeadEnvelope<Nonce, Mac, Data>;
    /// [`Vec`]-based XChaCha20-Poly1305-IETF AEAD box.
    pub type VecBox = super::VecBox;
    /// [`Vec`]-based XChaCha20-Poly1305-IETF AEAD envelope.
    pub type VecEnvelope = super::VecEnvelope;
}

/// ChaCha20-Poly1305-IETF Rustaceous AEAD API.
///
/// A nonce must never repeat with the same key. RFC 8439 requires callers to
/// manage these 96-bit nonces uniquely, typically with a counter, rather than
/// generate them randomly. Accordingly, this variant does not provide the
/// generated-nonce [`AeadEnvelope::seal`] convenience available to XChaCha20.
/// Use [`AeadBox::encrypt`] with an explicitly managed nonce; an
/// [`AeadEnvelope`] can store that nonce via [`AeadEnvelope::from_parts`].
///
/// ## Rustaceous API example
///
/// ```
/// use dryoc::dryocaead::chacha20poly1305_ietf::*;
///
/// let key = Key::generate();
/// // This 96-bit nonce must be unique for every message encrypted with `key`.
/// let nonce = Nonce::from([0u8; 12]);
/// let message = b"Better three hours too soon than a minute too late.";
/// let aad = b"metadata";
///
/// let dryocaead =
///     VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("encrypt failed");
/// let bytes = dryocaead.to_vec();
/// let dryocaead = VecBox::from_bytes(&bytes).expect("from bytes");
/// let decrypted = dryocaead
///     .decrypt_to_vec(Some(aad), &nonce, &key)
///     .expect("decrypt failed");
///
/// assert_eq!(message, decrypted.as_slice());
/// ```
pub mod chacha20poly1305_ietf {
    pub use super::{AeadAlgorithm, AeadBox, AeadEnvelope, ChaCha20Poly1305Ietf};
    use crate::constants::{
        CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
        CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
    };
    pub use crate::types::*;

    /// Stack-allocated secret key.
    pub type Key = StackByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES>;
    /// Stack-allocated public nonce.
    pub type Nonce = StackByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES>;
    /// Stack-allocated authentication tag.
    pub type Mac = StackByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES>;
    /// ChaCha20-Poly1305-IETF AEAD box.
    pub type DryocAead<Mac, Data> = AeadBox<ChaCha20Poly1305Ietf, Mac, Data>;
    /// ChaCha20-Poly1305-IETF AEAD envelope with stored nonce.
    pub type DryocAeadEnvelope<Nonce, Mac, Data> =
        AeadEnvelope<ChaCha20Poly1305Ietf, Nonce, Mac, Data>;
    /// [`Vec`]-based ChaCha20-Poly1305-IETF AEAD box.
    pub type VecBox = DryocAead<Mac, Vec<u8>>;
    /// [`Vec`]-based ChaCha20-Poly1305-IETF AEAD envelope.
    pub type VecEnvelope = DryocAeadEnvelope<Nonce, Mac, Vec<u8>>;

    #[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
    #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
    pub mod protected {
        //! Protected-memory aliases for ChaCha20-Poly1305-IETF.
        use super::*;
        pub use crate::protected::*;

        /// Heap-allocated, page-aligned secret key.
        pub type Key = HeapByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES>;
        /// Heap-allocated, page-aligned public nonce.
        pub type Nonce = HeapByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES>;
        /// Heap-allocated, page-aligned authentication tag.
        pub type Mac = HeapByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES>;
        /// Locked AEAD box.
        pub type LockedBox = AeadBox<ChaCha20Poly1305Ietf, Locked<Mac>, LockedBytes>;
        /// Locked AEAD envelope with stored nonce.
        pub type LockedEnvelope =
            AeadEnvelope<ChaCha20Poly1305Ietf, Locked<Nonce>, Locked<Mac>, LockedBytes>;
    }
}

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`AeadBox`] and [`AeadEnvelope`]
    //!
    //! This mod provides protected-memory type aliases for the
    //! XChaCha20-Poly1305-IETF Rustaceous AEAD API.
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret key for XChaCha20-Poly1305-IETF.
    pub type Key = HeapByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>;
    /// Heap-allocated, page-aligned public nonce for XChaCha20-Poly1305-IETF.
    pub type Nonce = HeapByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>;
    /// Heap-allocated, page-aligned authentication tag for
    /// XChaCha20-Poly1305-IETF.
    pub type Mac = HeapByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>;

    /// Locked AEAD box, provided as a type alias for convenience.
    pub type LockedBox = AeadBox<XChaCha20Poly1305Ietf, Locked<Mac>, LockedBytes>;
    /// Locked AEAD envelope with stored nonce, provided as a type alias for
    /// convenience.
    pub type LockedEnvelope =
        AeadEnvelope<XChaCha20Poly1305Ietf, Locked<Nonce>, Locked<Mac>, LockedBytes>;
}

#[cfg_attr(feature = "serde", derive(Clone, Debug, Serialize, Deserialize))]
#[cfg_attr(not(feature = "serde"), derive(Clone, Debug))]
/// Authenticated encrypted data for a concrete AEAD algorithm.
///
/// The byte representation for the supported algorithms is `ciphertext || tag`.
pub struct AeadBox<Algorithm: AeadAlgorithm, Mac, Data> {
    #[cfg_attr(feature = "serde", serde(skip))]
    algorithm: PhantomData<Algorithm>,
    tag: Mac,
    data: Data,
}

#[cfg_attr(feature = "serde", derive(Clone, Debug, Serialize, Deserialize))]
#[cfg_attr(not(feature = "serde"), derive(Clone, Debug))]
/// Authenticated encrypted data with its nonce stored alongside it.
///
/// The byte representation for the supported algorithms is
/// `nonce || ciphertext || tag`.
pub struct AeadEnvelope<Algorithm: AeadAlgorithm, Nonce, Mac, Data> {
    #[cfg_attr(feature = "serde", serde(skip))]
    algorithm: PhantomData<Algorithm>,
    nonce: Nonce,
    tag: Mac,
    data: Data,
}

/// Generates the wincode schema implementations for one algorithm's `VecBox`
/// and `VecEnvelope`: `ciphertext || tag` for the box and
/// `nonce || ciphertext || tag` for the envelope.
#[cfg(feature = "wincode")]
macro_rules! impl_wincode_aead {
    ($box:ty, $envelope:ty, $abytes:expr, $npubbytes:expr) => {
        // SAFETY: The implementation writes exactly the fields used to
        // reconstruct the box below, using `wincode` schema implementations
        // for each initialized field and preserving their order.
        unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for $box {
            type Src = Self;

            fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
                Ok(<Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?
                    + <[u8; $abytes] as wincode::SchemaWrite<C>>::size_of(src.tag.as_array())?)
            }

            fn write(
                mut writer: impl wincode::io::Writer,
                src: &Self::Src,
            ) -> wincode::WriteResult<()> {
                <Vec<u8> as wincode::SchemaWrite<C>>::write(writer.by_ref(), &src.data)?;
                <[u8; $abytes] as wincode::SchemaWrite<C>>::write(writer, src.tag.as_array())
            }
        }

        // SAFETY: The implementation fully initializes `dst` with a valid box
        // after successfully reading each field in the same order as
        // `SchemaWrite`.
        unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for $box {
            type Dst = Self;

            fn read(
                mut reader: impl wincode::io::Reader<'de>,
                dst: &mut std::mem::MaybeUninit<Self::Dst>,
            ) -> wincode::ReadResult<()> {
                let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
                let tag = <[u8; $abytes] as wincode::SchemaRead<'de, C>>::get(reader)?;
                dst.write(Self {
                    algorithm: PhantomData,
                    tag: tag.into(),
                    data,
                });
                Ok(())
            }
        }

        // SAFETY: The implementation writes exactly the fields used to
        // reconstruct the envelope below, using `wincode` schema
        // implementations for each initialized field and preserving their
        // order.
        unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for $envelope {
            type Src = Self;

            fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
                Ok(
                    <[u8; $npubbytes] as wincode::SchemaWrite<C>>::size_of(src.nonce.as_array())?
                        + <Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?
                        + <[u8; $abytes] as wincode::SchemaWrite<C>>::size_of(src.tag.as_array())?,
                )
            }

            fn write(
                mut writer: impl wincode::io::Writer,
                src: &Self::Src,
            ) -> wincode::WriteResult<()> {
                <[u8; $npubbytes] as wincode::SchemaWrite<C>>::write(
                    writer.by_ref(),
                    src.nonce.as_array(),
                )?;
                <Vec<u8> as wincode::SchemaWrite<C>>::write(writer.by_ref(), &src.data)?;
                <[u8; $abytes] as wincode::SchemaWrite<C>>::write(writer, src.tag.as_array())
            }
        }

        // SAFETY: The implementation fully initializes `dst` with a valid
        // envelope after successfully reading each field in the same order as
        // `SchemaWrite`.
        unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for $envelope {
            type Dst = Self;

            fn read(
                mut reader: impl wincode::io::Reader<'de>,
                dst: &mut std::mem::MaybeUninit<Self::Dst>,
            ) -> wincode::ReadResult<()> {
                let nonce =
                    <[u8; $npubbytes] as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
                let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
                let tag = <[u8; $abytes] as wincode::SchemaRead<'de, C>>::get(reader)?;
                dst.write(Self {
                    algorithm: PhantomData,
                    nonce: nonce.into(),
                    tag: tag.into(),
                    data,
                });
                Ok(())
            }
        }
    };
}

#[cfg(feature = "wincode")]
impl_wincode_aead!(
    VecBox,
    VecEnvelope,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
);
#[cfg(feature = "wincode")]
impl_wincode_aead!(
    chacha20poly1305_ietf::VecBox,
    chacha20poly1305_ietf::VecEnvelope,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
);

/// Generates the algorithm-specific [`AeadBox`] and [`AeadEnvelope`] methods
/// for one AEAD construction: `encrypt`, `decrypt`, `from_bytes`, `open`, and
/// the `VecBox`/`VecEnvelope` convenience wrappers, all dispatching to the
/// Classic implementation in `crate::classic::$module`.
macro_rules! impl_aead_algorithm {
    (
        algorithm:
        $algorithm:ident,module:
        $module:ident,encrypt_detached:
        $encrypt_detached:ident,decrypt_detached:
        $decrypt_detached:ident,keybytes:
        $keybytes:expr,npubbytes:
        $npubbytes:expr,abytes:
        $abytes:expr
    ) => {
        impl<Mac: NewByteArray<$abytes> + Zeroize, Data: NewBytes + ResizableBytes + Zeroize>
            AeadBox<$algorithm, Mac, Data>
        {
            /// Encrypts a message using `key`, `nonce`, and optional associated data.
            ///
            /// # Errors
            ///
            /// Returns an error if the message exceeds the construction's maximum
            /// length or the output storage does not resize to the message length.
            pub fn encrypt<
                Message: Bytes + ?Sized,
                Nonce: ByteArray<$npubbytes>,
                SecretKey: ByteArray<$keybytes>,
            >(
                message: &Message,
                associated_data: Option<&[u8]>,
                nonce: &Nonce,
                key: &SecretKey,
            ) -> Result<Self, Error> {
                use crate::classic::$module::$encrypt_detached;

                let mut new = Self {
                    algorithm: PhantomData,
                    tag: Mac::new_byte_array(),
                    data: Data::new_bytes(),
                };
                new.data.resize(message.len(), 0);

                $encrypt_detached(
                    new.data.as_mut_slice(),
                    new.tag.as_mut_array(),
                    message.as_slice(),
                    associated_data,
                    nonce.as_array(),
                    key.as_array(),
                )?;

                Ok(new)
            }
        }

        impl<
            'a,
            Mac: ByteArray<$abytes> + std::convert::TryFrom<&'a [u8]> + Zeroize,
            Data: Bytes + From<&'a [u8]> + Zeroize,
        > AeadBox<$algorithm, Mac, Data>
        {
            /// Initializes an [`AeadBox`] from `ciphertext || tag`.
            ///
            /// # Errors
            ///
            /// Returns an error if `bytes` is shorter than one authentication tag or
            /// the tag cannot be converted to `Mac`.
            pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
                let (data, tag) = split_suffix(bytes, $abytes, ErrorContext::AeadCiphertext)?;
                Ok(Self {
                    algorithm: PhantomData,
                    tag: Mac::try_from(tag)
                        .map_err(|_| Error::invalid_encoding(ErrorContext::AuthenticationTag))?,
                    data: Data::from(data),
                })
            }
        }

        impl<Mac: ByteArray<$abytes>, Data: Bytes> AeadBox<$algorithm, Mac, Data> {
            /// Decrypts this box using `key`, `nonce`, and optional associated data.
            ///
            /// # Errors
            ///
            /// Returns an error if the ciphertext exceeds the construction's maximum
            /// length, the output storage has the wrong length, or authentication
            /// fails. Authentication fails when the key, nonce, associated data,
            /// ciphertext, or tag does not match the value used during encryption.
            pub fn decrypt<
                Output: ResizableBytes + NewBytes,
                Nonce: ByteArray<$npubbytes>,
                SecretKey: ByteArray<$keybytes>,
            >(
                &self,
                associated_data: Option<&[u8]>,
                nonce: &Nonce,
                key: &SecretKey,
            ) -> Result<Output, Error> {
                use crate::classic::$module::$decrypt_detached;

                let mut message = Output::new_bytes();
                message.resize(self.data.as_slice().len(), 0);

                $decrypt_detached(
                    message.as_mut_slice(),
                    self.data.as_slice(),
                    self.tag.as_array(),
                    associated_data,
                    nonce.as_array(),
                    key.as_array(),
                )?;

                Ok(message)
            }
        }

        impl<
            'a,
            Nonce: ByteArray<$npubbytes> + std::convert::TryFrom<&'a [u8]> + Zeroize,
            Mac: ByteArray<$abytes> + std::convert::TryFrom<&'a [u8]> + Zeroize,
            Data: Bytes + From<&'a [u8]> + Zeroize,
        > AeadEnvelope<$algorithm, Nonce, Mac, Data>
        {
            /// Initializes an [`AeadEnvelope`] from `nonce || ciphertext || tag`.
            ///
            /// # Errors
            ///
            /// Returns an error if `bytes` is shorter than one nonce plus one
            /// authentication tag, or if either field cannot be converted to its
            /// target type.
            pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
                validate_length!(min $npubbytes + $abytes, bytes.len(), ErrorContext::AeadEnvelope);
                let (nonce, rest) = bytes.split_at($npubbytes);
                let (data, tag) = rest.split_at(rest.len() - $abytes);
                Ok(Self {
                    algorithm: PhantomData,
                    nonce: Nonce::try_from(nonce)
                        .map_err(|_| Error::invalid_encoding(ErrorContext::Nonce))?,
                    tag: Mac::try_from(tag)
                        .map_err(|_| Error::invalid_encoding(ErrorContext::AuthenticationTag))?,
                    data: Data::from(data),
                })
            }
        }

        impl<Nonce: ByteArray<$npubbytes>, Mac: ByteArray<$abytes>, Data: Bytes>
            AeadEnvelope<$algorithm, Nonce, Mac, Data>
        {
            /// Decrypts this envelope using `key` and optional associated data.
            ///
            /// # Errors
            ///
            /// Returns an error if the ciphertext exceeds the construction's maximum
            /// length, the output storage has the wrong length, or authentication
            /// fails. Authentication fails when the key, associated data, stored
            /// nonce, ciphertext, or tag does not match the value used during
            /// encryption.
            pub fn open<Output: ResizableBytes + NewBytes, SecretKey: ByteArray<$keybytes>>(
                &self,
                associated_data: Option<&[u8]>,
                key: &SecretKey,
            ) -> Result<Output, Error> {
                use crate::classic::$module::$decrypt_detached;

                let mut message = Output::new_bytes();
                message.resize(self.data.as_slice().len(), 0);

                $decrypt_detached(
                    message.as_mut_slice(),
                    self.data.as_slice(),
                    self.tag.as_array(),
                    associated_data,
                    self.nonce.as_array(),
                    key.as_array(),
                )?;

                Ok(message)
            }
        }

        impl AeadBox<$algorithm, StackByteArray<$abytes>, Vec<u8>> {
            /// Encrypts a message and returns a [`VecBox`].
            ///
            /// # Errors
            ///
            /// Returns an error if the message exceeds the construction's maximum
            /// length.
            pub fn encrypt_to_vecbox<Message: Bytes + ?Sized, SecretKey: ByteArray<$keybytes>>(
                message: &Message,
                associated_data: Option<&[u8]>,
                nonce: &StackByteArray<$npubbytes>,
                key: &SecretKey,
            ) -> Result<Self, Error> {
                Self::encrypt(message, associated_data, nonce, key)
            }

            /// Decrypts this box and returns the plaintext as a [`Vec`].
            ///
            /// # Errors
            ///
            /// Returns an error if the ciphertext exceeds the construction's maximum
            /// length or authentication fails because the key, nonce, associated data,
            /// ciphertext, or tag does not match.
            pub fn decrypt_to_vec<SecretKey: ByteArray<$keybytes>>(
                &self,
                associated_data: Option<&[u8]>,
                nonce: &StackByteArray<$npubbytes>,
                key: &SecretKey,
            ) -> Result<Vec<u8>, Error> {
                self.decrypt(associated_data, nonce, key)
            }

            /// Consumes this box and returns it as `ciphertext || tag`.
            pub fn into_vec(mut self) -> Vec<u8> {
                self.data.resize(self.data.len() + $abytes, 0);
                let tag_offset = self.data.len() - $abytes;
                self.data[tag_offset..].copy_from_slice(self.tag.as_slice());
                self.data
            }
        }

        impl
            AeadEnvelope<$algorithm, StackByteArray<$npubbytes>, StackByteArray<$abytes>, Vec<u8>>
        {
            /// Decrypts this envelope and returns the plaintext as a [`Vec`].
            ///
            /// # Errors
            ///
            /// Returns an error if the ciphertext exceeds the construction's maximum
            /// length or authentication fails because the key, associated data, stored
            /// nonce, ciphertext, or tag does not match.
            pub fn open_to_vec<SecretKey: ByteArray<$keybytes>>(
                &self,
                associated_data: Option<&[u8]>,
                key: &SecretKey,
            ) -> Result<Vec<u8>, Error> {
                self.open(associated_data, key)
            }

            /// Consumes this envelope and returns it as `nonce || ciphertext || tag`.
            pub fn into_vec(self) -> Vec<u8> {
                let mut output = self.nonce.to_vec();
                output.extend_from_slice(self.data.as_slice());
                output.extend_from_slice(self.tag.as_slice());
                output
            }
        }
    };
}

/// Generates the random-nonce `seal` family for one AEAD construction whose
/// nonce is large enough to choose at random (XChaCha20-Poly1305-IETF).
macro_rules! impl_aead_envelope_seal {
    (
        algorithm:
        $algorithm:ident,keybytes:
        $keybytes:expr,npubbytes:
        $npubbytes:expr,abytes:
        $abytes:expr
    ) => {
        impl<
            Nonce: NewByteArray<$npubbytes> + Zeroize,
            Mac: NewByteArray<$abytes> + Zeroize,
            Data: NewBytes + ResizableBytes + Zeroize,
        > AeadEnvelope<$algorithm, Nonce, Mac, Data>
        {
            /// Encrypts a message with a generated nonce and stores that nonce with the
            /// ciphertext and tag.
            ///
            /// # Errors
            ///
            /// Returns an error if the message exceeds the construction's maximum
            /// length or the output storage does not resize to the message length.
            ///
            /// # Panics
            ///
            /// Panics if the operating system's random number generator fails.
            pub fn seal<Message: Bytes + ?Sized, SecretKey: ByteArray<$keybytes>>(
                message: &Message,
                associated_data: Option<&[u8]>,
                key: &SecretKey,
            ) -> Result<Self, Error> {
                let nonce = Nonce::generate();
                let aead_box = AeadBox::<$algorithm, Mac, Data>::encrypt(
                    message,
                    associated_data,
                    &nonce,
                    key,
                )?;
                let (tag, data) = aead_box.into_parts();

                Ok(Self {
                    algorithm: PhantomData,
                    nonce,
                    tag,
                    data,
                })
            }
        }

        impl
            AeadEnvelope<$algorithm, StackByteArray<$npubbytes>, StackByteArray<$abytes>, Vec<u8>>
        {
            /// Encrypts a message with a generated nonce and returns a [`VecEnvelope`].
            ///
            /// # Errors
            ///
            /// Returns an error if the message exceeds the construction's maximum
            /// length.
            ///
            /// # Panics
            ///
            /// Panics if the operating system's random number generator fails.
            pub fn seal_to_vec<Message: Bytes + ?Sized, SecretKey: ByteArray<$keybytes>>(
                message: &Message,
                associated_data: Option<&[u8]>,
                key: &SecretKey,
            ) -> Result<Self, Error> {
                Self::seal(message, associated_data, key)
            }
        }
    };
}

impl_aead_algorithm! {
    algorithm: XChaCha20Poly1305Ietf,
    module: crypto_aead_xchacha20poly1305_ietf,
    encrypt_detached: crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    decrypt_detached: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    keybytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    npubbytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
    abytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
}

impl_aead_envelope_seal! {
    algorithm: XChaCha20Poly1305Ietf,
    keybytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    npubbytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
    abytes: CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
}

impl_aead_algorithm! {
    algorithm: ChaCha20Poly1305Ietf,
    module: crypto_aead_chacha20poly1305_ietf,
    encrypt_detached: crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    decrypt_detached: crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    keybytes: CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    npubbytes: CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
    abytes: CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES
}

impl<Algorithm: AeadAlgorithm, Mac: Zeroize, Data: Zeroize> Zeroize
    for AeadBox<Algorithm, Mac, Data>
{
    fn zeroize(&mut self) {
        self.tag.zeroize();
        self.data.zeroize();
    }
}

impl<Algorithm: AeadAlgorithm, Nonce: Zeroize, Mac: Zeroize, Data: Zeroize> Zeroize
    for AeadEnvelope<Algorithm, Nonce, Mac, Data>
{
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.tag.zeroize();
        self.data.zeroize();
    }
}

impl<Algorithm: AeadAlgorithm, Mac, Data> AeadBox<Algorithm, Mac, Data> {
    /// Returns a new AEAD box from `tag` and ciphertext `data`.
    pub fn from_parts(tag: Mac, data: Data) -> Self {
        Self {
            algorithm: PhantomData,
            tag,
            data,
        }
    }

    /// Returns the authentication tag.
    pub fn tag(&self) -> &Mac {
        &self.tag
    }

    /// Returns the ciphertext.
    pub fn data(&self) -> &Data {
        &self.data
    }

    /// Moves the tag and ciphertext out of this instance.
    pub fn into_parts(self) -> (Mac, Data) {
        (self.tag, self.data)
    }
}

impl<Algorithm: AeadAlgorithm, Mac: Bytes, Data: Bytes> AeadBox<Algorithm, Mac, Data> {
    /// Copies `self` into a new [`Vec`].
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Copies `self` into the target as `ciphertext || tag`.
    pub fn to_bytes<Output: NewBytes + ResizableBytes>(&self) -> Output {
        concat_bytes(self.data.as_slice(), self.tag.as_slice())
    }
}

impl<Algorithm: AeadAlgorithm, Nonce, Mac, Data> AeadEnvelope<Algorithm, Nonce, Mac, Data> {
    /// Returns a new AEAD envelope from `nonce`, `tag`, and ciphertext `data`.
    pub fn from_parts(nonce: Nonce, tag: Mac, data: Data) -> Self {
        Self {
            algorithm: PhantomData,
            nonce,
            tag,
            data,
        }
    }

    /// Returns the stored nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the authentication tag.
    pub fn tag(&self) -> &Mac {
        &self.tag
    }

    /// Returns the ciphertext.
    pub fn data(&self) -> &Data {
        &self.data
    }

    /// Moves the nonce, tag, and ciphertext out of this instance.
    pub fn into_parts(self) -> (Nonce, Mac, Data) {
        (self.nonce, self.tag, self.data)
    }
}

impl<Algorithm: AeadAlgorithm, Nonce: Bytes, Mac: Bytes, Data: Bytes>
    AeadEnvelope<Algorithm, Nonce, Mac, Data>
{
    /// Copies `self` into a new [`Vec`].
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Copies `self` into the target as `nonce || ciphertext || tag`.
    pub fn to_bytes<Output: NewBytes + ResizableBytes>(&self) -> Output {
        let mut data = Output::new_bytes();
        data.resize(self.nonce.len() + self.data.len() + self.tag.len(), 0);
        let s = data.as_mut_slice();
        s[..self.nonce.len()].copy_from_slice(self.nonce.as_slice());
        s[self.nonce.len()..self.nonce.len() + self.data.len()]
            .copy_from_slice(self.data.as_slice());
        s[self.nonce.len() + self.data.len()..].copy_from_slice(self.tag.as_slice());
        data
    }
}

impl<'a, Algorithm: AeadAlgorithm, Mac, Data: From<&'a [u8]>> AeadBox<Algorithm, Mac, Data> {
    /// Returns a new box with ciphertext copied from `input` and `tag`
    /// consumed.
    pub fn with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            algorithm: PhantomData,
            tag,
            data: input.into(),
        }
    }
}

impl<'a, Algorithm: AeadAlgorithm, Nonce, Mac, Data: From<&'a [u8]>>
    AeadEnvelope<Algorithm, Nonce, Mac, Data>
{
    /// Returns a new envelope with nonce and tag consumed and ciphertext copied
    /// from `input`.
    pub fn with_nonce_data_and_mac(nonce: Nonce, tag: Mac, input: &'a [u8]) -> Self {
        Self {
            algorithm: PhantomData,
            nonce,
            tag,
            data: input.into(),
        }
    }
}

impl<Algorithm: AeadAlgorithm, Mac: Bytes, Data: Bytes> PartialEq
    for AeadBox<Algorithm, Mac, Data>
{
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.tag.as_slice(), other.tag.as_slice())
            && ct_eq_bytes(self.data.as_slice(), other.data.as_slice())
    }
}

impl<Algorithm: AeadAlgorithm, Nonce: Bytes, Mac: Bytes, Data: Bytes> PartialEq
    for AeadEnvelope<Algorithm, Nonce, Mac, Data>
{
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.nonce.as_slice(), other.nonce.as_slice())
            && ct_eq_bytes(self.tag.as_slice(), other.tag.as_slice())
            && ct_eq_bytes(self.data.as_slice(), other.data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explicit_box_layout() {
        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"hello";
        let aad = b"metadata";

        let aead = VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("encrypt");
        let bytes = aead.to_vec();
        assert_eq!(
            bytes.len(),
            message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
        );

        let parsed = VecBox::from_bytes(&bytes).expect("from bytes");
        let decrypted = parsed
            .decrypt_to_vec(Some(aad), &nonce, &key)
            .expect("decrypt");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_explicit_box_failures() {
        let key = Key::generate();
        let nonce = Nonce::generate();
        let message = b"hello";
        let aad = b"metadata";

        let aead = VecBox::encrypt_to_vecbox(message, Some(aad), &nonce, &key).expect("encrypt");

        aead.decrypt_to_vec(Some(b"wrong aad"), &nonce, &key)
            .expect_err("wrong aad should fail");

        let mut wrong_key = key.clone();
        wrong_key.as_mut_slice()[0] ^= 1;
        aead.decrypt_to_vec(Some(aad), &nonce, &wrong_key)
            .expect_err("wrong key should fail");

        let mut wrong_nonce = nonce.clone();
        wrong_nonce.as_mut_slice()[0] ^= 1;
        aead.decrypt_to_vec(Some(aad), &wrong_nonce, &key)
            .expect_err("wrong nonce should fail");

        let mut modified_ciphertext = aead.clone();
        modified_ciphertext.data.as_mut_slice()[0] ^= 1;
        modified_ciphertext
            .decrypt_to_vec(Some(aad), &nonce, &key)
            .expect_err("modified ciphertext should fail");

        let mut modified_tag = aead.clone();
        modified_tag.tag.as_mut_slice()[0] ^= 1;
        modified_tag
            .decrypt_to_vec(Some(aad), &nonce, &key)
            .expect_err("modified tag should fail");
    }

    #[test]
    fn test_explicit_box_empty_message_and_no_aad() {
        let key = Key::generate();
        let nonce = Nonce::generate();

        let aead = VecBox::encrypt_to_vecbox(&[], None, &nonce, &key).expect("encrypt");
        assert_eq!(
            aead.to_vec().len(),
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
        );

        let decrypted = aead
            .decrypt_to_vec(None, &nonce, &key)
            .expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_envelope_layout() {
        let key = Key::generate();
        let message = b"hello";
        let aad = b"metadata";

        let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("seal");
        let bytes = envelope.to_vec();
        assert_eq!(
            bytes.len(),
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                + message.len()
                + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
        );
        assert_eq!(
            &bytes[..CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES],
            envelope.nonce().as_slice()
        );

        let parsed = VecEnvelope::from_bytes(&bytes).expect("from bytes");
        let decrypted = parsed.open_to_vec(Some(aad), &key).expect("open");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_envelope_failures() {
        let key = Key::generate();
        let message = b"hello";
        let aad = b"metadata";

        let envelope = VecEnvelope::seal_to_vec(message, Some(aad), &key).expect("seal");

        envelope
            .open_to_vec(Some(b"wrong aad"), &key)
            .expect_err("wrong aad should fail");

        let mut wrong_key = key.clone();
        wrong_key.as_mut_slice()[0] ^= 1;
        envelope
            .open_to_vec(Some(aad), &wrong_key)
            .expect_err("wrong key should fail");

        let mut modified_nonce = envelope.clone();
        modified_nonce.nonce.as_mut_slice()[0] ^= 1;
        modified_nonce
            .open_to_vec(Some(aad), &key)
            .expect_err("modified nonce should fail");

        let mut modified_ciphertext = envelope.clone();
        modified_ciphertext.data.as_mut_slice()[0] ^= 1;
        modified_ciphertext
            .open_to_vec(Some(aad), &key)
            .expect_err("modified ciphertext should fail");

        let mut modified_tag = envelope.clone();
        modified_tag.tag.as_mut_slice()[0] ^= 1;
        modified_tag
            .open_to_vec(Some(aad), &key)
            .expect_err("modified tag should fail");
    }

    #[test]
    fn test_envelope_empty_message_and_no_aad() {
        let key = Key::generate();

        let envelope = VecEnvelope::seal_to_vec(&[], None, &key).expect("seal");
        assert_eq!(
            envelope.to_vec().len(),
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
        );

        let decrypted = envelope.open_to_vec(None, &key).expect("open empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_from_bytes_boundaries() {
        assert!(VecBox::from_bytes(&[]).is_err());

        let empty_box_bytes = [0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        let empty_box = VecBox::from_bytes(&empty_box_bytes).expect("empty box parses");
        assert!(empty_box.data().is_empty());
        assert_eq!(empty_box.tag().as_slice(), empty_box_bytes.as_slice());

        let short_envelope_bytes = [0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
            - 1];
        const ENVELOPE_MIN: usize = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        // Truncated envelopes report the whole input against the whole minimum,
        // whether the truncation lands inside the nonce or inside the tag.
        for short in [&short_envelope_bytes[..], &short_envelope_bytes[..1]] {
            assert!(matches!(
                VecEnvelope::from_bytes(short),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::AeadEnvelope,
                    actual,
                    constraint: crate::error::LengthConstraint::AtLeast(ENVELOPE_MIN),
                }) if actual == short.len()
            ));
        }

        let empty_envelope_bytes = [0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
        let empty_envelope =
            VecEnvelope::from_bytes(&empty_envelope_bytes).expect("empty envelope parses");
        assert!(empty_envelope.data().is_empty());
        assert_eq!(
            empty_envelope.nonce().as_slice(),
            &empty_envelope_bytes[..CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES]
        );
        assert_eq!(
            empty_envelope.tag().as_slice(),
            &empty_envelope_bytes[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES..]
        );
    }

    /// Known-answer vectors shared by the ChaCha20-Poly1305-IETF (RFC 8439
    /// section 2.8.2) and XChaCha20-Poly1305-IETF tests. The XChaCha case
    /// reuses the RFC 8439 key, associated data and message with a 24-byte
    /// nonce; its expected bytes are libsodium's output for those inputs, the
    /// same vector `classic::crypto_aead_xchacha20poly1305_ietf` checks against
    /// libsodium at runtime in its native tests.
    mod kat {
        use super::*;
        use crate::classic::crypto_aead_chacha20poly1305_ietf::{
            crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_encrypt,
        };
        use crate::classic::crypto_aead_xchacha20poly1305_ietf::{
            crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt,
        };
        use crate::dryocaead::chacha20poly1305_ietf as chacha;

        const MESSAGE: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const AD: &[u8] = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        const KEY: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        const CHACHA_NONCE: [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        const CHACHA_EXPECTED: &str = concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69",
            "da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67594",
            "5585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
        );
        const XCHACHA_NONCE: [u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES] = [
            0xf2, 0x8a, 0x50, 0xa7, 0x8a, 0x7e, 0x23, 0xc9, 0xcb, 0xa6, 0x78, 0x34, 0x66, 0xf8,
            0x03, 0x59, 0x0f, 0x04, 0xe9, 0x22, 0x31, 0xa3, 0x2d, 0x5d,
        ];
        const XCHACHA_EXPECTED: &str = concat!(
            "20f1ae75e1e5e00040294f0fb10ebb0810c593c7dba4ec104c1e5ef9507faeef58fc2898bbd0e47b2f5331fb",
            "c367d3c2784e3648ce1eaa7787ad186db2685ee89ae4d3441f6ea0b2224cd5a134161b554d8b48350b4ad401",
            "15db81ea820968e943892f2b8051cb5f7a8666e7e7ef7f84c0a2f80a12d06680c8eebbd93004109de842",
        );

        fn chacha_expected() -> Vec<u8> {
            hex::decode(CHACHA_EXPECTED).expect("hex")
        }

        fn xchacha_expected() -> Vec<u8> {
            hex::decode(XCHACHA_EXPECTED).expect("hex")
        }

        #[test]
        fn chacha_box_and_envelope_match_rfc_8439_and_classic() {
            let key = chacha::Key::from(KEY);
            let nonce = chacha::Nonce::from(CHACHA_NONCE);
            let expected = chacha_expected();

            let aead = chacha::VecBox::encrypt_to_vecbox(MESSAGE, Some(AD), &nonce, &key)
                .expect("encrypt");
            assert_eq!(aead.to_vec(), expected);
            assert_eq!(aead.clone().into_vec(), expected);
            assert_eq!(aead.data(), &expected[..MESSAGE.len()]);
            assert_eq!(aead.tag().as_slice(), &expected[MESSAGE.len()..]);

            // Rustaceous bytes decrypt with the Classic API and vice versa.
            let mut classic_decrypted = vec![0u8; MESSAGE.len()];
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut classic_decrypted,
                &aead.to_vec(),
                Some(AD),
                &CHACHA_NONCE,
                &KEY,
            )
            .expect("classic decrypt");
            assert_eq!(classic_decrypted, MESSAGE);

            let mut classic_ciphertext =
                vec![0u8; MESSAGE.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
            crypto_aead_chacha20poly1305_ietf_encrypt(
                &mut classic_ciphertext,
                MESSAGE,
                Some(AD),
                &CHACHA_NONCE,
                &KEY,
            )
            .expect("classic encrypt");
            let parsed = chacha::VecBox::from_bytes(&classic_ciphertext).expect("parse");
            assert_eq!(parsed, aead);
            assert_eq!(
                parsed
                    .decrypt_to_vec(Some(AD), &nonce, &key)
                    .expect("decrypt"),
                MESSAGE
            );

            let (tag, data) = parsed.into_parts();
            let envelope = chacha::VecEnvelope::from_parts(nonce.clone(), tag, data);
            let mut envelope_bytes = CHACHA_NONCE.to_vec();
            envelope_bytes.extend_from_slice(&expected);
            assert_eq!(envelope.to_vec(), envelope_bytes);
            assert_eq!(envelope.clone().into_vec(), envelope_bytes);
            let envelope = chacha::VecEnvelope::from_bytes(&envelope_bytes).expect("parse");
            assert_eq!(envelope.nonce(), &nonce);
            assert_eq!(envelope.open_to_vec(Some(AD), &key).expect("open"), MESSAGE);
        }

        #[test]
        fn xchacha_box_and_envelope_match_libsodium_vector_and_classic() {
            let key = Key::from(KEY);
            let nonce = Nonce::from(XCHACHA_NONCE);
            let expected = xchacha_expected();

            let aead = VecBox::encrypt_to_vecbox(MESSAGE, Some(AD), &nonce, &key).expect("encrypt");
            assert_eq!(aead.to_vec(), expected);
            assert_eq!(aead.clone().into_vec(), expected);

            let mut classic_decrypted = vec![0u8; MESSAGE.len()];
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                &mut classic_decrypted,
                &aead.to_vec(),
                Some(AD),
                &XCHACHA_NONCE,
                &KEY,
            )
            .expect("classic decrypt");
            assert_eq!(classic_decrypted, MESSAGE);

            let mut classic_ciphertext =
                vec![0u8; MESSAGE.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                &mut classic_ciphertext,
                MESSAGE,
                Some(AD),
                &XCHACHA_NONCE,
                &KEY,
            )
            .expect("classic encrypt");
            let parsed = VecBox::from_bytes(&classic_ciphertext).expect("parse");
            assert_eq!(parsed, aead);
            assert_eq!(
                parsed
                    .decrypt_to_vec(Some(AD), &nonce, &key)
                    .expect("decrypt"),
                MESSAGE
            );

            let mut envelope_bytes = XCHACHA_NONCE.to_vec();
            envelope_bytes.extend_from_slice(&expected);
            let envelope = VecEnvelope::from_bytes(&envelope_bytes).expect("parse");
            assert_eq!(envelope.to_vec(), envelope_bytes);
            assert_eq!(envelope.open_to_vec(Some(AD), &key).expect("open"), MESSAGE);
            let (parsed_nonce, tag, data) = envelope.into_parts();
            assert_eq!(parsed_nonce, nonce);
            assert_eq!(
                VecEnvelope::with_nonce_data_and_mac(parsed_nonce, tag, &data).into_vec(),
                envelope_bytes
            );
        }

        #[test]
        fn chacha_tampering_and_wrong_inputs_are_rejected() {
            let key = chacha::Key::from(KEY);
            let nonce = chacha::Nonce::from(CHACHA_NONCE);
            let expected = chacha_expected();
            let aead = chacha::VecBox::from_bytes(&expected).expect("parse");

            assert!(matches!(
                aead.decrypt_to_vec(None, &nonce, &key),
                Err(Error::AuthenticationFailed)
            ));
            assert!(matches!(
                aead.decrypt_to_vec(Some(&AD[..AD.len() - 1]), &nonce, &key),
                Err(Error::AuthenticationFailed)
            ));

            let mut wrong_key = key.clone();
            wrong_key[31] ^= 1;
            assert!(matches!(
                aead.decrypt_to_vec(Some(AD), &nonce, &wrong_key),
                Err(Error::AuthenticationFailed)
            ));

            let mut wrong_nonce = nonce.clone();
            wrong_nonce[0] ^= 1;
            assert!(matches!(
                aead.decrypt_to_vec(Some(AD), &wrong_nonce, &key),
                Err(Error::AuthenticationFailed)
            ));

            let tag_start = expected.len() - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
            for index in [0, tag_start - 1, tag_start, expected.len() - 1] {
                let mut tampered = expected.clone();
                tampered[index] ^= 0x80;
                let tampered = chacha::VecBox::from_bytes(&tampered).expect("parse");
                assert!(matches!(
                    tampered.decrypt_to_vec(Some(AD), &nonce, &key),
                    Err(Error::AuthenticationFailed)
                ));

                let mut envelope_bytes = CHACHA_NONCE.to_vec();
                envelope_bytes.extend_from_slice(tampered.to_vec().as_slice());
                let envelope = chacha::VecEnvelope::from_bytes(&envelope_bytes).expect("parse");
                assert!(matches!(
                    envelope.open_to_vec(Some(AD), &key),
                    Err(Error::AuthenticationFailed)
                ));
            }

            // A ChaCha20 box must not open under XChaCha20 with a zero-extended
            // nonce.
            let mut xnonce = [0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES];
            xnonce[..CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES].copy_from_slice(&CHACHA_NONCE);
            let as_xchacha = VecBox::from_bytes(&expected).expect("parse");
            assert!(
                as_xchacha
                    .decrypt_to_vec(Some(AD), &Nonce::from(xnonce), &Key::from(KEY))
                    .is_err()
            );

            assert_eq!(
                aead.decrypt_to_vec(Some(AD), &nonce, &key)
                    .expect("decrypt"),
                MESSAGE
            );
        }

        #[test]
        fn chacha_from_bytes_boundaries() {
            const BOX_MIN: usize = CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
            const ENVELOPE_MIN: usize = CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
                + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;

            for len in [0, 1, BOX_MIN - 1] {
                assert!(matches!(
                    chacha::VecBox::from_bytes(&vec![0u8; len]),
                    Err(Error::InvalidLength {
                        context: ErrorContext::AeadCiphertext,
                        actual,
                        constraint: crate::error::LengthConstraint::AtLeast(BOX_MIN),
                    }) if actual == len
                ));
            }
            let empty_box = chacha::VecBox::from_bytes(&[0x5au8; BOX_MIN]).expect("empty box");
            assert!(empty_box.data().is_empty());
            assert_eq!(empty_box.tag().as_slice(), &[0x5au8; BOX_MIN]);

            for len in [
                0,
                1,
                CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES,
                ENVELOPE_MIN - 1,
            ] {
                assert!(matches!(
                    chacha::VecEnvelope::from_bytes(&vec![0u8; len]),
                    Err(Error::InvalidLength {
                        context: ErrorContext::AeadEnvelope,
                        actual,
                        constraint: crate::error::LengthConstraint::AtLeast(ENVELOPE_MIN),
                    }) if actual == len
                ));
            }
            let mut envelope_bytes = CHACHA_NONCE.to_vec();
            envelope_bytes.extend_from_slice(&[0x5au8; BOX_MIN]);
            let empty_envelope =
                chacha::VecEnvelope::from_bytes(&envelope_bytes).expect("empty envelope");
            assert!(empty_envelope.data().is_empty());
            assert_eq!(empty_envelope.nonce().as_slice(), &CHACHA_NONCE);
            assert_eq!(empty_envelope.tag().as_slice(), &[0x5au8; BOX_MIN]);

            // An XChaCha envelope is one nonce longer; the ChaCha parser sees
            // the extra 12 bytes as ciphertext rather than
            // rejecting them.
            let xchacha_min = [0u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
            assert_eq!(
                chacha::VecEnvelope::from_bytes(&xchacha_min)
                    .expect("parses")
                    .data()
                    .len(),
                CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                    - CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
            );
            assert!(VecEnvelope::from_bytes(&envelope_bytes).is_err());
        }

        #[cfg(feature = "serde")]
        #[test]
        fn chacha_and_xchacha_json_round_trips_decrypt_with_classic() {
            let expected = chacha_expected();
            let aead = chacha::VecBox::from_bytes(&expected).expect("parse");
            let json = serde_json::to_string(&aead).expect("serialize box");
            let decoded: chacha::VecBox = serde_json::from_str(&json).expect("deserialize box");
            assert_eq!(decoded, aead);
            let mut decrypted = vec![0u8; MESSAGE.len()];
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut decrypted,
                &decoded.to_vec(),
                Some(AD),
                &CHACHA_NONCE,
                &KEY,
            )
            .expect("classic decrypt");
            assert_eq!(decrypted, MESSAGE);

            let mut envelope_bytes = CHACHA_NONCE.to_vec();
            envelope_bytes.extend_from_slice(&expected);
            let envelope = chacha::VecEnvelope::from_bytes(&envelope_bytes).expect("parse");
            let json = serde_json::to_string(&envelope).expect("serialize envelope");
            let decoded: chacha::VecEnvelope =
                serde_json::from_str(&json).expect("deserialize envelope");
            assert_eq!(decoded, envelope);
            assert_eq!(decoded.to_vec(), envelope_bytes);
            assert_eq!(
                decoded
                    .open_to_vec(Some(AD), &chacha::Key::from(KEY))
                    .expect("open"),
                MESSAGE
            );

            let xexpected = xchacha_expected();
            let xaead = VecBox::from_bytes(&xexpected).expect("parse");
            let decoded: VecBox =
                serde_json::from_str(&serde_json::to_string(&xaead).expect("ser")).expect("de");
            assert_eq!(decoded.to_vec(), xexpected);
            let mut xenvelope_bytes = XCHACHA_NONCE.to_vec();
            xenvelope_bytes.extend_from_slice(&xexpected);
            let xenvelope = VecEnvelope::from_bytes(&xenvelope_bytes).expect("parse");
            let decoded: VecEnvelope =
                serde_json::from_str(&serde_json::to_string(&xenvelope).expect("ser")).expect("de");
            assert_eq!(decoded.to_vec(), xenvelope_bytes);
            let mut decrypted = vec![0u8; MESSAGE.len()];
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                &mut decrypted,
                &decoded.to_vec()[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES..],
                Some(AD),
                &XCHACHA_NONCE,
                &KEY,
            )
            .expect("classic decrypt");
            assert_eq!(decrypted, MESSAGE);
        }

        #[cfg(feature = "wincode")]
        #[test]
        fn chacha_wincode_round_trips_decrypt_with_classic() {
            let expected = chacha_expected();
            let aead = chacha::VecBox::from_bytes(&expected).expect("parse");
            let encoded = wincode::serialize(&aead).expect("serialize box");
            let decoded: chacha::VecBox = wincode::deserialize(&encoded).expect("deserialize box");
            assert_eq!(decoded, aead);
            let mut decrypted = vec![0u8; MESSAGE.len()];
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut decrypted,
                &decoded.to_vec(),
                Some(AD),
                &CHACHA_NONCE,
                &KEY,
            )
            .expect("classic decrypt");
            assert_eq!(decrypted, MESSAGE);

            let mut envelope_bytes = CHACHA_NONCE.to_vec();
            envelope_bytes.extend_from_slice(&expected);
            let envelope = chacha::VecEnvelope::from_bytes(&envelope_bytes).expect("parse");
            let encoded = wincode::serialize(&envelope).expect("serialize envelope");
            let decoded: chacha::VecEnvelope =
                wincode::deserialize(&encoded).expect("deserialize envelope");
            assert_eq!(decoded, envelope);
            assert_eq!(decoded.to_vec(), envelope_bytes);
            assert_eq!(
                decoded
                    .open_to_vec(Some(AD), &chacha::Key::from(KEY))
                    .expect("open"),
                MESSAGE
            );

            // Truncated encodings are rejected rather than misparsed.
            for encoded in [wincode::serialize(&aead).expect("ser"), encoded] {
                assert!(
                    wincode::deserialize::<chacha::VecBox>(&encoded[..encoded.len() - 1]).is_err()
                );
                assert!(
                    wincode::deserialize::<chacha::VecEnvelope>(&encoded[..encoded.len() - 1])
                        .is_err()
                );
            }
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    mod property_tests {
        use proptest::prelude::*;

        use super::*;
        use crate::classic::crypto_aead_xchacha20poly1305_ietf::{
            Mac as ClassicMac, crypto_aead_xchacha20poly1305_ietf_decrypt,
            crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
            crypto_aead_xchacha20poly1305_ietf_decrypt_inplace,
            crypto_aead_xchacha20poly1305_ietf_encrypt,
            crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
            crypto_aead_xchacha20poly1305_ietf_encrypt_inplace,
        };

        fn length_strategy(max: usize) -> impl Strategy<Value = usize> {
            prop_oneof![
                Just(0usize),
                Just(1),
                Just(15),
                Just(16),
                Just(17),
                Just(63),
                Just(64),
                Just(65),
                Just(max.saturating_sub(1)),
                Just(max),
                0usize..=max,
            ]
        }

        fn bytes_strategy(max: usize) -> impl Strategy<Value = Vec<u8>> {
            length_strategy(max).prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
        }

        fn aad_strategy() -> impl Strategy<Value = Option<Vec<u8>>> {
            prop::option::of(bytes_strategy(256))
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(96))]

            #[test]
            fn proptest_classic_modes_and_rustaceous_layouts_agree(
                key in any::<[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES]>(),
                nonce in any::<[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES]>(),
                aad in aad_strategy(),
                message in bytes_strategy(512),
            ) {
                let aad = aad.as_deref();

                let mut combined =
                    vec![0u8; message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    &mut combined,
                    &message,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic combined encrypt");

                let mut decrypted = vec![0u8; message.len()];
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    &mut decrypted,
                    &combined,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic combined decrypt");
                prop_assert_eq!(decrypted.as_slice(), message.as_slice());

                let mut detached = vec![0u8; message.len()];
                let mut mac = ClassicMac::default();
                crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                    &mut detached,
                    &mut mac,
                    &message,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic detached encrypt");
                prop_assert_eq!(&detached, &combined[..message.len()]);
                prop_assert_eq!(mac.as_slice(), &combined[message.len()..]);

                let mut detached_decrypted = vec![0u8; message.len()];
                crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                    &mut detached_decrypted,
                    &detached,
                    &mac,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic detached decrypt");
                prop_assert_eq!(detached_decrypted.as_slice(), message.as_slice());

                let mut inplace = message.clone();
                inplace.resize(message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, 0);
                crypto_aead_xchacha20poly1305_ietf_encrypt_inplace(
                    &mut inplace,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic inplace encrypt");
                prop_assert_eq!(&inplace, &combined);

                crypto_aead_xchacha20poly1305_ietf_decrypt_inplace(
                    &mut inplace,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic inplace decrypt");
                prop_assert_eq!(&inplace[..message.len()], message.as_slice());

                let rust_key = Key::from(key);
                let rust_nonce = Nonce::from(nonce);
                let aead = VecBox::encrypt_to_vecbox(&message, aad, &rust_nonce, &rust_key)
                    .expect("rustaceous encrypt");
                let aead_bytes = aead.to_vec();
                prop_assert_eq!(aead_bytes.as_slice(), combined.as_slice());
                let aead_decrypted = aead
                    .decrypt_to_vec(aad, &rust_nonce, &rust_key)
                    .expect("rustaceous decrypt");
                prop_assert_eq!(aead_decrypted.as_slice(), message.as_slice());

                let mut envelope_bytes = rust_nonce.to_vec();
                envelope_bytes.extend_from_slice(&combined);
                let envelope = VecEnvelope::from_bytes(&envelope_bytes).expect("envelope parses");
                prop_assert_eq!(envelope.to_vec(), envelope_bytes);
                let envelope_decrypted = envelope
                    .open_to_vec(aad, &rust_key)
                    .expect("rustaceous envelope open");
                prop_assert_eq!(envelope_decrypted.as_slice(), message.as_slice());
            }

            #[test]
            fn proptest_tampering_is_rejected_without_mutating_outputs(
                key in any::<[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES]>(),
                nonce in any::<[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES]>(),
                aad in aad_strategy(),
                message in bytes_strategy(512),
                tamper_index in any::<usize>(),
            ) {
                let aad = aad.as_deref();
                let rust_key = Key::from(key);
                let rust_nonce = Nonce::from(nonce);
                let mut combined =
                    vec![0u8; message.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES];
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    &mut combined,
                    &message,
                    aad,
                    &nonce,
                    &key,
                )
                .expect("classic combined encrypt");

                let mut tampered = combined;
                let tamper_index = tamper_index % tampered.len();
                tampered[tamper_index] ^= 1;

                let mut output = vec![0xa5; message.len()];
                let original_output = output.clone();
                prop_assert!(
                    crypto_aead_xchacha20poly1305_ietf_decrypt(
                        &mut output,
                        &tampered,
                        aad,
                        &nonce,
                        &key,
                    )
                    .is_err()
                );
                prop_assert_eq!(output, original_output);

                let parsed_box = VecBox::from_bytes(&tampered).expect("tampered box parses");
                prop_assert!(
                    parsed_box
                        .decrypt_to_vec(aad, &rust_nonce, &rust_key)
                        .is_err()
                );

                let mut tampered_envelope = rust_nonce.to_vec();
                tampered_envelope.extend_from_slice(&tampered);
                let parsed_envelope =
                    VecEnvelope::from_bytes(&tampered_envelope).expect("tampered envelope parses");
                prop_assert!(parsed_envelope.open_to_vec(aad, &rust_key).is_err());
            }

            #[test]
            fn proptest_from_bytes_round_trips_or_rejects_by_length(
                raw in bytes_strategy(768),
            ) {
                match VecBox::from_bytes(&raw) {
                    Ok(parsed) => {
                        prop_assert!(raw.len() >= CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
                        let bytes = parsed.to_vec();
                        prop_assert_eq!(bytes.as_slice(), raw.as_slice());
                    }
                    Err(_) => {
                        prop_assert!(raw.len() < CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
                    }
                }

                let envelope_min_len = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                    + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
                match VecEnvelope::from_bytes(&raw) {
                    Ok(parsed) => {
                        prop_assert!(raw.len() >= envelope_min_len);
                        let bytes = parsed.to_vec();
                        prop_assert_eq!(bytes.as_slice(), raw.as_slice());
                    }
                    Err(_) => {
                        prop_assert!(raw.len() < envelope_min_len);
                    }
                }
            }
        }
    }
}

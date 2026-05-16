//! # Authenticated encryption with additional data
//!
//! [`DryocAead`] implements libsodium's XChaCha20-Poly1305-IETF AEAD
//! construction. It encrypts messages, authenticates optional additional data,
//! and is compatible with `crypto_aead_xchacha20poly1305_ietf_*`.
//!
//! Use [`DryocAead`] when you already manage nonces and need libsodium's
//! `ciphertext || tag` wire format. Use [`DryocAeadEnvelope`] when you want
//! dryoc to generate a random XChaCha nonce and store it with the ciphertext as
//! `nonce || ciphertext || tag`.
//!
//! If the `serde` feature is enabled, [`serde::Deserialize`] and
//! [`serde::Serialize`] are implemented for [`AeadBox`] and [`AeadEnvelope`].
//! If the `wincode` feature is enabled,
//! [`wincode::SchemaRead`] and [`wincode::SchemaWrite`]
//! are implemented for [`VecBox`] and [`VecEnvelope`].
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
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
};
use crate::error::Error;
pub use crate::types::*;

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
/// The byte representation for XChaCha20-Poly1305-IETF is `ciphertext || tag`.
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
/// The byte representation for XChaCha20-Poly1305-IETF is
/// `nonce || ciphertext || tag`.
pub struct AeadEnvelope<Algorithm: AeadAlgorithm, Nonce, Mac, Data> {
    #[cfg_attr(feature = "serde", serde(skip))]
    algorithm: PhantomData<Algorithm>,
    nonce: Nonce,
    tag: Mac,
    data: Data,
}

#[cfg(feature = "wincode")]
// SAFETY: The implementation writes exactly the fields used to reconstruct
// `VecBox` below, using `wincode` schema implementations for each initialized
// field and preserving their order.
unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for VecBox {
    type Src = Self;

    fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(<Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?
            + <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaWrite<
                C,
            >>::size_of(src.tag.as_array())?)
    }

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        <Vec<u8> as wincode::SchemaWrite<C>>::write(writer.by_ref(), &src.data)?;
        <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaWrite<C>>::write(
            writer,
            src.tag.as_array(),
        )
    }
}

#[cfg(feature = "wincode")]
// SAFETY: The implementation fully initializes `dst` with a valid `VecBox`
// after successfully reading each field in the same order as `SchemaWrite`.
unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for VecBox {
    type Dst = Self;

    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
        let tag = <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaRead<
            'de,
            C,
        >>::get(reader)?;
        dst.write(Self {
            algorithm: PhantomData,
            tag: tag.into(),
            data,
        });
        Ok(())
    }
}

#[cfg(feature = "wincode")]
// SAFETY: The implementation writes exactly the fields used to reconstruct
// `VecEnvelope` below, using `wincode` schema implementations for each
// initialized field and preserving their order.
unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for VecEnvelope {
    type Src = Self;

    fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(
            <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES] as wincode::SchemaWrite<
                C,
            >>::size_of(src.nonce.as_array())?
                + <Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?
                + <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaWrite<
                    C,
                >>::size_of(src.tag.as_array())?,
        )
    }

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES] as wincode::SchemaWrite<C>>::write(
            writer.by_ref(),
            src.nonce.as_array(),
        )?;
        <Vec<u8> as wincode::SchemaWrite<C>>::write(writer.by_ref(), &src.data)?;
        <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaWrite<C>>::write(
            writer,
            src.tag.as_array(),
        )
    }
}

#[cfg(feature = "wincode")]
// SAFETY: The implementation fully initializes `dst` with a valid
// `VecEnvelope` after successfully reading each field in the same order as
// `SchemaWrite`.
unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for VecEnvelope {
    type Dst = Self;

    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let nonce = <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES] as wincode::SchemaRead<
            'de,
            C,
        >>::get(reader.by_ref())?;
        let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
        let tag = <[u8; CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES] as wincode::SchemaRead<
            'de,
            C,
        >>::get(reader)?;
        dst.write(Self {
            algorithm: PhantomData,
            nonce: nonce.into(),
            tag: tag.into(),
            data,
        });
        Ok(())
    }
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

impl<
    Mac: NewByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> AeadBox<XChaCha20Poly1305Ietf, Mac, Data>
{
    /// Encrypts a message using `key`, `nonce`, and optional associated data.
    pub fn encrypt<
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        message: &Message,
        associated_data: Option<&[u8]>,
        nonce: &Nonce,
        key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::classic::crypto_aead_xchacha20poly1305_ietf::crypto_aead_xchacha20poly1305_ietf_encrypt_detached;

        let mut new = Self {
            algorithm: PhantomData,
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };
        new.data.resize(message.len(), 0);

        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
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
    Nonce: NewByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES> + Zeroize,
    Mac: NewByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> AeadEnvelope<XChaCha20Poly1305Ietf, Nonce, Mac, Data>
{
    /// Encrypts a message with a generated nonce and stores that nonce with the
    /// ciphertext and tag.
    pub fn seal<
        Message: Bytes + ?Sized,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        message: &Message,
        associated_data: Option<&[u8]>,
        key: &SecretKey,
    ) -> Result<Self, Error> {
        let nonce = Nonce::generate();
        let aead_box = AeadBox::<XChaCha20Poly1305Ietf, Mac, Data>::encrypt(
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

impl<
    'a,
    Mac: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>
        + std::convert::TryFrom<&'a [u8]>
        + Zeroize,
    Data: Bytes + From<&'a [u8]> + Zeroize,
> AeadBox<XChaCha20Poly1305Ietf, Mac, Data>
{
    /// Initializes an [`AeadBox`] from `ciphertext || tag`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
            )))
        } else {
            let (data, tag) =
                bytes.split_at(bytes.len() - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
            Ok(Self {
                algorithm: PhantomData,
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
    }
}

impl<
    'a,
    Nonce: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>
        + std::convert::TryFrom<&'a [u8]>
        + Zeroize,
    Mac: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>
        + std::convert::TryFrom<&'a [u8]>
        + Zeroize,
    Data: Bytes + From<&'a [u8]> + Zeroize,
> AeadEnvelope<XChaCha20Poly1305Ietf, Nonce, Mac, Data>
{
    /// Initializes an [`AeadEnvelope`] from `nonce || ciphertext || tag`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let minimum_len = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if bytes.len() < minimum_len {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                minimum_len
            )))
        } else {
            let (nonce, rest) = bytes.split_at(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            let (data, tag) = rest.split_at(rest.len() - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
            Ok(Self {
                algorithm: PhantomData,
                nonce: Nonce::try_from(nonce).map_err(|_e| dryoc_error!("invalid nonce"))?,
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
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
        let mut data = Output::new_bytes();
        data.resize(self.data.len() + self.tag.len(), 0);
        let s = data.as_mut_slice();
        s[..self.data.len()].copy_from_slice(self.data.as_slice());
        s[self.data.len()..].copy_from_slice(self.tag.as_slice());
        data
    }
}

impl<Mac: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>, Data: Bytes>
    AeadBox<XChaCha20Poly1305Ietf, Mac, Data>
{
    /// Decrypts this box using `key`, `nonce`, and optional associated data.
    pub fn decrypt<
        Output: ResizableBytes + NewBytes,
        Nonce: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        &self,
        associated_data: Option<&[u8]>,
        nonce: &Nonce,
        key: &SecretKey,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_aead_xchacha20poly1305_ietf::crypto_aead_xchacha20poly1305_ietf_decrypt_detached;

        let mut message = Output::new_bytes();
        message.resize(self.data.as_slice().len(), 0);

        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
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

impl<
    Nonce: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES>,
    Mac: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES>,
    Data: Bytes,
> AeadEnvelope<XChaCha20Poly1305Ietf, Nonce, Mac, Data>
{
    /// Decrypts this envelope using `key` and optional associated data.
    pub fn open<
        Output: ResizableBytes + NewBytes,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        &self,
        associated_data: Option<&[u8]>,
        key: &SecretKey,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_aead_xchacha20poly1305_ietf::crypto_aead_xchacha20poly1305_ietf_decrypt_detached;

        let mut message = Output::new_bytes();
        message.resize(self.data.as_slice().len(), 0);

        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
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

impl DryocAead<Mac, Vec<u8>> {
    /// Encrypts a message and returns a [`VecBox`].
    pub fn encrypt_to_vecbox<
        Message: Bytes + ?Sized,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        message: &Message,
        associated_data: Option<&[u8]>,
        nonce: &Nonce,
        key: &SecretKey,
    ) -> Result<Self, Error> {
        Self::encrypt(message, associated_data, nonce, key)
    }

    /// Decrypts this box and returns the plaintext as a [`Vec`].
    pub fn decrypt_to_vec<SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>>(
        &self,
        associated_data: Option<&[u8]>,
        nonce: &Nonce,
        key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(associated_data, nonce, key)
    }

    /// Consumes this box and returns it as `ciphertext || tag`.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.data.resize(
            self.data.len() + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES,
            0,
        );
        let tag_offset = self.data.len() - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        self.data[tag_offset..].copy_from_slice(self.tag.as_slice());
        self.data
    }
}

impl DryocAeadEnvelope<Nonce, Mac, Vec<u8>> {
    /// Encrypts a message with a generated nonce and returns a [`VecEnvelope`].
    pub fn seal_to_vec<
        Message: Bytes + ?Sized,
        SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>,
    >(
        message: &Message,
        associated_data: Option<&[u8]>,
        key: &SecretKey,
    ) -> Result<Self, Error> {
        Self::seal(message, associated_data, key)
    }

    /// Decrypts this envelope and returns the plaintext as a [`Vec`].
    pub fn open_to_vec<SecretKey: ByteArray<CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES>>(
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
        self.tag.as_slice().ct_eq(other.tag.as_slice()).unwrap_u8() == 1
            && self
                .data
                .as_slice()
                .ct_eq(other.data.as_slice())
                .unwrap_u8()
                == 1
    }
}

impl<Algorithm: AeadAlgorithm, Nonce: Bytes, Mac: Bytes, Data: Bytes> PartialEq
    for AeadEnvelope<Algorithm, Nonce, Mac, Data>
{
    fn eq(&self, other: &Self) -> bool {
        self.nonce
            .as_slice()
            .ct_eq(other.nonce.as_slice())
            .unwrap_u8()
            == 1
            && self.tag.as_slice().ct_eq(other.tag.as_slice()).unwrap_u8() == 1
            && self
                .data
                .as_slice()
                .ct_eq(other.data.as_slice())
                .unwrap_u8()
                == 1
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
        assert!(VecEnvelope::from_bytes(&short_envelope_bytes).is_err());

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

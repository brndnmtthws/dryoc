//! # Public-key authenticated encryption
//!
//! [`DryocBox`] provides libsodium-compatible public-key authenticated
//! encryption, also known as a _box_. It uses X25519 to establish a shared
//! key, XSalsa20 to encrypt the message, and Poly1305 to detect tampering.
//!
//! Use a [`DryocBox`] when a sender and recipient have each other's public keys
//! and need to exchange encrypted messages. The recipient can verify that a
//! message was created with the sender's secret key. A box is not a public
//! signature: the recipient can also create messages that appear to come from
//! the sender.
//!
//! [`DryocBox::seal`] provides anonymous encryption instead. It creates a new
//! temporary keypair for each message and stores the temporary public key with
//! the ciphertext. A sealed box proves that the ciphertext was not changed,
//! but it does not identify the sender.
//!
//! Nonces are public, but a nonce must never repeat for the same sender and
//! recipient keypair. The two parties share one nonce space unless they use
//! separate keys for each direction. Callers of [`DryocBox::encrypt`] must
//! enforce this rule. [`DryocBox::seal`] handles nonce generation internally.
//!
//! With the `serde` feature,
//! [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) and
//! [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) are implemented
//! for [`DryocBox`]. With `wincode`,
//! [`wincode::SchemaRead`](https://docs.rs/wincode/latest/wincode/trait.SchemaRead.html) and
//! [`wincode::SchemaWrite`](https://docs.rs/wincode/latest/wincode/trait.SchemaWrite.html) are
//! implemented for [`VecBox`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::dryocbox::*;
//!
//! // In a real exchange, each party keeps its secret key private and shares
//! // only its public key.
//! let sender_keypair = KeyPair::generate();
//! let recipient_keypair = KeyPair::generate();
//!
//! // Generate a random nonce. At 24 bytes, the chance of a random nonce
//! // repeating is negligible.
//! let nonce = Nonce::generate();
//!
//! let message = b"All that glitters is not gold";
//!
//! // Encrypt the message into a Vec<u8>-based box.
//! let dryocbox = DryocBox::encrypt_to_vecbox(
//!     message,
//!     &nonce,
//!     &recipient_keypair.public_key,
//!     &sender_keypair.secret_key,
//! )
//! .expect("unable to encrypt");
//!
//! // Serialize the box in libsodium's wire format, then read it back.
//! let sodium_box = dryocbox.to_vec();
//! let dryocbox = DryocBox::from_bytes(&sodium_box).expect("failed to read box");
//!
//! // Decrypt with the recipient's secret key and the sender's public key.
//! let decrypted = dryocbox
//!     .decrypt_to_vec(
//!         &nonce,
//!         &sender_keypair.public_key,
//!         &recipient_keypair.secret_key,
//!     )
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```
//!
//! ## Sealed box example
//!
//! ```
//! use dryoc::dryocbox::*;
//!
//! let recipient_keypair = KeyPair::generate();
//! let message = b"Now is the winter of our discontent.";
//!
//! let dryocbox = DryocBox::seal_to_vecbox(message, &recipient_keypair.public_key.clone())
//!     .expect("unable to seal");
//!
//! let decrypted = dryocbox
//!     .unseal_to_vec(&recipient_keypair)
//!     .expect("unable to unseal");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```
//!
//! ## Additional resources
//!
//! * See the [libsodium documentation](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
//!   for more about authenticated public-key encryption
//! * For shared-key encryption, see [`DryocSecretBox`](crate::dryocsecretbox)
//! * For encrypted message streams, see [`DryocStream`](crate::dryocstream)
//! * See the [`protected`] module for an example that stores keys in protected
//!   memory

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES,
    CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES, CRYPTO_BOX_SECRETKEYBYTES,
};
use crate::error::*;
pub use crate::types::*;
use crate::utils::{ct_eq_bytes, split_prefix};

/// Stack-allocated public key for authenticated public-key boxes.
pub type PublicKey = StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
/// Stack-allocated secret key for authenticated public-key boxes.
pub type SecretKey = StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
/// Stack-allocated nonce for authenticated public-key boxes.
pub type Nonce = StackByteArray<CRYPTO_BOX_NONCEBYTES>;
/// Stack-allocated message authentication code for authenticated public-key
/// boxes.
pub type Mac = StackByteArray<CRYPTO_BOX_MACBYTES>;
/// Stack-allocated public/secret keypair for authenticated public-key
/// boxes.
pub type KeyPair = crate::keypair::KeyPair<PublicKey, SecretKey>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`DryocBox`]
    //!
    //! Type aliases for using [`DryocBox`] with protected memory.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::dryocbox::DryocBox;
    //! use dryoc::dryocbox::protected::*;
    //!
    //! // Generate a random sender and recipient keypair, into locked, readonly
    //! // memory.
    //! let sender_keypair = LockedROKeyPair::generate_readonly_locked_keypair().expect("keypair");
    //! let recipient_keypair = LockedROKeyPair::generate_readonly_locked_keypair().expect("keypair");
    //!
    //! // Generate a random nonce, into locked, readonly memory.
    //! let nonce = Nonce::generate_readonly_locked().expect("nonce failed");
    //!
    //! // Read message into locked, readonly memory.
    //! let message = HeapBytes::from_slice_into_readonly_locked(b"Secret message from Santa Claus")
    //!     .expect("message failed");
    //!
    //! // Encrypt message into a locked box.
    //! let dryocbox: LockedBox = DryocBox::encrypt(
    //!     &message,
    //!     &nonce,
    //!     &recipient_keypair.public_key,
    //!     &sender_keypair.secret_key,
    //! )
    //! .expect("encrypt failed");
    //!
    //! // Decrypt message into locked bytes.
    //! let decrypted: LockedBytes = dryocbox
    //!     .decrypt(
    //!         &nonce,
    //!         &sender_keypair.public_key,
    //!         &recipient_keypair.secret_key,
    //!     )
    //!     .expect("decrypt failed");
    //!
    //! assert_eq!(message.as_slice(), decrypted.as_slice());
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned public key for authenticated public-key
    /// boxes, for use with protected memory.
    pub type PublicKey = HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
    /// Heap-allocated, page-aligned secret key for authenticated public-key
    /// boxes, for use with protected memory.
    pub type SecretKey = HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
    /// Heap-allocated, page-aligned nonce for authenticated public-key
    /// boxes, for use with protected memory.
    pub type Nonce = HeapByteArray<CRYPTO_BOX_NONCEBYTES>;
    /// Heap-allocated, page-aligned message authentication code for
    /// authenticated public-key boxes, for use with protected memory.
    pub type Mac = HeapByteArray<CRYPTO_BOX_MACBYTES>;

    /// Heap-allocated, page-aligned public/secret keypair for
    /// authenticated public-key boxes, for use with protected memory.
    pub type LockedKeyPair = crate::keypair::KeyPair<Locked<PublicKey>, Locked<SecretKey>>;
    /// Heap-allocated, page-aligned public/secret keypair for
    /// authenticated public-key boxes, for use with protected memory.
    pub type LockedROKeyPair = crate::keypair::KeyPair<LockedRO<PublicKey>, LockedRO<SecretKey>>;
    /// Locked [DryocBox], provided as a type alias for convenience.
    pub type LockedBox = DryocBox<Locked<PublicKey>, Locked<Mac>, LockedBytes>;
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A libsodium public-key authenticated encrypted box.
///
/// Refer to [crate::dryocbox] for sample usage.
pub struct DryocBox<
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: Bytes + Zeroize,
> {
    ephemeral_pk: Option<EphemeralPublicKey>,
    tag: Mac,
    data: Data,
}

/// [Vec]-based authenticated public-key box.
pub type VecBox = DryocBox<PublicKey, Mac, Vec<u8>>;

#[cfg(feature = "wincode")]
// SAFETY: The implementation writes exactly the fields used to reconstruct
// `VecBox` below, using `wincode` schema implementations for each initialized
// field and preserving their order.
unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for VecBox {
    type Src = Self;

    fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(
            <Option<[u8; CRYPTO_BOX_PUBLICKEYBYTES]> as wincode::SchemaWrite<C>>::size_of(
                &src.ephemeral_pk.as_ref().map(|epk| *epk.as_array()),
            )? + <[u8; CRYPTO_BOX_MACBYTES] as wincode::SchemaWrite<C>>::size_of(
                src.tag.as_array(),
            )? + <Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?,
        )
    }

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        <Option<[u8; CRYPTO_BOX_PUBLICKEYBYTES]> as wincode::SchemaWrite<C>>::write(
            writer.by_ref(),
            &src.ephemeral_pk.as_ref().map(|epk| *epk.as_array()),
        )?;
        <[u8; CRYPTO_BOX_MACBYTES] as wincode::SchemaWrite<C>>::write(
            writer.by_ref(),
            src.tag.as_array(),
        )?;
        <Vec<u8> as wincode::SchemaWrite<C>>::write(writer, &src.data)
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
        let ephemeral_pk = <Option<[u8; CRYPTO_BOX_PUBLICKEYBYTES]> as wincode::SchemaRead<
            'de,
            C,
        >>::get(reader.by_ref())?
        .map(Into::into);
        let tag = <[u8; CRYPTO_BOX_MACBYTES] as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
        let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader)?;
        dst.write(Self {
            ephemeral_pk,
            tag: tag.into(),
            data,
        });
        Ok(())
    }
}

impl<
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: NewByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [`DryocBox`] with ciphertext and tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long, `recipient_public_key` is
    /// an unacceptable low-order key, or the output storage does not resize to
    /// the message length.
    pub fn encrypt<
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
        RecipientPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SenderSecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &RecipientPublicKey,
        sender_secret_key: &SenderSecretKey,
    ) -> Result<Self, Error> {
        use crate::classic::crypto_box::crypto_box_detached;

        let mut dryocbox = Self {
            ephemeral_pk: None,
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };

        dryocbox.data.resize(message.as_slice().len(), 0);

        crypto_box_detached(
            dryocbox.data.as_mut_slice(),
            dryocbox.tag.as_mut_array(),
            message.as_slice(),
            nonce.as_array(),
            recipient_public_key.as_array(),
            sender_secret_key.as_array(),
        )?;

        Ok(dryocbox)
    }

    /// Encrypts a message using `precalc_secret_key`, and returns a new
    /// [`DryocBox`] with ciphertext and tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long or the output storage does
    /// not resize to the message length.
    pub fn precalc_encrypt<
        PrecalcSecretKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize,
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        precalc_secret_key: &PrecalcSecretKey,
    ) -> Result<Self, Error> {
        use crate::classic::crypto_box::crypto_box_detached_afternm;

        let mut dryocbox = Self {
            ephemeral_pk: None,
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };

        dryocbox.data.resize(message.as_slice().len(), 0);

        crypto_box_detached_afternm(
            dryocbox.data.as_mut_slice(),
            dryocbox.tag.as_mut_array(),
            message.as_slice(),
            nonce.as_array(),
            precalc_secret_key.as_array(),
        )?;

        Ok(dryocbox)
    }
}

impl<
    EphemeralPublicKey: NewByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: NewByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Encrypts a message for `recipient_public_key`, using an ephemeral secret
    /// key and nonce. Returns a new [`DryocBox`] with ciphertext, tag, and
    /// ephemeral public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long, `recipient_public_key` is
    /// an unacceptable low-order key, or the output storage does not resize to
    /// the message length.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails while
    /// creating the ephemeral keypair.
    pub fn seal<
        Message: Bytes + ?Sized,
        RecipientPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
    >(
        message: &Message,
        recipient_public_key: &RecipientPublicKey,
    ) -> Result<Self, Error> {
        use crate::classic::crypto_box::{
            crypto_box_detached, crypto_box_keypair, crypto_box_seal_nonce,
        };

        let mut nonce = Nonce::new_byte_array();
        let (epk, esk) = crypto_box_keypair();
        let esk = Zeroizing::new(esk);
        crypto_box_seal_nonce(nonce.as_mut_array(), &epk, recipient_public_key.as_array());

        let mut pk = EphemeralPublicKey::new_byte_array();
        pk.copy_from_slice(&epk);

        let mut dryocbox = Self {
            ephemeral_pk: Some(pk),
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };

        dryocbox.data.resize(message.as_slice().len(), 0);

        crypto_box_detached(
            dryocbox.data.as_mut_slice(),
            dryocbox.tag.as_mut_array(),
            message.as_slice(),
            nonce.as_array(),
            recipient_public_key.as_array(),
            &esk,
        )?;

        Ok(dryocbox)
    }
}

impl<
    'a,
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    Data: Bytes + From<&'a [u8]> + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Initializes a [`DryocBox`] from a slice. Expects the first
    /// [`CRYPTO_BOX_MACBYTES`] bytes to contain the message authentication tag,
    /// with the remaining bytes containing the encrypted message.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is shorter than one authentication tag or
    /// the tag cannot be converted to `Mac`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let (tag, data) = split_prefix(bytes, CRYPTO_BOX_MACBYTES, ErrorContext::Box)?;
        Ok(Self {
            ephemeral_pk: None,
            tag: Mac::try_from(tag)
                .map_err(|_| Error::invalid_encoding(ErrorContext::AuthenticationTag))?,
            data: Data::from(data),
        })
    }

    /// Initializes a sealed [`DryocBox`] from a slice. Expects the first
    /// [`CRYPTO_BOX_PUBLICKEYBYTES`] bytes to contain the ephemeral public key,
    /// the next [`CRYPTO_BOX_MACBYTES`] bytes to be the message authentication
    /// tag, with the remaining bytes containing the encrypted message.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is shorter than one ephemeral public key
    /// plus one authentication tag, or if either field cannot be converted to
    /// its target type.
    pub fn from_sealed_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        validate_length!(min CRYPTO_BOX_SEALBYTES, bytes.len(), crate::ErrorContext::SealedBox);

        let (seal, data) = bytes.split_at(CRYPTO_BOX_SEALBYTES);
        let (epk, tag) = seal.split_at(CRYPTO_BOX_PUBLICKEYBYTES);
        Ok(Self {
            ephemeral_pk: Some(
                EphemeralPublicKey::try_from(epk)
                    .map_err(|_| Error::invalid_key(crate::ErrorContext::EphemeralPublicKey))?,
            ),
            tag: Mac::try_from(tag)
                .map_err(|_| Error::invalid_encoding(crate::ErrorContext::AuthenticationTag))?,
            data: Data::from(data),
        })
    }
}

impl<
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: Bytes + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Returns a new box with `tag`, `data` and (optional) `ephemeral_pk`,
    /// consuming each.
    pub fn from_parts(tag: Mac, data: Data, ephemeral_pk: Option<EphemeralPublicKey>) -> Self {
        Self {
            ephemeral_pk,
            tag,
            data,
        }
    }

    /// Copies `self` into a new [`Vec`]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Moves the tag, data, and (optional) ephemeral public key out of this
    /// instance, returning them as a tuple.
    pub fn into_parts(self) -> (Mac, Data, Option<EphemeralPublicKey>) {
        (self.tag, self.data, self.ephemeral_pk)
    }

    /// Decrypts this box using `nonce`, `recipient_secret_key`, and
    /// `sender_public_key`, returning the decrypted message upon success.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long, `sender_public_key` is
    /// an unacceptable low-order key, the output storage has the wrong length,
    /// or authentication fails. Authentication fails for a wrong key, nonce,
    /// tag, or ciphertext.
    pub fn decrypt<
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
        SenderPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        RecipientSecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        Output: ResizableBytes + NewBytes,
    >(
        &self,
        nonce: &Nonce,
        sender_public_key: &SenderPublicKey,
        recipient_secret_key: &RecipientSecretKey,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_box::*;

        let mut message = Output::new_bytes();
        message.resize(self.data.as_slice().len(), 0);

        crypto_box_open_detached(
            message.as_mut_slice(),
            self.tag.as_array(),
            self.data.as_slice(),
            nonce.as_array(),
            sender_public_key.as_array(),
            recipient_secret_key.as_array(),
        )?;

        Ok(message)
    }

    /// Decrypts this box using `nonce` and `precalc_secret_key`, returning the
    /// decrypted message upon success.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long, the output storage has
    /// the wrong length, or authentication fails because the precomputed key,
    /// nonce, tag, or ciphertext does not match.
    pub fn precalc_decrypt<
        PrecalcSecretKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize,
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
        Output: ResizableBytes + NewBytes,
    >(
        &self,
        nonce: &Nonce,
        precalc_secret_key: &PrecalcSecretKey,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_box::crypto_box_open_detached_afternm;

        let mut message = Output::new_bytes();
        message.resize(self.data.as_slice().len(), 0);

        crypto_box_open_detached_afternm(
            message.as_mut_slice(),
            self.tag.as_array(),
            self.data.as_slice(),
            nonce.as_array(),
            precalc_secret_key.as_array(),
        )?;

        Ok(message)
    }

    /// Decrypts this sealed box using `recipient_keypair`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long, the box has no
    /// ephemeral public key, that key is an unacceptable low-order key, the
    /// output storage has the wrong length, or authentication fails.
    /// Authentication fails for the wrong recipient key pair or modified box
    /// data.
    pub fn unseal<
        RecipientPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
        RecipientSecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
        Output: ResizableBytes + NewBytes + Zeroize,
    >(
        &self,
        recipient_keypair: &crate::keypair::KeyPair<RecipientPublicKey, RecipientSecretKey>,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_box::*;

        match &self.ephemeral_pk {
            Some(epk) => {
                let mut nonce = Nonce::new_byte_array();
                crypto_box_seal_nonce(
                    nonce.as_mut_array(),
                    epk.as_array(),
                    recipient_keypair.public_key.as_array(),
                );

                let mut message = Output::new_bytes();
                message.resize(self.data.as_slice().len(), 0);

                crypto_box_open_detached(
                    message.as_mut_slice(),
                    self.tag.as_array(),
                    self.data.as_slice(),
                    nonce.as_array(),
                    epk.as_array(),
                    recipient_keypair.secret_key.as_array(),
                )?;

                Ok(message)
            }
            None => Err(Error::missing_data(crate::ErrorContext::EphemeralPublicKey)),
        }
    }

    /// Copies `self` into the target. Can be used with protected memory.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        match &self.ephemeral_pk {
            Some(epk) => {
                let mut data = Bytes::new_bytes();
                data.resize(epk.len() + self.tag.len() + self.data.len(), 0);
                let s = data.as_mut_slice();
                s[..CRYPTO_BOX_PUBLICKEYBYTES].copy_from_slice(epk.as_slice());
                s[CRYPTO_BOX_PUBLICKEYBYTES..CRYPTO_BOX_SEALBYTES]
                    .copy_from_slice(self.tag.as_slice());
                s[CRYPTO_BOX_SEALBYTES..].copy_from_slice(self.data.as_slice());
                data
            }
            None => concat_bytes(self.tag.as_slice(), self.data.as_slice()),
        }
    }
}

impl DryocBox<PublicKey, Mac, Vec<u8>> {
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [`DryocBox`] with ciphertext and tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long or `recipient_public_key` is
    /// an unacceptable low-order key.
    pub fn encrypt_to_vecbox<
        Message: Bytes + ?Sized,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        Self::encrypt(message, nonce, recipient_public_key, sender_secret_key)
    }

    /// Encrypts a message using `precalc_secret_key`, and returns a new
    /// [`DryocBox`] with ciphertext and tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long or the output storage cannot
    /// hold the ciphertext.
    pub fn precalc_encrypt_to_vecbox<
        Message: Bytes + ?Sized,
        PrecalcSecretKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize,
    >(
        message: &Message,
        nonce: &Nonce,
        precalc_secret_key: &PrecalcSecretKey,
    ) -> Result<Self, Error> {
        Self::precalc_encrypt(message, nonce, precalc_secret_key)
    }

    /// Encrypts a message for `recipient_public_key`, using an ephemeral secret
    /// key and nonce, and returns a new [`DryocBox`] with the ciphertext,
    /// ephemeral public key, and tag.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long or `recipient_public_key` is
    /// an unacceptable low-order key.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails while
    /// creating the ephemeral keypair.
    pub fn seal_to_vecbox<Message: Bytes + ?Sized>(
        message: &Message,
        recipient_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        Self::seal(message, recipient_public_key)
    }

    /// Decrypts this box using `nonce`, `recipient_secret_key` and
    /// `sender_public_key`, returning the decrypted message upon success.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long, `sender_public_key` is
    /// an unacceptable low-order key, or authentication fails because a key,
    /// nonce, tag, or ciphertext is wrong.
    pub fn decrypt_to_vec<SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>>(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(nonce, sender_public_key, recipient_secret_key)
    }

    /// Decrypts this box using `nonce` and
    /// `precalc_secret_key`, returning the decrypted message upon
    /// success.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long or authentication fails
    /// because the precomputed key, nonce, tag, or ciphertext does not match.
    pub fn precalc_decrypt_to_vec<
        PrecalcSecretKey: ByteArray<CRYPTO_BOX_BEFORENMBYTES> + Zeroize,
    >(
        &self,
        nonce: &Nonce,
        precalc_secret_key: &PrecalcSecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.precalc_decrypt(nonce, precalc_secret_key)
    }

    /// Decrypts this sealed box using `recipient_keypair`.
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext is too long, the box has no
    /// ephemeral public key, that key is an unacceptable low-order key, or
    /// authentication fails because the recipient key pair or box data is
    /// wrong.
    pub fn unseal_to_vec<
        RecipientPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
        RecipientSecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Zeroize,
    >(
        &self,
        recipient_keypair: &crate::keypair::KeyPair<RecipientPublicKey, RecipientSecretKey>,
    ) -> Result<Vec<u8>, Error> {
        self.unseal(recipient_keypair)
    }
}

impl<
    'a,
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: Bytes + ResizableBytes + From<&'a [u8]> + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Returns a new box with ciphertext copied from `input` and the supplied
    /// `tag`. The box has no ephemeral public key.
    pub fn new_with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            ephemeral_pk: None,
            tag,
            data: input.into(),
        }
    }

    /// Returns a new sealed box with ciphertext copied from `input` and the
    /// supplied `ephemeral_pk` and `tag`.
    pub fn new_with_epk_data_and_mac(
        ephemeral_pk: EphemeralPublicKey,
        tag: Mac,
        input: &'a [u8],
    ) -> Self {
        Self {
            ephemeral_pk: Some(ephemeral_pk),
            tag,
            data: input.into(),
        }
    }
}

impl<
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: Bytes + Zeroize,
> PartialEq<DryocBox<EphemeralPublicKey, Mac, Data>> for DryocBox<EphemeralPublicKey, Mac, Data>
{
    fn eq(&self, other: &Self) -> bool {
        if let Some(our_epk) = &self.ephemeral_pk {
            if let Some(their_epk) = &other.ephemeral_pk {
                ct_eq_bytes(self.tag.as_slice(), other.tag.as_slice())
                    && ct_eq_bytes(self.data.as_slice(), other.data.as_slice())
                    && ct_eq_bytes(our_epk.as_slice(), their_epk.as_slice())
            } else {
                false
            }
        } else if other.ephemeral_pk.is_none() {
            ct_eq_bytes(self.tag.as_slice(), other.tag.as_slice())
                && ct_eq_bytes(self.data.as_slice(), other.data.as_slice())
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CRYPTO_BOX_SEEDBYTES;
    use crate::precalc::PrecalcSecretKey;

    #[test]
    fn unseal_requires_an_ephemeral_public_key() {
        let box_without_ephemeral_key =
            VecBox::from_bytes(&[0u8; CRYPTO_BOX_MACBYTES]).expect("a regular box should parse");
        let recipient_keypair = KeyPair::generate();

        let error = box_without_ephemeral_key
            .unseal::<_, _, Vec<u8>>(&recipient_keypair)
            .expect_err("a regular box cannot be unsealed");
        assert!(matches!(
            error,
            Error::MissingData {
                context: crate::ErrorContext::EphemeralPublicKey,
            }
        ));
    }

    /// NaCl `tests/box.c` vector (also RFC 7748 section 6.1 keys): Alice's
    /// and Bob's X25519 keys, the nonce, the 131-byte message, and the
    /// 147-byte `tag || ciphertext` output. `beforenm(bobpk, alicesk)` is the
    /// `firstkey` used by NaCl's secretbox vector.
    const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_KEY: &str = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
    const NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    const MESSAGE: &str = concat!(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d4",
        "5e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a",
        "024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
    );
    const BOXED: &str = concat!(
        "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c5",
        "31a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8a",
        "b932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622",
        "a43d14a6599b1f654cb45a74e355a5",
    );

    fn array<const N: usize>(hex: &str) -> StackByteArray<N> {
        StackByteArray::try_from(hex::decode(hex).expect("hex").as_slice()).expect("length")
    }

    struct NaclVector {
        alice: KeyPair,
        bob: KeyPair,
        nonce: Nonce,
        message: Vec<u8>,
        boxed: Vec<u8>,
    }

    fn nacl_vector() -> NaclVector {
        NaclVector {
            alice: KeyPair::from_slices(
                &hex::decode(ALICE_PK).expect("hex"),
                &hex::decode(ALICE_SK).expect("hex"),
            )
            .expect("alice keypair"),
            bob: KeyPair::from_slices(
                &hex::decode(BOB_PK).expect("hex"),
                &hex::decode(BOB_SK).expect("hex"),
            )
            .expect("bob keypair"),
            nonce: array(NONCE),
            message: hex::decode(MESSAGE).expect("hex"),
            boxed: hex::decode(BOXED).expect("hex"),
        }
    }

    #[test]
    fn nacl_vector_encrypts_to_known_bytes_and_decrypts_with_swapped_keys() {
        let v = nacl_vector();
        assert_eq!(
            KeyPair::from_secret_key(v.alice.secret_key.clone()).public_key,
            v.alice.public_key
        );
        assert_eq!(
            KeyPair::from_secret_key(v.bob.secret_key.clone()).public_key,
            v.bob.public_key
        );

        let dryocbox = DryocBox::encrypt_to_vecbox(
            &v.message,
            &v.nonce,
            &v.bob.public_key,
            &v.alice.secret_key,
        )
        .expect("encrypt failed");
        assert_eq!(dryocbox.to_vec(), v.boxed);
        assert_eq!(dryocbox.tag.as_slice(), &v.boxed[..CRYPTO_BOX_MACBYTES]);
        assert_eq!(dryocbox.data, v.boxed[CRYPTO_BOX_MACBYTES..]);
        assert!(dryocbox.ephemeral_pk.is_none());

        let parsed = VecBox::from_bytes(&v.boxed).expect("known-good box should parse");
        assert_eq!(parsed, dryocbox);
        assert_eq!(
            parsed
                .decrypt_to_vec(&v.nonce, &v.alice.public_key, &v.bob.secret_key)
                .expect("decrypt failed"),
            v.message
        );

        // The DH shared key is symmetric, so Bob-to-Alice under the same nonce
        // is the identical box; this is why both directions share one nonce
        // space.
        let reverse = DryocBox::encrypt_to_vecbox(
            &v.message,
            &v.nonce,
            &v.alice.public_key,
            &v.bob.secret_key,
        )
        .expect("encrypt failed");
        assert_eq!(reverse.to_vec(), v.boxed);
    }

    #[test]
    fn nacl_vector_precalculated_key_and_ciphertext_match() {
        let v = nacl_vector();
        let expected_key: StackByteArray<CRYPTO_BOX_BEFORENMBYTES> = array(SHARED_KEY);

        let alice_side = PrecalcSecretKey::precalculate(&v.bob.public_key, &v.alice.secret_key)
            .expect("precalculation failed");
        let bob_side = v
            .bob
            .precalculate(&v.alice.public_key)
            .expect("precalculation failed");
        assert_eq!(alice_side.as_array(), expected_key.as_array());
        assert_eq!(alice_side, bob_side);

        let dryocbox = DryocBox::precalc_encrypt_to_vecbox(&v.message, &v.nonce, &alice_side)
            .expect("encrypt failed");
        assert_eq!(dryocbox.to_vec(), v.boxed);

        let parsed = VecBox::from_bytes(&v.boxed).expect("parse");
        assert_eq!(
            parsed
                .precalc_decrypt_to_vec(&v.nonce, &bob_side)
                .expect("decrypt failed"),
            v.message
        );
        // Precalculated and direct decryption interoperate.
        assert_eq!(
            parsed
                .decrypt_to_vec(&v.nonce, &v.alice.public_key, &v.bob.secret_key)
                .expect("decrypt failed"),
            v.message
        );
    }

    #[test]
    fn tampering_and_wrong_keys_are_rejected_and_the_box_stays_usable() {
        let v = nacl_vector();
        let dryocbox = VecBox::from_bytes(&v.boxed).expect("parse");
        let precalc = v.bob.precalculate(&v.alice.public_key).expect("precalc");
        let stranger = KeyPair::from_seed(&[9u8; CRYPTO_BOX_SEEDBYTES]);

        // Wrong sender: authentication binds the sender's public key.
        assert!(matches!(
            dryocbox.decrypt_to_vec(&v.nonce, &stranger.public_key, &v.bob.secret_key),
            Err(Error::AuthenticationFailed)
        ));
        // Wrong recipient.
        assert!(matches!(
            dryocbox.decrypt_to_vec(&v.nonce, &v.alice.public_key, &stranger.secret_key),
            Err(Error::AuthenticationFailed)
        ));
        // Low-order sender key is rejected before authentication.
        assert!(
            dryocbox
                .decrypt_to_vec(&v.nonce, &PublicKey::default(), &v.bob.secret_key)
                .is_err()
        );

        let mut wrong_nonce = v.nonce.clone();
        wrong_nonce[0] ^= 1;
        assert!(matches!(
            dryocbox.decrypt_to_vec(&wrong_nonce, &v.alice.public_key, &v.bob.secret_key),
            Err(Error::AuthenticationFailed)
        ));
        assert!(matches!(
            dryocbox.precalc_decrypt_to_vec(&wrong_nonce, &precalc),
            Err(Error::AuthenticationFailed)
        ));

        for index in [
            0,
            CRYPTO_BOX_MACBYTES - 1,
            CRYPTO_BOX_MACBYTES,
            v.boxed.len() - 1,
        ] {
            let mut tampered = v.boxed.clone();
            tampered[index] ^= 0x80;
            let tampered = VecBox::from_bytes(&tampered).expect("parse");
            assert!(matches!(
                tampered.decrypt_to_vec(&v.nonce, &v.alice.public_key, &v.bob.secret_key),
                Err(Error::AuthenticationFailed)
            ));
            assert!(matches!(
                tampered.precalc_decrypt_to_vec(&v.nonce, &precalc),
                Err(Error::AuthenticationFailed)
            ));
        }

        let mut wrong_precalc = precalc.clone();
        wrong_precalc.as_mut_array()[0] ^= 1;
        assert!(matches!(
            dryocbox.precalc_decrypt_to_vec(&v.nonce, &wrong_precalc),
            Err(Error::AuthenticationFailed)
        ));

        // Rejections leave the box untouched and decryptable.
        assert_eq!(dryocbox.to_vec(), v.boxed);
        assert_eq!(
            dryocbox
                .decrypt_to_vec(&v.nonce, &v.alice.public_key, &v.bob.secret_key)
                .expect("decrypt"),
            v.message
        );
    }

    #[test]
    fn encrypt_rejects_low_order_recipient_key() {
        let v = nacl_vector();
        let mut identity = PublicKey::default();
        identity[0] = 1;
        for low_order in [PublicKey::default(), identity] {
            assert!(
                DryocBox::encrypt_to_vecbox(&v.message, &v.nonce, &low_order, &v.alice.secret_key)
                    .is_err()
            );
            assert!(PrecalcSecretKey::precalculate(&low_order, &v.alice.secret_key).is_err());
        }
    }

    #[test]
    fn from_bytes_and_from_sealed_bytes_require_their_prefixes() {
        for len in 0..CRYPTO_BOX_MACBYTES {
            assert!(matches!(
                VecBox::from_bytes(&vec![0u8; len]),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::Box,
                    actual,
                    ..
                }) if actual == len
            ));
        }
        for len in [0, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES - 1] {
            assert!(matches!(
                VecBox::from_sealed_bytes(&vec![0u8; len]),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::SealedBox,
                    actual,
                    ..
                }) if actual == len
            ));
        }

        let empty_sealed =
            VecBox::from_sealed_bytes(&[0x5au8; CRYPTO_BOX_SEALBYTES]).expect("empty sealed box");
        assert!(empty_sealed.data.is_empty());
        assert_eq!(
            empty_sealed.ephemeral_pk.as_ref().map(|epk| epk.as_slice()),
            Some(&[0x5au8; CRYPTO_BOX_PUBLICKEYBYTES][..])
        );
    }

    #[test]
    fn sealed_wire_format_is_ephemeral_key_then_tag_then_ciphertext() {
        let epk: PublicKey = array(ALICE_PK);
        let tag: Mac = array(&NONCE[..CRYPTO_BOX_MACBYTES * 2]);
        let data = hex::decode(MESSAGE).expect("hex");

        let mut expected = epk.to_vec();
        expected.extend_from_slice(tag.as_slice());
        expected.extend_from_slice(&data);

        let sealed = VecBox::from_parts(tag.clone(), data.clone(), Some(epk.clone()));
        assert_eq!(sealed.to_vec(), expected);
        let reparsed = VecBox::from_sealed_bytes(&expected).expect("parse");
        assert_eq!(reparsed, sealed);
        let (parsed_tag, parsed_data, parsed_epk) = reparsed.into_parts();
        assert_eq!(parsed_tag, tag);
        assert_eq!(parsed_data, data);
        assert_eq!(parsed_epk.as_ref(), Some(&epk));

        // Without an ephemeral key the same tag and data serialize as a regular
        // box.
        let regular = VecBox::from_parts(tag.clone(), data.clone(), None);
        assert_eq!(regular.to_vec(), &expected[CRYPTO_BOX_PUBLICKEYBYTES..]);
        assert_eq!(regular, DryocBox::new_with_data_and_mac(tag.clone(), &data));
        assert_eq!(VecBox::new_with_epk_data_and_mac(epk, tag, &data), sealed);
    }

    #[test]
    fn sealed_box_authenticates_recipient_and_contents() {
        let v = nacl_vector();
        let sealed = DryocBox::seal_to_vecbox(&v.message, &v.bob.public_key).expect("seal");
        assert_eq!(sealed.unseal_to_vec(&v.bob).expect("unseal"), v.message);

        let wrong_recipient = sealed.unseal_to_vec(&v.alice);
        assert!(matches!(wrong_recipient, Err(Error::AuthenticationFailed)));

        let bytes = sealed.to_vec();
        for index in [
            0,
            CRYPTO_BOX_PUBLICKEYBYTES,
            CRYPTO_BOX_SEALBYTES,
            bytes.len() - 1,
        ] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x80;
            let tampered = VecBox::from_sealed_bytes(&tampered).expect("parse");
            assert!(tampered.unseal_to_vec(&v.bob).is_err());
        }
        assert_eq!(
            VecBox::from_sealed_bytes(&bytes)
                .expect("parse")
                .unseal_to_vec(&v.bob)
                .expect("unseal"),
            v.message
        );
    }

    #[test]
    fn test_precalc_encrypt_decrypt() {
        let keypair_sender = KeyPair::generate();
        let keypair_recipient = KeyPair::generate();
        let nonce = Nonce::generate();

        let message = b"To be, or not to be, that is the question:";
        let precalc_secret_key = PrecalcSecretKey::precalculate(
            &keypair_recipient.public_key,
            &keypair_sender.secret_key,
        )
        .expect("precalculation failed");

        let dryocbox: VecBox = DryocBox::precalc_encrypt(message, &nonce, &precalc_secret_key)
            .expect("unable to encrypt");

        let decrypted: Vec<u8> = dryocbox
            .precalc_decrypt(&nonce, &precalc_secret_key)
            .expect("unable to decrypt");

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_precalc_encrypt_to_vecbox_decrypt_to_vecbox() {
        let keypair_sender = KeyPair::generate();
        let keypair_recipient = KeyPair::generate();
        let nonce = Nonce::generate();

        let message = b"All the world's a stage, and all the men and women merely players:";
        let precalc_secret_key = PrecalcSecretKey::precalculate(
            &keypair_recipient.public_key,
            &keypair_sender.secret_key,
        )
        .expect("precalculation failed");

        let dryocbox = DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &precalc_secret_key)
            .expect("unable to encrypt");

        let decrypted = dryocbox
            .precalc_decrypt_to_vec(&nonce, &precalc_secret_key)
            .expect("unable to decrypt");

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_precalc_encrypt_decrypt_with_different_messages() {
        let keypair_sender = KeyPair::generate();
        let keypair_recipient = KeyPair::generate();
        let nonce = Nonce::generate();

        let messages: Vec<&[u8]> = vec![
            b"Now is the winter of our discontent, made glorious summer by this sun of York;",
            b"Friends, Romans, countrymen, lend me your ears; I come to bury Caesar, not to praise him.",
            b"A horse! a horse! my kingdom for a horse!",
            b"Good night, good night! parting is such sweet sorrow, that I shall say good night till it be morrow.",
        ];

        let precalc_secret_key = PrecalcSecretKey::precalculate(
            &keypair_recipient.public_key,
            &keypair_sender.secret_key,
        )
        .expect("precalculation failed");

        for message in &messages {
            let dryocbox: VecBox = DryocBox::precalc_encrypt(message, &nonce, &precalc_secret_key)
                .expect("unable to encrypt");

            let decrypted: Vec<u8> = dryocbox
                .precalc_decrypt(&nonce, &precalc_secret_key)
                .expect("unable to decrypt");

            assert_eq!(*message, decrypted.as_slice());
        }
    }

    #[test]
    fn test_precalc_encrypt_to_vecbox_decrypt_to_vecbox_with_different_messages() {
        let keypair_sender = KeyPair::generate();
        let keypair_recipient = KeyPair::generate();
        let nonce = Nonce::generate();

        let messages: Vec<&[u8]> = vec![
            b"Out, out brief candle! Life's but a walking shadow, a poor player that struts and frets his hour upon the stage and then is heard no more.",
            b"Some are born great, some achieve greatness, and some have greatness thrust upon them.",
            b"The lady doth protest too much, methinks.",
            b"What's in a name? That which we call a rose by any other name would smell as sweet.",
        ];

        let precalc_secret_key = PrecalcSecretKey::precalculate(
            &keypair_recipient.public_key,
            &keypair_sender.secret_key,
        )
        .expect("precalculation failed");

        for message in &messages {
            let dryocbox =
                DryocBox::precalc_encrypt_to_vecbox(message, &nonce, &precalc_secret_key)
                    .expect("unable to encrypt");

            let decrypted = dryocbox
                .precalc_decrypt_to_vec(&nonce, &precalc_secret_key)
                .expect("unable to decrypt");

            assert_eq!(*message, decrypted.as_slice());
        }
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;

        #[test]
        fn nacl_vector_matches_sodiumoxide_and_libsodium_beforenm() {
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{
                Nonce as SONonce, PublicKey as SOPublicKey, SecretKey as SOSecretKey,
            };

            let v = nacl_vector();
            let so_boxed = box_::seal(
                &v.message,
                &SONonce::from_slice(&v.nonce).unwrap(),
                &SOPublicKey::from_slice(&v.bob.public_key).unwrap(),
                &SOSecretKey::from_slice(&v.alice.secret_key).unwrap(),
            );
            assert_eq!(so_boxed, v.boxed);

            let precalc = v.alice.precalculate(&v.bob.public_key).expect("precalc");
            let so_precalc = box_::precompute(
                &SOPublicKey::from_slice(&v.bob.public_key).unwrap(),
                &SOSecretKey::from_slice(&v.alice.secret_key).unwrap(),
            );
            assert_eq!(precalc.as_slice(), so_precalc.as_ref());

            let mut sodium_key = [0u8; CRYPTO_BOX_BEFORENMBYTES];
            let rc = unsafe {
                libsodium_sys::crypto_box_beforenm(
                    sodium_key.as_mut_ptr(),
                    v.bob.public_key.as_ptr(),
                    v.alice.secret_key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(precalc.as_array(), &sodium_key);
        }

        #[test]
        fn sodiumoxide_regular_and_precomputed_boxes_decrypt_with_rustaceous() {
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{
                Nonce as SONonce, PublicKey as SOPublicKey, SecretKey as SOSecretKey,
            };

            let v = nacl_vector();
            let so_nonce = SONonce::from_slice(&v.nonce).unwrap();
            let so_bob_pk = SOPublicKey::from_slice(&v.bob.public_key).unwrap();
            let so_alice_sk = SOSecretKey::from_slice(&v.alice.secret_key).unwrap();
            let so_alice_pk = SOPublicKey::from_slice(&v.alice.public_key).unwrap();
            let so_bob_sk = SOSecretKey::from_slice(&v.bob.secret_key).unwrap();
            let so_precalc = box_::precompute(&so_bob_pk, &so_alice_sk);
            let precalc = v.bob.precalculate(&v.alice.public_key).expect("precalc");

            for len in [0, 1, 15, 16, 17, 63, 64, 65, v.message.len()] {
                let plaintext = &v.message[..len];

                let so_boxed = box_::seal(plaintext, &so_nonce, &so_bob_pk, &so_alice_sk);
                let dryocbox = VecBox::from_bytes(&so_boxed).expect("sodium box should parse");
                assert_eq!(
                    dryocbox
                        .decrypt_to_vec(&v.nonce, &v.alice.public_key, &v.bob.secret_key)
                        .expect("decrypt failed"),
                    plaintext
                );
                assert_eq!(
                    dryocbox
                        .precalc_decrypt_to_vec(&v.nonce, &precalc)
                        .expect("precalc decrypt failed"),
                    plaintext
                );

                let so_afternm = box_::seal_precomputed(plaintext, &so_nonce, &so_precalc);
                assert_eq!(so_afternm, so_boxed);
                let dryocbox =
                    VecBox::from_bytes(&so_afternm).expect("sodium afternm box should parse");
                assert_eq!(
                    dryocbox
                        .precalc_decrypt_to_vec(&v.nonce, &precalc)
                        .expect("precalc decrypt failed"),
                    plaintext
                );

                let precalc_box =
                    DryocBox::precalc_encrypt_to_vecbox(plaintext, &v.nonce, &precalc)
                        .expect("precalc encrypt failed");
                assert_eq!(
                    box_::open_precomputed(&precalc_box.to_vec(), &so_nonce, &so_precalc)
                        .expect("sodium open_precomputed failed"),
                    plaintext
                );
                assert_eq!(
                    box_::open(&precalc_box.to_vec(), &so_nonce, &so_alice_pk, &so_bob_sk)
                        .expect("sodium open failed"),
                    plaintext
                );
            }
        }

        #[test]
        fn sodiumoxide_sealed_box_rejects_wrong_recipient_and_modification() {
            use sodiumoxide::crypto::box_::PublicKey as SOPublicKey;
            use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

            let v = nacl_vector();
            let ciphertext = curve25519blake2bxsalsa20poly1305::seal(
                &v.message,
                &SOPublicKey::from_slice(&v.bob.public_key).unwrap(),
            );
            let sealed = VecBox::from_sealed_bytes(&ciphertext).expect("parse");
            assert_eq!(sealed.unseal_to_vec(&v.bob).expect("unseal"), v.message);
            assert!(matches!(
                sealed.unseal_to_vec(&v.alice),
                Err(Error::AuthenticationFailed)
            ));

            for index in [0, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES] {
                let mut tampered = ciphertext.clone();
                tampered[index] ^= 0x80;
                assert!(
                    VecBox::from_sealed_bytes(&tampered)
                        .expect("parse")
                        .unseal_to_vec(&v.bob)
                        .is_err()
                );
            }
        }

        #[test]
        fn test_dryocbox_vecbox() {
            for i in 0..20 {
                use base64::Engine as _;
                use base64::engine::general_purpose;
                use sodiumoxide::crypto::box_;
                use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};

                let keypair_sender = KeyPair::generate();
                let keypair_recipient = KeyPair::generate();
                let keypair_sender_copy = keypair_sender.clone();
                let keypair_recipient_copy = keypair_recipient.clone();
                let nonce = Nonce::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ");
                let message_copy = message.clone();
                let dryocbox = DryocBox::encrypt_to_vecbox(
                    message.as_bytes(),
                    &nonce,
                    &keypair_recipient.public_key,
                    &keypair_sender.secret_key,
                )
                .unwrap();

                let ciphertext = dryocbox.to_vec();

                let so_ciphertext = box_::seal(
                    message_copy.as_bytes(),
                    &SONonce::from_slice(&nonce).unwrap(),
                    &PublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                    &SecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
                );

                assert_eq!(
                    general_purpose::STANDARD.encode(&ciphertext),
                    general_purpose::STANDARD.encode(&so_ciphertext)
                );

                let keypair_sender = keypair_sender_copy.clone();
                let keypair_recipient = keypair_recipient_copy.clone();

                let m = dryocbox
                    .decrypt_to_vec(
                        &nonce,
                        &keypair_sender.public_key,
                        &keypair_recipient.secret_key,
                    )
                    .expect("hmm");
                let so_m = box_::open(
                    &ciphertext,
                    &SONonce::from_slice(&nonce).unwrap(),
                    &PublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                    &SecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
                )
                .expect("HMMM");

                assert_eq!(m, message_copy.as_bytes());
                assert_eq!(m, so_m);
            }
        }

        #[test]
        fn test_decrypt_failure() {
            for i in 0..20 {
                use base64::Engine as _;
                use base64::engine::general_purpose;
                use sodiumoxide::crypto::box_;
                use sodiumoxide::crypto::box_::{
                    Nonce as SONonce, PublicKey as SOPublicKey, SecretKey as SOSecretKey,
                };

                let keypair_sender = KeyPair::generate();
                let keypair_recipient = KeyPair::generate();
                let keypair_sender_copy = keypair_sender.clone();
                let keypair_recipient_copy = keypair_recipient.clone();
                let nonce = Nonce::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ");
                let message_copy = message.clone();
                let dryocbox = DryocBox::encrypt_to_vecbox(
                    message.as_bytes(),
                    &nonce,
                    &keypair_recipient.public_key,
                    &keypair_sender.secret_key,
                )
                .unwrap();

                let ciphertext = dryocbox.to_vec();

                let so_ciphertext = box_::seal(
                    message_copy.as_bytes(),
                    &SONonce::from_slice(&nonce).unwrap(),
                    &SOPublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                    &SOSecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
                );

                assert_eq!(
                    general_purpose::STANDARD.encode(&ciphertext),
                    general_purpose::STANDARD.encode(&so_ciphertext)
                );

                let invalid_key = KeyPair::generate();
                let invalid_key_copy_1 = invalid_key.clone();
                let invalid_key_copy_2 = invalid_key.clone();

                DryocBox::decrypt::<Nonce, PublicKey, SecretKey, Vec<u8>>(
                    &dryocbox,
                    &nonce,
                    &invalid_key_copy_1.public_key,
                    &invalid_key_copy_2.secret_key,
                )
                .expect_err("hmm");
                box_::open(
                    &ciphertext,
                    &SONonce::from_slice(&nonce).unwrap(),
                    &SOPublicKey::from_slice(&invalid_key.public_key).unwrap(),
                    &SOSecretKey::from_slice(&invalid_key.secret_key).unwrap(),
                )
                .expect_err("HMMM");
            }
        }

        #[test]
        fn test_dryocbox_seal_vecbox() {
            for i in 0..20 {
                use sodiumoxide::crypto::box_::{
                    PublicKey as SOPublicKey, SecretKey as SOSecretKey,
                };
                use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

                let keypair_recipient = KeyPair::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ");
                let message_copy = message.clone();
                let dryocbox =
                    DryocBox::seal_to_vecbox(message.as_bytes(), &keypair_recipient.public_key)
                        .unwrap();

                let ciphertext = dryocbox.to_vec();

                let m = dryocbox.unseal_to_vec(&keypair_recipient).expect("hmm");
                let so_m = curve25519blake2bxsalsa20poly1305::open(
                    ciphertext.as_slice(),
                    &SOPublicKey::from_slice(keypair_recipient.public_key.as_slice()).unwrap(),
                    &SOSecretKey::from_slice(keypair_recipient.secret_key.as_slice()).unwrap(),
                )
                .unwrap();

                assert_eq!(m, message_copy.as_bytes());
                assert_eq!(m, so_m);
            }
        }

        #[test]
        fn test_dryocbox_unseal_vecbox() {
            for i in 0..20 {
                use sodiumoxide::crypto::box_::PublicKey as SOPublicKey;
                use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

                let keypair_recipient = KeyPair::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ");

                let ciphertext = curve25519blake2bxsalsa20poly1305::seal(
                    message.as_bytes(),
                    &SOPublicKey::from_slice(keypair_recipient.public_key.as_slice()).unwrap(),
                );

                let dryocbox =
                    DryocBox::from_sealed_bytes(&ciphertext).expect("from sealed bytes failed");

                let m = dryocbox.unseal_to_vec(&keypair_recipient).expect("hmm");

                assert_eq!(m, message.as_bytes());
            }
        }
    }
}

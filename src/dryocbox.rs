//! # Public-key authenticated encryption
//!
//! [`DryocBox`] implements libsodium's public-key authenticated encryption,
//! also known as a _box_. This implementation uses X25519 for key derivation,
//! the XSalsa20 stream cipher, and Poly1305 for message authentication.
//!
//! You should use a [`DryocBox`] when you want to:
//!
//! * exchange messages between two parties
//! * authenticate the messages with public keys, rather than a pre-shared
//!   secret
//! * avoid secret sharing between parties
//!
//! The public keys of the sender and recipient must be known ahead of time, but
//! the sender's secret key can be used once and discarded, if desired. The
//! [`DryocBox::seal`] and corresponding [`DryocBox::unseal`] functions do just
//! this, by generating an ephemeral secret key, deriving a nonce, and including
//! the sender's public key in the box.
//!
//! If the `serde` feature is enabled, the [`serde::Deserialize`] and
//! [`serde::Serialize`] traits will be implemented for [`DryocBox`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::dryocbox::*;
//!
//! // Randomly generate sender/recipient keypairs. Under normal circumstances, the
//! // sender would only know the recipient's public key, and the recipient would
//! // only know the sender's public key.
//! let sender_keypair = KeyPair::gen();
//! let recipient_keypair = KeyPair::gen();
//!
//! // Randomly generate a nonce
//! let nonce = Nonce::gen();
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
//! // Convert into a libsodium compatible box as a Vec<u8>
//! let sodium_box = dryocbox.to_vec();
//!
//! // Load the libsodium box into a DryocBox
//! let dryocbox = DryocBox::from_bytes(&sodium_box).expect("failed to read box");
//!
//! // Decrypt the same box back to the original message, with the sender/recipient
//! // keypairs flipped.
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
//! let recipient_keypair = KeyPair::gen();
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
//! * See <https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption>
//!   for additional details on crypto boxes
//! * For secret-key based encryption, see
//!   [`DryocSecretBox`](crate::dryocsecretbox)
//! * For stream encryption, see [`DryocStream`](crate::dryocstream)
//! * See the [protected] mod for an example using the protected memory features
//!   with [`DryocBox`]

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES,
    CRYPTO_BOX_SECRETKEYBYTES,
};
use crate::error::*;
pub use crate::types::*;

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

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`DryocBox`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`DryocBox`]. These type aliases are provided for convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::dryocbox::protected::*;
    //! use dryoc::dryocbox::DryocBox;
    //!
    //! // Generate a random sender and recipient keypair, into locked, readonly
    //! // memory.
    //! let sender_keypair = LockedROKeyPair::gen_readonly_locked_keypair().expect("keypair");
    //! let recipient_keypair = LockedROKeyPair::gen_readonly_locked_keypair().expect("keypair");
    //!
    //! // Generate a random nonce, into locked, readonly memory.
    //! let nonce = Nonce::gen_readonly_locked().expect("nonce failed");
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

impl<
    EphemeralPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Zeroize,
    Mac: NewByteArray<CRYPTO_BOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocBox<EphemeralPublicKey, Mac, Data>
{
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag.
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
        );

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
    /// key and nonce. Returns a new [DryocBox] with ciphertext, tag, and
    /// ephemeral public key.
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
        );

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
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CRYPTO_BOX_MACBYTES {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                CRYPTO_BOX_MACBYTES
            )))
        } else {
            let (tag, data) = bytes.split_at(CRYPTO_BOX_MACBYTES);
            Ok(Self {
                ephemeral_pk: None,
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
    }

    /// Initializes a sealed [`DryocBox`] from a slice. Expects the first
    /// [`CRYPTO_BOX_PUBLICKEYBYTES`] bytes to contain the ephemeral public key,
    /// the next [`CRYPTO_BOX_MACBYTES`] bytes to be the message authentication
    /// tag, with the remaining bytes containing the encrypted message.
    pub fn from_sealed_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CRYPTO_BOX_SEALBYTES {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                CRYPTO_BOX_SEALBYTES
            )))
        } else {
            let (seal, data) = bytes.split_at(CRYPTO_BOX_SEALBYTES);
            let (epk, tag) = seal.split_at(CRYPTO_BOX_PUBLICKEYBYTES);
            Ok(Self {
                ephemeral_pk: Some(
                    EphemeralPublicKey::try_from(epk)
                        .map_err(|_e| dryoc_error!("invalid ephemeral public key"))?,
                ),
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
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

    /// Decrypts this sealed box using `recipient_secret_key`, and
    /// returning the decrypted message upon success.
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
            None => Err(dryoc_error!(
                "ephemeral public key is missing, cannot unseal"
            )),
        }
    }

    /// Copies `self` into the target. Can be used with protected memory.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        let mut data = Bytes::new_bytes();
        match &self.ephemeral_pk {
            Some(epk) => {
                data.resize(epk.len() + self.tag.len() + self.data.len(), 0);
                let s = data.as_mut_slice();
                s[..CRYPTO_BOX_PUBLICKEYBYTES].copy_from_slice(epk.as_slice());
                s[CRYPTO_BOX_PUBLICKEYBYTES..CRYPTO_BOX_SEALBYTES]
                    .copy_from_slice(self.tag.as_slice());
                s[CRYPTO_BOX_SEALBYTES..].copy_from_slice(self.data.as_slice());
            }
            None => {
                data.resize(self.tag.len() + self.data.len(), 0);
                let s = data.as_mut_slice();
                s[..CRYPTO_BOX_MACBYTES].copy_from_slice(self.tag.as_slice());
                s[CRYPTO_BOX_MACBYTES..].copy_from_slice(self.data.as_slice());
            }
        }
        data
    }
}

impl DryocBox<PublicKey, Mac, Vec<u8>> {
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag.
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

    /// Encrypts a message for `recipient_public_key`, using an ephemeral secret
    /// key and nonce, and returns a new [DryocBox] with the ciphertext,
    /// ephemeral public key, and tag.
    pub fn seal_to_vecbox<Message: Bytes + ?Sized>(
        message: &Message,
        recipient_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        Self::seal(message, recipient_public_key)
    }

    /// Decrypts this box using `nonce`, `recipient_secret_key` and
    /// `sender_public_key`, returning the decrypted message upon success.
    pub fn decrypt_to_vec<SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>>(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(nonce, sender_public_key, recipient_secret_key)
    }

    /// Decrypts this sealed box using `recipient_secret_key`, returning the
    /// decrypted message upon success.
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
    /// Returns a new box with `data` and `tag`, with data copied from `input`
    /// and `tag` consumed. The ephemeral public key is assumed not to be
    /// present.
    pub fn new_with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            ephemeral_pk: None,
            tag,
            data: input.into(),
        }
    }

    /// Returns a new sealed box with `ephemeral_pk`, `data` and `tag`, where
    /// data copied from `input` and `ephemeral_pk` & `tag` are consumed.
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
                self.tag.as_slice().ct_eq(other.tag.as_slice()).unwrap_u8() == 1
                    && self
                        .data
                        .as_slice()
                        .ct_eq(other.data.as_slice())
                        .unwrap_u8()
                        == 1
                    && our_epk.as_slice().ct_eq(their_epk.as_slice()).unwrap_u8() == 1
            } else {
                false
            }
        } else if other.ephemeral_pk.is_none() {
            self.tag.as_slice().ct_eq(other.tag.as_slice()).unwrap_u8() == 1
                && self
                    .data
                    .as_slice()
                    .ct_eq(other.data.as_slice())
                    .unwrap_u8()
                    == 1
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dryocbox_vecbox() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = Nonce::gen();
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
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{
                Nonce as SONonce, PublicKey as SOPublicKey, SecretKey as SOSecretKey,
            };

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = Nonce::gen();
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

            let invalid_key = KeyPair::gen();
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
    fn test_decrypt_failure_empty() {
        for _ in 0..20 {
            use crate::keypair::*;

            let invalid_key = KeyPair::gen();
            let invalid_key_copy_1 = invalid_key.clone();
            let invalid_key_copy_2 = invalid_key.clone();
            let nonce = Nonce::gen();

            let dryocbox: VecBox =
                DryocBox::from_bytes(b"trollolllololololollollolololololol").expect("ok");
            DryocBox::decrypt::<
                Nonce,
                crate::classic::crypto_box::PublicKey,
                crate::classic::crypto_box::SecretKey,
                Vec<u8>,
            >(
                &dryocbox,
                &nonce,
                &invalid_key_copy_1.public_key,
                &invalid_key_copy_2.secret_key,
            )
            .expect_err("hmm");
        }
    }

    #[test]
    fn test_copy() {
        for _ in 0..20 {
            use std::convert::TryFrom;

            use crate::rng::*;

            let mut data1: Vec<u8> = vec![0u8; 1024];
            copy_randombytes(data1.as_mut_slice());
            let data1_copy = data1.clone();

            let dryocbox: VecBox = DryocBox::from_bytes(&data1).expect("ok");
            assert_eq!(dryocbox.data.as_slice(), &data1_copy[CRYPTO_BOX_MACBYTES..]);
            assert_eq!(dryocbox.tag.as_slice(), &data1_copy[..CRYPTO_BOX_MACBYTES]);

            let data1 = data1_copy.clone();
            let (tag, data) = data1.split_at(CRYPTO_BOX_MACBYTES);
            let dryocbox: VecBox =
                DryocBox::new_with_data_and_mac(Mac::try_from(tag).expect("mac"), data);
            assert_eq!(dryocbox.data.as_slice(), &data1_copy[CRYPTO_BOX_MACBYTES..]);
            assert_eq!(dryocbox.tag.as_array(), &data1_copy[..CRYPTO_BOX_MACBYTES]);
        }
    }

    #[test]
    fn test_dryocbox_seal_vecbox() {
        for i in 0..20 {
            use sodiumoxide::crypto::box_::{PublicKey as SOPublicKey, SecretKey as SOSecretKey};
            use sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305;

            let keypair_recipient = KeyPair::gen();
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

            let keypair_recipient = KeyPair::gen();
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

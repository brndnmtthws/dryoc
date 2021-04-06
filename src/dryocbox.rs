//! # Public-key authenticated encryption
//!
//! _For secret-key based encryption, see
//! [`DryocSecretBox`](crate::dryocsecretbox). For stream encryption, see
//! [`DryocStream`](crate::dryocstream)_.
//!
//! See [protected] for an example using the protected memory features with
//! [`DryocBox`].
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::dryocbox::*;
//!
//! // Randomly generate sender/recipient keypairs
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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES, CRYPTO_BOX_PUBLICKEYBYTES,
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
    //! let sender_keypair = LockedKeyPair::gen_locked_keypair().expect("keypair");
    //! let recipient_keypair = LockedKeyPair::gen_locked_keypair().expect("keypair");
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
    pub use crate::keypair::protected::*;
    pub use crate::protected::*;
    pub use crate::types::*;

    /// Heap-allocated, page-aligned public key for authenticated public-key
    /// boxes, for use with protected memory
    pub type PublicKey = HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
    /// Heap-allocated, page-aligned secret key for authenticated public-key
    /// boxes, for use with protected memory
    pub type SecretKey = HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
    /// Heap-allocated, page-aligned nonce for authenticated public-key
    /// boxes, for use with protected memory
    pub type Nonce = HeapByteArray<CRYPTO_BOX_NONCEBYTES>;
    /// Heap-allocated, page-aligned message authentication code for
    /// authenticated public-key boxes, for use with protected memory
    pub type Mac = HeapByteArray<CRYPTO_BOX_MACBYTES>;

    /// Heap-allocated, page-aligned public/secret keypair for
    /// authenticated public-key boxes, for use with protected memory
    pub type LockedKeyPair = crate::keypair::KeyPair<Locked<PublicKey>, Locked<SecretKey>>;
    /// Locked [DryocBox], provided as a type alias for convenience.
    pub type LockedBox = DryocBox<Locked<Mac>, LockedBytes>;
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocBox<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> {
    /// libsodium box authentication tag, usually prepended to each box
    tag: Mac,
    /// libsodium box message or ciphertext, depending on state
    data: Data,
}

/// [Vec]-based authenticated public-key box.
pub type VecBox = DryocBox<Mac, Vec<u8>>;

impl<Mac: NewByteArray<CRYPTO_BOX_MACBYTES>, Data: NewBytes + ResizableBytes> DryocBox<Mac, Data> {
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag
    pub fn encrypt<
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::crypto_box_detached;

        let mut dryocbox = Self {
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
    'a,
    Mac: ByteArray<CRYPTO_BOX_MACBYTES> + std::convert::TryFrom<&'a [u8]>,
    Data: Bytes + From<&'a [u8]>,
> DryocBox<Mac, Data>
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
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
    }
}

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> DryocBox<Mac, Data> {
    /// Returns a new box with `tag` and `data`, consuming both
    pub fn from_data_and_mac(tag: Mac, data: Data) -> Self {
        Self { tag, data }
    }

    /// Copies this box into a new [`Vec`]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> DryocBox<Mac, Data> {
    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocBox] with decrypted message
    pub fn decrypt<
        Nonce: ByteArray<CRYPTO_BOX_NONCEBYTES>,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
        Output: ResizableBytes + NewBytes,
    >(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Output, Error> {
        use crate::crypto_box::*;

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

    /// Copies `self` into the target. Can be used with protected memory.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        let mut data = Bytes::new_bytes();
        data.resize(self.tag.len() + self.data.len(), 0);
        let s = data.as_mut_slice();
        s[..CRYPTO_BOX_MACBYTES].copy_from_slice(self.tag.as_slice());
        s[CRYPTO_BOX_MACBYTES..].copy_from_slice(self.data.as_slice());
        data
    }
}

impl DryocBox<Mac, Vec<u8>> {
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag.
    pub fn encrypt_to_vecbox<
        Message: Bytes + ?Sized,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        Self::encrypt(message, nonce, recipient_public_key, sender_secret_key)
    }

    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocBox] with decrypted message
    pub fn decrypt_to_vec<
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(nonce, sender_public_key, recipient_secret_key)
    }
}

impl<'a, Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes + ResizableBytes + From<&'a [u8]>>
    DryocBox<Mac, Data>
{
    /// Returns a new box with `data` and `tag`, with data copied from `input`
    /// and `tag` consumed.
    pub fn with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            tag,
            data: input.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dryocbox_vecbox() {
        for i in 0..20 {
            use base64::encode;
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
                keypair_recipient.public_key.as_array(),
                keypair_sender.secret_key.as_array(),
            )
            .unwrap();

            let ciphertext = dryocbox.to_vec();

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

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
            use base64::encode;
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

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

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
                crate::crypto_box::PublicKey,
                crate::crypto_box::SecretKey,
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
                DryocBox::with_data_and_mac(Mac::try_from(tag).expect("mac"), data);
            assert_eq!(dryocbox.data.as_slice(), &data1_copy[CRYPTO_BOX_MACBYTES..]);
            assert_eq!(dryocbox.tag.as_array(), &data1_copy[..CRYPTO_BOX_MACBYTES]);
        }
    }
}

//! # Public-key authenticated encryption
//!
//! _For secret-key based encryption, see [crate::dryocsecretbox]_.
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::prelude::*;
//!
//! let sender_keypair = KeyPair::gen();
//! let recipient_keypair = KeyPair::gen();
//! let nonce = BoxNonce::gen();
//! let message = "hey";
//!
//! let dryocbox = DryocBox::encrypt(
//!     &message.into(),
//!     &nonce,
//!     &recipient_keypair.public_key,
//!     &sender_keypair.secret_key,
//! )
//! .expect("unable to encrypt");
//!
//! let decrypted = dryocbox
//!     .decrypt(&nonce, &sender_keypair.public_key, &recipient_keypair.secret_key)
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message.as_bytes(), decrypted.as_slice());
//! ```

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::b64::{as_base64, bytearray_from_base64, vec_from_base64};
use crate::constants::CRYPTO_BOX_MACBYTES;
use crate::dryocsecretbox::DryocSecretBox;
use crate::error::Error;
use crate::message::Message;
use crate::types::{BoxMac, BoxNonce, InputBase, OutputBase, PublicKey, SecretKey};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

type Nonce = BoxNonce;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Clone, Debug)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocBox {
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(
            serialize_with = "as_base64",
            deserialize_with = "bytearray_from_base64"
        )
    )]
    /// libsodium box authentication tag, usually prepended to each box
    pub tag: BoxMac,
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(serialize_with = "as_base64", deserialize_with = "vec_from_base64")
    )]
    /// libsodium box message or ciphertext, depending on state
    pub data: Vec<u8>,
}

impl DryocBox {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            tag: BoxMac::new(),
            data: vec![],
        }
    }

    /// Returns a box with an empty `tag`, and data from `data`, consuming `data`
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            tag: BoxMac::new(),
            data,
        }
    }

    /// Returns a new box with `tag` and `data`, consuming both
    pub fn from_data_and_mac(tag: [u8; CRYPTO_BOX_MACBYTES], data: Vec<u8>) -> Self {
        Self {
            tag: tag.into(),
            data,
        }
    }

    /// Returns a box with `data` copied from slice `input`
    pub fn with_data(input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            tag: BoxMac::new(),
            data,
        }
    }

    /// Returns a new box with `data` and `tag` copied from `input` and `tag`
    /// respectively
    pub fn with_data_and_mac(tag: &BoxMac, input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            tag: tag.clone(),
            data,
        }
    }

    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag
    pub fn encrypt(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox =
            crypto_box_detached(&message.0, nonce, &recipient_public_key, &sender_secret_key)?;

        Ok(dryocbox)
    }

    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocBox] with decrypted message
    pub fn decrypt(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<OutputBase, Error> {
        use crate::crypto_box::*;
        let dryocbox = crypto_box_open_detached(
            &self.tag,
            &self.data,
            nonce,
            &sender_public_key,
            &recipient_secret_key,
        )?;

        Ok(dryocbox)
    }

    /// Copies this box into a new Vec
    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.tag.as_slice());
        data.extend(&self.data);
        data
    }

    /// Consumes this box and returns it as a Vec
    pub fn into_vec(mut self) -> Vec<u8> {
        self.data.resize(self.data.len() + CRYPTO_BOX_MACBYTES, 0);
        self.data.rotate_right(CRYPTO_BOX_MACBYTES);
        self.data[0..CRYPTO_BOX_MACBYTES].copy_from_slice(self.tag.as_slice());
        self.data
    }
}

impl Default for DryocBox {
    fn default() -> Self {
        Self::new()
    }
}

impl From<DryocSecretBox> for DryocBox {
    fn from(other: DryocSecretBox) -> Self {
        Self {
            tag: other.tag,
            data: other.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_eq<T>(t: &[T], v: T) -> bool
    where
        T: PartialEq,
    {
        t.iter().fold(true, |acc, x| acc && *x == v)
    }

    #[test]
    fn test_new() {
        let dryocbox = DryocBox::new();

        assert_eq!(all_eq(dryocbox.tag.as_slice(), 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_default() {
        let dryocbox = DryocBox::default();

        assert_eq!(all_eq(dryocbox.tag.as_slice(), 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_dryocbox() {
        for i in 0..20 {
            use crate::keypair::*;
            use crate::types::BoxNonce;
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = BoxNonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocbox = DryocBox::encrypt(
                &message.into(),
                &nonce,
                &keypair_recipient.public_key,
                &keypair_sender.secret_key,
            )
            .unwrap();

            let ciphertext = dryocbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocbox.to_vec());

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(keypair_recipient_copy.public_key.as_slice()).unwrap(),
                &SecretKey::from_slice(keypair_sender_copy.secret_key.as_slice()).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let keypair_sender = keypair_sender_copy.clone();
            let keypair_recipient = keypair_recipient_copy.clone();

            let m = dryocbox
                .decrypt(
                    &nonce,
                    &keypair_sender.public_key,
                    &keypair_recipient.secret_key,
                )
                .expect("hmm");
            let so_m = box_::open(
                &ciphertext,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(keypair_recipient_copy.public_key.as_slice()).unwrap(),
                &SecretKey::from_slice(keypair_sender_copy.secret_key.as_slice()).unwrap(),
            )
            .expect("HMMM");

            assert_eq!(m, message_copy.as_bytes());
            assert_eq!(m, so_m);
        }
    }

    #[test]
    fn test_decrypt_failure() {
        for i in 0..20 {
            use crate::keypair::*;
            use crate::types::BoxNonce;
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = BoxNonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocbox = DryocBox::encrypt(
                &message.into(),
                &nonce,
                &keypair_recipient.public_key,
                &keypair_sender.secret_key,
            )
            .unwrap();

            let ciphertext = dryocbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocbox.to_vec());

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(keypair_recipient_copy.public_key.as_slice()).unwrap(),
                &SecretKey::from_slice(keypair_sender_copy.secret_key.as_slice()).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let invalid_key = KeyPair::gen();
            let invalid_key_copy_1 = invalid_key.clone();
            let invalid_key_copy_2 = invalid_key.clone();

            dryocbox
                .decrypt(
                    &nonce,
                    &invalid_key_copy_1.public_key,
                    &invalid_key_copy_2.secret_key,
                )
                .expect_err("hmm");
            box_::open(
                &ciphertext,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &PublicKey::from_slice(invalid_key.public_key.as_slice()).unwrap(),
                &SecretKey::from_slice(invalid_key.secret_key.as_slice()).unwrap(),
            )
            .expect_err("HMMM");
        }
    }

    #[test]
    fn test_decrypt_failure_empty() {
        for _ in 0..20 {
            use crate::keypair::*;
            use crate::types::BoxNonce;

            let invalid_key = KeyPair::gen();
            let invalid_key_copy_1 = invalid_key.clone();
            let invalid_key_copy_2 = invalid_key.clone();
            let nonce = BoxNonce::gen();

            let dryocbox = DryocBox::from_data("lol".as_bytes().into());
            dryocbox
                .decrypt(
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
            use crate::rng::*;

            let mut data1: Vec<u8> = vec![0u8; 1024];
            copy_randombytes(data1.as_mut_slice());
            let data1_copy = data1.clone();

            let dryocbox = DryocBox::from_data(data1);
            assert_eq!(&dryocbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let dryocbox = DryocBox::with_data(&data1);
            assert_eq!(&dryocbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let tag = BoxMac::new();
            let dryocbox = DryocBox::with_data_and_mac(&tag, &data1);
            assert_eq!(&dryocbox.data, &data1_copy);
            assert_eq!(dryocbox.tag.as_slice(), &[0u8; CRYPTO_BOX_MACBYTES]);
        }
    }
}

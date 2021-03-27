//! # Secret-key authenticated encryption
//!
//! _For public-key based encryption, see [crate::dryocbox]_.
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::prelude::*;
//!
//! let secret_key = SecretBoxKey::gen();
//! let nonce = SecretBoxNonce::gen();
//! let message = "hey";
//!
//! let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);
//!
//! let decrypted = dryocsecretbox
//!     .decrypt(&nonce, &secret_key)
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message.as_bytes(), decrypted.as_slice());
//! ```

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::b64::{as_base64, bytearray_from_base64, vec_from_base64};
use crate::constants::CRYPTO_SECRETBOX_MACBYTES;
use crate::error::Error;
use crate::message::Message;
use crate::types::{InputBase, OutputBase, SecretBoxKey, SecretBoxMac, SecretBoxNonce};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

type Nonce = SecretBoxNonce;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Clone, Debug)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocSecretBox {
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(
            serialize_with = "as_base64",
            deserialize_with = "bytearray_from_base64"
        )
    )]
    /// libsodium box authentication tag, usually prepended to each box
    pub tag: SecretBoxMac,
    #[cfg_attr(
        all(feature = "serde", feature = "base64"),
        serde(serialize_with = "as_base64", deserialize_with = "vec_from_base64")
    )]
    /// libsodium box message or ciphertext, depending on state
    pub data: Vec<u8>,
}

impl DryocSecretBox {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            tag: SecretBoxMac::new(),
            data: vec![],
        }
    }

    /// Returns a box with an empty `tag`, and data from `data`, consuming `data`
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            tag: SecretBoxMac::new(),
            data,
        }
    }

    /// Returns a new box with `tag` and `data`, consuming both
    pub fn from_data_and_mac(tag: SecretBoxMac, data: Vec<u8>) -> Self {
        Self { tag, data }
    }

    /// Returns a box with `data` copied from slice `input`
    pub fn with_data(input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            tag: SecretBoxMac::new(),
            data,
        }
    }

    /// Returns a new box with `data` and `tag` copied from `input` and `tag`
    /// respectively
    pub fn with_data_and_mac(tag: &SecretBoxMac, input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            tag: tag.clone(),
            data,
        }
    }

    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocSecretBox] with ciphertext and tag
    pub fn encrypt(message: &Message, nonce: &Nonce, secret_key: &SecretBoxKey) -> Self {
        use crate::crypto_secretbox::crypto_secretbox_detached;
        crypto_secretbox_detached(&message.0, nonce, &secret_key)
    }

    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocSecretBox] with decrypted message
    pub fn decrypt(&self, nonce: &Nonce, secret_key: &SecretBoxKey) -> Result<OutputBase, Error> {
        use crate::crypto_secretbox::crypto_secretbox_open_detached;
        let dryocsecretbox =
            crypto_secretbox_open_detached(&self.tag, &self.data, nonce, &secret_key)?;

        Ok(dryocsecretbox)
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
        self.data
            .resize(self.data.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
        self.data.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
        self.data[0..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(self.tag.as_slice());
        self.data
    }
}

impl Default for DryocSecretBox {
    fn default() -> Self {
        Self::new()
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
        let dryocsecretbox = DryocSecretBox::new();

        assert_eq!(all_eq(dryocsecretbox.tag.as_slice(), 0), true);
        assert_eq!(all_eq(&dryocsecretbox.data, 0), true);
    }

    #[test]
    fn test_default() {
        let dryocsecretbox = DryocSecretBox::default();

        assert_eq!(all_eq(dryocsecretbox.tag.as_slice(), 0), true);
        assert_eq!(all_eq(&dryocsecretbox.data, 0), true);
    }

    #[test]
    fn test_dryocbox() {
        for i in 0..20 {
            use crate::dryocsecretbox::*;
            use crate::types::SecretBoxNonce;
            use base64::encode;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key, Nonce as SONonce};

            let secret_key = SecretBoxKey::gen();
            let nonce = SecretBoxNonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);

            let ciphertext = dryocsecretbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocsecretbox.to_vec());

            let ciphertext_copy = ciphertext.clone();

            let so_ciphertext = secretbox::seal(
                &message_copy.as_bytes(),
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &Key::from_slice(secret_key.as_slice()).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &Key::from_slice(secret_key.as_slice()).unwrap(),
            )
            .expect("decrypt failed");

            let m = dryocsecretbox
                .decrypt(&nonce, &secret_key)
                .expect("decrypt failed");
            assert_eq!(m, message_copy.as_bytes());
            assert_eq!(m, so_decrypted);
        }
    }

    #[test]
    fn test_copy() {
        for _ in 0..20 {
            use crate::rng::*;

            let mut data1: Vec<u8> = vec![0u8; 1024];
            copy_randombytes(data1.as_mut_slice());
            let data1_copy = data1.clone();

            let dryocsecretbox = DryocSecretBox::from_data(data1);
            assert_eq!(&dryocsecretbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let dryocsecretbox = DryocSecretBox::with_data(&data1);
            assert_eq!(&dryocsecretbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let tag: [u8; CRYPTO_SECRETBOX_MACBYTES] = [0u8; CRYPTO_SECRETBOX_MACBYTES];
            let dryocsecretbox = DryocSecretBox::with_data_and_mac(&tag.into(), &data1);
            assert_eq!(&dryocsecretbox.data, &data1_copy);
            assert_eq!(
                dryocsecretbox.tag.as_slice(),
                &[0u8; CRYPTO_SECRETBOX_MACBYTES]
            );
        }
    }
}

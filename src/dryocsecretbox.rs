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
//! let nonce = Nonce::gen();
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

use crate::constants::CRYPTO_SECRETBOX_MACBYTES;
use crate::error::Error;
use crate::message::Message;
use crate::nonce::Nonce;
use crate::secretboxkey::SecretBoxKey;
use crate::types::{InputBase, MacBase, OutputBase};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize, Zeroize, Clone))]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocSecretBox {
    /// libsodium box authentication tag, usually prepended to each box
    pub mac: MacBase,
    /// libsodium box message or ciphertext, depending on state
    pub data: Vec<u8>,
}

impl DryocSecretBox {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data: vec![],
        }
    }

    /// Returns a box with an empty `mac`, and data from `data`, consuming `data`
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }

    /// Returns a new box with `mac` and `data`, consuming both
    pub fn from_data_and_mac(mac: [u8; CRYPTO_SECRETBOX_MACBYTES], data: Vec<u8>) -> Self {
        Self { mac, data }
    }

    /// Returns a box with `data` copied from slice `input`
    pub fn with_data(input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }

    /// Returns a new box with `data` and `mac` copied from `input` and `mac`
    /// respectively
    pub fn with_data_and_mac(mac: &MacBase, input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        let mut r = Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        };
        r.mac.copy_from_slice(mac);
        r
    }

    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocSecretBox] with ciphertext and mac
    pub fn encrypt(message: &Message, nonce: &Nonce, secret_key: &SecretBoxKey) -> Self {
        use crate::crypto_secretbox::crypto_secretbox_detached;
        crypto_secretbox_detached(&message.0, nonce, &secret_key.0)
    }

    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocSecretBox] with decrypted message
    pub fn decrypt(&self, nonce: &Nonce, secret_key: &SecretBoxKey) -> Result<OutputBase, Error> {
        use crate::crypto_secretbox::crypto_secretbox_open_detached;
        let dryocsecretbox =
            crypto_secretbox_open_detached(&self.mac, &self.data, nonce, &secret_key.0)?;

        Ok(dryocsecretbox)
    }

    /// Consumes this box and returns it as a Vec
    pub fn to_vec(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.mac);
        data.extend(&self.data);
        data
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

        assert_eq!(all_eq(&dryocsecretbox.mac, 0), true);
        assert_eq!(all_eq(&dryocsecretbox.data, 0), true);
    }

    #[test]
    fn test_default() {
        let dryocsecretbox = DryocSecretBox::default();

        assert_eq!(all_eq(&dryocsecretbox.mac, 0), true);
        assert_eq!(all_eq(&dryocsecretbox.data, 0), true);
    }

    #[test]
    fn test_dryocbox() {
        for i in 0..20 {
            use crate::dryocsecretbox::*;
            use crate::nonce::*;
            use base64::encode;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key, Nonce as SONonce};

            let secret_key = SecretBoxKey::gen();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocsecretbox = DryocSecretBox::encrypt(&message.into(), &nonce, &secret_key);
            let ciphertext = dryocsecretbox.clone().to_vec();
            let ciphertext_copy = ciphertext.clone();

            let so_ciphertext = secretbox::seal(
                &message_copy.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&secret_key.0).unwrap(),
            );
            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &Key::from_slice(&secret_key.0).unwrap(),
            )
            .expect("decrypt failed");

            let m = dryocsecretbox
                .decrypt(&nonce, &secret_key)
                .expect("decrypt failed");
            assert_eq!(m, message_copy.as_bytes());
            assert_eq!(m, so_decrypted);
        }
    }
}

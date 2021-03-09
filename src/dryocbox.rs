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
//! let nonce = Nonce::gen();
//! let message = "hey";
//!
//! let dryocbox = DryocBox::encrypt(
//!     &message.into(),
//!     &nonce,
//!     &recipient_keypair.clone().into(),
//!     &sender_keypair.clone().into(),
//! )
//! .expect("unable to encrypt");
//!
//! let decrypted = dryocbox
//!     .decrypt(&nonce, &sender_keypair.into(), &recipient_keypair.into())
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message.as_bytes(), decrypted.as_slice());
//! ```

use crate::constants::CRYPTO_BOX_MACBYTES;
use crate::dryocsecretbox::DryocSecretBox;
use crate::error::Error;
use crate::keypair::{PublicKey, SecretKey};
use crate::message::Message;
use crate::nonce::Nonce;
use crate::types::{InputBase, MacBase, OutputBase};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize, Zeroize, Clone))]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocBox {
    /// libsodium box authentication tag, usually prepended to each box
    pub mac: MacBase,
    /// libsodium box message or ciphertext, depending on state
    pub data: Vec<u8>,
}

impl DryocBox {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            mac: [0u8; CRYPTO_BOX_MACBYTES],
            data: vec![],
        }
    }

    /// Returns a box with an empty `mac`, and data from `data`, consuming `data`
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            mac: [0u8; CRYPTO_BOX_MACBYTES],
            data,
        }
    }

    /// Returns a new box with `mac` and `data`, consuming both
    pub fn from_data_and_mac(mac: [u8; CRYPTO_BOX_MACBYTES], data: Vec<u8>) -> Self {
        Self { mac, data }
    }

    /// Returns a box with `data` copied from slice `input`
    pub fn with_data(input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            mac: [0u8; CRYPTO_BOX_MACBYTES],
            data,
        }
    }

    /// Returns a new box with `data` and `mac` copied from `input` and `mac`
    /// respectively
    pub fn with_data_and_mac(mac: &MacBase, input: &InputBase) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        let mut r = Self {
            mac: [0u8; CRYPTO_BOX_MACBYTES],
            data,
        };
        r.mac.copy_from_slice(mac);
        r
    }

    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and mac
    pub fn encrypt(
        message: &Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox = crypto_box_detached(
            &message.0,
            nonce,
            &recipient_public_key.0,
            &sender_secret_key.0,
        )?;

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
            &self.mac,
            &self.data,
            nonce,
            &sender_public_key.0,
            &recipient_secret_key.0,
        )?;

        Ok(dryocbox)
    }

    /// Copies this box into a new Vec
    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.mac);
        data.extend(&self.data);
        data
    }

    /// Consumes this box and returns it as a Vec
    pub fn into_vec(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.mac);
        data.extend(&self.data);
        data
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
            mac: other.mac,
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

        assert_eq!(all_eq(&dryocbox.mac, 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_default() {
        let dryocbox = DryocBox::default();

        assert_eq!(all_eq(&dryocbox.mac, 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_dryocbox() {
        for i in 0..20 {
            use crate::dryocbox::*;
            use crate::keypair::*;
            use crate::nonce::*;
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
            let dryocbox = DryocBox::encrypt(
                &message.into(),
                &nonce,
                &keypair_recipient.into(),
                &keypair_sender.into(),
            )
            .unwrap();
            let ciphertext = dryocbox.clone().to_vec();

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient_copy.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender_copy.secret_key.0).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let keypair_sender = keypair_sender_copy.clone();
            let keypair_recipient = keypair_recipient_copy.clone();

            let m = dryocbox
                .decrypt(&nonce, &keypair_sender.into(), &keypair_recipient.into())
                .expect("hmm");
            let so_m = box_::open(
                &ciphertext,
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient_copy.public_key.0).unwrap(),
                &SecretKey::from_slice(&keypair_sender_copy.secret_key.0).unwrap(),
            )
            .expect("HMMM");

            assert_eq!(m, message_copy.as_bytes());
            assert_eq!(m, so_m);
        }
    }
}

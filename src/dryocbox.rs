//! # Public-key authenticated encryption

use crate::constants::*;
use crate::error::*;
use crate::types::*;

/// A libsodium public-key authenticated encrypted box
pub struct DryocBox {
    /// libsodium box authentication tag, usually prepended to each box
    pub mac: Mac,
    /// libsodium box message or ciphertext, depending on state
    pub data: Vec<u8>,
}

impl DryocBox {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data: vec![],
        }
    }
    /// Returns a box with an empty `mac`, and data from `data`
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }
    /// Returns a new box with `mac` and `data`
    pub fn from_data_and_mac(mac: [u8; CRYPTO_SECRETBOX_MACBYTES], data: Vec<u8>) -> Self {
        Self { mac, data }
    }
    /// Returns a box with `data` copied from slice `input`
    pub fn with_data(input: &Input) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }
    /// Returns a new box with `data` and `mac` copied from `input` and `mac` respectively
    pub fn with_data_and_mac(mac: &Mac, input: &Input) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        let mut r = Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        };
        r.mac.copy_from_slice(mac);
        r
    }

    /// Encrypts this box using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new box with ciphertext and mac
    pub fn encrypt_pk(
        &self,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox =
            crypto_box_detached(&self.data, nonce, recipient_public_key, sender_secret_key)?;

        Ok(dryocbox)
    }

    /// Encrypts string `message` using `sender_secret_key` for
    /// `recipient_public_key`, and returns a new box with ciphertext and mac
    pub fn encrypt_string_pk(
        message: &str,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox = crypto_box_detached(
            message.as_bytes(),
            nonce,
            recipient_public_key,
            sender_secret_key,
        )?;

        Ok(dryocbox)
    }

    /// Encrypts byte slice `message` using `sender_secret_key` for
    /// `recipient_public_key`, and returns a new box with ciphertext and mac
    pub fn encrypt_slice_pk(
        message: &[u8],
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox =
            crypto_box_detached(message, nonce, recipient_public_key, sender_secret_key)?;

        Ok(dryocbox)
    }

    /// Encrypts this box using `secret_key` and returns a new box with
    /// ciphertext and mac
    pub fn encrypt_sk(&self, nonce: &Nonce, secret_key: &SecretKey) -> Self {
        use crate::crypto_secretbox::*;
        let dryocbox = crypto_secretbox_detached(&self.data, nonce, secret_key);

        dryocbox
    }

    /// Encrypt a string `message` using `secret_key` and return a new box with
    /// ciphertext and mac
    pub fn encrypt_string_sk(
        message: &str,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox = crypto_box_detached(
            message.as_bytes(),
            nonce,
            recipient_public_key,
            sender_secret_key,
        )?;

        Ok(dryocbox)
    }

    /// Encrypt a byte slice `message` using `sender_secret_key` for
    /// `recipient_public_key`, and return a new box with ciphertext and mac
    pub fn encrypt_slice_sk(
        message: &[u8],
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;
        let dryocbox =
            crypto_box_detached(message, nonce, recipient_public_key, sender_secret_key)?;

        Ok(dryocbox)
    }

    /// Combine mac and data, return a Vec
    pub fn to_vec(&self) -> Vec<u8> {
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

mod tests {
    use super::*;

    #[test]
    fn test_dryocbox() {}
}

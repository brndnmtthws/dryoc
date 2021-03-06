//! # Public-key authenticated encryption

use crate::constants::*;
use crate::types::*;

/// A libsodium public-key authenticated encrypted box
pub struct DryocBox {
    pub mac: Mac,
    pub data: Vec<u8>,
}

impl DryocBox {
    pub fn new() -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data: vec![],
        }
    }

    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }
    pub fn from_data_and_mac(mac: [u8; CRYPTO_SECRETBOX_MACBYTES], data: Vec<u8>) -> Self {
        Self { mac, data }
    }
    pub fn with_data(input: &Input) -> Self {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(input);
        Self {
            mac: [0u8; CRYPTO_SECRETBOX_MACBYTES],
            data,
        }
    }
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

use crate::constants::*;

pub type PublicKey = [u8; CRYPTO_BOX_PUBLICKEYBYTES];
pub type SecretKey = [u8; CRYPTO_BOX_SECRETKEYBYTES];

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

pub type Nonce = [u8];

pub type Output = Vec<u8>;
pub type Input = [u8];

pub type Mac = [u8; CRYPTO_BOX_MACBYTES];

pub struct CryptoBox {
    pub mac: Mac,
    pub data: Vec<u8>,
}

pub type SecretboxKey = [u8; CRYPTO_SECRETBOX_KEYBYTES];

impl CryptoBox {
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

impl Default for CryptoBox {
    fn default() -> Self {
        Self::new()
    }
}

use crate::constants::*;

pub type Nonce = [u8];

pub type Output = Vec<u8>;
pub type Input = [u8];

pub type Mac = [u8; CRYPTO_BOX_MACBYTES];

pub type SecretboxKey = [u8; CRYPTO_SECRETBOX_KEYBYTES];

pub type PublicKey = [u8; CRYPTO_BOX_PUBLICKEYBYTES];
pub type SecretKey = [u8; CRYPTO_BOX_SECRETKEYBYTES];

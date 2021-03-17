use crate::constants::*;

pub type OutputBase = Vec<u8>;
pub type InputBase = [u8];

pub type MacBase = [u8; CRYPTO_BOX_MACBYTES];

pub type SecretBoxKeyBase = [u8; CRYPTO_SECRETBOX_KEYBYTES];
pub type SecretStreamKeyBase = [u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES];

pub type PublicKeyBase = [u8; CRYPTO_BOX_PUBLICKEYBYTES];
pub type SecretKeyBase = [u8; CRYPTO_BOX_SECRETKEYBYTES];

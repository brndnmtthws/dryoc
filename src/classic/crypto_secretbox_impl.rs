#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
use salsa20::cipher::{KeyIvInit, StreamCipher};
#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
use salsa20::{Key as SalsaKey, XNonce, XSalsa20};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::classic::crypto_secretbox::{Key, Mac, Nonce};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};

#[cfg(all(feature = "simd_backend", feature = "nightly"))]
struct SecretBoxCipher {
    cipher: crate::classic::salsa20_simd::XSalsa20,
    first_block: crate::classic::salsa20_simd::FirstBlock,
}

#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
struct SecretBoxCipher {
    cipher: XSalsa20,
}

#[cfg(all(feature = "simd_backend", feature = "nightly"))]
impl SecretBoxCipher {
    fn new(nonce: &Nonce, key: &Key) -> Self {
        let cipher = crate::classic::salsa20_simd::XSalsa20::new(nonce, key);
        let first_block = cipher.first_block();

        Self {
            cipher,
            first_block,
        }
    }

    fn poly1305_key(&mut self, mac_key: &mut Poly1305Key) {
        self.first_block.poly1305_key(mac_key);
    }

    fn xor(&mut self, data: &mut [u8]) {
        self.cipher.xor_after_first_block(data, &self.first_block);
    }
}

#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
impl SecretBoxCipher {
    fn new(nonce: &Nonce, key: &Key) -> Self {
        let key = SalsaKey::from(*key);
        let nonce = XNonce::from(*nonce);

        Self {
            cipher: XSalsa20::new(&key, &nonce),
        }
    }

    fn poly1305_key(&mut self, mac_key: &mut Poly1305Key) {
        self.cipher.apply_keystream(mac_key);
    }

    fn xor(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

pub(crate) fn crypto_secretbox_detached_inplace(
    data: &mut [u8],
    mac: &mut Mac,
    nonce: &Nonce,
    key: &Key,
) {
    let mut mac_key = Poly1305Key::new();
    {
        let mut cipher = SecretBoxCipher::new(nonce, key);
        cipher.poly1305_key(&mut mac_key);
        cipher.xor(data);
    }

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(data);
    computed_mac.finalize(mac);
}

pub(crate) fn crypto_secretbox_open_detached_inplace(
    data: &mut [u8],
    mac: &Mac,
    nonce: &Nonce,
    key: &Key,
) -> Result<(), Error> {
    let mut cipher = SecretBoxCipher::new(nonce, key);
    let mut mac_key = Poly1305Key::new();
    cipher.poly1305_key(&mut mac_key);

    let mut computed_mac = Poly1305::new(&mac_key);
    mac_key.zeroize();

    computed_mac.update(data);
    let computed_mac = computed_mac.finalize_to_array();

    cipher.xor(data);
    drop(cipher);

    if mac.ct_eq(&computed_mac).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(dryoc_error!("decryption error (authentication failure)"))
    }
}

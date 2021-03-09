use crate::constants::CRYPTO_BOX_NONCEBYTES;
use crate::rng::copy_randombytes;
pub use crate::traits::Gen;

/// Base type for nonces
pub type Nonce = [u8; CRYPTO_BOX_NONCEBYTES];

impl Gen for Nonce {
    fn gen() -> Self {
        let mut nonce: Nonce = [0u8; CRYPTO_BOX_NONCEBYTES];
        copy_randombytes(&mut nonce);
        nonce
    }
}

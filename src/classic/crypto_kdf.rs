//! # Key derivation function
//!
//! Implements libsodium's key derivation functions (`crypto_kdf_*`).
//!
//! For details, refer to [libsodium docs](https://doc.libsodium.org/key_derivation).
//!
//! # Classic API example
//!
//! ```
//! use base64::engine::general_purpose;
//! use base64::Engine as _;
//! use dryoc::classic::crypto_kdf::*;
//!
//! // Generate a random main key
//! let main_key = crypto_kdf_keygen();
//! // Provide 8 bytes of context data, can be any data
//! let context = b"hello123";
//!
//! // Derive 20 subkeys
//! for i in 0..20 {
//!     let mut key = Key::default();
//!     crypto_kdf_derive_from_key(&mut key, i, context, &main_key).expect("kdf failed");
//!     println!("Subkey {}: {}", i, general_purpose::STANDARD.encode(&key));
//! }
//! ```

use crate::blake2b;
use crate::constants::{
    CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES, CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES,
    CRYPTO_KDF_BLAKE2B_BYTES_MAX, CRYPTO_KDF_BLAKE2B_BYTES_MIN, CRYPTO_KDF_CONTEXTBYTES,
    CRYPTO_KDF_KEYBYTES,
};
use crate::error::Error;

/// Key type for the main key used for deriving subkeys.
pub type Key = [u8; CRYPTO_KDF_KEYBYTES];
/// Context for key derivation.
pub type Context = [u8; CRYPTO_KDF_CONTEXTBYTES];

/// Generates a random key, suitable for use as a main key with
/// [`crypto_kdf_derive_from_key`].
pub fn crypto_kdf_keygen() -> Key {
    use crate::rng::copy_randombytes;
    let mut key = Key::default();
    copy_randombytes(&mut key);
    key
}

/// Derives `subkey` from `main_key`, using `context` and `subkey_id` such that
/// `subkey` will always be the same for the given set of inputs, but `main_key`
/// cannot be derived from `subkey`.
pub fn crypto_kdf_derive_from_key(
    subkey: &mut [u8],
    subkey_id: u64,
    context: &Context,
    main_key: &Key,
) -> Result<(), Error> {
    if subkey.len() < CRYPTO_KDF_BLAKE2B_BYTES_MIN || subkey.len() > CRYPTO_KDF_BLAKE2B_BYTES_MAX {
        Err(dryoc_error!(format!(
            "invalid subkey length {}, should be at least {} and no more than {}",
            subkey.len(),
            CRYPTO_KDF_BLAKE2B_BYTES_MIN,
            CRYPTO_KDF_BLAKE2B_BYTES_MAX
        )))
    } else {
        let mut ctx_padded = [0u8; CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES];
        let mut salt = [0u8; CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES];

        ctx_padded[..CRYPTO_KDF_CONTEXTBYTES].copy_from_slice(context);
        salt[..8].copy_from_slice(&subkey_id.to_le_bytes());

        let state = blake2b::State::init(
            CRYPTO_KDF_KEYBYTES as u8,
            Some(main_key),
            Some(&salt),
            Some(&ctx_padded),
        )?;
        state.finalize(subkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        use sodiumoxide::crypto::{kdf, secretbox};
        let main_key = crypto_kdf_keygen();
        let context = b"hello123";

        for i in 0..20 {
            let mut key = Key::default();
            crypto_kdf_derive_from_key(&mut key, i, context, &main_key).expect("kdf failed");

            let mut so_key = secretbox::Key([0; secretbox::KEYBYTES]);
            kdf::derive_from_key(
                &mut so_key.0[..],
                i,
                *context,
                &kdf::blake2b::Key::from_slice(&main_key).expect("key failed"),
            )
            .expect("so kdf failed");

            assert_eq!(so_key.0, key);
        }
    }
}

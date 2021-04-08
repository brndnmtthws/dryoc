use crate::blake2b;
use crate::constants::{
    CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX, CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX,
};
use crate::error::Error;

fn crypto_generichash_blake2b(output: &mut [u8], input: &[u8], key: &[u8]) -> Result<(), Error> {
    if output.is_empty() || output.len() > CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX {
        return Err(dryoc_error!(format!(
            "output length is {}, expected non-empty and less than {} bytes",
            output.len(),
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX
        )));
    }

    if key.len() > CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX {
        return Err(dryoc_error!(format!(
            "key length is {}, expected non-empty and less than {} bytes",
            key.len(),
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX
        )));
    }

    blake2b::hash(output, input, key)
}

pub fn crypto_generichash(output: &mut [u8], input: &[u8], key: &[u8]) -> Result<(), Error> {
    crypto_generichash_blake2b(output, input, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generichash() {
        use libsodium_sys::crypto_generichash as so_crypto_generichash;

        use crate::rng::copy_randombytes;

        let mut output = [0u8; 32];
        let mut input = [0u8; 1791];
        let mut key = [0u8; 16];

        copy_randombytes(&mut input);
        copy_randombytes(&mut key);

        let mut so_output = output.clone();

        crypto_generichash(&mut output, &input, &key).ok();

        unsafe {
            so_crypto_generichash(
                &mut so_output as *mut u8,
                so_output.len(),
                &input as *const u8,
                input.len() as u64,
                &key as *const u8,
                key.len(),
            );
        }

        assert_eq!(output, so_output);
    }
}

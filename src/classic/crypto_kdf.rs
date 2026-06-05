//! # Key derivation function
//!
//! Implements libsodium's key derivation functions (`crypto_kdf_*`).
//!
//! The Blake2b `crypto_kdf_*` functions derive bounded subkeys from a random
//! main key and an 8-byte application context. The HKDF functions derive output
//! keying material from existing input keying material, using an optional salt
//! and a public context string.
//!
//! Use `crypto_kdf_derive_from_key` when you have one random main key and need
//! numbered subkeys. Use the HKDF functions when you already have keying
//! material, such as a key-exchange result, and need to turn it into one or more
//! purpose-specific keys.
//!
//! For details, refer to [libsodium docs](https://doc.libsodium.org/key_derivation).
//!
//! # Classic API example
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::classic::crypto_kdf::*;
//!
//! // Generate a random main key
//! let main_key = crypto_kdf_keygen();
//! // Provide exactly 8 bytes of public context data
//! let context = b"WTCHKEYS";
//!
//! // Derive 20 subkeys
//! for i in 0..20 {
//!     let mut key = Key::default();
//!     crypto_kdf_derive_from_key(&mut key, i, context, &main_key).expect("kdf failed");
//!     println!("Subkey {}: {}", i, general_purpose::STANDARD.encode(&key));
//! }
//! ```
//!
//! # HKDF-SHA-256 example
//!
//! ```
//! use dryoc::classic::crypto_kdf::*;
//!
//! let mut prk = HkdfSha256Key::default();
//! crypto_kdf_hkdf_sha256_extract(&mut prk, Some(b"salt"), b"Some rise by sin");
//!
//! let mut output = [0u8; 42];
//! crypto_kdf_hkdf_sha256_expand(&mut output, b"encryption key", &prk)
//!     .expect("expand failed");
//! ```
//!
//! The HKDF extract step can also be fed incrementally. This is useful when the
//! input keying material arrives in pieces:
//!
//! ```
//! use dryoc::classic::crypto_kdf::*;
//!
//! let mut state = crypto_kdf_hkdf_sha256_extract_init(Some(b"salt"));
//! crypto_kdf_hkdf_sha256_extract_update(&mut state, b"Some rise ");
//! crypto_kdf_hkdf_sha256_extract_update(&mut state, b"by sin");
//!
//! let mut prk = HkdfSha256Key::default();
//! crypto_kdf_hkdf_sha256_extract_final(state, &mut prk);
//! ```
//!
//! # HKDF-SHA-512 example
//!
//! ```
//! use dryoc::classic::crypto_kdf::*;
//!
//! let mut prk: HkdfSha512Key = [0u8; 64];
//! crypto_kdf_hkdf_sha512_extract(&mut prk, None, b"and some by virtue fall");
//!
//! let mut output = [0u8; 64];
//! crypto_kdf_hkdf_sha512_expand(&mut output, b"authentication key", &prk)
//!     .expect("expand failed");
//! ```

use zeroize::Zeroize;

use crate::blake2b;
use crate::classic::crypto_auth_hmac_impl::{
    HmacHash, HmacState, hmac_final, hmac_init, hmac_keygen, hmac_update,
};
use crate::constants::{
    CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES, CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES,
    CRYPTO_KDF_BLAKE2B_BYTES_MAX, CRYPTO_KDF_BLAKE2B_BYTES_MIN, CRYPTO_KDF_CONTEXTBYTES,
    CRYPTO_KDF_HKDF_SHA256_BYTES_MAX, CRYPTO_KDF_HKDF_SHA256_BYTES_MIN,
    CRYPTO_KDF_HKDF_SHA256_KEYBYTES, CRYPTO_KDF_HKDF_SHA512_BYTES_MAX,
    CRYPTO_KDF_HKDF_SHA512_BYTES_MIN, CRYPTO_KDF_HKDF_SHA512_KEYBYTES, CRYPTO_KDF_KEYBYTES,
};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::sha256::Sha256;
use crate::sha512::Sha512;

/// Key type for the main key used for deriving subkeys.
pub type Key = [u8; CRYPTO_KDF_KEYBYTES];
/// Context for key derivation.
pub type Context = [u8; CRYPTO_KDF_CONTEXTBYTES];
/// Pseudorandom key for HKDF-SHA-256.
pub type HkdfSha256Key = [u8; CRYPTO_KDF_HKDF_SHA256_KEYBYTES];
/// Pseudorandom key for HKDF-SHA-512.
pub type HkdfSha512Key = [u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];

/// Internal state for incremental HKDF-SHA-256 extract.
pub struct HkdfSha256State(HmacState<Sha256, 64, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>);

/// Internal state for incremental HKDF-SHA-512 extract.
pub struct HkdfSha512State(HmacState<Sha512, 128, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>);

/// Generates a random key, suitable for use as a main key with
/// [`crypto_kdf_derive_from_key`].
pub fn crypto_kdf_keygen() -> Key {
    let mut key = Key::default();
    copy_randombytes(&mut key);
    key
}

/// Generates a random pseudorandom key for HKDF-SHA-256 expand.
pub fn crypto_kdf_hkdf_sha256_keygen() -> HkdfSha256Key {
    hmac_keygen()
}

/// Generates a random pseudorandom key for HKDF-SHA-512 expand.
pub fn crypto_kdf_hkdf_sha512_keygen() -> HkdfSha512Key {
    hmac_keygen()
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

fn validate_hkdf_output_len(
    output_len: usize,
    min_len: usize,
    max_len: usize,
) -> Result<(), Error> {
    if output_len < min_len || output_len > max_len {
        Err(dryoc_error!(format!(
            "invalid output length {}, should be at least {} and no more than {}",
            output_len, min_len, max_len
        )))
    } else {
        Ok(())
    }
}

/// Creates an HKDF-SHA-256 pseudorandom key from input keying material.
pub fn crypto_kdf_hkdf_sha256_extract(prk: &mut HkdfSha256Key, salt: Option<&[u8]>, ikm: &[u8]) {
    let mut state = crypto_kdf_hkdf_sha256_extract_init(salt);
    crypto_kdf_hkdf_sha256_extract_update(&mut state, ikm);
    crypto_kdf_hkdf_sha256_extract_final(state, prk);
}

/// Initializes incremental HKDF-SHA-256 extract.
pub fn crypto_kdf_hkdf_sha256_extract_init(salt: Option<&[u8]>) -> HkdfSha256State {
    HkdfSha256State(hmac_init::<Sha256, 64, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>(
        salt.unwrap_or(&[]),
    ))
}

/// Updates incremental HKDF-SHA-256 extract with input keying material.
pub fn crypto_kdf_hkdf_sha256_extract_update(state: &mut HkdfSha256State, ikm: &[u8]) {
    hmac_update(&mut state.0, ikm);
}

/// Finalizes incremental HKDF-SHA-256 extract and writes the pseudorandom key.
pub fn crypto_kdf_hkdf_sha256_extract_final(state: HkdfSha256State, prk: &mut HkdfSha256Key) {
    hmac_final(state.0, prk);
}

/// Expands an HKDF-SHA-256 pseudorandom key into output keying material.
pub fn crypto_kdf_hkdf_sha256_expand(
    output: &mut [u8],
    context: &[u8],
    prk: &HkdfSha256Key,
) -> Result<(), Error> {
    hkdf_expand::<Sha256, 64, CRYPTO_KDF_HKDF_SHA256_KEYBYTES>(
        output,
        context,
        prk,
        CRYPTO_KDF_HKDF_SHA256_BYTES_MIN,
        CRYPTO_KDF_HKDF_SHA256_BYTES_MAX,
    )
}

/// Creates an HKDF-SHA-512 pseudorandom key from input keying material.
pub fn crypto_kdf_hkdf_sha512_extract(prk: &mut HkdfSha512Key, salt: Option<&[u8]>, ikm: &[u8]) {
    let mut state = crypto_kdf_hkdf_sha512_extract_init(salt);
    crypto_kdf_hkdf_sha512_extract_update(&mut state, ikm);
    crypto_kdf_hkdf_sha512_extract_final(state, prk);
}

/// Initializes incremental HKDF-SHA-512 extract.
pub fn crypto_kdf_hkdf_sha512_extract_init(salt: Option<&[u8]>) -> HkdfSha512State {
    HkdfSha512State(hmac_init::<Sha512, 128, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>(
        salt.unwrap_or(&[]),
    ))
}

/// Updates incremental HKDF-SHA-512 extract with input keying material.
pub fn crypto_kdf_hkdf_sha512_extract_update(state: &mut HkdfSha512State, ikm: &[u8]) {
    hmac_update(&mut state.0, ikm);
}

/// Finalizes incremental HKDF-SHA-512 extract and writes the pseudorandom key.
pub fn crypto_kdf_hkdf_sha512_extract_final(state: HkdfSha512State, prk: &mut HkdfSha512Key) {
    hmac_final(state.0, prk);
}

/// Expands an HKDF-SHA-512 pseudorandom key into output keying material.
pub fn crypto_kdf_hkdf_sha512_expand(
    output: &mut [u8],
    context: &[u8],
    prk: &HkdfSha512Key,
) -> Result<(), Error> {
    hkdf_expand::<Sha512, 128, CRYPTO_KDF_HKDF_SHA512_KEYBYTES>(
        output,
        context,
        prk,
        CRYPTO_KDF_HKDF_SHA512_BYTES_MIN,
        CRYPTO_KDF_HKDF_SHA512_BYTES_MAX,
    )
}

fn hkdf_expand<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    output: &mut [u8],
    context: &[u8],
    prk: &[u8; OUT_BYTES],
    min_len: usize,
    max_len: usize,
) -> Result<(), Error>
where
    H: HmacHash<OUT_BYTES>,
{
    validate_hkdf_output_len(output.len(), min_len, max_len)?;

    let mut previous = [0u8; OUT_BYTES];
    let mut offset = 0usize;
    for counter in 1..=255u8 {
        if offset == output.len() {
            break;
        }

        let mut state = hmac_init::<H, BLOCK_BYTES, OUT_BYTES>(prk);
        if counter > 1 {
            hmac_update(&mut state, &previous);
        }
        hmac_update(&mut state, context);
        hmac_update(&mut state, &[counter]);
        hmac_final(state, &mut previous);

        let chunk_len = (output.len() - offset).min(previous.len());
        output[offset..offset + chunk_len].copy_from_slice(&previous[..chunk_len]);
        offset += chunk_len;
    }

    previous.zeroize();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_in_range(start: u8, end_inclusive: u8) -> Vec<u8> {
        (start..=end_inclusive).collect()
    }

    fn assert_hkdf_sha256(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_len: usize,
        expected_prk_hex: &str,
        expected_okm_hex: &str,
    ) {
        let expected_prk = hex::decode(expected_prk_hex).expect("hex failed");
        let expected_okm = hex::decode(expected_okm_hex).expect("hex failed");
        let mut prk = HkdfSha256Key::default();
        crypto_kdf_hkdf_sha256_extract(&mut prk, salt, ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let mut okm = vec![0u8; output_len];
        crypto_kdf_hkdf_sha256_expand(&mut okm, info, &prk).expect("expand failed");
        assert_eq!(okm, expected_okm);
    }

    fn assert_hkdf_sha512(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_len: usize,
        expected_prk_hex: &str,
        expected_okm_hex: &str,
    ) {
        let expected_prk = hex::decode(expected_prk_hex).expect("hex failed");
        let expected_okm = hex::decode(expected_okm_hex).expect("hex failed");
        let mut prk = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        crypto_kdf_hkdf_sha512_extract(&mut prk, salt, ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let mut okm = vec![0u8; output_len];
        crypto_kdf_hkdf_sha512_expand(&mut okm, info, &prk).expect("expand failed");
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_sha256_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").expect("hex failed");
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("hex failed");
        assert_hkdf_sha256(
            &ikm,
            Some(&salt),
            &info,
            42,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a",
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865",
            ),
        );
    }

    #[test]
    fn test_hkdf_sha256_rfc5869_case_2() {
        let ikm = bytes_in_range(0x00, 0x4f);
        let salt = bytes_in_range(0x60, 0xaf);
        let info = bytes_in_range(0xb0, 0xff);
        assert_hkdf_sha256(
            &ikm,
            Some(&salt),
            &info,
            82,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            concat!(
                "b11e398dc80327a1c8e7f78c596a4934",
                "4f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09",
                "da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f",
                "1d87",
            ),
        );
    }

    #[test]
    fn test_hkdf_sha256_rfc5869_case_3_no_salt_or_info() {
        let ikm = [0x0bu8; 22];
        assert_hkdf_sha256(
            &ikm,
            None,
            &[],
            42,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            concat!(
                "8da4e775a563c18f715f802a063c5a31",
                "b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8",
            ),
        );
    }

    #[test]
    fn test_hkdf_sha512_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").expect("hex failed");
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("hex failed");
        assert_hkdf_sha512(
            &ikm,
            Some(&salt),
            &info,
            42,
            "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        );
    }

    #[test]
    fn test_hkdf_sha512_long_inputs_openssl_vector() {
        let ikm = bytes_in_range(0x00, 0x4f);
        let salt = bytes_in_range(0x60, 0xaf);
        let info = bytes_in_range(0xb0, 0xff);
        assert_hkdf_sha512(
            &ikm,
            Some(&salt),
            &info,
            82,
            concat!(
                "35672542907d4e142c00e84499e74e1d",
                "e08be86535f924e022804ad775dde27e",
                "c86cd1e5b7d178c74489bdbeb30712be",
                "b82d4f97416c5a94ea81ebdf3e629e4a",
            ),
            concat!(
                "ce6c97192805b346e6161e821ed16567",
                "3b84f400a2b514b2fe23d84cd189ddf1",
                "b695b48cbd1c8388441137b3ce28f16a",
                "a64ba33ba466b24df6cfcb021ecff235",
                "f6a2056ce3af1de44d572097a8505d",
                "9e7a93",
            ),
        );
    }

    #[test]
    fn test_hkdf_sha512_no_salt_or_info_openssl_vector() {
        let ikm = [0x0bu8; 22];
        assert_hkdf_sha512(
            &ikm,
            None,
            &[],
            42,
            concat!(
                "fd200c4987ac491313bd4a2a13287121",
                "247239e11c9ef82802044b66ef357e5b",
                "194498d0682611382348572a7b1611de",
                "54764094286320578a863f36562b0df6",
            ),
            concat!(
                "f5fa02b18298a72a8c23898a8703472c",
                "6eb179dc204c03425c970e3b164bf90f",
                "ff22d04836d0e2343bac",
            ),
        );
    }

    #[test]
    fn test_hkdf_output_length_limits() {
        let prk256 = HkdfSha256Key::default();
        let mut okm256 = vec![0u8; CRYPTO_KDF_HKDF_SHA256_BYTES_MAX + 1];
        crypto_kdf_hkdf_sha256_expand(&mut okm256, b"context", &prk256)
            .expect_err("oversized output should fail");

        let prk512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        let mut okm512 = vec![0u8; CRYPTO_KDF_HKDF_SHA512_BYTES_MAX + 1];
        crypto_kdf_hkdf_sha512_expand(&mut okm512, b"context", &prk512)
            .expect_err("oversized output should fail");
    }

    #[test]
    fn test_hkdf_empty_and_max_output_lengths() {
        let prk256 = HkdfSha256Key::default();
        let mut empty256 = [];
        crypto_kdf_hkdf_sha256_expand(&mut empty256, b"context", &prk256)
            .expect("empty SHA-256 output should be allowed");
        let mut max256 = vec![0u8; CRYPTO_KDF_HKDF_SHA256_BYTES_MAX];
        crypto_kdf_hkdf_sha256_expand(&mut max256, b"context", &prk256)
            .expect("max SHA-256 output should be allowed");

        let prk512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        let mut empty512 = [];
        crypto_kdf_hkdf_sha512_expand(&mut empty512, b"context", &prk512)
            .expect("empty SHA-512 output should be allowed");
        let mut max512 = vec![0u8; CRYPTO_KDF_HKDF_SHA512_BYTES_MAX];
        crypto_kdf_hkdf_sha512_expand(&mut max512, b"context", &prk512)
            .expect("max SHA-512 output should be allowed");
    }

    #[test]
    fn test_hkdf_digest_boundary_output_lengths() {
        let prk256 = HkdfSha256Key::default();
        for len in [31, 32, 33] {
            let mut okm = vec![0u8; len];
            crypto_kdf_hkdf_sha256_expand(&mut okm, b"context", &prk256)
                .expect("SHA-256 boundary output should be allowed");
        }

        let prk512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        for len in [63, 64, 65] {
            let mut okm = vec![0u8; len];
            crypto_kdf_hkdf_sha512_expand(&mut okm, b"context", &prk512)
                .expect("SHA-512 boundary output should be allowed");
        }
    }

    #[test]
    fn test_hkdf_none_and_empty_salt_match() {
        let ikm = [0xabu8; 20];

        let mut none_salt256 = HkdfSha256Key::default();
        let mut empty_salt256 = HkdfSha256Key::default();
        crypto_kdf_hkdf_sha256_extract(&mut none_salt256, None, &ikm);
        crypto_kdf_hkdf_sha256_extract(&mut empty_salt256, Some(&[]), &ikm);
        assert_eq!(none_salt256, empty_salt256);

        let mut none_salt512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        let mut empty_salt512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        crypto_kdf_hkdf_sha512_extract(&mut none_salt512, None, &ikm);
        crypto_kdf_hkdf_sha512_extract(&mut empty_salt512, Some(&[]), &ikm);
        assert_eq!(none_salt512, empty_salt512);
    }

    #[test]
    fn test_hkdf_incremental_extract_matches_one_shot() {
        let salt = b"salt";
        let ikm_parts = [
            b"input ".as_slice(),
            b"keying ".as_slice(),
            b"material".as_slice(),
        ];
        let ikm = ikm_parts.concat();

        let mut one_shot256 = HkdfSha256Key::default();
        crypto_kdf_hkdf_sha256_extract(&mut one_shot256, Some(salt), &ikm);

        let mut state256 = crypto_kdf_hkdf_sha256_extract_init(Some(salt));
        for part in ikm_parts {
            crypto_kdf_hkdf_sha256_extract_update(&mut state256, part);
        }
        let mut incremental256 = HkdfSha256Key::default();
        crypto_kdf_hkdf_sha256_extract_final(state256, &mut incremental256);
        assert_eq!(one_shot256, incremental256);

        let mut one_shot512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        crypto_kdf_hkdf_sha512_extract(&mut one_shot512, Some(salt), &ikm);

        let mut state512 = crypto_kdf_hkdf_sha512_extract_init(Some(salt));
        for part in ikm_parts {
            crypto_kdf_hkdf_sha512_extract_update(&mut state512, part);
        }
        let mut incremental512 = [0u8; CRYPTO_KDF_HKDF_SHA512_KEYBYTES];
        crypto_kdf_hkdf_sha512_extract_final(state512, &mut incremental512);
        assert_eq!(one_shot512, incremental512);
    }

    #[cfg(dryoc_native_tests)]
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

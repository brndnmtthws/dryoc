#![allow(missing_docs)]

const fn min(a: usize, b: usize) -> usize {
    [a, b][(a > b) as usize]
}
const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}
const fn min_usize_u64(a: usize, b: u64) -> usize {
    if (a as u64) < b { a } else { b as usize }
}

const SODIUM_SIZE_MAX: usize = min(usize::MAX, u64::MAX as usize);

pub const CRYPTO_SCALARMULT_CURVE25519_BYTES: usize = 32;
pub const CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES: usize = 32;

pub const CRYPTO_SCALARMULT_BYTES: usize = CRYPTO_SCALARMULT_CURVE25519_BYTES;
pub const CRYPTO_SCALARMULT_SCALARBYTES: usize = CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES;

const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES: usize = 32;
const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES: usize = 32;
const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES: usize = 16;
const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES: usize = 24;
const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES: usize = 32;
const CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES: usize = 32;

const CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX: usize = SODIUM_SIZE_MAX;

pub const CRYPTO_BOX_PUBLICKEYBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
pub const CRYPTO_BOX_SECRETKEYBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
pub const CRYPTO_BOX_MACBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
pub const CRYPTO_BOX_NONCEBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES;
pub const CRYPTO_BOX_SEEDBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SEEDBYTES;
pub const CRYPTO_BOX_BEFORENMBYTES: usize = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES;
pub const CRYPTO_BOX_SEALBYTES: usize = CRYPTO_BOX_PUBLICKEYBYTES + CRYPTO_BOX_MACBYTES;
pub const CRYPTO_BOX_MESSAGEBYTES_MAX: usize =
    CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX - CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;

pub const CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES: usize = 32;
pub const CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES: usize = 24;
pub const CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES: usize = 16;
pub const CRYPTO_SECRETBOX_XSALSA20POLY1305_MESSAGEBYTES_MAX: usize =
    CRYPTO_STREAM_XSALSA20_MESSAGEBYTES_MAX - CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;

pub const CRYPTO_SECRETBOX_KEYBYTES: usize = CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES;
pub const CRYPTO_SECRETBOX_NONCEBYTES: usize = CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES;
pub const CRYPTO_SECRETBOX_MACBYTES: usize = CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;
pub const CRYPTO_SECRETBOX_PRIMITIVE: &str = "xsalsa20poly1305";
pub const CRYPTO_SECRETBOX_MESSAGEBYTES_MAX: usize =
    CRYPTO_SECRETBOX_XSALSA20POLY1305_MESSAGEBYTES_MAX;

pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES: usize = 32;
pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES: usize = 0;
pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES: usize = 12;
pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES: usize = 16;
pub const CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX: usize = min_usize_u64(
    SODIUM_SIZE_MAX - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
    64u64 * ((1u64 << 32) - 1u64),
);

pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES: usize = 32;
pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES: usize = 0;
pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES: usize = 24;
pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES: usize = 16;
// Match libsodium's XChaCha20-Poly1305-IETF API. This is larger than plain
// RFC 8439 ChaCha20-Poly1305-IETF because libsodium's XChaCha path uses an
// extended-counter XChaCha20 stream internally.
pub const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX: usize =
    SODIUM_SIZE_MAX - CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES: usize =
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES: usize =
    CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_INONCEBYTES: usize = 8;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_COUNTERBYTES: usize = 4;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES: usize =
    1 + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX: usize = min_usize_u64(
    SODIUM_SIZE_MAX - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    64u64 * ((1u64 << 32) - 2u64),
);

pub const CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES: usize = 32;
pub const CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES: usize = 12;

pub const CRYPTO_CORE_HCHACHA20_INPUTBYTES: usize = 16;
pub const CRYPTO_CORE_HCHACHA20_OUTPUTBYTES: usize = 32;
pub const CRYPTO_CORE_HCHACHA20_KEYBYTES: usize = 32;

pub const CRYPTO_CORE_HSALSA20_OUTPUTBYTES: usize = 32;
pub const CRYPTO_CORE_HSALSA20_INPUTBYTES: usize = 16;
pub const CRYPTO_CORE_HSALSA20_KEYBYTES: usize = 32;
pub const CRYPTO_CORE_HSALSA20_CONSTBYTES: usize = 16;

pub const CRYPTO_SECRETSTREAM_PADBYTES: usize = 8;

pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE: u8 = 0x00;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH: u8 = 0x01;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY: u8 = 0x02;
pub const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL: u8 =
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH
        | CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY;

pub const CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN: usize = 16;
pub const CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX: usize = 64;
pub const CRYPTO_GENERICHASH_BLAKE2B_BYTES: usize = 32;
pub const CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN: usize = 16;
pub const CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX: usize = 64;
pub const CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES: usize = 32;
pub const CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES: usize = 16;
pub const CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES: usize = 16;

pub const CRYPTO_GENERICHASH_BYTES: usize = CRYPTO_GENERICHASH_BLAKE2B_BYTES;
pub const CRYPTO_GENERICHASH_KEYBYTES: usize = CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES;
pub const CRYPTO_GENERICHASH_BYTES_MIN: usize = CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN;
pub const CRYPTO_GENERICHASH_BYTES_MAX: usize = CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX;
pub const CRYPTO_GENERICHASH_KEYBYTES_MIN: usize = CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN;
pub const CRYPTO_GENERICHASH_KEYBYTES_MAX: usize = CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX;

pub const CRYPTO_ONETIMEAUTH_POLY1305_BYTES: usize = 16;
pub const CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES: usize = 32;

pub const CRYPTO_ONETIMEAUTH_BYTES: usize = CRYPTO_ONETIMEAUTH_POLY1305_BYTES;
pub const CRYPTO_ONETIMEAUTH_KEYBYTES: usize = CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES;

pub const CRYPTO_AUTH_HMACSHA512256_BYTES: usize = 32;
pub const CRYPTO_AUTH_HMACSHA512256_KEYBYTES: usize = 32;

pub const CRYPTO_AUTH_HMACSHA256_BYTES: usize = 32;
pub const CRYPTO_AUTH_HMACSHA256_KEYBYTES: usize = 32;
pub const CRYPTO_AUTH_HMACSHA512_BYTES: usize = 64;
pub const CRYPTO_AUTH_HMACSHA512_KEYBYTES: usize = 32;

pub const CRYPTO_AUTH_BYTES: usize = CRYPTO_AUTH_HMACSHA512256_BYTES;
pub const CRYPTO_AUTH_KEYBYTES: usize = CRYPTO_AUTH_HMACSHA512256_KEYBYTES;

pub const CRYPTO_HASH_SHA256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA512_BYTES: usize = 64;
pub const CRYPTO_HASH_SHA3256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA3512_BYTES: usize = 64;
pub const CRYPTO_HASH_BYTES: usize = CRYPTO_HASH_SHA512_BYTES;
pub const CRYPTO_HASH_PRIMITIVE: &str = "sha512";

pub const CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES: usize = 1184;
pub const CRYPTO_KEM_MLKEM768_SECRETKEYBYTES: usize = 2400;
pub const CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES: usize = 1088;
pub const CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES: usize = 32;
pub const CRYPTO_KEM_MLKEM768_SEEDBYTES: usize = 64;
/// Length of the `crypto_kem_mlkem768_enc_deterministic` seed (the ML-KEM
/// message `m`). libsodium has no named constant for it.
pub const CRYPTO_KEM_MLKEM768_ENCSEEDBYTES: usize = 32;

pub const CRYPTO_KEM_XWING_PUBLICKEYBYTES: usize = 1216;
pub const CRYPTO_KEM_XWING_SECRETKEYBYTES: usize = 32;
pub const CRYPTO_KEM_XWING_CIPHERTEXTBYTES: usize = 1120;
pub const CRYPTO_KEM_XWING_SHAREDSECRETBYTES: usize = 32;
pub const CRYPTO_KEM_XWING_SEEDBYTES: usize = 32;
/// Length of the `crypto_kem_xwing_enc_deterministic` seed. libsodium has no
/// named constant for it.
pub const CRYPTO_KEM_XWING_ENCSEEDBYTES: usize = 64;

pub const CRYPTO_KEM_PUBLICKEYBYTES: usize = CRYPTO_KEM_XWING_PUBLICKEYBYTES;
pub const CRYPTO_KEM_SECRETKEYBYTES: usize = CRYPTO_KEM_XWING_SECRETKEYBYTES;
pub const CRYPTO_KEM_CIPHERTEXTBYTES: usize = CRYPTO_KEM_XWING_CIPHERTEXTBYTES;
pub const CRYPTO_KEM_SHAREDSECRETBYTES: usize = CRYPTO_KEM_XWING_SHAREDSECRETBYTES;
pub const CRYPTO_KEM_SEEDBYTES: usize = CRYPTO_KEM_XWING_SEEDBYTES;
pub const CRYPTO_KEM_PRIMITIVE: &str = "xwing";

pub const CRYPTO_XOF_SHAKE128_BLOCKBYTES: usize = 168;
pub const CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD: u8 = 0x1f;
pub const CRYPTO_XOF_SHAKE256_BLOCKBYTES: usize = 136;
pub const CRYPTO_XOF_SHAKE256_DOMAIN_STANDARD: u8 = 0x1f;
pub const CRYPTO_XOF_TURBOSHAKE128_BLOCKBYTES: usize = 168;
pub const CRYPTO_XOF_TURBOSHAKE128_DOMAIN_STANDARD: u8 = 0x1f;
pub const CRYPTO_XOF_TURBOSHAKE256_BLOCKBYTES: usize = 136;
pub const CRYPTO_XOF_TURBOSHAKE256_DOMAIN_STANDARD: u8 = 0x1f;

pub const CRYPTO_KDF_BLAKE2B_KEYBYTES: usize = 32;
pub const CRYPTO_KDF_BLAKE2B_CONTEXTBYTES: usize = 8;
pub const CRYPTO_KDF_BLAKE2B_BYTES_MIN: usize = 16;
pub const CRYPTO_KDF_BLAKE2B_BYTES_MAX: usize = 64;

pub const CRYPTO_KDF_HKDF_SHA256_KEYBYTES: usize = CRYPTO_AUTH_HMACSHA256_BYTES;
pub const CRYPTO_KDF_HKDF_SHA256_BYTES_MIN: usize = 0;
pub const CRYPTO_KDF_HKDF_SHA256_BYTES_MAX: usize = 255 * CRYPTO_AUTH_HMACSHA256_BYTES;
pub const CRYPTO_KDF_HKDF_SHA512_KEYBYTES: usize = CRYPTO_AUTH_HMACSHA512_BYTES;
pub const CRYPTO_KDF_HKDF_SHA512_BYTES_MIN: usize = 0;
pub const CRYPTO_KDF_HKDF_SHA512_BYTES_MAX: usize = 255 * CRYPTO_AUTH_HMACSHA512_BYTES;

pub const CRYPTO_KDF_KEYBYTES: usize = CRYPTO_KDF_BLAKE2B_KEYBYTES;
pub const CRYPTO_KDF_CONTEXTBYTES: usize = CRYPTO_KDF_BLAKE2B_CONTEXTBYTES;

pub const CRYPTO_KX_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_KX_SECRETKEYBYTES: usize = 32;
pub const CRYPTO_KX_SEEDBYTES: usize = 32;
pub const CRYPTO_KX_SESSIONKEYBYTES: usize = 32;

pub const CRYPTO_SIGN_ED25519_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_SIGN_ED25519_SECRETKEYBYTES: usize = 32 + 32;
pub const CRYPTO_SIGN_ED25519_BYTES: usize = 64;
pub const CRYPTO_SIGN_ED25519_SEEDBYTES: usize = 32;
pub const CRYPTO_SIGN_ED25519_MESSAGEBYTES_MAX: usize = SODIUM_SIZE_MAX - CRYPTO_SIGN_ED25519_BYTES;
pub const CRYPTO_CORE_ED25519_BYTES: usize = 32;

pub const CRYPTO_SIGN_BYTES: usize = CRYPTO_SIGN_ED25519_BYTES;
pub const CRYPTO_SIGN_SEEDBYTES: usize = CRYPTO_SIGN_ED25519_SEEDBYTES;
pub const CRYPTO_SIGN_PUBLICKEYBYTES: usize = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES;
pub const CRYPTO_SIGN_SECRETKEYBYTES: usize = CRYPTO_SIGN_ED25519_SECRETKEYBYTES;
pub const CRYPTO_SIGN_MESSAGEBYTES_MAX: usize = CRYPTO_SIGN_ED25519_MESSAGEBYTES_MAX;

pub const CRYPTO_SHORTHASH_SIPHASH24_BYTES: usize = 8;
pub const CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES: usize = 16;

pub const CRYPTO_SHORTHASH_BYTES: usize = CRYPTO_SHORTHASH_SIPHASH24_BYTES;
pub const CRYPTO_SHORTHASH_KEYBYTES: usize = CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES;

pub const CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13: usize = 1;
pub const CRYPTO_PWHASH_ARGON2I_BYTES_MAX: usize = min(SODIUM_SIZE_MAX, 4294967295);
pub const CRYPTO_PWHASH_ARGON2I_BYTES_MIN: usize = 16;
pub const CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE: usize = 33554432;
pub const CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MAX: usize = max(
    min_usize_u64(SODIUM_SIZE_MAX, 4398046510080),
    max(
        min(SODIUM_SIZE_MAX, 2147483648),
        min(SODIUM_SIZE_MAX, 32768),
    ),
);
pub const CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN: usize = 8192;
pub const CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MODERATE: usize = 134217728;
pub const CRYPTO_PWHASH_ARGON2I_MEMLIMIT_SENSITIVE: usize = 536870912;
pub const CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE: u64 = 4;
pub const CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MAX: u64 = 4294967295;
pub const CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN: u64 = 3;
pub const CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MODERATE: u64 = 6;
pub const CRYPTO_PWHASH_ARGON2I_OPSLIMIT_SENSITIVE: u64 = 8;
pub const CRYPTO_PWHASH_ARGON2I_PASSWD_MAX: usize = 4294967295;
pub const CRYPTO_PWHASH_ARGON2I_PASSWD_MIN: usize = 0;
pub const CRYPTO_PWHASH_ARGON2I_SALTBYTES_MAX: usize = 0xFFFFFFFF;
pub const CRYPTO_PWHASH_ARGON2I_SALTBYTES_MIN: usize = 8;
pub const CRYPTO_PWHASH_ARGON2I_SALTBYTES: usize = 16;
pub const CRYPTO_PWHASH_ARGON2I_STRBYTES: usize = 128;
pub const CRYPTO_PWHASH_ARGON2I_STRPREFIX: &str = "$argon2i$";

pub const CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13: usize = 2;
pub const CRYPTO_PWHASH_ARGON2ID_BYTES_MAX: usize = min(SODIUM_SIZE_MAX, 4294967295);
pub const CRYPTO_PWHASH_ARGON2ID_BYTES_MIN: usize = 16;
pub const CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE: usize = 67108864;
pub const CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN: usize = 8192;
pub const CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX: usize = max(
    min_usize_u64(SODIUM_SIZE_MAX, 4398046510080),
    max(
        min(SODIUM_SIZE_MAX, 2147483648),
        min(SODIUM_SIZE_MAX, 32768),
    ),
);
pub const CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE: usize = 268435456;
pub const CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE: usize = 1073741824;
pub const CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE: u64 = 2;
pub const CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX: u64 = 4294967295;
pub const CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN: u64 = 1;
pub const CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE: u64 = 3;
pub const CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE: u64 = 4;
pub const CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX: usize = 4294967295;
pub const CRYPTO_PWHASH_ARGON2ID_PASSWD_MIN: usize = 0;
pub const CRYPTO_PWHASH_ARGON2ID_SALTBYTES_MAX: usize = 0xFFFFFFFF;
pub const CRYPTO_PWHASH_ARGON2ID_SALTBYTES_MIN: usize = 8;
pub const CRYPTO_PWHASH_ARGON2ID_SALTBYTES: usize = 16;
pub const CRYPTO_PWHASH_ARGON2ID_STRBYTES: usize = 128;
pub const CRYPTO_PWHASH_ARGON2ID_STRPREFIX: &str = "$argon2id$";

pub const CRYPTO_PWHASH_ALG_ARGON2I13: usize = CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13;
pub const CRYPTO_PWHASH_ALG_ARGON2ID13: usize = CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13;
pub const CRYPTO_PWHASH_ALG_DEFAULT: usize = CRYPTO_PWHASH_ALG_ARGON2ID13;
pub const CRYPTO_PWHASH_BYTES_MAX: usize = CRYPTO_PWHASH_ARGON2ID_BYTES_MAX;
pub const CRYPTO_PWHASH_BYTES_MIN: usize = CRYPTO_PWHASH_ARGON2ID_BYTES_MIN;
pub const CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE: usize = CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE;
pub const CRYPTO_PWHASH_MEMLIMIT_MAX: usize = CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX;
pub const CRYPTO_PWHASH_MEMLIMIT_MIN: usize = CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN;
pub const CRYPTO_PWHASH_MEMLIMIT_MODERATE: usize = CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE;
pub const CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: usize = CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE;
pub const CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE: u64 = CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE;
pub const CRYPTO_PWHASH_OPSLIMIT_MAX: u64 = CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX;
pub const CRYPTO_PWHASH_OPSLIMIT_MIN: u64 = CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN;
pub const CRYPTO_PWHASH_OPSLIMIT_MODERATE: u64 = CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE;
pub const CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: u64 = CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE;
pub const CRYPTO_PWHASH_PASSWD_MAX: usize = CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX;
pub const CRYPTO_PWHASH_PASSWD_MIN: usize = CRYPTO_PWHASH_ARGON2ID_PASSWD_MIN;
pub const CRYPTO_PWHASH_SALTBYTES_MAX: usize = CRYPTO_PWHASH_ARGON2ID_SALTBYTES_MAX;
pub const CRYPTO_PWHASH_SALTBYTES_MIN: usize = CRYPTO_PWHASH_ARGON2ID_SALTBYTES_MIN;
pub const CRYPTO_PWHASH_SALTBYTES: usize = CRYPTO_PWHASH_ARGON2ID_SALTBYTES;
pub const CRYPTO_PWHASH_STRBYTES: usize = CRYPTO_PWHASH_ARGON2ID_STRBYTES;
pub const CRYPTO_PWHASH_STRPREFIX: &str = CRYPTO_PWHASH_ARGON2ID_STRPREFIX;

#[cfg(test)]
mod tests {
    /// Every constant mirrored from libsodium equals the value reported by
    /// the corresponding `libsodium_sys` getter. Constants without a getter
    /// (`*_INONCEBYTES`, `*_COUNTERBYTES`, `*_PADBYTES`, the HKDF sizes,
    /// `*_SALTBYTES_MIN/MAX`, the KEM `*_ENCSEEDBYTES`) are defined only by
    /// this crate.
    #[cfg(dryoc_native_tests)]
    #[test]
    fn test_libsodium_constants() {
        use std::ffi::CStr;

        use libsodium_sys::*;

        use super::*;

        crate::native_test_util::init();

        // SAFETY: These parameter-free libsodium functions only return
        // compile-time constants.
        macro_rules! check_numeric {
            ($($ours:ident == $theirs:ident),* $(,)?) => {$(
                assert_eq!($ours as u64, unsafe { $theirs() } as u64, stringify!($ours));
            )*};
        }

        // SAFETY: These parameter-free libsodium functions return pointers to
        // static NUL-terminated strings.
        macro_rules! check_str {
            ($($ours:ident == $theirs:ident),* $(,)?) => {$(
                let theirs = unsafe { CStr::from_ptr($theirs()) };
                assert_eq!($ours.as_bytes(), theirs.to_bytes(), stringify!($ours));
            )*};
        }

        check_numeric!(
            CRYPTO_SCALARMULT_CURVE25519_BYTES == crypto_scalarmult_curve25519_bytes,
            CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES == crypto_scalarmult_curve25519_scalarbytes,
            CRYPTO_SCALARMULT_BYTES == crypto_scalarmult_bytes,
            CRYPTO_SCALARMULT_SCALARBYTES == crypto_scalarmult_scalarbytes,
            CRYPTO_BOX_PUBLICKEYBYTES == crypto_box_publickeybytes,
            CRYPTO_BOX_SECRETKEYBYTES == crypto_box_secretkeybytes,
            CRYPTO_BOX_MACBYTES == crypto_box_macbytes,
            CRYPTO_BOX_NONCEBYTES == crypto_box_noncebytes,
            CRYPTO_BOX_SEEDBYTES == crypto_box_seedbytes,
            CRYPTO_BOX_BEFORENMBYTES == crypto_box_beforenmbytes,
            CRYPTO_BOX_SEALBYTES == crypto_box_sealbytes,
            CRYPTO_BOX_MESSAGEBYTES_MAX == crypto_box_messagebytes_max,
            CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES
                == crypto_secretbox_xsalsa20poly1305_keybytes,
            CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES
                == crypto_secretbox_xsalsa20poly1305_noncebytes,
            CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES
                == crypto_secretbox_xsalsa20poly1305_macbytes,
            CRYPTO_SECRETBOX_XSALSA20POLY1305_MESSAGEBYTES_MAX
                == crypto_secretbox_xsalsa20poly1305_messagebytes_max,
            CRYPTO_SECRETBOX_KEYBYTES == crypto_secretbox_keybytes,
            CRYPTO_SECRETBOX_NONCEBYTES == crypto_secretbox_noncebytes,
            CRYPTO_SECRETBOX_MACBYTES == crypto_secretbox_macbytes,
            CRYPTO_SECRETBOX_MESSAGEBYTES_MAX == crypto_secretbox_messagebytes_max,
            CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES
                == crypto_aead_chacha20poly1305_ietf_keybytes,
            CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES
                == crypto_aead_chacha20poly1305_ietf_nsecbytes,
            CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
                == crypto_aead_chacha20poly1305_ietf_npubbytes,
            CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES == crypto_aead_chacha20poly1305_ietf_abytes,
            CRYPTO_AEAD_CHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
                == crypto_aead_chacha20poly1305_ietf_messagebytes_max,
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
                == crypto_aead_xchacha20poly1305_ietf_keybytes,
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES
                == crypto_aead_xchacha20poly1305_ietf_nsecbytes,
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
                == crypto_aead_xchacha20poly1305_ietf_npubbytes,
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES == crypto_aead_xchacha20poly1305_ietf_abytes,
            CRYPTO_AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX
                == crypto_aead_xchacha20poly1305_ietf_messagebytes_max,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES
                == crypto_secretstream_xchacha20poly1305_keybytes,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
                == crypto_secretstream_xchacha20poly1305_headerbytes,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES
                == crypto_secretstream_xchacha20poly1305_abytes,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX
                == crypto_secretstream_xchacha20poly1305_messagebytes_max,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE
                == crypto_secretstream_xchacha20poly1305_tag_message,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH
                == crypto_secretstream_xchacha20poly1305_tag_push,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
                == crypto_secretstream_xchacha20poly1305_tag_rekey,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                == crypto_secretstream_xchacha20poly1305_tag_final,
            CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES == crypto_stream_chacha20_ietf_keybytes,
            CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES == crypto_stream_chacha20_ietf_noncebytes,
            CRYPTO_CORE_HCHACHA20_INPUTBYTES == crypto_core_hchacha20_inputbytes,
            CRYPTO_CORE_HCHACHA20_OUTPUTBYTES == crypto_core_hchacha20_outputbytes,
            CRYPTO_CORE_HCHACHA20_KEYBYTES == crypto_core_hchacha20_keybytes,
            CRYPTO_CORE_HSALSA20_OUTPUTBYTES == crypto_core_hsalsa20_outputbytes,
            CRYPTO_CORE_HSALSA20_INPUTBYTES == crypto_core_hsalsa20_inputbytes,
            CRYPTO_CORE_HSALSA20_KEYBYTES == crypto_core_hsalsa20_keybytes,
            CRYPTO_CORE_HSALSA20_CONSTBYTES == crypto_core_hsalsa20_constbytes,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN == crypto_generichash_blake2b_bytes_min,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX == crypto_generichash_blake2b_bytes_max,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES == crypto_generichash_blake2b_bytes,
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN == crypto_generichash_blake2b_keybytes_min,
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX == crypto_generichash_blake2b_keybytes_max,
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES == crypto_generichash_blake2b_keybytes,
            CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES == crypto_generichash_blake2b_saltbytes,
            CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES == crypto_generichash_blake2b_personalbytes,
            CRYPTO_GENERICHASH_BYTES == crypto_generichash_bytes,
            CRYPTO_GENERICHASH_KEYBYTES == crypto_generichash_keybytes,
            CRYPTO_GENERICHASH_BYTES_MIN == crypto_generichash_bytes_min,
            CRYPTO_GENERICHASH_BYTES_MAX == crypto_generichash_bytes_max,
            CRYPTO_GENERICHASH_KEYBYTES_MIN == crypto_generichash_keybytes_min,
            CRYPTO_GENERICHASH_KEYBYTES_MAX == crypto_generichash_keybytes_max,
            CRYPTO_ONETIMEAUTH_POLY1305_BYTES == crypto_onetimeauth_poly1305_bytes,
            CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES == crypto_onetimeauth_poly1305_keybytes,
            CRYPTO_ONETIMEAUTH_BYTES == crypto_onetimeauth_bytes,
            CRYPTO_ONETIMEAUTH_KEYBYTES == crypto_onetimeauth_keybytes,
            CRYPTO_AUTH_HMACSHA512256_BYTES == crypto_auth_hmacsha512256_bytes,
            CRYPTO_AUTH_HMACSHA512256_KEYBYTES == crypto_auth_hmacsha512256_keybytes,
            CRYPTO_AUTH_HMACSHA256_BYTES == crypto_auth_hmacsha256_bytes,
            CRYPTO_AUTH_HMACSHA256_KEYBYTES == crypto_auth_hmacsha256_keybytes,
            CRYPTO_AUTH_HMACSHA512_BYTES == crypto_auth_hmacsha512_bytes,
            CRYPTO_AUTH_HMACSHA512_KEYBYTES == crypto_auth_hmacsha512_keybytes,
            CRYPTO_AUTH_BYTES == crypto_auth_bytes,
            CRYPTO_AUTH_KEYBYTES == crypto_auth_keybytes,
            CRYPTO_HASH_SHA256_BYTES == crypto_hash_sha256_bytes,
            CRYPTO_HASH_SHA512_BYTES == crypto_hash_sha512_bytes,
            CRYPTO_HASH_BYTES == crypto_hash_bytes,
            CRYPTO_KDF_BLAKE2B_KEYBYTES == crypto_kdf_blake2b_keybytes,
            CRYPTO_KDF_BLAKE2B_CONTEXTBYTES == crypto_kdf_blake2b_contextbytes,
            CRYPTO_KDF_BLAKE2B_BYTES_MIN == crypto_kdf_blake2b_bytes_min,
            CRYPTO_KDF_BLAKE2B_BYTES_MAX == crypto_kdf_blake2b_bytes_max,
            CRYPTO_KDF_KEYBYTES == crypto_kdf_keybytes,
            CRYPTO_KDF_CONTEXTBYTES == crypto_kdf_contextbytes,
            CRYPTO_KX_PUBLICKEYBYTES == crypto_kx_publickeybytes,
            CRYPTO_KX_SECRETKEYBYTES == crypto_kx_secretkeybytes,
            CRYPTO_KX_SEEDBYTES == crypto_kx_seedbytes,
            CRYPTO_KX_SESSIONKEYBYTES == crypto_kx_sessionkeybytes,
            CRYPTO_SIGN_ED25519_PUBLICKEYBYTES == crypto_sign_ed25519_publickeybytes,
            CRYPTO_SIGN_ED25519_SECRETKEYBYTES == crypto_sign_ed25519_secretkeybytes,
            CRYPTO_SIGN_ED25519_BYTES == crypto_sign_ed25519_bytes,
            CRYPTO_SIGN_ED25519_SEEDBYTES == crypto_sign_ed25519_seedbytes,
            CRYPTO_SIGN_ED25519_MESSAGEBYTES_MAX == crypto_sign_ed25519_messagebytes_max,
            CRYPTO_CORE_ED25519_BYTES == crypto_core_ed25519_bytes,
            CRYPTO_SIGN_BYTES == crypto_sign_bytes,
            CRYPTO_SIGN_SEEDBYTES == crypto_sign_seedbytes,
            CRYPTO_SIGN_PUBLICKEYBYTES == crypto_sign_publickeybytes,
            CRYPTO_SIGN_SECRETKEYBYTES == crypto_sign_secretkeybytes,
            CRYPTO_SIGN_MESSAGEBYTES_MAX == crypto_sign_messagebytes_max,
            CRYPTO_SHORTHASH_SIPHASH24_BYTES == crypto_shorthash_siphash24_bytes,
            CRYPTO_SHORTHASH_SIPHASH24_KEYBYTES == crypto_shorthash_siphash24_keybytes,
            CRYPTO_SHORTHASH_BYTES == crypto_shorthash_bytes,
            CRYPTO_SHORTHASH_KEYBYTES == crypto_shorthash_keybytes,
            CRYPTO_PWHASH_ARGON2I_ALG_ARGON2I13 == crypto_pwhash_argon2i_alg_argon2i13,
            CRYPTO_PWHASH_ARGON2I_BYTES_MAX == crypto_pwhash_argon2i_bytes_max,
            CRYPTO_PWHASH_ARGON2I_BYTES_MIN == crypto_pwhash_argon2i_bytes_min,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_INTERACTIVE
                == crypto_pwhash_argon2i_memlimit_interactive,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MAX == crypto_pwhash_argon2i_memlimit_max,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MIN == crypto_pwhash_argon2i_memlimit_min,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_MODERATE == crypto_pwhash_argon2i_memlimit_moderate,
            CRYPTO_PWHASH_ARGON2I_MEMLIMIT_SENSITIVE == crypto_pwhash_argon2i_memlimit_sensitive,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_INTERACTIVE
                == crypto_pwhash_argon2i_opslimit_interactive,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MAX == crypto_pwhash_argon2i_opslimit_max,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MIN == crypto_pwhash_argon2i_opslimit_min,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_MODERATE == crypto_pwhash_argon2i_opslimit_moderate,
            CRYPTO_PWHASH_ARGON2I_OPSLIMIT_SENSITIVE == crypto_pwhash_argon2i_opslimit_sensitive,
            CRYPTO_PWHASH_ARGON2I_PASSWD_MAX == crypto_pwhash_argon2i_passwd_max,
            CRYPTO_PWHASH_ARGON2I_PASSWD_MIN == crypto_pwhash_argon2i_passwd_min,
            CRYPTO_PWHASH_ARGON2I_SALTBYTES == crypto_pwhash_argon2i_saltbytes,
            CRYPTO_PWHASH_ARGON2I_STRBYTES == crypto_pwhash_argon2i_strbytes,
            CRYPTO_PWHASH_ARGON2ID_ALG_ARGON2ID13 == crypto_pwhash_argon2id_alg_argon2id13,
            CRYPTO_PWHASH_ARGON2ID_BYTES_MAX == crypto_pwhash_argon2id_bytes_max,
            CRYPTO_PWHASH_ARGON2ID_BYTES_MIN == crypto_pwhash_argon2id_bytes_min,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE
                == crypto_pwhash_argon2id_memlimit_interactive,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MIN == crypto_pwhash_argon2id_memlimit_min,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MAX == crypto_pwhash_argon2id_memlimit_max,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_MODERATE == crypto_pwhash_argon2id_memlimit_moderate,
            CRYPTO_PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE == crypto_pwhash_argon2id_memlimit_sensitive,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE
                == crypto_pwhash_argon2id_opslimit_interactive,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MAX == crypto_pwhash_argon2id_opslimit_max,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MIN == crypto_pwhash_argon2id_opslimit_min,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_MODERATE == crypto_pwhash_argon2id_opslimit_moderate,
            CRYPTO_PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE == crypto_pwhash_argon2id_opslimit_sensitive,
            CRYPTO_PWHASH_ARGON2ID_PASSWD_MAX == crypto_pwhash_argon2id_passwd_max,
            CRYPTO_PWHASH_ARGON2ID_PASSWD_MIN == crypto_pwhash_argon2id_passwd_min,
            CRYPTO_PWHASH_ARGON2ID_SALTBYTES == crypto_pwhash_argon2id_saltbytes,
            CRYPTO_PWHASH_ARGON2ID_STRBYTES == crypto_pwhash_argon2id_strbytes,
            CRYPTO_PWHASH_ALG_ARGON2I13 == crypto_pwhash_alg_argon2i13,
            CRYPTO_PWHASH_ALG_ARGON2ID13 == crypto_pwhash_alg_argon2id13,
            CRYPTO_PWHASH_ALG_DEFAULT == crypto_pwhash_alg_default,
            CRYPTO_PWHASH_BYTES_MAX == crypto_pwhash_bytes_max,
            CRYPTO_PWHASH_BYTES_MIN == crypto_pwhash_bytes_min,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE == crypto_pwhash_memlimit_interactive,
            CRYPTO_PWHASH_MEMLIMIT_MAX == crypto_pwhash_memlimit_max,
            CRYPTO_PWHASH_MEMLIMIT_MIN == crypto_pwhash_memlimit_min,
            CRYPTO_PWHASH_MEMLIMIT_MODERATE == crypto_pwhash_memlimit_moderate,
            CRYPTO_PWHASH_MEMLIMIT_SENSITIVE == crypto_pwhash_memlimit_sensitive,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE == crypto_pwhash_opslimit_interactive,
            CRYPTO_PWHASH_OPSLIMIT_MAX == crypto_pwhash_opslimit_max,
            CRYPTO_PWHASH_OPSLIMIT_MIN == crypto_pwhash_opslimit_min,
            CRYPTO_PWHASH_OPSLIMIT_MODERATE == crypto_pwhash_opslimit_moderate,
            CRYPTO_PWHASH_OPSLIMIT_SENSITIVE == crypto_pwhash_opslimit_sensitive,
            CRYPTO_PWHASH_PASSWD_MAX == crypto_pwhash_passwd_max,
            CRYPTO_PWHASH_PASSWD_MIN == crypto_pwhash_passwd_min,
            CRYPTO_PWHASH_SALTBYTES == crypto_pwhash_saltbytes,
            CRYPTO_PWHASH_STRBYTES == crypto_pwhash_strbytes,
            CRYPTO_HASH_SHA3256_BYTES == crypto_hash_sha3256_bytes,
            CRYPTO_HASH_SHA3512_BYTES == crypto_hash_sha3512_bytes,
            CRYPTO_XOF_SHAKE128_BLOCKBYTES == crypto_xof_shake128_blockbytes,
            CRYPTO_XOF_SHAKE128_DOMAIN_STANDARD == crypto_xof_shake128_domain_standard,
            CRYPTO_XOF_SHAKE256_BLOCKBYTES == crypto_xof_shake256_blockbytes,
            CRYPTO_XOF_SHAKE256_DOMAIN_STANDARD == crypto_xof_shake256_domain_standard,
            CRYPTO_XOF_TURBOSHAKE128_BLOCKBYTES == crypto_xof_turboshake128_blockbytes,
            CRYPTO_XOF_TURBOSHAKE128_DOMAIN_STANDARD == crypto_xof_turboshake128_domain_standard,
            CRYPTO_XOF_TURBOSHAKE256_BLOCKBYTES == crypto_xof_turboshake256_blockbytes,
            CRYPTO_XOF_TURBOSHAKE256_DOMAIN_STANDARD == crypto_xof_turboshake256_domain_standard,
            CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES == crypto_kem_mlkem768_publickeybytes,
            CRYPTO_KEM_MLKEM768_SECRETKEYBYTES == crypto_kem_mlkem768_secretkeybytes,
            CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES == crypto_kem_mlkem768_ciphertextbytes,
            CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES == crypto_kem_mlkem768_sharedsecretbytes,
            CRYPTO_KEM_MLKEM768_SEEDBYTES == crypto_kem_mlkem768_seedbytes,
            CRYPTO_KEM_XWING_PUBLICKEYBYTES == crypto_kem_xwing_publickeybytes,
            CRYPTO_KEM_XWING_SECRETKEYBYTES == crypto_kem_xwing_secretkeybytes,
            CRYPTO_KEM_XWING_CIPHERTEXTBYTES == crypto_kem_xwing_ciphertextbytes,
            CRYPTO_KEM_XWING_SHAREDSECRETBYTES == crypto_kem_xwing_sharedsecretbytes,
            CRYPTO_KEM_XWING_SEEDBYTES == crypto_kem_xwing_seedbytes,
            CRYPTO_KEM_PUBLICKEYBYTES == crypto_kem_publickeybytes,
            CRYPTO_KEM_SECRETKEYBYTES == crypto_kem_secretkeybytes,
            CRYPTO_KEM_CIPHERTEXTBYTES == crypto_kem_ciphertextbytes,
            CRYPTO_KEM_SHAREDSECRETBYTES == crypto_kem_sharedsecretbytes,
            CRYPTO_KEM_SEEDBYTES == crypto_kem_seedbytes,
        );

        check_str!(
            CRYPTO_SECRETBOX_PRIMITIVE == crypto_secretbox_primitive,
            CRYPTO_HASH_PRIMITIVE == crypto_hash_primitive,
            CRYPTO_PWHASH_ARGON2I_STRPREFIX == crypto_pwhash_argon2i_strprefix,
            CRYPTO_PWHASH_ARGON2ID_STRPREFIX == crypto_pwhash_argon2id_strprefix,
            CRYPTO_PWHASH_STRPREFIX == crypto_pwhash_strprefix,
            CRYPTO_KEM_PRIMITIVE == crypto_kem_primitive,
        );
    }
}

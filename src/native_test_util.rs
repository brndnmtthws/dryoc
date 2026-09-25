//! Safe wrappers over the libsodium calls that the native compatibility tests
//! compare dryoc against.
//!
//! Each wrapper takes byte slices, checks that every fixed-size argument has
//! libsodium's length before passing its pointer, and returns owned output.
//! Calls that cannot fail for valid inputs (sealing, signing, hashing, key
//! derivation) assert that libsodium reports success; calls that
//! authenticate their input return `Err(())` or `false` on rejection so tests
//! can assert it.

use libc::c_ulonglong;
use libsodium_sys as ffi;

use crate::test_prelude::*;

/// Views `bytes` as an array of exactly `N` bytes, panicking otherwise.
fn fixed<const N: usize>(bytes: &[u8]) -> &[u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

/// Pointer and length for optional associated data; `None` is null and 0.
fn ad_parts(ad: Option<&[u8]>) -> (*const u8, c_ulonglong) {
    ad.map_or((std::ptr::null(), 0), |ad| {
        (ad.as_ptr(), ad.len() as c_ulonglong)
    })
}

/// Maps a libsodium return code to `Ok(value)` on success.
fn checked<T>(rc: libc::c_int, value: T) -> Result<T, ()> {
    if rc == 0 { Ok(value) } else { Err(()) }
}

/// libsodium state types that are plain `#[repr(C)]` structs of byte and
/// integer arrays, so all-zero bytes are a valid value.
trait PlainState: Copy {}

impl PlainState for ffi::crypto_hash_sha512_state {}
impl PlainState for ffi::crypto_hash_sha3256_state {}
impl PlainState for ffi::crypto_hash_sha3512_state {}
impl PlainState for ffi::crypto_xof_shake128_state {}
impl PlainState for ffi::crypto_xof_shake256_state {}
impl PlainState for ffi::crypto_xof_turboshake128_state {}
impl PlainState for ffi::crypto_xof_turboshake256_state {}
impl PlainState for ffi::crypto_sign_ed25519ph_state {}
impl PlainState for ffi::crypto_secretstream_xchacha20poly1305_state {}
impl PlainState for ffi::crypto_generichash_state {}

/// A zero-filled state for a libsodium `init` function to set up. The
/// `init` functions write only the part of the opaque storage they use, so
/// the state starts fully initialized instead of uninitialized.
fn zeroed_state<T: PlainState>() -> T {
    // SAFETY: `PlainState` types are structs of byte and integer arrays, for
    // which all-zero bytes are a valid value.
    unsafe { std::mem::zeroed() }
}

/// Runs `sodium_init` once per process; every call returns after it has
/// completed. libsodium lazily sets up its random number generator and, in
/// `sodium_init`, writes the global pointers that select its
/// runtime-dispatched implementations, all without synchronizing with
/// threads that did not call it. Parallel tests therefore race unless each
/// one passes through this [`Once`](std::sync::Once) before calling into
/// libsodium: every wrapper here calls it, and so must any test that calls
/// `libsodium_sys` directly.
pub(crate) fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: `sodium_init` takes no arguments.
        assert!(unsafe { ffi::sodium_init() } >= 0, "sodium_init failed");
    });
}

const BOX_MACBYTES: usize = ffi::crypto_box_MACBYTES as usize;
const BOX_SEALBYTES: usize = ffi::crypto_box_SEALBYTES as usize;

/// `crypto_box_curve25519xsalsa20poly1305_seed_keypair`.
#[cfg(feature = "alloc")]
pub(crate) fn box_seed_keypair(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    init();
    let seed = fixed::<32>(seed);
    let (mut pk, mut sk) = ([0u8; 32], [0u8; 32]);
    // SAFETY: `pk` and `sk` are writable 32-byte arrays and `seed` is 32
    // bytes, the sizes libsodium requires.
    let rc = unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_seed_keypair(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    (pk, sk)
}

/// `crypto_box_easy`: the MAC followed by the ciphertext.
pub(crate) fn box_easy(message: &[u8], nonce: &[u8], pk: &[u8], sk: &[u8]) -> Vec<u8> {
    init();
    let (nonce, pk, sk) = (fixed::<24>(nonce), fixed::<32>(pk), fixed::<32>(sk));
    let mut ciphertext = vec![0u8; message.len() + BOX_MACBYTES];
    // SAFETY: `ciphertext` has room for the message plus the MAC, and the
    // nonce and keys are arrays of libsodium's sizes.
    let rc = unsafe {
        ffi::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            nonce.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    ciphertext
}

/// `crypto_box_open_easy`.
pub(crate) fn box_open_easy(
    ciphertext: &[u8],
    nonce: &[u8],
    pk: &[u8],
    sk: &[u8],
) -> Result<Vec<u8>, ()> {
    init();
    let (nonce, pk, sk) = (fixed::<24>(nonce), fixed::<32>(pk), fixed::<32>(sk));
    let len = ciphertext.len().checked_sub(BOX_MACBYTES).ok_or(())?;
    let mut message = vec![0u8; len];
    // SAFETY: `ciphertext` is at least a MAC long and `message` has room for
    // the rest; the nonce and keys are arrays of libsodium's sizes.
    let rc = unsafe {
        ffi::crypto_box_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            nonce.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };
    checked(rc, message)
}

/// `crypto_box_curve25519xsalsa20poly1305_beforenm`.
#[cfg(feature = "alloc")]
pub(crate) fn box_beforenm(pk: &[u8], sk: &[u8]) -> [u8; 32] {
    init();
    let (pk, sk) = (fixed::<32>(pk), fixed::<32>(sk));
    let mut key = [0u8; 32];
    // SAFETY: `key` is a writable 32-byte array and both keys are 32 bytes.
    let rc = unsafe {
        ffi::crypto_box_curve25519xsalsa20poly1305_beforenm(
            key.as_mut_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    key
}

/// `crypto_box_easy_afternm`.
#[cfg(feature = "alloc")]
pub(crate) fn box_easy_afternm(message: &[u8], nonce: &[u8], key: &[u8]) -> Vec<u8> {
    init();
    let (nonce, key) = (fixed::<24>(nonce), fixed::<32>(key));
    let mut ciphertext = vec![0u8; message.len() + BOX_MACBYTES];
    // SAFETY: as in `box_easy`, with the precomputed key in place of the
    // key pair.
    let rc = unsafe {
        ffi::crypto_box_easy_afternm(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    ciphertext
}

/// `crypto_box_open_easy_afternm`.
#[cfg(feature = "alloc")]
pub(crate) fn box_open_easy_afternm(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, ()> {
    init();
    let (nonce, key) = (fixed::<24>(nonce), fixed::<32>(key));
    let len = ciphertext.len().checked_sub(BOX_MACBYTES).ok_or(())?;
    let mut message = vec![0u8; len];
    // SAFETY: as in `box_open_easy`, with the precomputed key in place of
    // the key pair.
    let rc = unsafe {
        ffi::crypto_box_open_easy_afternm(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    checked(rc, message)
}

/// `crypto_box_seal`.
pub(crate) fn box_seal(message: &[u8], pk: &[u8]) -> Vec<u8> {
    init();
    let pk = fixed::<32>(pk);
    let mut ciphertext = vec![0u8; message.len() + BOX_SEALBYTES];
    // SAFETY: `ciphertext` has room for the message plus the ephemeral key
    // and MAC, and `pk` is 32 bytes.
    let rc = unsafe {
        ffi::crypto_box_seal(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            pk.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    ciphertext
}

/// `crypto_box_seal_open`.
pub(crate) fn box_seal_open(ciphertext: &[u8], pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, ()> {
    init();
    let (pk, sk) = (fixed::<32>(pk), fixed::<32>(sk));
    let len = ciphertext.len().checked_sub(BOX_SEALBYTES).ok_or(())?;
    let mut message = vec![0u8; len];
    // SAFETY: `ciphertext` is at least the seal overhead long, `message` has
    // room for the rest, and both keys are 32 bytes.
    let rc = unsafe {
        ffi::crypto_box_seal_open(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            pk.as_ptr(),
            sk.as_ptr(),
        )
    };
    checked(rc, message)
}

const SECRETBOX_MACBYTES: usize = ffi::crypto_secretbox_MACBYTES as usize;

/// `crypto_secretbox_easy`: the MAC followed by the ciphertext.
pub(crate) fn secretbox_easy(message: &[u8], nonce: &[u8], key: &[u8]) -> Vec<u8> {
    init();
    let (nonce, key) = (fixed::<24>(nonce), fixed::<32>(key));
    let mut ciphertext = vec![0u8; message.len() + SECRETBOX_MACBYTES];
    // SAFETY: `ciphertext` has room for the message plus the MAC, and the
    // nonce and key are arrays of libsodium's sizes.
    let rc = unsafe {
        ffi::crypto_secretbox_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    ciphertext
}

/// `crypto_secretbox_open_easy`.
pub(crate) fn secretbox_open_easy(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, ()> {
    init();
    let (nonce, key) = (fixed::<24>(nonce), fixed::<32>(key));
    let len = ciphertext.len().checked_sub(SECRETBOX_MACBYTES).ok_or(())?;
    let mut message = vec![0u8; len];
    // SAFETY: `ciphertext` is at least a MAC long, `message` has room for the
    // rest, and the nonce and key are arrays of libsodium's sizes.
    let rc = unsafe {
        ffi::crypto_secretbox_open_easy(
            message.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    checked(rc, message)
}

/// Defines combined-mode `encrypt`/`decrypt` wrappers for one IETF
/// ChaCha20-Poly1305 AEAD construction.
macro_rules! aead_wrappers {
    ($encrypt:ident, $decrypt:ident, $nonce_bytes:literal, $abytes:ident) => {
        #[doc = concat!("`", stringify!($encrypt), "`.")]
        pub(crate) fn $encrypt(
            message: &[u8],
            ad: Option<&[u8]>,
            nonce: &[u8],
            key: &[u8],
        ) -> Vec<u8> {
            init();
            let (nonce, key) = (fixed::<$nonce_bytes>(nonce), fixed::<32>(key));
            let (ad_ptr, ad_len) = ad_parts(ad);
            let mut ciphertext = vec![0u8; message.len() + ffi::$abytes as usize];
            let mut ciphertext_len: c_ulonglong = 0;
            // SAFETY: `ciphertext` has room for the message plus the tag, the
            // associated data is null with length 0 or a live slice, `nsec` is
            // unused and null, and the nonce and key have libsodium's sizes.
            let rc = unsafe {
                ffi::$encrypt(
                    ciphertext.as_mut_ptr(),
                    &mut ciphertext_len,
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    ad_ptr,
                    ad_len,
                    std::ptr::null(),
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            };
            assert_eq!((rc, ciphertext_len as usize), (0, ciphertext.len()));
            ciphertext
        }

        #[doc = concat!("`", stringify!($decrypt), "`.")]
        pub(crate) fn $decrypt(
            ciphertext: &[u8],
            ad: Option<&[u8]>,
            nonce: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, ()> {
            init();
            let (nonce, key) = (fixed::<$nonce_bytes>(nonce), fixed::<32>(key));
            let (ad_ptr, ad_len) = ad_parts(ad);
            let len = ciphertext
                .len()
                .checked_sub(ffi::$abytes as usize)
                .ok_or(())?;
            let mut message = vec![0u8; len];
            let mut message_len: c_ulonglong = 0;
            // SAFETY: `ciphertext` is at least a tag long and `message` has
            // room for the rest; the other arguments are as in the encrypt
            // wrapper.
            let rc = unsafe {
                ffi::$decrypt(
                    message.as_mut_ptr(),
                    &mut message_len,
                    std::ptr::null_mut(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as c_ulonglong,
                    ad_ptr,
                    ad_len,
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            };
            message.truncate(message_len as usize);
            checked(rc, message)
        }
    };
}

aead_wrappers!(
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt,
    12,
    crypto_aead_chacha20poly1305_ietf_ABYTES
);
aead_wrappers!(
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    24,
    crypto_aead_xchacha20poly1305_ietf_ABYTES
);

/// Defines a one-shot MAC wrapper over a libsodium `(out, in, inlen, k)`
/// function with fixed key and tag sizes.
macro_rules! mac_wrapper {
    ($name:ident, $ffi:ident, $key_bytes:literal, $tag_bytes:literal) => {
        #[doc = concat!("`", stringify!($ffi), "`.")]
        pub(crate) fn $name(message: &[u8], key: &[u8]) -> [u8; $tag_bytes] {
            init();
            let key = fixed::<$key_bytes>(key);
            let mut tag = [0u8; $tag_bytes];
            // SAFETY: `tag` and `key` are arrays of libsodium's tag and key
            // sizes, and `message` is live for its length.
            let rc = unsafe {
                ffi::$ffi(
                    tag.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                    key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            tag
        }
    };
}

mac_wrapper!(auth_hmacsha256, crypto_auth_hmacsha256, 32, 32);
mac_wrapper!(auth_hmacsha512, crypto_auth_hmacsha512, 32, 64);
mac_wrapper!(auth_hmacsha512256, crypto_auth_hmacsha512256, 32, 32);
mac_wrapper!(onetimeauth_poly1305, crypto_onetimeauth_poly1305, 32, 16);
mac_wrapper!(shorthash_siphash24, crypto_shorthash_siphash24, 16, 8);

/// Defines a one-shot hash wrapper and a streaming state wrapper over one
/// libsodium `crypto_hash_*` function family with a `BYTES`-byte digest.
macro_rules! hash_wrappers {
    (
        $oneshot:ident,
        $state:ident($ffi_state:ident),
        $init:ident,
        $update:ident,
        $final:ident,
        $bytes:literal
    ) => {
        #[doc = concat!("`", stringify!($oneshot), "`.")]
        pub(crate) fn $oneshot(message: &[u8]) -> [u8; $bytes] {
            init();
            let mut digest = [0u8; $bytes];
            // SAFETY: `digest` is writable for the digest size and `message`
            // is live for its length.
            let rc = unsafe {
                ffi::$oneshot(
                    digest.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                )
            };
            assert_eq!(rc, 0);
            digest
        }

        #[doc = concat!("Streaming `", stringify!($oneshot), "_*` state.")]
        pub(crate) struct $state(ffi::$ffi_state);

        impl $state {
            #[doc = concat!("`", stringify!($final), "`.")]
            pub(crate) fn finalize(mut self) -> [u8; $bytes] {
                init();
                let mut digest = [0u8; $bytes];
                // SAFETY: the state was set up by `new`, and `digest` is
                // writable for the digest size.
                let rc = unsafe { ffi::$final(&mut self.0, digest.as_mut_ptr()) };
                assert_eq!(rc, 0);
                digest
            }

            #[doc = concat!("`", stringify!($init), "`.")]
            pub(crate) fn new() -> Self {
                init();
                let mut state = zeroed_state::<ffi::$ffi_state>();
                // SAFETY: `state` is a live, fully initialized state value.
                let rc = unsafe { ffi::$init(&mut state) };
                assert_eq!(rc, 0);
                Self(state)
            }

            #[doc = concat!("`", stringify!($update), "`.")]
            pub(crate) fn update(&mut self, message: &[u8]) {
                init();
                // SAFETY: the state was set up by `new`, and `message` is
                // live for its length.
                let rc = unsafe {
                    ffi::$update(&mut self.0, message.as_ptr(), message.len() as c_ulonglong)
                };
                assert_eq!(rc, 0);
            }
        }
    };
}

hash_wrappers!(
    crypto_hash_sha512,
    HashSha512State(crypto_hash_sha512_state),
    crypto_hash_sha512_init,
    crypto_hash_sha512_update,
    crypto_hash_sha512_final,
    64
);
hash_wrappers!(
    crypto_hash_sha3256,
    HashSha3256State(crypto_hash_sha3256_state),
    crypto_hash_sha3256_init,
    crypto_hash_sha3256_update,
    crypto_hash_sha3256_final,
    32
);
hash_wrappers!(
    crypto_hash_sha3512,
    HashSha3512State(crypto_hash_sha3512_state),
    crypto_hash_sha3512_init,
    crypto_hash_sha3512_update,
    crypto_hash_sha3512_final,
    64
);

/// Defines a one-shot wrapper and a streaming state wrapper over one
/// libsodium `crypto_xof_*` family.
macro_rules! xof_wrappers {
    (
        $oneshot:ident,
        $state:ident($ffi_state:ident),
        $init:ident,
        $init_with_domain:ident,
        $update:ident,
        $squeeze:ident
    ) => {
        #[doc = concat!("`", stringify!($oneshot), "`: `len` bytes of output.")]
        pub(crate) fn $oneshot(message: &[u8], len: usize) -> Vec<u8> {
            init();
            let mut output = vec![0u8; len];
            // SAFETY: `output` is writable for `len` bytes and `message` is
            // live for its length.
            let rc = unsafe {
                ffi::$oneshot(
                    output.as_mut_ptr(),
                    len,
                    message.as_ptr(),
                    message.len() as c_ulonglong,
                )
            };
            assert_eq!(rc, 0);
            output
        }

        #[doc = concat!("Streaming `", stringify!($oneshot), "_*` state.")]
        pub(crate) struct $state(ffi::$ffi_state);

        impl $state {
            #[doc = concat!("`", stringify!($init), "`.")]
            pub(crate) fn new() -> Self {
                init();
                let mut state = zeroed_state::<ffi::$ffi_state>();
                // SAFETY: `state` is a live, fully initialized state value.
                let rc = unsafe { ffi::$init(&mut state) };
                assert_eq!(rc, 0);
                Self(state)
            }

            #[doc = concat!("`", stringify!($squeeze), "`: the next `len` output bytes.")]
            pub(crate) fn squeeze(&mut self, len: usize) -> Vec<u8> {
                init();
                let mut output = vec![0u8; len];
                // SAFETY: the state is initialized and `output` is writable
                // for `len` bytes.
                let rc = unsafe { ffi::$squeeze(&mut self.0, output.as_mut_ptr(), len) };
                assert_eq!(rc, 0);
                output
            }

            #[doc = concat!("`", stringify!($update), "`.")]
            pub(crate) fn update(&mut self, message: &[u8]) {
                init();
                // SAFETY: the state is initialized and `message` is live for
                // its length.
                let rc = unsafe {
                    ffi::$update(&mut self.0, message.as_ptr(), message.len() as c_ulonglong)
                };
                assert_eq!(rc, 0);
            }

            #[doc = concat!(
                                "`", stringify!($init_with_domain), "`. libsodium 1.0.22 accepts\n",
                                "every domain byte; `Err` means it reported failure."
                            )]
            pub(crate) fn with_domain(domain: u8) -> Result<Self, ()> {
                init();
                let mut state = zeroed_state::<ffi::$ffi_state>();
                // SAFETY: `state` is a live, fully initialized state value.
                let rc = unsafe { ffi::$init_with_domain(&mut state, domain) };
                checked(rc, Self(state))
            }
        }
    };
}

xof_wrappers!(
    crypto_xof_shake128,
    XofShake128State(crypto_xof_shake128_state),
    crypto_xof_shake128_init,
    crypto_xof_shake128_init_with_domain,
    crypto_xof_shake128_update,
    crypto_xof_shake128_squeeze
);
xof_wrappers!(
    crypto_xof_shake256,
    XofShake256State(crypto_xof_shake256_state),
    crypto_xof_shake256_init,
    crypto_xof_shake256_init_with_domain,
    crypto_xof_shake256_update,
    crypto_xof_shake256_squeeze
);
xof_wrappers!(
    crypto_xof_turboshake128,
    XofTurboShake128State(crypto_xof_turboshake128_state),
    crypto_xof_turboshake128_init,
    crypto_xof_turboshake128_init_with_domain,
    crypto_xof_turboshake128_update,
    crypto_xof_turboshake128_squeeze
);
xof_wrappers!(
    crypto_xof_turboshake256,
    XofTurboShake256State(crypto_xof_turboshake256_state),
    crypto_xof_turboshake256_init,
    crypto_xof_turboshake256_init_with_domain,
    crypto_xof_turboshake256_update,
    crypto_xof_turboshake256_squeeze
);

/// Defines `seed_keypair`, `enc` and `dec` wrappers for one libsodium KEM,
/// plus `enc_deterministic` when given, with libsodium's key, ciphertext
/// and seed sizes.
macro_rules! kem_wrappers {
    (
        pk: $pk:literal, sk: $sk:literal, ct: $ct:literal, seed: $seed:literal,
        $seed_keypair:ident, $enc:ident, $dec:ident
        $(, $enc_deterministic:ident($enc_seed:literal))? $(,)?
    ) => {
        #[doc = concat!("`", stringify!($seed_keypair), "`.")]
        pub(crate) fn $seed_keypair(seed: &[u8]) -> ([u8; $pk], [u8; $sk]) {
            init();
            let seed = fixed::<$seed>(seed);
            let (mut pk, mut sk) = ([0u8; $pk], [0u8; $sk]);
            // SAFETY: `pk`, `sk` and `seed` are arrays of libsodium's sizes.
            let rc = unsafe { ffi::$seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
            assert_eq!(rc, 0);
            (pk, sk)
        }

        #[doc = concat!("`", stringify!($enc), "`, returning the ciphertext and shared secret.")]
        pub(crate) fn $enc(pk: &[u8]) -> Result<([u8; $ct], [u8; 32]), ()> {
            init();
            let pk = fixed::<$pk>(pk);
            let (mut ct, mut ss) = ([0u8; $ct], [0u8; 32]);
            // SAFETY: `ct`, `ss` and `pk` are arrays of libsodium's sizes.
            let rc = unsafe { ffi::$enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
            checked(rc, (ct, ss))
        }

        #[doc = concat!("`", stringify!($dec), "`, returning the shared secret.")]
        pub(crate) fn $dec(ct: &[u8], sk: &[u8]) -> Result<[u8; 32], ()> {
            init();
            let (ct, sk) = (fixed::<$ct>(ct), fixed::<$sk>(sk));
            let mut ss = [0u8; 32];
            // SAFETY: `ss`, `ct` and `sk` are arrays of libsodium's sizes.
            let rc = unsafe { ffi::$dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
            checked(rc, ss)
        }

        $(
            #[doc = concat!(
                "`", stringify!($enc_deterministic),
                "`, returning the ciphertext and shared secret."
            )]
            pub(crate) fn $enc_deterministic(
                pk: &[u8],
                seed: &[u8],
            ) -> Result<([u8; $ct], [u8; 32]), ()> {
                init();
                let (pk, seed) = (fixed::<$pk>(pk), fixed::<$enc_seed>(seed));
                let (mut ct, mut ss) = ([0u8; $ct], [0u8; 32]);
                // SAFETY: `ct`, `ss`, `pk` and `seed` are arrays of the sizes
                // libsodium reads and writes.
                let rc = unsafe {
                    ffi::$enc_deterministic(
                        ct.as_mut_ptr(),
                        ss.as_mut_ptr(),
                        pk.as_ptr(),
                        seed.as_ptr(),
                    )
                };
                checked(rc, (ct, ss))
            }
        )?
    };
}

kem_wrappers!(
    pk: 1184, sk: 2400, ct: 1088, seed: 64,
    crypto_kem_mlkem768_seed_keypair,
    crypto_kem_mlkem768_enc,
    crypto_kem_mlkem768_dec,
    crypto_kem_mlkem768_enc_deterministic(32),
);
kem_wrappers!(
    pk: 1216, sk: 32, ct: 1120, seed: 32,
    crypto_kem_xwing_seed_keypair,
    crypto_kem_xwing_enc,
    crypto_kem_xwing_dec,
    crypto_kem_xwing_enc_deterministic(64),
);
kem_wrappers!(
    pk: 1216, sk: 32, ct: 1120, seed: 32,
    crypto_kem_seed_keypair,
    crypto_kem_enc,
    crypto_kem_dec,
);

/// `crypto_kdf_blake2b_derive_from_key` for an `N`-byte subkey.
pub(crate) fn kdf_blake2b_derive_from_key<const N: usize>(
    subkey_id: u64,
    context: &[u8],
    key: &[u8],
) -> [u8; N] {
    init();
    let (context, key) = (fixed::<8>(context), fixed::<32>(key));
    let mut subkey = [0u8; N];
    // SAFETY: `subkey` is writable for `N` bytes, `context` is 8 bytes and
    // `key` is 32 bytes, the sizes libsodium requires.
    let rc = unsafe {
        ffi::crypto_kdf_blake2b_derive_from_key(
            subkey.as_mut_ptr(),
            N,
            subkey_id,
            context.as_ptr().cast(),
            key.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    subkey
}

/// Pointer and length for an optional generic-hash key. `Some` of an empty
/// slice passes a non-null pointer with length 0, as a C caller with an empty
/// key buffer would; `None` is null and 0.
fn generichash_key_parts(key: Option<&[u8]>) -> (*const u8, usize) {
    key.map_or((std::ptr::null(), 0), |key| (key.as_ptr(), key.len()))
}

/// `crypto_generichash` for an `outlen`-byte output, or `Err(())` when
/// libsodium rejects the output or key length.
pub(crate) fn generichash(outlen: usize, input: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>, ()> {
    init();
    let (key, key_len) = generichash_key_parts(key);
    let mut output = vec![0u8; outlen];
    // SAFETY: `output` is writable for `outlen` bytes, `input` is readable for
    // its length, and `key` is null with length 0 or readable for `key_len`
    // bytes. libsodium checks the lengths and returns -1 when it rejects them.
    let rc = unsafe {
        ffi::crypto_generichash(
            output.as_mut_ptr(),
            outlen,
            input.as_ptr(),
            input.len() as c_ulonglong,
            key,
            key_len,
        )
    };
    checked(rc, output)
}

/// `crypto_generichash_init` for `init_outlen`, `crypto_generichash_update`
/// over each of `parts`, then `crypto_generichash_final` with a
/// `final_outlen`-byte output. Returns `Err(())` when `init` rejects the
/// output or key length. `final_outlen` must be 1 to 64: libsodium aborts the
/// process for any other final length.
pub(crate) fn generichash_multipart(
    key: Option<&[u8]>,
    init_outlen: usize,
    parts: &[&[u8]],
    final_outlen: usize,
) -> Result<Vec<u8>, ()> {
    init();
    assert!(
        (1..=64).contains(&final_outlen),
        "libsodium aborts on a final length of {final_outlen}"
    );
    let (key, key_len) = generichash_key_parts(key);
    let mut state: ffi::crypto_generichash_state = zeroed_state();
    // SAFETY: `state` is a writable libsodium state and `key` is null with
    // length 0 or readable for `key_len` bytes; libsodium checks the lengths.
    let rc = unsafe { ffi::crypto_generichash_init(&mut state, key, key_len, init_outlen) };
    checked(rc, ())?;
    for part in parts {
        // SAFETY: `state` was initialized above and `part` is readable for
        // its length.
        let rc = unsafe {
            ffi::crypto_generichash_update(&mut state, part.as_ptr(), part.len() as c_ulonglong)
        };
        assert_eq!(rc, 0);
    }
    let mut output = vec![0u8; final_outlen];
    // SAFETY: `state` was initialized above and `output` is writable for
    // `final_outlen` bytes, a length libsodium accepts.
    let rc =
        unsafe { ffi::crypto_generichash_final(&mut state, output.as_mut_ptr(), final_outlen) };
    checked(rc, output)
}

/// Defines a `crypto_kx_*_session_keys` wrapper returning `(rx, tx)`.
macro_rules! kx_wrapper {
    ($name:ident, $ffi:ident) => {
        #[doc = concat!("`", stringify!($ffi), "`, returning `(rx, tx)`.")]
        pub(crate) fn $name(
            pk: &[u8],
            sk: &[u8],
            peer_pk: &[u8],
        ) -> Result<([u8; 32], [u8; 32]), ()> {
            init();
            let (pk, sk, peer_pk) = (fixed::<32>(pk), fixed::<32>(sk), fixed::<32>(peer_pk));
            let (mut rx, mut tx) = ([0u8; 32], [0u8; 32]);
            // SAFETY: `rx` and `tx` are writable 32-byte arrays and all three
            // keys are 32 bytes.
            let rc = unsafe {
                ffi::$ffi(
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    pk.as_ptr(),
                    sk.as_ptr(),
                    peer_pk.as_ptr(),
                )
            };
            checked(rc, (rx, tx))
        }
    };
}

kx_wrapper!(kx_client_session_keys, crypto_kx_client_session_keys);
kx_wrapper!(kx_server_session_keys, crypto_kx_server_session_keys);

/// `crypto_scalarmult_curve25519_base`.
pub(crate) fn scalarmult_curve25519_base(scalar: &[u8]) -> [u8; 32] {
    init();
    let scalar = fixed::<32>(scalar);
    let mut point = [0u8; 32];
    // SAFETY: `point` is a writable 32-byte array and `scalar` is 32 bytes.
    let rc = unsafe { ffi::crypto_scalarmult_curve25519_base(point.as_mut_ptr(), scalar.as_ptr()) };
    assert_eq!(rc, 0);
    point
}

/// `crypto_scalarmult_curve25519`; libsodium rejects low-order points.
pub(crate) fn scalarmult_curve25519(scalar: &[u8], point: &[u8]) -> Result<[u8; 32], ()> {
    init();
    let (scalar, point) = (fixed::<32>(scalar), fixed::<32>(point));
    let mut shared = [0u8; 32];
    // SAFETY: `shared` is a writable 32-byte array and both inputs are 32
    // bytes.
    let rc = unsafe {
        ffi::crypto_scalarmult_curve25519(shared.as_mut_ptr(), scalar.as_ptr(), point.as_ptr())
    };
    checked(rc, shared)
}

/// Length of a NUL-padded `crypto_pwhash_argon2id_str` string buffer.
#[cfg(feature = "base64")]
const PWHASH_ARGON2ID_STRBYTES: usize = ffi::crypto_pwhash_argon2id_STRBYTES as usize;

/// `crypto_pwhash_argon2id` with `crypto_pwhash_argon2id_ALG_ARGON2ID13`.
#[cfg(feature = "alloc")]
pub(crate) fn pwhash_argon2id<const N: usize>(
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> [u8; N] {
    init();
    let salt = fixed::<16>(salt);
    let mut hash = [0u8; N];
    // SAFETY: `hash` is writable for `N` bytes, `password` is live for its
    // length and `salt` is 16 bytes, libsodium's salt size.
    let rc = unsafe {
        ffi::crypto_pwhash_argon2id(
            hash.as_mut_ptr(),
            N as c_ulonglong,
            password.as_ptr().cast(),
            password.len() as c_ulonglong,
            salt.as_ptr(),
            opslimit,
            memlimit,
            ffi::crypto_pwhash_argon2id_ALG_ARGON2ID13 as libc::c_int,
        )
    };
    assert_eq!(rc, 0);
    hash
}

/// `crypto_pwhash_argon2id_str`: the encoded hash, NUL-padded.
#[cfg(feature = "base64")]
pub(crate) fn pwhash_argon2id_str(
    password: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> [u8; PWHASH_ARGON2ID_STRBYTES] {
    init();
    let mut encoded = [0u8; PWHASH_ARGON2ID_STRBYTES];
    // SAFETY: `encoded` is writable for the `STRBYTES` libsodium fills, and
    // `password` is live for its length.
    let rc = unsafe {
        ffi::crypto_pwhash_argon2id_str(
            encoded.as_mut_ptr().cast(),
            password.as_ptr().cast(),
            password.len() as c_ulonglong,
            opslimit,
            memlimit,
        )
    };
    assert_eq!(rc, 0);
    encoded
}

/// `crypto_pwhash_argon2id_str_verify` for a NUL-padded encoded hash.
#[cfg(feature = "base64")]
pub(crate) fn pwhash_argon2id_str_verify(encoded: &[u8], password: &[u8]) -> bool {
    init();
    let encoded = fixed::<PWHASH_ARGON2ID_STRBYTES>(encoded);
    assert!(encoded.contains(&0), "encoded hash is not NUL-terminated");
    // SAFETY: `encoded` holds a NUL within its bounds, so libsodium's C
    // string read stays inside it; `password` is live for its length.
    unsafe {
        ffi::crypto_pwhash_argon2id_str_verify(
            encoded.as_ptr().cast(),
            password.as_ptr().cast(),
            password.len() as c_ulonglong,
        ) == 0
    }
}

const SIGN_BYTES: usize = ffi::crypto_sign_ed25519_BYTES as usize;

/// `crypto_sign_ed25519_seed_keypair`.
pub(crate) fn sign_ed25519_seed_keypair(seed: &[u8]) -> ([u8; 32], [u8; 64]) {
    init();
    let seed = fixed::<32>(seed);
    let (mut pk, mut sk) = ([0u8; 32], [0u8; 64]);
    // SAFETY: `pk` and `sk` are writable arrays of libsodium's key sizes and
    // `seed` is 32 bytes.
    let rc = unsafe {
        ffi::crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
    };
    assert_eq!(rc, 0);
    (pk, sk)
}

/// `crypto_sign_ed25519`: the signature followed by the message.
pub(crate) fn sign_ed25519(message: &[u8], sk: &[u8]) -> Vec<u8> {
    init();
    let sk = fixed::<64>(sk);
    let mut signed = vec![0u8; message.len() + SIGN_BYTES];
    let mut signed_len: c_ulonglong = 0;
    // SAFETY: `signed` has room for the signature plus the message, and `sk`
    // is 64 bytes.
    let rc = unsafe {
        ffi::crypto_sign_ed25519(
            signed.as_mut_ptr(),
            &mut signed_len,
            message.as_ptr(),
            message.len() as c_ulonglong,
            sk.as_ptr(),
        )
    };
    assert_eq!((rc, signed_len as usize), (0, signed.len()));
    signed
}

/// `crypto_sign_ed25519_open`, returning the message.
pub(crate) fn sign_ed25519_open(signed: &[u8], pk: &[u8]) -> Result<Vec<u8>, ()> {
    init();
    let pk = fixed::<32>(pk);
    let mut message = vec![0u8; signed.len()];
    let mut message_len: c_ulonglong = 0;
    // SAFETY: `message` is as long as `signed`, which bounds the message
    // libsodium writes, and `pk` is 32 bytes.
    let rc = unsafe {
        ffi::crypto_sign_ed25519_open(
            message.as_mut_ptr(),
            &mut message_len,
            signed.as_ptr(),
            signed.len() as c_ulonglong,
            pk.as_ptr(),
        )
    };
    message.truncate(message_len as usize);
    checked(rc, message)
}

/// `crypto_sign_ed25519_detached`.
#[cfg(feature = "alloc")]
pub(crate) fn sign_ed25519_detached(message: &[u8], sk: &[u8]) -> [u8; 64] {
    init();
    let sk = fixed::<64>(sk);
    let mut signature = [0u8; 64];
    let mut signature_len: c_ulonglong = 0;
    // SAFETY: `signature` is a writable 64-byte array, `message` is live for
    // its length and `sk` is 64 bytes.
    let rc = unsafe {
        ffi::crypto_sign_ed25519_detached(
            signature.as_mut_ptr(),
            &mut signature_len,
            message.as_ptr(),
            message.len() as c_ulonglong,
            sk.as_ptr(),
        )
    };
    assert_eq!((rc, signature_len as usize), (0, SIGN_BYTES));
    signature
}

/// `crypto_sign_ed25519_verify_detached`.
pub(crate) fn sign_ed25519_verify_detached(signature: &[u8], message: &[u8], pk: &[u8]) -> bool {
    init();
    let (signature, pk) = (fixed::<64>(signature), fixed::<32>(pk));
    // SAFETY: `signature` is 64 bytes, `pk` is 32 bytes and `message` is live
    // for its length.
    unsafe {
        ffi::crypto_sign_ed25519_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            pk.as_ptr(),
        ) == 0
    }
}

/// A `crypto_sign_ed25519ph` state that has absorbed `parts` in order.
fn sign_ed25519ph_state(parts: &[&[u8]]) -> ffi::crypto_sign_ed25519ph_state {
    init();
    let mut state = zeroed_state::<ffi::crypto_sign_ed25519ph_state>();
    // SAFETY: `state` is a live, fully initialized state value.
    assert_eq!(unsafe { ffi::crypto_sign_ed25519ph_init(&mut state) }, 0);
    for part in parts {
        // SAFETY: the state is initialized and `part` is live for its length.
        let rc = unsafe {
            ffi::crypto_sign_ed25519ph_update(&mut state, part.as_ptr(), part.len() as c_ulonglong)
        };
        assert_eq!(rc, 0);
    }
    state
}

/// `crypto_sign_ed25519ph_final_create` over the concatenation of `parts`.
pub(crate) fn sign_ed25519ph(parts: &[&[u8]], sk: &[u8]) -> [u8; 64] {
    init();
    let sk = fixed::<64>(sk);
    let mut state = sign_ed25519ph_state(parts);
    let mut signature = [0u8; 64];
    let mut signature_len: c_ulonglong = 0;
    // SAFETY: the state is initialized, `signature` is a writable 64-byte
    // array and `sk` is 64 bytes.
    let rc = unsafe {
        ffi::crypto_sign_ed25519ph_final_create(
            &mut state,
            signature.as_mut_ptr(),
            &mut signature_len,
            sk.as_ptr(),
        )
    };
    assert_eq!((rc, signature_len as usize), (0, SIGN_BYTES));
    signature
}

/// `crypto_sign_ed25519ph_final_verify` over the concatenation of `parts`.
pub(crate) fn sign_ed25519ph_verify(parts: &[&[u8]], signature: &[u8], pk: &[u8]) -> bool {
    init();
    let (signature, pk) = (fixed::<64>(signature), fixed::<32>(pk));
    let mut state = sign_ed25519ph_state(parts);
    // SAFETY: the state is initialized, `signature` is 64 bytes and `pk` is
    // 32 bytes.
    unsafe {
        ffi::crypto_sign_ed25519ph_final_verify(&mut state, signature.as_ptr(), pk.as_ptr()) == 0
    }
}

/// `crypto_secretstream_xchacha20poly1305` tags.
#[cfg(feature = "alloc")]
pub(crate) const SECRETSTREAM_TAG_MESSAGE: u8 =
    ffi::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8;
#[cfg(feature = "alloc")]
pub(crate) const SECRETSTREAM_TAG_PUSH: u8 =
    ffi::crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8;
#[cfg(feature = "alloc")]
pub(crate) const SECRETSTREAM_TAG_REKEY: u8 =
    ffi::crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8;
#[cfg(feature = "alloc")]
pub(crate) const SECRETSTREAM_TAG_FINAL: u8 =
    ffi::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8;

#[cfg(feature = "alloc")]
const SECRETSTREAM_ABYTES: usize = ffi::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// One direction of a `crypto_secretstream_xchacha20poly1305` stream. It
/// records when a `FINAL` tag has been pushed or pulled; a finalized stream
/// refuses further pushes, pulls and rekeys.
#[cfg(feature = "alloc")]
pub(crate) struct SecretStream {
    finalized: bool,
    state: ffi::crypto_secretstream_xchacha20poly1305_state,
}

#[cfg(feature = "alloc")]
impl SecretStream {
    /// `crypto_secretstream_xchacha20poly1305_init_pull`.
    pub(crate) fn init_pull(header: &[u8], key: &[u8]) -> Result<Self, ()> {
        init();
        let (header, key) = (fixed::<24>(header), fixed::<32>(key));
        let mut state = zeroed_state::<ffi::crypto_secretstream_xchacha20poly1305_state>();
        // SAFETY: `state` is a live, fully initialized state value, `header`
        // is 24 bytes and `key` is 32 bytes.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_init_pull(
                &mut state,
                header.as_ptr(),
                key.as_ptr(),
            )
        };
        checked(
            rc,
            Self {
                finalized: false,
                state,
            },
        )
    }

    /// `crypto_secretstream_xchacha20poly1305_init_push`, returning the
    /// stream and its header.
    pub(crate) fn init_push(key: &[u8]) -> (Self, [u8; 24]) {
        init();
        let key = fixed::<32>(key);
        let mut state = zeroed_state::<ffi::crypto_secretstream_xchacha20poly1305_state>();
        let mut header = [0u8; 24];
        // SAFETY: `state` is a live, fully initialized state value, `header`
        // is a writable 24-byte array and `key` is 32 bytes.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_init_push(
                &mut state,
                header.as_mut_ptr(),
                key.as_ptr(),
            )
        };
        assert_eq!(rc, 0);
        let stream = Self {
            finalized: false,
            state,
        };
        (stream, header)
    }

    pub(crate) fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// `crypto_secretstream_xchacha20poly1305_pull`, returning the message
    /// and its tag.
    pub(crate) fn pull(
        &mut self,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, u8), ()> {
        init();
        if self.finalized {
            return Err(());
        }
        let len = ciphertext
            .len()
            .checked_sub(SECRETSTREAM_ABYTES)
            .ok_or(())?;
        let (ad_ptr, ad_len) = ad_parts(ad);
        let mut message = vec![0u8; len];
        let mut message_len: c_ulonglong = 0;
        let mut tag = 0u8;
        // SAFETY: the state is initialized, `ciphertext` is at least the
        // overhead long, `message` has room for the rest, and the associated
        // data is null with length 0 or a live slice.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state,
                message.as_mut_ptr(),
                &mut message_len,
                &mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as c_ulonglong,
                ad_ptr,
                ad_len,
            )
        };
        checked(rc, ())?;
        message.truncate(message_len as usize);
        if tag == SECRETSTREAM_TAG_FINAL {
            self.finalized = true;
        }
        Ok((message, tag))
    }

    /// `crypto_secretstream_xchacha20poly1305_push`.
    pub(crate) fn push(
        &mut self,
        message: &[u8],
        ad: Option<&[u8]>,
        tag: u8,
    ) -> Result<Vec<u8>, ()> {
        init();
        if self.finalized {
            return Err(());
        }
        let (ad_ptr, ad_len) = ad_parts(ad);
        let mut ciphertext = vec![0u8; message.len() + SECRETSTREAM_ABYTES];
        let mut ciphertext_len: c_ulonglong = 0;
        // SAFETY: the state is initialized, `ciphertext` has room for the
        // message plus the overhead, and the associated data is null with
        // length 0 or a live slice.
        let rc = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_push(
                &mut self.state,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                message.as_ptr(),
                message.len() as c_ulonglong,
                ad_ptr,
                ad_len,
                tag,
            )
        };
        checked(rc, ())?;
        ciphertext.truncate(ciphertext_len as usize);
        if tag == SECRETSTREAM_TAG_FINAL {
            self.finalized = true;
        }
        Ok(ciphertext)
    }

    /// `crypto_secretstream_xchacha20poly1305_rekey`.
    pub(crate) fn rekey(&mut self) -> Result<(), ()> {
        init();
        if self.finalized {
            return Err(());
        }
        // SAFETY: the state is initialized.
        unsafe { ffi::crypto_secretstream_xchacha20poly1305_rekey(&mut self.state) };
        Ok(())
    }
}

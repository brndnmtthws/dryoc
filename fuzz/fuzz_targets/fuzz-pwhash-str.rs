#![no_main]
//! The libsodium password-hash string parsers (`PwHash::from_string`,
//! `crypto_pwhash_str_needs_rehash`, `crypto_pwhash_str_verify`) on arbitrary
//! strings. No Argon2 hash is computed, so fuzzed cost parameters cannot slow
//! the target down; instead every accepted string is checked for invariants
//! that hold for libsodium's format:
//!
//! - parsing and verification accept valid strings, while `needs_rehash` and
//!   string re-encoding also require the value to fit libsodium's fixed buffer;
//! - the format is canonical (minimal decimals, unpadded base64 with zero pad
//!   bits), so re-encoding an in-range accepted string reproduces it exactly;
//! - an accepted string is `$argon2i$` or `$argon2id$`, then
//!   `v=19$m=M,t=T,p=P$`, and needs no rehash for exactly its own `T` and `M`
//!   KiB.
//!
//! Valid argon2i/argon2id strings (generated with dryoc and verified by
//! libsodium, at minimal costs) and boundary cases live in
//! `seeds/fuzz-pwhash-str`; pass that directory after the corpus:
//! `cargo fuzz run fuzz-pwhash-str corpus/fuzz-pwhash-str
//! seeds/fuzz-pwhash-str`.
#[cfg(feature = "base64")]
use dryoc::classic::crypto_pwhash::{crypto_pwhash_str_needs_rehash, crypto_pwhash_str_verify};
#[cfg(feature = "base64")]
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_STRBYTES,
};
#[cfg(feature = "base64")]
use dryoc::pwhash::PwHash;
use libfuzzer_sys::fuzz_target;

/// The `M` and `T` of an accepted string, read with plain string splitting.
#[cfg(feature = "base64")]
fn costs(hashed_password: &str) -> (u64, u64) {
    let fields: Vec<&str> = hashed_password.split('$').collect();
    assert!(
        matches!(
            fields.as_slice(),
            ["", "argon2i" | "argon2id", "v=19", _, _, _]
        ),
        "accepted {hashed_password:?}"
    );
    let params: Vec<&str> = fields[3].split(',').collect();
    let [m, t, p] = params.as_slice() else {
        panic!("accepted parameters {:?}", fields[3]);
    };
    assert!(p.starts_with("p="), "accepted parameters {:?}", fields[3]);
    let value = |field: &str, prefix: &str| -> u64 {
        field
            .strip_prefix(prefix)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("accepted parameter {field:?}"))
    };
    (value(m, "m="), value(t, "t="))
}

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "base64")]
    {
        let hashed_password = String::from_utf8_lossy(data);
        let rehash = crypto_pwhash_str_needs_rehash(
            &hashed_password,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );
        let parsed = PwHash::<Vec<u8>, Vec<u8>>::from_string(&hashed_password);
        if hashed_password.len() < CRYPTO_PWHASH_STRBYTES {
            assert_eq!(rehash.is_ok(), parsed.is_ok(), "{hashed_password:?}");
        }

        let Ok(parsed) = parsed else {
            // Rejected before any hashing, so this stays cheap.
            assert!(crypto_pwhash_str_verify(&hashed_password, b"password").is_err());
            return;
        };
        if hashed_password.len() >= CRYPTO_PWHASH_STRBYTES {
            assert!(rehash.is_err(), "oversized needs_rehash accepted");
            assert!(parsed.to_encoded_string().is_err(), "oversized re-encode accepted");
            return;
        }
        assert_eq!(parsed.to_encoded_string().expect("re-encode"), hashed_password, "not canonical");
        let (m_cost, t_cost) = costs(&hashed_password);
        let memlimit = usize::try_from(m_cost * 1024).expect("memlimit fits");
        assert_eq!(
            crypto_pwhash_str_needs_rehash(&hashed_password, t_cost, memlimit).ok(),
            Some(false)
        );
        if let Some(other_t) = t_cost.checked_add(1).filter(|&t| t <= u64::from(u32::MAX)) {
            assert_eq!(
                crypto_pwhash_str_needs_rehash(&hashed_password, other_t, memlimit).ok(),
                Some(true)
            );
        }
    }

    #[cfg(not(feature = "base64"))]
    let _ = data;
});

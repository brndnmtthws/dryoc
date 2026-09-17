#![no_main]
#[cfg(feature = "base64")]
use dryoc::classic::crypto_pwhash::crypto_pwhash_str_needs_rehash;
#[cfg(feature = "base64")]
use dryoc::constants::{CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE};
#[cfg(feature = "base64")]
use dryoc::pwhash::PwHash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "base64")]
    {
        let hashed_password = String::from_utf8_lossy(data);
        let _ = crypto_pwhash_str_needs_rehash(
            &hashed_password,
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        );
        let _ = PwHash::<Vec<u8>, Vec<u8>>::from_string(&hashed_password);
    }

    #[cfg(not(feature = "base64"))]
    let _ = data;
});

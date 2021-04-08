#![no_main]
use libfuzzer_sys::fuzz_target;

use dryoc::generichash::{GenericHash, Key};

fuzz_target!(|data: &[u8]| {
    GenericHash::hash_with_defaults_to_vec::<_, Key>(data, None).ok();
});

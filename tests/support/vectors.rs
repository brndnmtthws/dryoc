//! Parser for the known-answer files in `src/mlkem/test-vectors/`, shared by
//! the unit tests (`src/mlkem/tests.rs`), the integration tests and the
//! WebAssembly tests through `#[path]`. It uses nothing from the crate, so it
//! builds in all three.

use std::collections::BTreeMap;
use std::vec::Vec;

/// Parses a vector file: `#` comments, then blank-line-separated records of
/// `key = value` lines. Works line by line, so a CRLF checkout (Windows)
/// parses the same; a repeated key within a record is an error rather than
/// a silent merge of two records.
pub(crate) fn records(text: &str) -> Vec<BTreeMap<&str, &str>> {
    let mut records = vec![BTreeMap::new()];
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let record = records.last_mut().expect("at least one record");
        if line.is_empty() {
            if !record.is_empty() {
                records.push(BTreeMap::new());
            }
        } else {
            let (key, value) = line.split_once(" = ").expect("key = value");
            assert!(record.insert(key, value).is_none(), "repeated key {key}");
        }
    }
    records.retain(|record| !record.is_empty());
    records
}

/// Decodes the hex field `key` of `record`.
pub(crate) fn bytes(record: &BTreeMap<&str, &str>, key: &str) -> Vec<u8> {
    hex::decode(record[key]).expect("hex field")
}

/// Decodes the hex field `key` of `record` into a fixed-size array.
#[allow(dead_code)] // The integration tests only use `bytes`.
pub(crate) fn field<const LEN: usize>(record: &BTreeMap<&str, &str>, key: &str) -> [u8; LEN] {
    bytes(record, key).try_into().expect("field length")
}

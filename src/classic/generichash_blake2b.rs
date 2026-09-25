use crate::blake2b;
use crate::constants::{
    CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX, CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX,
    CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES, CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES,
};
use crate::error::Error;

/// The shortest output libsodium accepts.
/// `CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN` (16) is only the recommended minimum;
/// libsodium's `crypto_generichash` and `crypto_generichash_init` accept any
/// output of 1 to 64 bytes.
const OUTPUT_BYTES_MIN: usize = 1;

/// Checks `key` against libsodium's accepted key lengths, 0 to 64 bytes.
/// `CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN` (16) is only the recommended
/// minimum.
#[inline]
pub(crate) fn crypto_generichash_blake2b_validate_key(key: Option<&[u8]>) -> Result<(), Error> {
    let key_len = key.map_or(0, <[u8]>::len);
    if key_len > CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX {
        return Err(length_error!(
            crate::ErrorContext::Blake2bKey,
            key_len,
            max CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX
        ));
    }
    Ok(())
}

/// Checks `outlen` against libsodium's accepted output lengths, 1 to 64 bytes.
#[inline]
pub(crate) fn crypto_generichash_blake2b_validate_outlen(outlen: usize) -> Result<(), Error> {
    if !(OUTPUT_BYTES_MIN..=CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX).contains(&outlen) {
        return Err(length_error!(
            crate::ErrorContext::Output,
            outlen,
            range OUTPUT_BYTES_MIN,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX
        ));
    }
    Ok(())
}

/// Like libsodium, an empty key means an unkeyed hash, not a key block of
/// zeros.
#[inline]
fn nonempty_key(key: Option<&[u8]>) -> Option<&[u8]> {
    key.filter(|key| !key.is_empty())
}

#[inline]
pub(crate) fn crypto_generichash_blake2b(
    output: &mut [u8],
    input: &[u8],
    key: Option<&[u8]>,
) -> Result<(), Error> {
    crypto_generichash_blake2b_validate_outlen(output.len())?;
    crypto_generichash_blake2b_validate_key(key)?;

    blake2b::hash(output, input, nonempty_key(key))
}

#[inline]
pub(crate) fn crypto_generichash_blake2b_init(
    key: Option<&[u8]>,
    outlen: usize,
    salt: Option<&[u8; CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES]>,
    personal: Option<&[u8; CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES]>,
) -> Result<blake2b::State, Error> {
    crypto_generichash_blake2b_validate_outlen(outlen)?;
    crypto_generichash_blake2b_validate_key(key)?;

    blake2b::State::init(outlen as u8, nonempty_key(key), salt, personal)
}

#[inline]
pub(crate) fn crypto_generichash_blake2b_update(state: &mut blake2b::State, input: &[u8]) {
    state.update(input)
}

#[inline]
pub(crate) fn crypto_generichash_blake2b_final(
    state: blake2b::State,
    output: &mut [u8],
) -> Result<(), Error> {
    state.finalize(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorContext, LengthConstraint};

    /// Keys of 0 to 64 bytes and outputs of 1 to 64 bytes are accepted, as
    /// in libsodium; the recommended minimums are not enforced.
    #[test]
    fn validation_accepts_libsodium_ranges_and_reports_bounds() {
        assert!(crypto_generichash_blake2b_validate_key(None).is_ok());
        for key_len in [0, 1, 15, 16, CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX] {
            let key = vec![0u8; key_len];
            assert!(
                crypto_generichash_blake2b_validate_key(Some(&key)).is_ok(),
                "key {key_len}"
            );
        }
        let key = vec![0u8; CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX + 1];
        assert!(matches!(
            crypto_generichash_blake2b_validate_key(Some(&key)),
            Err(Error::InvalidLength {
                context: ErrorContext::Blake2bKey,
                actual: 65,
                constraint: LengthConstraint::AtMost(64),
            })
        ));

        for output_len in [1, 15, 16, CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX] {
            assert!(
                crypto_generichash_blake2b_validate_outlen(output_len).is_ok(),
                "output {output_len}"
            );
        }
        for output_len in [0, CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX + 1] {
            assert!(matches!(
                crypto_generichash_blake2b_validate_outlen(output_len),
                Err(Error::InvalidLength {
                    context: ErrorContext::Output,
                    actual,
                    constraint: LengthConstraint::Between { min: 1, max: 64 },
                }) if actual == output_len
            ));
        }
    }

    /// An empty key hashes exactly like no key, one-shot and incrementally.
    #[test]
    fn empty_key_is_unkeyed() {
        let input = b"empty keys select the unkeyed hash";
        for outlen in [1, 32, 64] {
            let mut unkeyed = vec![0u8; outlen];
            crypto_generichash_blake2b(&mut unkeyed, input, None).expect("unkeyed");
            let mut empty = vec![0u8; outlen];
            crypto_generichash_blake2b(&mut empty, input, Some(&[])).expect("empty key");
            assert_eq!(empty, unkeyed, "one-shot {outlen}");

            let mut state =
                crypto_generichash_blake2b_init(Some(&[]), outlen, None, None).expect("init");
            crypto_generichash_blake2b_update(&mut state, input);
            let mut incremental = vec![0u8; outlen];
            crypto_generichash_blake2b_final(state, &mut incremental).expect("final");
            assert_eq!(incremental, unkeyed, "incremental {outlen}");
        }
    }
}

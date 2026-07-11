use crate::blake2b;
use crate::constants::{
    CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX, CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN,
    CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX, CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN,
    CRYPTO_GENERICHASH_BLAKE2B_PERSONALBYTES, CRYPTO_GENERICHASH_BLAKE2B_SALTBYTES,
};
use crate::error::Error;

#[inline]
pub(crate) fn crypto_generichash_blake2b_validate_key(key: Option<&[u8]>) -> Result<(), Error> {
    match key {
        Some(key) => {
            if key.len() < CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN
                || key.len() > CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX
            {
                return Err(length_error!(
                    crate::ErrorContext::Blake2bKey,
                    key.len(),
                    range CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN,
                    CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX
                ));
            }
            Ok(())
        }
        None => Ok(()),
    }
}

#[inline]
pub(crate) fn crypto_generichash_blake2b_validate_outlen(outlen: usize) -> Result<(), Error> {
    if !(CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN..=CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX)
        .contains(&outlen)
    {
        return Err(length_error!(
            crate::ErrorContext::Output,
            outlen,
            range CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX
        ));
    }
    Ok(())
}

#[inline]
pub(crate) fn crypto_generichash_blake2b(
    output: &mut [u8],
    input: &[u8],
    key: Option<&[u8]>,
) -> Result<(), Error> {
    crypto_generichash_blake2b_validate_outlen(output.len())?;
    crypto_generichash_blake2b_validate_key(key)?;

    blake2b::hash(output, input, key)
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

    blake2b::State::init(outlen as u8, key, salt, personal)
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

    #[test]
    fn validation_reports_key_and_output_bounds() {
        assert!(crypto_generichash_blake2b_validate_key(None).is_ok());
        assert!(
            crypto_generichash_blake2b_validate_key(Some(
                &[0u8; CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN]
            ))
            .is_ok()
        );

        for key_len in [
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN - 1,
            CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX + 1,
        ] {
            let key = vec![0u8; key_len];
            assert!(matches!(
                crypto_generichash_blake2b_validate_key(Some(&key)),
                Err(Error::InvalidLength {
                    context: ErrorContext::Blake2bKey,
                    actual,
                    constraint: LengthConstraint::Between { .. },
                }) if actual == key_len
            ));
        }

        for output_len in [
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN - 1,
            CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX + 1,
        ] {
            assert!(matches!(
                crypto_generichash_blake2b_validate_outlen(output_len),
                Err(Error::InvalidLength {
                    context: ErrorContext::Output,
                    actual,
                    constraint: LengthConstraint::Between { .. },
                }) if actual == output_len
            ));
        }
    }
}

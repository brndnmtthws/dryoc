use crate::constants::{
    CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_CORE_HCHACHA20_KEYBYTES, CRYPTO_SCALARMULT_BYTES,
};
use crate::scalarmult_curve25519::crypto_scalarmult_curve25519_base;
use crate::types::OutputBase;

/// Computes the public key for a previously generated secret key.
pub fn crypto_scalarmult_base(n: &[u8; CRYPTO_SCALARMULT_BYTES]) -> [u8; CRYPTO_SCALARMULT_BYTES] {
    crypto_scalarmult_curve25519_base(n)
}

/// Implements the HSalso20 function, but unlike the libsodium version does not permit specifying constants
pub fn crypto_core_hchacha20(input: &[u8], key: &[u8]) -> OutputBase {
    use generic_array::GenericArray;
    use salsa20::hsalsa20;
    assert_eq!(input.len(), CRYPTO_CORE_HCHACHA20_INPUTBYTES);
    assert_eq!(key.len(), CRYPTO_CORE_HCHACHA20_KEYBYTES);
    let output = hsalsa20(
        GenericArray::from_slice(key),
        GenericArray::from_slice(input),
    );
    output.as_slice().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_box::*;

    #[test]
    fn test_crypto_scalarmult_base() {
        use base64::encode;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{scalarmult_base, Scalar};

            let keypair = crypto_box_keypair();

            let public_key = crypto_scalarmult_base(&keypair.secret_key.0);

            assert_eq!(keypair.public_key.0, public_key);

            let ge = scalarmult_base(&Scalar::from_slice(&keypair.secret_key.0).unwrap());

            assert_eq!(encode(ge.as_ref()), encode(public_key));
        }
    }
}

use crate::constants::*;
use crate::scalarmult_curve25519::*;

/// Computes the public key for a previously generated secret key.
pub fn crypto_scalarmult_base(n: &[u8; CRYPTO_SCALARMULT_BYTES]) -> [u8; CRYPTO_SCALARMULT_BYTES] {
    crypto_scalarmult_curve25519_base(n)
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

use super::crypto_sign_ed25519::*;
pub use super::crypto_sign_ed25519::{PublicKey, SecretKey};
use crate::constants::CRYPTO_SIGN_BYTES;
use crate::error::Error;

/// Randomly generates a new Ed25519 `(PublicKey, SecretKey)` keypair that can
/// be used for message signing.
pub fn crypto_sign_keypair() -> (PublicKey, SecretKey) {
    crypto_sign_ed25519_keypair()
}

/// Returns a keypair derived from `seed`, which can be used for message
/// signing.
pub fn crypto_sign_seed_keypair(seed: &[u8; 32]) -> (PublicKey, SecretKey) {
    crypto_sign_ed25519_seed_keypair(seed)
}

/// Signs `message`, placing the result into `signed_message`. The length of
/// `signed_message` should be the length of the message plus
/// [`CRYPTO_SIGN_BYTES`].
///
/// This function is compatible with libsodium`s `crypto_sign`, however the
/// `ED25519_NONDETERMINISTIC` feature is not supported.
pub fn crypto_sign(
    signed_message: &mut [u8],
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    if signed_message.len() != message.len() + CRYPTO_SIGN_BYTES {
        Err(dryoc_error!(format!(
            "signed_message length incorrect (expect {}, got {})",
            message.len() + CRYPTO_SIGN_BYTES,
            signed_message.len()
        )))
    } else {
        crypto_sign_ed25519(signed_message, message, secret_key)
    }
}

/// Verifies the signature of `signed_message`, placing the result into
/// `message`. The length of `message` should be the length of the signed
/// message minus [`CRYPTO_SIGN_BYTES`].
///
/// This function is compatible with libsodium`s `crypto_sign_open`, however the
/// `ED25519_NONDETERMINISTIC` feature is not supported.
pub fn crypto_sign_open(
    message: &mut [u8],
    signed_message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    if message.len() != signed_message.len() - CRYPTO_SIGN_BYTES {
        Err(dryoc_error!(format!(
            "message length incorrect (expect {}, got {})",
            signed_message.len() - CRYPTO_SIGN_BYTES,
            message.len()
        )))
    } else {
        crypto_sign_ed25519_open(message, signed_message, public_key)
    }
}

/// Signs `message`, placing the signature into `signature` upon success.
/// Detached variant of [`crypto_sign_open`].
///
/// This function is compatible with libsodium`s `crypto_sign_detached`, however
/// the `ED25519_NONDETERMINISTIC` feature is not supported.
pub fn crypto_sign_detached(
    signature: &mut [u8; CRYPTO_SIGN_BYTES],
    message: &[u8],
    secret_key: &SecretKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_detached(signature, message, secret_key)
}

/// Verifies that `signature` is a valid signature for `message` using the given
/// `public_key`.
///
/// This function is compatible with libsodium`s `crypto_sign_verify_detached`,
/// however the `ED25519_NONDETERMINISTIC` feature is not supported.
pub fn crypto_sign_verify_detached(
    signature: &[u8; CRYPTO_SIGN_BYTES],
    message: &[u8],
    public_key: &PublicKey,
) -> Result<(), Error> {
    crypto_sign_ed25519_verify_detached(signature, message, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_sign() {
        use base64::encode;
        use sodiumoxide::crypto::sign;

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
            crypto_sign(&mut signed_message, message, &secret_key).expect("sign failed");

            let so_signed_message = sign::sign(
                message,
                &sign::SecretKey::from_slice(&secret_key).expect("secret key failed"),
            );

            assert_eq!(encode(&signed_message), encode(&so_signed_message));

            let so_m = sign::verify(
                &signed_message,
                &sign::PublicKey::from_slice(&public_key).expect("public key failed"),
            )
            .expect("verify failed");

            assert_eq!(so_m, message);
        }
    }

    #[test]
    fn test_crypto_sign_open() {
        use base64::encode;
        use sodiumoxide::crypto::sign;

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_BYTES];
            crypto_sign(&mut signed_message, message, &secret_key).expect("sign failed");

            let so_signed_message = sign::sign(
                message,
                &sign::SecretKey::from_slice(&secret_key).expect("secret key failed"),
            );

            assert_eq!(encode(&signed_message), encode(&so_signed_message));

            let so_m = sign::verify(
                &signed_message,
                &sign::PublicKey::from_slice(&public_key).expect("public key failed"),
            )
            .expect("verify failed");

            assert_eq!(so_m, message);

            let mut opened_message = vec![0u8; message.len()];

            crypto_sign_open(&mut opened_message, &signed_message, &public_key)
                .expect("verify failed");

            assert_eq!(opened_message, message);
        }
    }

    #[test]
    fn test_crypto_sign_detached() {
        use sodiumoxide::crypto::sign;

        for _ in 0..10 {
            let (public_key, secret_key) = crypto_sign_keypair();
            let message = b"important message";
            let mut signature = [0u8; CRYPTO_SIGN_BYTES];
            crypto_sign_detached(&mut signature, message, &secret_key).expect("sign failed");

            assert!(sign::verify_detached(
                &sign::Signature::from_slice(&signature).expect("signature failed"),
                message,
                &sign::PublicKey::from_slice(&public_key).expect("public key failed"),
            ));

            crypto_sign_verify_detached(&signature, message, &public_key).expect("verify failed");
        }
    }
}

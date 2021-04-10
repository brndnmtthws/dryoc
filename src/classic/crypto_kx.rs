//! # Key exchange
//!
//! This module implements libsodium's key exchange functions, which uses a
//! combination of Curve25519, Diffie-Hellman, and Blake2b to generate shared
//! session keys.
//!
//! ## Classic API example
//!
//! ```
//! use dryoc::classic::crypto_kx::*;
//!
//! // Generate random client & server keypairs
//! let (client_pk, client_sk) = crypto_kx_keypair();
//! let (server_pk, server_sk) = crypto_kx_keypair();
//!
//! // Variables for client & server rx/tx session keys
//! let (mut crx, mut ctx, mut srx, mut stx) = (
//!     SessionKey::default(),
//!     SessionKey::default(),
//!     SessionKey::default(),
//!     SessionKey::default(),
//! );
//!
//! // Calculate the client Rx & Tx keys
//! crypto_kx_client_session_keys(&mut crx, &mut ctx, &client_pk, &client_sk, &server_pk)
//!     .expect("client kx failed");
//!
//! // Calculate the server Rx & Tx keys
//! crypto_kx_server_session_keys(&mut srx, &mut stx, &server_pk, &server_sk, &client_pk)
//!     .expect("server kx failed");
//!
//! assert_eq!(crx, stx);
//! assert_eq!(ctx, srx);
//! ```

use zeroize::Zeroize;

use super::crypto_core::{crypto_scalarmult, crypto_scalarmult_base};
use super::crypto_generichash::{
    crypto_generichash, crypto_generichash_final, crypto_generichash_init,
    crypto_generichash_update,
};
use crate::constants::{
    CRYPTO_KX_PUBLICKEYBYTES, CRYPTO_KX_SECRETKEYBYTES, CRYPTO_KX_SEEDBYTES,
    CRYPTO_KX_SESSIONKEYBYTES, CRYPTO_SCALARMULT_BYTES,
};
use crate::error::Error;
use crate::types::*;

/// Public key type for key exchange
pub type PublicKey = [u8; CRYPTO_KX_PUBLICKEYBYTES];
/// Secret key type for key exchange
pub type SecretKey = [u8; CRYPTO_KX_SECRETKEYBYTES];
/// Session data type for key exchange
pub type SessionKey = [u8; CRYPTO_KX_SESSIONKEYBYTES];

/// Computes and returns a keypair of `(PublicKey, SecretKey)` based on `seed`
/// upon success. Uses the Blake2b function to derive a secret from `seed`.
///
/// Compatible with libsodium's `crypto_kx_seed_keypair`.
pub fn crypto_kx_seed_keypair(
    seed: &[u8; CRYPTO_KX_SEEDBYTES],
) -> Result<(PublicKey, SecretKey), Error> {
    let mut sk = SecretKey::default();
    let mut pk = PublicKey::default();

    crypto_generichash(&mut sk, seed, None)?;

    crypto_scalarmult_base(&mut pk, &sk);

    Ok((pk, sk))
}

/// Returns a randomly generated keypair, suitable for use with key exchange.
///
/// Equivalent to libsodium's `crypto_kx_keypair`.
pub fn crypto_kx_keypair() -> (PublicKey, SecretKey) {
    let sk = SecretKey::gen();
    let mut pk = PublicKey::default();

    crypto_scalarmult_base(&mut pk, &sk);

    (pk, sk)
}

fn crypto_kx(
    x1: &mut SessionKey,
    x2: &mut SessionKey,
    client_pk: &PublicKey,
    server_pk: &PublicKey,
    mut shared_secret: [u8; CRYPTO_SCALARMULT_BYTES],
) -> Result<(), Error> {
    let mut keys = [0u8; 2 * CRYPTO_KX_SESSIONKEYBYTES];

    let mut hasher = crypto_generichash_init(None, 2 * CRYPTO_KX_SESSIONKEYBYTES)?;
    crypto_generichash_update(&mut hasher, &shared_secret);
    shared_secret.zeroize();
    crypto_generichash_update(&mut hasher, client_pk);
    crypto_generichash_update(&mut hasher, server_pk);
    crypto_generichash_final(hasher, &mut keys)?;

    x1.copy_from_slice(&keys[..CRYPTO_KX_SESSIONKEYBYTES]);
    x2.copy_from_slice(&keys[CRYPTO_KX_SESSIONKEYBYTES..]);

    keys.zeroize();

    Ok(())
}

/// Computes client session keys for `rx` and `tx`, using `client_pk`,
/// `client_sk`, and `server_pk`. Returns unit `()` upon success.
///
/// Compatible with libsodium's `crypto_kx_client_session_keys`.
pub fn crypto_kx_client_session_keys(
    rx: &mut SessionKey,
    tx: &mut SessionKey,
    client_pk: &PublicKey,
    client_sk: &SecretKey,
    server_pk: &PublicKey,
) -> Result<(), Error> {
    let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];

    crypto_scalarmult(&mut shared_secret, client_sk, server_pk);

    crypto_kx(rx, tx, client_pk, server_pk, shared_secret)
}

/// Computes server session keys for `rx` and `tx`, using `client_pk`,
/// `client_sk`, and `server_pk`. Returns unit `()` upon success.
///
/// Compatible with libsodium's `crypto_kx_server_session_keys`.
pub fn crypto_kx_server_session_keys(
    rx: &mut SessionKey,
    tx: &mut SessionKey,
    server_pk: &PublicKey,
    server_sk: &SecretKey,
    client_pk: &PublicKey,
) -> Result<(), Error> {
    let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];

    crypto_scalarmult(&mut shared_secret, server_sk, client_pk);

    crypto_kx(tx, rx, client_pk, server_pk, shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kx() {
        for _ in 0..20 {
            let (client_pk, client_sk) = crypto_kx_keypair();
            let (server_pk, server_sk) = crypto_kx_keypair();

            let (mut crx, mut ctx, mut srx, mut stx) = (
                SessionKey::default(),
                SessionKey::default(),
                SessionKey::default(),
                SessionKey::default(),
            );

            crypto_kx_client_session_keys(&mut crx, &mut ctx, &client_pk, &client_sk, &server_pk)
                .expect("client kx failed");

            crypto_kx_server_session_keys(&mut srx, &mut stx, &server_pk, &server_sk, &client_pk)
                .expect("server kx failed");

            assert_eq!(crx, stx);
            assert_eq!(ctx, srx);

            use sodiumoxide::crypto::kx;

            let client_pk = kx::PublicKey::from_slice(&client_pk).expect("client pk failed");
            let client_sk = kx::SecretKey::from_slice(&client_sk).expect("client sk failed");
            let server_pk = kx::PublicKey::from_slice(&server_pk).expect("server pk failed");
            let server_sk = kx::SecretKey::from_slice(&server_sk).expect("server sk failed");

            let (rx1, tx1) = match kx::client_session_keys(&client_pk, &client_sk, &server_pk) {
                Ok((rx, tx)) => (rx, tx),
                Err(()) => panic!("bad server signature"),
            };

            // server performs the same operation
            let (rx2, tx2) = match kx::server_session_keys(&server_pk, &server_sk, &client_pk) {
                Ok((rx, tx)) => (rx, tx),
                Err(()) => panic!("bad client signature"),
            };

            assert_eq!(rx1.as_ref(), crx);
            assert_eq!(rx2.as_ref(), srx);
            assert_eq!(tx1.as_ref(), ctx);
            assert_eq!(tx2.as_ref(), stx);
        }
    }
}

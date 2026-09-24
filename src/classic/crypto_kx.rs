//! # Key exchange
//!
//! Implements libsodium's client/server key-exchange construction. Each party
//! derives one key for receiving and another for sending. Applications must
//! authenticate peer public keys through a trusted channel.
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

use zeroize::Zeroizing;

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
///
/// # Errors
///
/// Returns an error if the underlying generic hash rejects the output. The
/// fixed output length used here is valid.
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
    let sk = SecretKey::generate();
    let mut pk = PublicKey::default();

    crypto_scalarmult_base(&mut pk, &sk);

    (pk, sk)
}

fn crypto_kx(
    x1: &mut SessionKey,
    x2: &mut SessionKey,
    client_pk: &PublicKey,
    server_pk: &PublicKey,
    shared_secret: Zeroizing<[u8; CRYPTO_SCALARMULT_BYTES]>,
) -> Result<(), Error> {
    let mut keys = Zeroizing::new([0u8; 2 * CRYPTO_KX_SESSIONKEYBYTES]);

    let mut hasher = crypto_generichash_init(None, 2 * CRYPTO_KX_SESSIONKEYBYTES)?;
    crypto_generichash_update(&mut hasher, &shared_secret[..]);
    crypto_generichash_update(&mut hasher, client_pk);
    crypto_generichash_update(&mut hasher, server_pk);
    crypto_generichash_final(hasher, &mut keys[..])?;

    x1.copy_from_slice(&keys[..CRYPTO_KX_SESSIONKEYBYTES]);
    x2.copy_from_slice(&keys[CRYPTO_KX_SESSIONKEYBYTES..]);

    Ok(())
}

/// Computes client session keys for `rx` and `tx`, using `client_pk`,
/// `client_sk`, and `server_pk`. Returns unit `()` upon success.
///
/// Compatible with libsodium's `crypto_kx_client_session_keys`.
///
/// # Errors
///
/// Returns an error if `server_pk` is an unacceptable low-order public key or
/// session-key derivation fails.
pub fn crypto_kx_client_session_keys(
    rx: &mut SessionKey,
    tx: &mut SessionKey,
    client_pk: &PublicKey,
    client_sk: &SecretKey,
    server_pk: &PublicKey,
) -> Result<(), Error> {
    let mut shared_secret = Zeroizing::new([0u8; CRYPTO_SCALARMULT_BYTES]);

    crypto_scalarmult(&mut shared_secret, client_sk, server_pk)?;

    crypto_kx(rx, tx, client_pk, server_pk, shared_secret)
}

/// Computes server session keys for `rx` and `tx`, using `server_pk`,
/// `server_sk`, and `client_pk`. Returns unit `()` upon success.
///
/// Compatible with libsodium's `crypto_kx_server_session_keys`.
///
/// # Errors
///
/// Returns an error if `client_pk` is an unacceptable low-order public key or
/// session-key derivation fails.
pub fn crypto_kx_server_session_keys(
    rx: &mut SessionKey,
    tx: &mut SessionKey,
    server_pk: &PublicKey,
    server_sk: &SecretKey,
    client_pk: &PublicKey,
) -> Result<(), Error> {
    let mut shared_secret = Zeroizing::new([0u8; CRYPTO_SCALARMULT_BYTES]);

    crypto_scalarmult(&mut shared_secret, server_sk, client_pk)?;

    crypto_kx(tx, rx, client_pk, server_pk, shared_secret)
}

#[cfg(all(test, dryoc_native_tests))]
mod tests {
    use super::*;
    use crate::scalarmult_curve25519::test_vectors::low_order_u_encodings;
    use crate::utils::test_util::XorShift64;

    fn sodium_kx_seed_keypair(seed: &[u8; CRYPTO_KX_SEEDBYTES]) -> (PublicKey, SecretKey) {
        let mut pk = PublicKey::default();
        let mut sk = SecretKey::default();
        let result = unsafe {
            libsodium_sys::crypto_kx_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };
        assert_eq!(result, 0);
        (pk, sk)
    }

    /// The seed-derived secret key (Blake2b-256 of the seed) and its public
    /// key are libsodium's, for the all-zero, all-ones and a random seed.
    #[test]
    fn test_kx_seed_keypair_matches_libsodium() {
        let mut rng = XorShift64::new(0x510e_527f_ade6_82d1);
        for seed in [
            [0u8; CRYPTO_KX_SEEDBYTES],
            [0xff; CRYPTO_KX_SEEDBYTES],
            rng.next_bytes32(),
        ] {
            let (pk, sk) = crypto_kx_seed_keypair(&seed).expect("seed keypair failed");
            let (sodium_pk, sodium_sk) = sodium_kx_seed_keypair(&seed);
            assert_eq!(sk, sodium_sk, "seed {seed:02x?}");
            assert_eq!(pk, sodium_pk, "seed {seed:02x?}");
        }
    }

    /// Both roles derive libsodium's session keys for a fixed seeded pair,
    /// and each side's rx is the other's tx.
    #[test]
    fn test_kx_session_keys_match_libsodium_for_seeded_pair() {
        let (client_pk, client_sk) = crypto_kx_seed_keypair(&[0x11; CRYPTO_KX_SEEDBYTES]).unwrap();
        let (server_pk, server_sk) = crypto_kx_seed_keypair(&[0x22; CRYPTO_KX_SEEDBYTES]).unwrap();

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

        let (mut so_crx, mut so_ctx, mut so_srx, mut so_stx) = (
            SessionKey::default(),
            SessionKey::default(),
            SessionKey::default(),
            SessionKey::default(),
        );
        let (client_result, server_result) = unsafe {
            (
                libsodium_sys::crypto_kx_client_session_keys(
                    so_crx.as_mut_ptr(),
                    so_ctx.as_mut_ptr(),
                    client_pk.as_ptr(),
                    client_sk.as_ptr(),
                    server_pk.as_ptr(),
                ),
                libsodium_sys::crypto_kx_server_session_keys(
                    so_srx.as_mut_ptr(),
                    so_stx.as_mut_ptr(),
                    server_pk.as_ptr(),
                    server_sk.as_ptr(),
                    client_pk.as_ptr(),
                ),
            )
        };
        assert_eq!(client_result, 0);
        assert_eq!(server_result, 0);
        assert_eq!(crx, so_crx);
        assert_eq!(ctx, so_ctx);
        assert_eq!(srx, so_srx);
        assert_eq!(stx, so_stx);
    }

    /// Every low-order peer key (libsodium's blacklist, with and without bit
    /// 255) is rejected by both roles before any session key is written, as
    /// libsodium does.
    #[test]
    fn test_kx_rejects_low_order_public_keys() {
        let (pk, sk) = crypto_kx_seed_keypair(&[0x33; CRYPTO_KX_SEEDBYTES]).unwrap();

        for peer_pk in low_order_u_encodings() {
            let mut rx = [0xa5; CRYPTO_KX_SESSIONKEYBYTES];
            let mut tx = [0x5a; CRYPTO_KX_SESSIONKEYBYTES];
            assert!(
                crypto_kx_client_session_keys(&mut rx, &mut tx, &pk, &sk, &peer_pk).is_err(),
                "client {peer_pk:02x?}"
            );
            assert!(
                crypto_kx_server_session_keys(&mut rx, &mut tx, &pk, &sk, &peer_pk).is_err(),
                "server {peer_pk:02x?}"
            );
            assert_eq!(rx, [0xa5; CRYPTO_KX_SESSIONKEYBYTES]);
            assert_eq!(tx, [0x5a; CRYPTO_KX_SESSIONKEYBYTES]);

            let (client_result, server_result) = unsafe {
                (
                    libsodium_sys::crypto_kx_client_session_keys(
                        rx.as_mut_ptr(),
                        tx.as_mut_ptr(),
                        pk.as_ptr(),
                        sk.as_ptr(),
                        peer_pk.as_ptr(),
                    ),
                    libsodium_sys::crypto_kx_server_session_keys(
                        rx.as_mut_ptr(),
                        tx.as_mut_ptr(),
                        pk.as_ptr(),
                        sk.as_ptr(),
                        peer_pk.as_ptr(),
                    ),
                )
            };
            assert_eq!(client_result, -1, "client {peer_pk:02x?}");
            assert_eq!(server_result, -1, "server {peer_pk:02x?}");
            assert_eq!(rx, [0xa5; CRYPTO_KX_SESSIONKEYBYTES]);
            assert_eq!(tx, [0x5a; CRYPTO_KX_SESSIONKEYBYTES]);
        }
    }

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

            use crate::native_test_util::{kx_client_session_keys, kx_server_session_keys};

            let (rx1, tx1) = match kx_client_session_keys(&client_pk, &client_sk, &server_pk) {
                Ok((rx, tx)) => (rx, tx),
                Err(()) => panic!("bad server signature"),
            };

            // server performs the same operation
            let (rx2, tx2) = match kx_server_session_keys(&server_pk, &server_sk, &client_pk) {
                Ok((rx, tx)) => (rx, tx),
                Err(()) => panic!("bad client signature"),
            };

            assert_eq!(rx1, crx);
            assert_eq!(rx2, srx);
            assert_eq!(tx1, ctx);
            assert_eq!(tx2, stx);
        }
    }
}

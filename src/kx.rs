//! # Key exchange functions
//!
//! [`Session`] implements libsodium's key exchange functions, which use a
//! combination of Curve25519, Diffie-Hellman, and Blake2b to generate shared
//! session keys between two parties who know each other's public keys.
//!
//! You should use [`Session`] when you want to:
//!
//! * derive shared secrets between two parties
//! * use public-key cryptography, but do so with another cipher that only
//!   supports pre-shared secrets
//! * create a session key or token that can't be used to derive the original
//!   inputs should it become compromised
//!
//! # Rustaceous API example
//!
//! ```
//! use dryoc::kx::*;
//!
//! // Generate random client/server keypairs
//! let client_keypair = KeyPair::generate();
//! let server_keypair = KeyPair::generate();
//!
//! // Compute client session keys, into default stack-allocated byte array
//! let client_session_keys =
//!     Session::new_client_with_defaults(&client_keypair, &server_keypair.public_key)
//!         .expect("compute client failed");
//!
//! // Compute server session keys, into default stack-allocated byte array
//! let server_session_keys =
//!     Session::new_server_with_defaults(&server_keypair, &client_keypair.public_key)
//!         .expect("compute client failed");
//!
//! let (client_rx, client_tx) = client_session_keys.into_parts();
//! let (server_rx, server_tx) = server_session_keys.into_parts();
//!
//! // Client Rx should match server Tx keys
//! assert_eq!(client_rx, server_tx);
//! // Client Tx should match server Rx keys
//! assert_eq!(client_tx, server_rx);
//! ```
//!
//! ## Additional resources
//!
//! * See <https://doc.libsodium.org/key_exchange> for additional details on key
//!   exchange

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_kx::{crypto_kx_client_session_keys, crypto_kx_server_session_keys};
use crate::constants::{
    CRYPTO_KX_PUBLICKEYBYTES, CRYPTO_KX_SECRETKEYBYTES, CRYPTO_KX_SESSIONKEYBYTES,
};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated session key type alias
pub type SessionKey = StackByteArray<CRYPTO_KX_SESSIONKEYBYTES>;
/// Stack-allocated public key type alias
pub type PublicKey = StackByteArray<CRYPTO_KX_PUBLICKEYBYTES>;
/// Stack-allocated secret key type alias
pub type SecretKey = StackByteArray<CRYPTO_KX_SECRETKEYBYTES>;
/// Stack-allocated keypair type alias
pub type KeyPair = crate::keypair::KeyPair<PublicKey, SecretKey>;

#[cfg_attr(feature = "serde", derive(Zeroize, Clone, Serialize, Deserialize))]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone))]
/// Key derivation implementation based on Curve25519, Diffie-Hellman, and
/// Blake2b. Compatible with libsodium's `crypto_kx_*` functions.
///
/// The session-key type must implement [`ZeroizeOnDrop`] so keys remain
/// self-wiping after [`Session::into_parts`] transfers ownership to the caller.
pub struct Session<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop> {
    rx_key: SessionKey,
    tx_key: SessionKey,
}

impl<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop> fmt::Debug
    for Session<SessionKey>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("rx_key", &"[REDACTED]")
            .field("tx_key", &"[REDACTED]")
            .finish()
    }
}

/// Stack-allocated type alias for [`Session`]. Provided for convenience.
pub type StackSession = Session<SessionKey>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`Session`]
    //!
    //! Protected-memory aliases for key exchange.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::kx::Session;
    //! use dryoc::kx::protected::*;
    //!
    //! // Generate random client/server keypairs
    //! let client_keypair = LockedROKeyPair::generate_readonly_locked_keypair()
    //!     .expect("couldn't generate client keypair");
    //! let server_keypair = LockedROKeyPair::generate_readonly_locked_keypair()
    //!     .expect("couldn't generate server keypair");
    //!
    //! // Compute client session keys, into default stack-allocated byte array
    //! let client_session_keys: LockedSession =
    //!     Session::new_client(&client_keypair, &server_keypair.public_key)
    //!         .expect("compute client failed");
    //!
    //! // Compute server session keys, into default stack-allocated byte array
    //! let server_session_keys: LockedSession =
    //!     Session::new_server(&server_keypair, &client_keypair.public_key)
    //!         .expect("compute client failed");
    //!
    //! let (client_rx, client_tx) = client_session_keys.into_parts();
    //! let (server_rx, server_tx) = server_session_keys.into_parts();
    //!
    //! // Client Rx should match server Tx keys
    //! assert_eq!(client_rx.as_slice(), server_tx.as_slice());
    //! // Client Tx should match server Rx keys
    //! assert_eq!(client_tx.as_slice(), server_rx.as_slice());
    //! ```
    use super::*;
    pub use crate::keypair::protected::*;

    /// Heap-allocated, page-aligned session key type alias for use with
    /// protected memory
    pub type SessionKey = HeapByteArray<CRYPTO_KX_SESSIONKEYBYTES>;
    /// Heap-allocated, page-aligned public key type alias for use with
    /// protected memory
    pub type PublicKey = HeapByteArray<CRYPTO_KX_PUBLICKEYBYTES>;
    /// Heap-allocated, page-aligned secret key type alias for use with
    /// protected memory
    pub type SecretKey = HeapByteArray<CRYPTO_KX_SECRETKEYBYTES>;

    /// Heap-allocated, page-aligned keypair type alias for use with
    /// protected memory
    pub type LockedKeyPair = crate::keypair::KeyPair<Locked<PublicKey>, Locked<SecretKey>>;
    /// Heap-allocated, page-aligned keypair type alias for use with
    /// protected memory
    pub type LockedROKeyPair = crate::keypair::KeyPair<LockedRO<PublicKey>, LockedRO<SecretKey>>;
    /// Locked session keys type alias, for use with protected memory
    pub type LockedSession = Session<Locked<SessionKey>>;
}

impl<SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop>
    Session<SessionKey>
{
    /// Computes client session keys, given `client_keypair` and
    /// `server_public_key`, returning a new session upon success.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_public_key` is unacceptable, including a
    /// low-order point that would produce an all-zero shared secret.
    pub fn new_client<
        PublicKey: ByteArray<CRYPTO_KX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: ByteArray<CRYPTO_KX_SECRETKEYBYTES> + Zeroize,
    >(
        client_keypair: &crate::keypair::KeyPair<PublicKey, SecretKey>,
        server_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        let mut rx_key = SessionKey::new_byte_array();
        let mut tx_key = SessionKey::new_byte_array();

        crypto_kx_client_session_keys(
            rx_key.as_mut_array(),
            tx_key.as_mut_array(),
            client_keypair.public_key.as_array(),
            client_keypair.secret_key.as_array(),
            server_public_key.as_array(),
        )?;

        Ok(Self { rx_key, tx_key })
    }

    /// Computes server session keys, given `server_keypair` and
    /// `client_public_key`, returning a new session upon success.
    ///
    /// # Errors
    ///
    /// Returns an error if `client_public_key` is unacceptable, including a
    /// low-order point that would produce an all-zero shared secret.
    pub fn new_server<
        PublicKey: ByteArray<CRYPTO_KX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: ByteArray<CRYPTO_KX_SECRETKEYBYTES> + Zeroize,
    >(
        server_keypair: &crate::keypair::KeyPair<PublicKey, SecretKey>,
        client_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        let mut rx_key = SessionKey::new_byte_array();
        let mut tx_key = SessionKey::new_byte_array();

        crypto_kx_server_session_keys(
            rx_key.as_mut_array(),
            tx_key.as_mut_array(),
            server_keypair.public_key.as_array(),
            server_keypair.secret_key.as_array(),
            client_public_key.as_array(),
        )?;

        Ok(Self { rx_key, tx_key })
    }
}

impl Session<SessionKey> {
    /// Returns a new client session upon success using the default types for
    /// the given `client_keypair` and `server_public_key`. Wraps
    /// [`Session::new_client`], provided for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_public_key` is unacceptable. See
    /// [`Session::new_client`].
    pub fn new_client_with_defaults<
        PublicKey: ByteArray<CRYPTO_KX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: ByteArray<CRYPTO_KX_SECRETKEYBYTES> + Zeroize,
    >(
        client_keypair: &crate::keypair::KeyPair<PublicKey, SecretKey>,
        server_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        Self::new_client(client_keypair, server_public_key)
    }

    /// Returns a new server session upon success using the default types for
    /// the given `server_keypair` and `client_public_key`. Wraps
    /// [`Session::new_server`], provided for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if `client_public_key` is unacceptable. See
    /// [`Session::new_server`].
    pub fn new_server_with_defaults<
        PublicKey: ByteArray<CRYPTO_KX_PUBLICKEYBYTES> + Zeroize,
        SecretKey: ByteArray<CRYPTO_KX_SECRETKEYBYTES> + Zeroize,
    >(
        server_keypair: &crate::keypair::KeyPair<PublicKey, SecretKey>,
        client_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        Self::new_server(server_keypair, client_public_key)
    }
}

impl<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize + ZeroizeOnDrop>
    Session<SessionKey>
{
    /// Moves the rx_key and tx_key out of this instance, returning them as a
    /// tuple with `(rx_key, tx_key)`.
    pub fn into_parts(self) -> (SessionKey, SessionKey) {
        (self.rx_key, self.tx_key)
    }

    /// Returns a reference to a slice of the Rx session key.
    #[inline]
    pub fn rx_as_slice(&self) -> &[u8] {
        self.rx_key.as_slice()
    }

    /// Returns a reference to a slice of the Tx session key.
    #[inline]
    pub fn tx_as_slice(&self) -> &[u8] {
        self.tx_key.as_slice()
    }

    /// Returns a reference to an array of the Rx session key.
    #[inline]
    pub fn rx_as_array(&self) -> &[u8; CRYPTO_KX_SESSIONKEYBYTES] {
        self.rx_key.as_array()
    }

    /// Returns a reference to an array of the Tx session key.
    #[inline]
    pub fn tx_as_array(&self) -> &[u8; CRYPTO_KX_SESSIONKEYBYTES] {
        self.tx_key.as_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_debug_redacts_keys() {
        let session = StackSession {
            rx_key: SessionKey::from([1u8; CRYPTO_KX_SESSIONKEYBYTES]),
            tx_key: SessionKey::from([2u8; CRYPTO_KX_SESSIONKEYBYTES]),
        };

        assert_eq!(
            format!("{session:?}"),
            "Session { rx_key: \"[REDACTED]\", tx_key: \"[REDACTED]\" }"
        );
    }

    use crate::classic::crypto_kx::{crypto_kx_client_session_keys, crypto_kx_server_session_keys};
    use crate::constants::CRYPTO_BOX_SEEDBYTES;
    use crate::utils::test_util::XorShift64;

    /// Client and server keypairs from `crypto_box_seed_keypair([1; 32])` and
    /// `[2; 32]`, with the session keys libsodium's `crypto_kx_*_session_keys`
    /// derive for them.
    const CLIENT_SEED: [u8; CRYPTO_BOX_SEEDBYTES] = [1u8; CRYPTO_BOX_SEEDBYTES];
    const SERVER_SEED: [u8; CRYPTO_BOX_SEEDBYTES] = [2u8; CRYPTO_BOX_SEEDBYTES];
    const CLIENT_RX: &str = "4081524abf55a75021ebd5e98e08552fb2bd26315c40e563b74e64abff1be442";
    const CLIENT_TX: &str = "2f9c2f944f504caf772db17affc91e3ba8886a806ba53ab37881d15c042f3410";

    fn kat_keypairs() -> (KeyPair, KeyPair) {
        (
            KeyPair::from_seed(&CLIENT_SEED),
            KeyPair::from_seed(&SERVER_SEED),
        )
    }

    fn low_order_public_keys() -> [PublicKey; 2] {
        let mut identity = PublicKey::default();
        identity[0] = 1;
        [PublicKey::default(), identity]
    }

    #[test]
    fn seeded_sessions_match_libsodium_known_answers_with_rx_tx_crossed() {
        let (client, server) = kat_keypairs();
        let client_rx = hex::decode(CLIENT_RX).expect("hex");
        let client_tx = hex::decode(CLIENT_TX).expect("hex");

        let client_session =
            Session::new_client_with_defaults(&client, &server.public_key).expect("client");
        let server_session =
            Session::new_server_with_defaults(&server, &client.public_key).expect("server");

        assert_eq!(client_session.rx_as_slice(), client_rx.as_slice());
        assert_eq!(client_session.tx_as_slice(), client_tx.as_slice());
        assert_eq!(client_session.rx_as_array(), &client_rx[..]);
        assert_eq!(client_session.tx_as_array(), &client_tx[..]);
        assert_eq!(server_session.rx_as_slice(), client_tx.as_slice());
        assert_eq!(server_session.tx_as_slice(), client_rx.as_slice());

        let (rx, tx) = client_session.into_parts();
        assert_eq!(rx.as_slice(), client_rx.as_slice());
        assert_eq!(tx.as_slice(), client_tx.as_slice());
        let (rx, tx) = server_session.into_parts();
        assert_eq!(rx.as_slice(), client_tx.as_slice());
        assert_eq!(tx.as_slice(), client_rx.as_slice());

        // Roles are part of the derivation: swapping them changes the keys.
        let swapped = Session::new_client_with_defaults(&server, &client.public_key).expect("kx");
        assert_ne!(swapped.rx_as_slice(), client_rx.as_slice());
        assert_ne!(swapped.rx_as_slice(), client_tx.as_slice());
    }

    #[test]
    fn sessions_match_classic_session_keys_for_generic_and_default_types() {
        let mut rng = XorShift64::new(0x6b78_5f73_6573_7300);
        for _ in 0..8 {
            let client = KeyPair::from_seed(&rng.next_bytes32());
            let server = KeyPair::from_seed(&rng.next_bytes32());

            let mut rx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
            let mut tx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
            crypto_kx_client_session_keys(
                &mut rx,
                &mut tx,
                client.public_key.as_array(),
                client.secret_key.as_array(),
                server.public_key.as_array(),
            )
            .expect("classic client");
            let session: Session<SessionKey> =
                Session::new_client(&client, &server.public_key).expect("client");
            assert_eq!(session.rx_as_array(), &rx);
            assert_eq!(session.tx_as_array(), &tx);
            let defaults =
                Session::new_client_with_defaults(&client, &server.public_key).expect("client");
            assert_eq!(defaults.rx_as_array(), &rx);
            assert_eq!(defaults.tx_as_array(), &tx);

            crypto_kx_server_session_keys(
                &mut rx,
                &mut tx,
                server.public_key.as_array(),
                server.secret_key.as_array(),
                client.public_key.as_array(),
            )
            .expect("classic server");
            let session: Session<SessionKey> =
                Session::new_server(&server, &client.public_key).expect("server");
            assert_eq!(session.rx_as_array(), &rx);
            assert_eq!(session.tx_as_array(), &tx);
            let defaults =
                Session::new_server_with_defaults(&server, &client.public_key).expect("server");
            assert_eq!(defaults.rx_as_array(), &rx);
            assert_eq!(defaults.tx_as_array(), &tx);
        }
    }

    #[test]
    fn low_order_peer_keys_are_rejected_on_both_sides() {
        let (client, server) = kat_keypairs();
        for low_order in low_order_public_keys() {
            assert!(Session::new_client_with_defaults(&client, &low_order).is_err());
            assert!(Session::new_server_with_defaults(&server, &low_order).is_err());
            let generic: Result<Session<SessionKey>, Error> =
                Session::new_client(&client, &low_order);
            assert!(generic.is_err());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_keeps_rx_and_tx_in_place() {
        use crate::dryocsecretbox::{DryocSecretBox, Nonce, VecBox};

        let (client, server) = kat_keypairs();
        let client_session =
            Session::new_client_with_defaults(&client, &server.public_key).expect("client");
        let server_session =
            Session::new_server_with_defaults(&server, &client.public_key).expect("server");

        let json = serde_json::to_string(&client_session).expect("serialize");
        let decoded: StackSession = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.rx_as_slice(), hex::decode(CLIENT_RX).expect("hex"));
        assert_eq!(decoded.tx_as_slice(), hex::decode(CLIENT_TX).expect("hex"));

        // The decoded client tx key opens what the server encrypts with its rx
        // key's counterpart, so the field order survived the round trip.
        let nonce = Nonce::from([7u8; crate::constants::CRYPTO_SECRETBOX_NONCEBYTES]);
        let (server_rx, server_tx) = server_session.into_parts();
        let (decoded_rx, decoded_tx) = decoded.into_parts();
        let from_server = DryocSecretBox::encrypt_to_vecbox(b"server says", &nonce, &server_tx);
        assert_eq!(
            VecBox::from_bytes(&from_server.to_vec())
                .expect("parse")
                .decrypt_to_vec(&nonce, &decoded_rx)
                .expect("decrypt"),
            b"server says"
        );
        let from_client = DryocSecretBox::encrypt_to_vecbox(b"client says", &nonce, &decoded_tx);
        assert_eq!(
            from_client
                .decrypt_to_vec(&nonce, &server_rx)
                .expect("decrypt"),
            b"client says"
        );
        assert!(from_client.decrypt_to_vec(&nonce, &server_tx).is_err());
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_sessions_match_stack_sessions() {
        use crate::kx::protected::*;

        let (client, server) = kat_keypairs();
        let locked_client = LockedKeyPair {
            public_key: protected::PublicKey::from_slice_into_locked(client.public_key.as_slice())
                .expect("lock client pk"),
            secret_key: protected::SecretKey::from_slice_into_locked(client.secret_key.as_slice())
                .expect("lock client sk"),
        };
        let locked_server_pk =
            protected::PublicKey::from_slice_into_locked(server.public_key.as_slice())
                .expect("lock server pk");

        let session: LockedSession =
            Session::new_client(&locked_client, &locked_server_pk).expect("client");
        assert_eq!(session.rx_as_slice(), hex::decode(CLIENT_RX).expect("hex"));
        assert_eq!(session.tx_as_slice(), hex::decode(CLIENT_TX).expect("hex"));

        let locked_low_order = protected::PublicKey::new_locked().expect("lock low-order key");
        let rejected: Result<LockedSession, Error> =
            Session::new_client(&locked_client, &locked_low_order);
        assert!(rejected.is_err());
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn sessions_match_libsodium_session_keys() {
        let mut rng = XorShift64::new(0x6c69_6273_6f64_6b78);
        for _ in 0..8 {
            let client = KeyPair::from_seed(&rng.next_bytes32());
            let server = KeyPair::from_seed(&rng.next_bytes32());
            let client_session =
                Session::new_client_with_defaults(&client, &server.public_key).expect("client");
            let server_session =
                Session::new_server_with_defaults(&server, &client.public_key).expect("server");

            let mut rx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
            let mut tx = [0u8; CRYPTO_KX_SESSIONKEYBYTES];
            let rc = unsafe {
                libsodium_sys::crypto_kx_client_session_keys(
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    client.public_key.as_ptr(),
                    client.secret_key.as_ptr(),
                    server.public_key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(client_session.rx_as_array(), &rx);
            assert_eq!(client_session.tx_as_array(), &tx);

            let rc = unsafe {
                libsodium_sys::crypto_kx_server_session_keys(
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    server.public_key.as_ptr(),
                    server.secret_key.as_ptr(),
                    client.public_key.as_ptr(),
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(server_session.rx_as_array(), &rx);
            assert_eq!(server_session.tx_as_array(), &tx);
        }
    }
}

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
use zeroize::Zeroize;

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
pub struct Session<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize> {
    rx_key: SessionKey,
    tx_key: SessionKey,
}

impl<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize> fmt::Debug
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

impl<SessionKey: NewByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize> Session<SessionKey> {
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

impl<SessionKey: ByteArray<CRYPTO_KX_SESSIONKEYBYTES> + Zeroize> Session<SessionKey> {
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

    #[test]
    fn test_kx() {
        let client_keypair = KeyPair::generate();
        let server_keypair = KeyPair::generate();

        let client_session_keys =
            Session::new_client_with_defaults(&client_keypair, &server_keypair.public_key)
                .expect("compute client failed");

        let server_session_keys =
            Session::new_server_with_defaults(&server_keypair, &client_keypair.public_key)
                .expect("compute client failed");

        let (client_rx, client_tx) = client_session_keys.into_parts();
        let (server_rx, server_tx) = server_session_keys.into_parts();

        assert_eq!(client_rx, server_tx);
        assert_eq!(client_tx, server_rx);
    }

    #[test]
    fn test_kx_rejects_low_order_public_key() {
        let client_keypair = KeyPair::generate();
        let low_order_public_key = PublicKey::default();

        assert!(Session::new_client_with_defaults(&client_keypair, &low_order_public_key).is_err());
    }
}

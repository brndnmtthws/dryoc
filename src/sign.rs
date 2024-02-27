//! # Public-key signatures
//!
//! This module implements libsodium's public-key signature functions. The
//! signatures are based on Ed25519 (EdDSA). It provides both a
//! [single-part](SigningKeyPair::sign) and [multi-part](IncrementalSigner)
//! interface.
//!
//! The single-part interface is convenient for short
//! messages, such as those small enough to fit in memory. The multi-part
//! interface may be more appropriate for lengthy messages, those which don't
//! fit in memory, or those for which the entire message isn't known at once
//! (i.e., during network communication, or reading a large file).
//!
//! The single-part and multi-part variants use slightly different algorithms,
//! and thus they are not compatible with each other.
//!
//! You should use a this module when you want to:
//!
//! * share a message with other parties, and provide a proof that the message
//!   is authentic
//! * verify that the message from another party was signed using their secret
//!   key, without having knowledge of the original secret
//!
//! The public key of the signer must be known to the verifier.
//!
//! One should take note that keys used for signing and encryption should remain
//! separate. While it's possible to convert Ed25519 keys to X25519 keys (or
//! derive them from the same seed), one is cautioned against doing so.
//!
//! ## Rustaceous API example, single-part
//!
//! ```
//! use dryoc::sign::*;
//!
//! // Generate a random keypair, using default types
//! let keypair = SigningKeyPair::gen_with_defaults();
//! let message = b"Fair is foul, and foul is fair: Hover through the fog and filthy air.";
//!
//! // Sign the message, using default types (stack-allocated byte array, Vec<u8>)
//! let signed_message = keypair.sign_with_defaults(message).expect("signing failed");
//!
//! // Verify the message signature
//! signed_message
//!     .verify(&keypair.public_key)
//!     .expect("verification failed");
//! ```
//!
//! ## Incremental (multi-part) interface
//!
//! ```
//! use dryoc::sign::*;
//!
//! // Generate a random keypair, using default types
//! let keypair = SigningKeyPair::gen_with_defaults();
//!
//! // Initialize the incremental signer interface
//! let mut signer = IncrementalSigner::new();
//! signer.update(b"This above all: to thine ownself be true.");
//! signer.update(b"And it must follow, as the night the day,");
//! signer.update(b"Thou canst not then be false to any man.");
//!
//! let signature: Signature = signer
//!     .finalize(&keypair.secret_key)
//!     .expect("signing failed");
//! ```
//!
//! ## Additional resources
//!
//! * See <https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures>
//!   for additional details on public-key signatures
//! * For secret-key based encryption, see
//!   [`DryocSecretBox`](crate::dryocsecretbox)
//! * For stream encryption, see [`DryocStream`](crate::dryocstream)
//! * See the [protected] mod for an example using the protected memory features

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_sign::{
    crypto_sign_detached, crypto_sign_final_create, crypto_sign_final_verify, crypto_sign_init,
    crypto_sign_keypair_inplace, crypto_sign_seed_keypair_inplace, crypto_sign_update,
    crypto_sign_verify_detached, SignerState,
};
use crate::constants::{
    CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES, CRYPTO_SIGN_SECRETKEYBYTES,
    CRYPTO_SIGN_SEEDBYTES,
};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated public key for message signing.
pub type PublicKey = StackByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>;
/// Stack-allocated secret key for message signing.
pub type SecretKey = StackByteArray<CRYPTO_SIGN_SECRETKEYBYTES>;
/// Stack-allocated signature for message signing.
pub type Signature = StackByteArray<CRYPTO_SIGN_BYTES>;
/// Heap-allocated message for message signing.
pub type Message = Vec<u8>;

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Debug, Clone)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, ZeroizeOnDrop, Debug, Clone))]
/// An Ed25519 keypair for public-key signatures
pub struct SigningKeyPair<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

impl<
    PublicKey: NewByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: NewByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Creates a new, empty signing keypair.
    pub fn new() -> Self {
        Self {
            public_key: PublicKey::new_byte_array(),
            secret_key: SecretKey::new_byte_array(),
        }
    }

    /// Generates a random signing keypair.
    pub fn gen() -> Self {
        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();
        crypto_sign_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());
        Self {
            public_key,
            secret_key,
        }
    }

    /// Derives a signing keypair from `secret_key`, and consumes it, returning
    /// a new keypair.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret_key.as_slice()[..32]);

        Self::from_seed(&seed)
    }

    /// Derives a signing keypair from `seed`, returning
    /// a new keypair.
    pub fn from_seed<Seed: ByteArray<CRYPTO_SIGN_SEEDBYTES>>(seed: &Seed) -> Self {
        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();

        crypto_sign_seed_keypair_inplace(
            public_key.as_mut_array(),
            secret_key.as_mut_array(),
            seed.as_array(),
        );

        Self {
            public_key,
            secret_key,
        }
    }
}

impl
    SigningKeyPair<
        StackByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>,
        StackByteArray<CRYPTO_SIGN_SECRETKEYBYTES>,
    >
{
    /// Randomly generates a new signing keypair, using default types
    /// (stack-allocated byte arrays). Provided for convenience.
    pub fn gen_with_defaults() -> Self {
        Self::gen()
    }
}

impl<
    'a,
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Constructs a new signing keypair from key slices, consuming them. Does
    /// not check validity or authenticity of keypair.
    pub fn from_slices(public_key: &'a [u8], secret_key: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            public_key: PublicKey::try_from(public_key)
                .map_err(|_e| dryoc_error!("invalid public key"))?,
            secret_key: SecretKey::try_from(secret_key)
                .map_err(|_e| dryoc_error!("invalid secret key"))?,
        })
    }
}

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory for [`SigningKeyPair`] and [`SignedMessage`].
    //!
    //! ## Example
    //! ```
    //! use dryoc::sign::protected::*;
    //! use dryoc::sign::SigningKeyPair;
    //!
    //! // Generate a random keypair, using default types
    //! let keypair = SigningKeyPair::gen_locked_keypair().expect("keypair gen failed");
    //! let message = Message::from_slice_into_locked(
    //!     b"Fair is foul, and foul is fair: Hover through the fog and filthy air.",
    //! )
    //! .expect("message lock failed");
    //!
    //! // Sign the message, using default types (stack-allocated byte array, Vec<u8>)
    //! let signed_message: LockedSignedMessage = keypair.sign(message).expect("signing failed");
    //!
    //! // Verify the message signature
    //! signed_message
    //!     .verify(&keypair.public_key)
    //!     .expect("verification failed");
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned public-key for signed messages,
    /// for use with protected memory.
    pub type PublicKey = HeapByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>;
    /// Heap-allocated, page-aligned secret-key for signed messages,
    /// for use with protected memory.
    pub type SecretKey = HeapByteArray<CRYPTO_SIGN_SECRETKEYBYTES>;
    /// Heap-allocated, page-aligned signature for signed messages,
    /// for use with protected memory.
    pub type Signature = HeapByteArray<CRYPTO_SIGN_BYTES>;
    /// Heap-allocated, page-aligned message for signed messages,
    /// for use with protected memory.
    pub type Message = HeapBytes;

    /// Heap-allocated, page-aligned public/secret keypair for message signing,
    /// for use with protected memory.
    pub type LockedSigningKeyPair = SigningKeyPair<Locked<PublicKey>, Locked<SecretKey>>;
    /// Heap-allocated, page-aligned signed message, for use with protected
    /// memory.
    pub type LockedSignedMessage = SignedMessage<Locked<Signature>, Locked<Message>>;

    impl
        SigningKeyPair<
            Locked<HeapByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>>,
            Locked<HeapByteArray<CRYPTO_SIGN_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new locked signing keypair.
        pub fn new_locked_keypair() -> Result<Self, std::io::Error> {
            Ok(Self {
                public_key: HeapByteArray::<CRYPTO_SIGN_PUBLICKEYBYTES>::new_locked()?,
                secret_key: HeapByteArray::<CRYPTO_SIGN_SECRETKEYBYTES>::new_locked()?,
            })
        }

        /// Returns a new randomly generated locked signing keypair.
        pub fn gen_locked_keypair() -> Result<Self, std::io::Error> {
            let mut res = Self::new_locked_keypair()?;

            crypto_sign_keypair_inplace(
                res.public_key.as_mut_array(),
                res.secret_key.as_mut_array(),
            );

            Ok(res)
        }
    }

    impl
        SigningKeyPair<
            LockedRO<HeapByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>>,
            LockedRO<HeapByteArray<CRYPTO_SIGN_SECRETKEYBYTES>>,
        >
    {
        /// Returns a new randomly generated locked, read-only signing keypair.
        pub fn gen_readonly_locked_keypair() -> Result<Self, std::io::Error> {
            let mut public_key = HeapByteArray::<CRYPTO_SIGN_PUBLICKEYBYTES>::new_locked()?;
            let mut secret_key = HeapByteArray::<CRYPTO_SIGN_SECRETKEYBYTES>::new_locked()?;

            crypto_sign_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());

            let public_key = public_key.mprotect_readonly()?;
            let secret_key = secret_key.mprotect_readonly()?;

            Ok(Self {
                public_key,
                secret_key,
            })
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A signed message, for use with [`SigningKeyPair`].
pub struct SignedMessage<
    Signature: ByteArray<CRYPTO_SIGN_BYTES> + Zeroize,
    Message: Bytes + Zeroize,
> {
    signature: Signature,
    message: Message,
}

/// [Vec]-based signed message.
pub type VecSignedMessage = SignedMessage<Signature, Vec<u8>>;

impl<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Signs `message` using this keypair, consuming the message, and returning
    /// a new [`SignedMessage`]. The type of `message` should match that of the
    /// target signed message.
    pub fn sign<Signature: NewByteArray<CRYPTO_SIGN_BYTES> + Zeroize, Message: Bytes + Zeroize>(
        &self,
        message: Message,
    ) -> Result<SignedMessage<Signature, Message>, Error> {
        let mut signature = Signature::new_byte_array();
        crypto_sign_detached(
            signature.as_mut_array(),
            message.as_slice(),
            self.secret_key.as_array(),
        )?;

        Ok(SignedMessage::<Signature, Message> { signature, message })
    }

    /// Signs `message`, putting the result into a [`Vec`]. Convenience wrapper
    /// for [`SigningKeyPair::sign`].
    pub fn sign_with_defaults<Message: Bytes>(
        &self,
        message: Message,
    ) -> Result<SignedMessage<StackByteArray<CRYPTO_SIGN_BYTES>, Vec<u8>>, Error> {
        self.sign(Vec::from(message.as_slice()))
    }
}

impl Default for SigningKeyPair<PublicKey, SecretKey> {
    fn default() -> Self {
        Self::new()
    }
}

/// Multi-part (incremental)  interface for [`SigningKeyPair`].
pub struct IncrementalSigner {
    state: SignerState,
}

impl IncrementalSigner {
    /// Returns a new incremental signer instance.
    pub fn new() -> Self {
        Self {
            state: crypto_sign_init(),
        }
    }

    /// Updates the state for this incremental signer with `message`.
    pub fn update<Message: Bytes>(&mut self, message: &Message) {
        crypto_sign_update(&mut self.state, message.as_slice())
    }

    /// Finalizes this incremental signer, returning the signature upon
    /// success.
    pub fn finalize<
        Signature: NewByteArray<CRYPTO_SIGN_BYTES>,
        SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES>,
    >(
        self,
        secret_key: &SecretKey,
    ) -> Result<Signature, Error> {
        let mut signature = Signature::new_byte_array();

        crypto_sign_final_create(self.state, signature.as_mut_array(), secret_key.as_array())?;

        Ok(signature)
    }

    /// Verifies `signature` as a valid signature for this signer.
    pub fn verify<
        Signature: ByteArray<CRYPTO_SIGN_BYTES>,
        PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>,
    >(
        self,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        crypto_sign_final_verify(self.state, signature.as_array(), public_key.as_array())?;

        Ok(())
    }
}

impl Default for IncrementalSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl<Signature: ByteArray<CRYPTO_SIGN_BYTES> + Zeroize, Message: Bytes + Zeroize>
    SignedMessage<Signature, Message>
{
    /// Verifies that this signed message is valid for `public_key`.
    pub fn verify<PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>>(
        &self,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        crypto_sign_verify_detached(
            self.signature.as_array(),
            self.message.as_slice(),
            public_key.as_array(),
        )
    }
}

impl<
    'a,
    Signature: ByteArray<CRYPTO_SIGN_BYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    Message: Bytes + From<&'a [u8]> + Zeroize,
> SignedMessage<Signature, Message>
{
    /// Initializes a [`SignedMessage`] from a slice. Expects the first
    /// [`CRYPTO_SIGN_BYTES`] bytes to contain the message signature,
    /// with the remaining bytes containing the message.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CRYPTO_SIGN_BYTES {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                CRYPTO_SIGN_BYTES
            )))
        } else {
            let (signature, message) = bytes.split_at(CRYPTO_SIGN_BYTES);
            Ok(Self {
                signature: Signature::try_from(signature)
                    .map_err(|_e| dryoc_error!("invalid signature"))?,
                message: Message::from(message),
            })
        }
    }
}

impl<Signature: ByteArray<CRYPTO_SIGN_BYTES> + Zeroize, Message: Bytes + Zeroize>
    SignedMessage<Signature, Message>
{
    /// Returns a new box with `tag`, `data` and (optional) `ephemeral_pk`,
    /// consuming each.
    pub fn from_parts(signature: Signature, message: Message) -> Self {
        Self { signature, message }
    }

    /// Copies `self` into a new [`Vec`]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Moves the tag, data, and (optional) ephemeral public key out of this
    /// instance, returning them as a tuple.
    pub fn into_parts(self) -> (Signature, Message) {
        (self.signature, self.message)
    }

    /// Copies `self` into the target. Can be used with protected memory.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        let mut data = Bytes::new_bytes();

        data.resize(self.signature.len() + self.message.len(), 0);
        let s = data.as_mut_slice();
        s[..CRYPTO_SIGN_BYTES].copy_from_slice(self.signature.as_slice());
        s[CRYPTO_SIGN_BYTES..].copy_from_slice(self.message.as_slice());

        data
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> PartialEq<SigningKeyPair<PublicKey, SecretKey>> for SigningKeyPair<PublicKey, SecretKey>
{
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .as_slice()
            .ct_eq(other.public_key.as_slice())
            .unwrap_u8()
            == 1
            && self
                .secret_key
                .as_slice()
                .ct_eq(other.secret_key.as_slice())
                .unwrap_u8()
                == 1
    }
}

impl<Signature: ByteArray<CRYPTO_SIGN_BYTES> + Zeroize, Message: Bytes + Zeroize>
    PartialEq<SignedMessage<Signature, Message>> for SignedMessage<Signature, Message>
{
    fn eq(&self, other: &Self) -> bool {
        self.signature
            .as_slice()
            .ct_eq(other.signature.as_slice())
            .unwrap_u8()
            == 1
            && self
                .message
                .as_slice()
                .ct_eq(other.message.as_slice())
                .unwrap_u8()
                == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_signing() {
        let keypair = SigningKeyPair::gen_with_defaults();
        let message = b"hello my frens";

        let signed_message = keypair.sign_with_defaults(message).expect("signing failed");

        signed_message
            .verify(&keypair.public_key)
            .expect("verification failed");
    }
}

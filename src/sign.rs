//! # Public-key signatures
//!
//! This module provides libsodium-compatible Ed25519 signatures. A signer uses
//! a secret key to sign a message. Anyone with the corresponding public key can
//! verify that signature and detect changes to the message. Signatures do not
//! encrypt the message.
//!
//! [`SigningKeyPair::sign`] signs a complete message with Ed25519. Use
//! [`IncrementalSigner`] when the message is too large to keep in memory or
//! arrives in parts. The incremental API uses Ed25519ph, so its signatures
//! cannot be verified by the single-part Ed25519 API, or vice versa.
//!
//! The verifier must obtain the signer's public key through a trusted channel.
//! A signature only proves control of the matching secret key; it does not
//! establish who owns that key.
//!
//! Keep signing and encryption keys separate. Although Ed25519 keys can be
//! converted to X25519 keys or derived from the same seed, doing so couples two
//! distinct security roles.
//!
//! Signing secret keys include both the seed and public key. Use
//! [`secret_key_to_seed`], [`secret_key_to_public_key`],
//! [`SigningKeyPair::to_seed`], or [`SigningKeyPair::to_public_key`] to extract
//! those parts when interoperating with libsodium-style key storage.
//!
//! ## Rustaceous API example, single-part
//!
//! ```
//! use dryoc::sign::*;
//!
//! // Generate a random keypair, using default types
//! let keypair = SigningKeyPair::<PublicKey, SecretKey>::generate();
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
//! ## Extracting key material
//!
//! ```
//! use dryoc::sign::*;
//!
//! let seed = Seed::from([7u8; dryoc::constants::CRYPTO_SIGN_SEEDBYTES]);
//! let keypair = SigningKeyPair::<PublicKey, SecretKey>::from_seed(&seed);
//!
//! let extracted_seed: Seed = keypair.to_seed();
//! let extracted_public_key: PublicKey = keypair.to_public_key();
//!
//! assert_eq!(extracted_seed, seed);
//! assert_eq!(extracted_public_key, keypair.public_key);
//! ```
//!
//! ## Incremental (multi-part) interface
//!
//! ```
//! use dryoc::sign::*;
//!
//! // Generate a random keypair, using default types
//! let keypair = SigningKeyPair::<PublicKey, SecretKey>::generate();
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
//! * See the [libsodium documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
//!   for more about public-key signatures
//! * For shared-key encryption, see [`DryocSecretBox`](crate::dryocsecretbox)
//! * For encrypted message streams, see [`DryocStream`](crate::dryocstream)
//! * See the [`protected`] module for examples that store keys in protected
//!   memory

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::classic::crypto_sign::{
    SignerState, crypto_sign_detached, crypto_sign_ed25519_sk_to_pk,
    crypto_sign_ed25519_sk_to_seed, crypto_sign_final_create, crypto_sign_final_verify,
    crypto_sign_init, crypto_sign_keypair_inplace, crypto_sign_seed_keypair_inplace,
    crypto_sign_update, crypto_sign_verify_detached,
};
use crate::constants::{
    CRYPTO_SIGN_BYTES, CRYPTO_SIGN_PUBLICKEYBYTES, CRYPTO_SIGN_SECRETKEYBYTES,
    CRYPTO_SIGN_SEEDBYTES,
};
use crate::error::{Error, ErrorContext};
use crate::types::*;
use crate::utils::{ct_eq_bytes, split_prefix};

/// Stack-allocated public key for message signing.
pub type PublicKey = StackByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>;
/// Stack-allocated secret key for message signing.
pub type SecretKey = StackByteArray<CRYPTO_SIGN_SECRETKEYBYTES>;
/// Stack-allocated seed for message signing.
pub type Seed = StackByteArray<CRYPTO_SIGN_SEEDBYTES>;
/// Stack-allocated signature for message signing.
pub type Signature = StackByteArray<CRYPTO_SIGN_BYTES>;
/// Heap-allocated message for message signing.
#[cfg(feature = "alloc")]
pub type Message = Vec<u8>;

/// Extracts the Ed25519 seed from a signing secret key.
pub fn secret_key_to_seed<
    SeedOut: NewByteArray<CRYPTO_SIGN_SEEDBYTES>,
    SigningSecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES>,
>(
    secret_key: &SigningSecretKey,
) -> SeedOut {
    let mut seed = SeedOut::new_byte_array();
    crypto_sign_ed25519_sk_to_seed(seed.as_mut_array(), secret_key.as_array());
    seed
}

/// Extracts the Ed25519 public key from a signing secret key.
pub fn secret_key_to_public_key<
    PublicKeyOut: NewByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>,
    SigningSecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES>,
>(
    secret_key: &SigningSecretKey,
) -> PublicKeyOut {
    let mut public_key = PublicKeyOut::new_byte_array();
    crypto_sign_ed25519_sk_to_pk(public_key.as_mut_array(), secret_key.as_array());
    public_key
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, ZeroizeOnDrop, Clone))]
/// An Ed25519 keypair for public-key signatures
///
/// Create keypairs with [`SigningKeyPair::generate`],
/// [`SigningKeyPair::from_seed`], or [`SigningKeyPair::from_secret_key`].
/// There is no `new` or [`Default`] constructor, so an all-zero secret key is
/// never produced implicitly.
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
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> fmt::Debug for SigningKeyPair<PublicKey, SecretKey>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("public_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl<
    PublicKey: NewByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: NewByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Generates a random signing keypair.
    pub fn generate() -> Self {
        let mut public_key = PublicKey::new_byte_array();
        let mut secret_key = SecretKey::new_byte_array();
        crypto_sign_keypair_inplace(public_key.as_mut_array(), secret_key.as_mut_array());
        Self {
            public_key,
            secret_key,
        }
    }

    /// Derives a signing keypair from `secret_key`, and consumes it, returning
    /// a new keypair. The consumed key is wiped, even if its type does not
    /// wipe itself on drop.
    pub fn from_secret_key(mut secret_key: SecretKey) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&secret_key.as_slice()[..32]);
        secret_key.zeroize();

        Self::from_seed(&*seed)
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

impl<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Extracts the Ed25519 seed from this keypair's secret key.
    pub fn to_seed<SeedOut: NewByteArray<CRYPTO_SIGN_SEEDBYTES>>(&self) -> SeedOut {
        secret_key_to_seed(&self.secret_key)
    }

    /// Extracts the Ed25519 public key embedded in this keypair's secret key.
    pub fn to_public_key<PublicKeyOut: NewByteArray<CRYPTO_SIGN_PUBLICKEYBYTES>>(
        &self,
    ) -> PublicKeyOut {
        secret_key_to_public_key(&self.secret_key)
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
    pub fn generate_with_defaults() -> Self {
        Self::generate()
    }
}

impl<
    'a,
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + core::convert::TryFrom<&'a [u8]> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + core::convert::TryFrom<&'a [u8]> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Constructs a new signing keypair from key slices, consuming them. Does
    /// not check validity or authenticity of keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if either slice has the wrong length for its key type,
    /// or if the target key type rejects the key bytes.
    pub fn from_slices(public_key: &'a [u8], secret_key: &'a [u8]) -> Result<Self, Error> {
        validate_length!(
            exact CRYPTO_SIGN_PUBLICKEYBYTES,
            public_key.len(),
            crate::ErrorContext::PublicKey
        );
        validate_length!(
            exact CRYPTO_SIGN_SECRETKEYBYTES,
            secret_key.len(),
            crate::ErrorContext::SecretKey
        );

        Ok(Self {
            public_key: PublicKey::try_from(public_key)
                .map_err(|_| Error::invalid_key(crate::ErrorContext::PublicKey))?,
            secret_key: SecretKey::try_from(secret_key)
                .map_err(|_| Error::invalid_key(crate::ErrorContext::SecretKey))?,
        })
    }
}

#[cfg(any(
    all(feature = "protected", any(unix, windows)),
    all(doc, not(doctest), feature = "std")
))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory for [`SigningKeyPair`] and [`SignedMessage`]
    //!
    //! ## Example
    //! ```
    //! use dryoc::sign::SigningKeyPair;
    //! use dryoc::sign::protected::*;
    //!
    //! // Generate a random keypair, using default types
    //! let keypair = SigningKeyPair::generate_locked_keypair().expect("keypair generate failed");
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
    /// Heap-allocated, page-aligned seed for signed messages,
    /// for use with protected memory.
    pub type Seed = HeapByteArray<CRYPTO_SIGN_SEEDBYTES>;
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
        /// Returns a new randomly generated locked signing keypair.
        ///
        /// # Errors
        ///
        /// Returns [`Error::Io`] if either allocation cannot be locked.
        ///
        /// # Panics
        ///
        /// Panics if either page-aligned allocation cannot be created, its
        /// size cannot be represented with guard pages, or the operating
        /// system's random number generator fails.
        pub fn generate_locked_keypair() -> Result<Self, Error> {
            let mut res = Self {
                public_key: HeapByteArray::<CRYPTO_SIGN_PUBLICKEYBYTES>::new_locked()?,
                secret_key: HeapByteArray::<CRYPTO_SIGN_SECRETKEYBYTES>::new_locked()?,
            };

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
        ///
        /// # Errors
        ///
        /// Returns [`Error::Io`] if either allocation cannot be locked or its
        /// page permissions cannot be changed to read-only.
        ///
        /// # Panics
        ///
        /// Panics if either page-aligned allocation cannot be created, its
        /// size cannot be represented with guard pages, or the operating
        /// system's random number generator fails.
        pub fn generate_readonly_locked_keypair() -> Result<Self, Error> {
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
#[cfg(feature = "alloc")]
pub type VecSignedMessage = SignedMessage<Signature, Vec<u8>>;

impl<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> SigningKeyPair<PublicKey, SecretKey>
{
    /// Signs `message` using this keypair, consuming the message, and returning
    /// a new [`SignedMessage`]. The type of `message` should match that of the
    /// target signed message.
    ///
    /// # Errors
    ///
    /// The fixed-size signature and secret-key types satisfy the current
    /// implementation's requirements, so this function does not return an
    /// error for valid type implementations. The [`Result`] is retained for
    /// compatibility with the underlying signing API.
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
    ///
    /// # Errors
    ///
    /// The default fixed-size types satisfy the current implementation's
    /// requirements, so this function does not return an error in normal use.
    /// The [`Result`] is retained for API compatibility.
    #[cfg(feature = "alloc")]
    pub fn sign_with_defaults<Message: Bytes>(
        &self,
        message: Message,
    ) -> Result<SignedMessage<StackByteArray<CRYPTO_SIGN_BYTES>, Vec<u8>>, Error> {
        self.sign(Vec::from(message.as_slice()))
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
    ///
    /// # Errors
    ///
    /// The fixed-size signature and secret-key types satisfy the current
    /// implementation's requirements, so this function does not return an
    /// error for valid type implementations. The [`Result`] is retained for
    /// compatibility with the underlying signing API.
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
    ///
    /// # Errors
    ///
    /// Returns an error if `signature` is not valid for the accumulated
    /// message and `public_key`.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is not valid for the message and
    /// `public_key`.
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
    Signature: ByteArray<CRYPTO_SIGN_BYTES> + core::convert::TryFrom<&'a [u8]> + Zeroize,
    Message: Bytes + From<&'a [u8]> + Zeroize,
> SignedMessage<Signature, Message>
{
    /// Initializes a [`SignedMessage`] from a slice. Expects the first
    /// [`CRYPTO_SIGN_BYTES`] bytes to contain the message signature,
    /// with the remaining bytes containing the message.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is shorter than a signature or the
    /// signature cannot be converted to the requested output type.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let (signature, message) =
            split_prefix(bytes, CRYPTO_SIGN_BYTES, ErrorContext::SignedMessage)?;
        Ok(Self {
            signature: Signature::try_from(signature)
                .map_err(|_| Error::invalid_encoding(ErrorContext::Signature))?,
            message: Message::from(message),
        })
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
    #[cfg(feature = "alloc")]
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
        concat_bytes(self.signature.as_array(), self.message.as_slice())
    }
}

impl<
    PublicKey: ByteArray<CRYPTO_SIGN_PUBLICKEYBYTES> + Zeroize,
    SecretKey: ByteArray<CRYPTO_SIGN_SECRETKEYBYTES> + Zeroize,
> PartialEq<SigningKeyPair<PublicKey, SecretKey>> for SigningKeyPair<PublicKey, SecretKey>
{
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.public_key.as_slice(), other.public_key.as_slice())
            && ct_eq_bytes(self.secret_key.as_slice(), other.secret_key.as_slice())
    }
}

impl<Signature: ByteArray<CRYPTO_SIGN_BYTES> + Zeroize, Message: Bytes + Zeroize>
    PartialEq<SignedMessage<Signature, Message>> for SignedMessage<Signature, Message>
{
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(self.signature.as_slice(), other.signature.as_slice())
            && ct_eq_bytes(self.message.as_slice(), other.message.as_slice())
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn signing_keypair_debug_redacts_keys_and_secret_key_reconstructs_keypair() {
        let keypair = SigningKeyPair::<PublicKey, SecretKey>::generate();
        let debug = format!("{keypair:?}");
        let reconstructed = SigningKeyPair::from_secret_key(keypair.secret_key.clone());

        assert_eq!(
            debug,
            "SigningKeyPair { public_key: \"[REDACTED]\", secret_key: \"[REDACTED]\" }"
        );
        assert_eq!(reconstructed, keypair);
    }

    #[test]
    fn test_message_signing() {
        let keypair = SigningKeyPair::generate_with_defaults();
        let message = b"hello my frens";

        let signed_message = keypair.sign_with_defaults(message).expect("signing failed");

        signed_message
            .verify(&keypair.public_key)
            .expect("verification failed");
    }

    #[test]
    fn test_secret_key_extraction() {
        let seed = Seed::generate();
        let keypair = SigningKeyPair::<PublicKey, SecretKey>::from_seed(&seed);

        let extracted_seed: Seed = keypair.to_seed();
        let extracted_public_key: PublicKey = keypair.to_public_key();
        assert_eq!(extracted_seed, seed);
        assert_eq!(extracted_public_key, keypair.public_key);

        let extracted_seed_array: [u8; CRYPTO_SIGN_SEEDBYTES] =
            secret_key_to_seed(&keypair.secret_key);
        let extracted_public_key_array: [u8; CRYPTO_SIGN_PUBLICKEYBYTES] =
            secret_key_to_public_key(&keypair.secret_key);
        assert_eq!(&extracted_seed_array, seed.as_array());
        assert_eq!(&extracted_public_key_array, keypair.public_key.as_array());
    }

    /// RFC 8032 section 7.1 (Ed25519) tests 1-3 and section 7.3 (Ed25519ph):
    /// `(seed, public key, message, signature)`.
    const RFC8032_ED25519: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            concat!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ),
    ];
    const RFC8032_ED25519PH: (&str, &str, &str, &str) = (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "616263",
        concat!(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41",
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
        ),
    );

    fn array<const N: usize>(hex: &str) -> StackByteArray<N> {
        StackByteArray::try_from(hex::decode(hex).expect("hex").as_slice()).expect("length")
    }

    fn rfc_keypair(seed: &str, public_key: &str) -> SigningKeyPair<PublicKey, SecretKey> {
        let keypair = SigningKeyPair::from_seed(&array::<CRYPTO_SIGN_SEEDBYTES>(seed));
        assert_eq!(
            keypair.public_key,
            array::<CRYPTO_SIGN_PUBLICKEYBYTES>(public_key)
        );
        assert_eq!(
            keypair.to_seed::<Seed>(),
            array::<CRYPTO_SIGN_SEEDBYTES>(seed)
        );
        keypair
    }

    #[test]
    fn rfc8032_detached_signatures_and_signed_message_wire_format() {
        for (seed, public_key, message, signature) in RFC8032_ED25519 {
            let keypair = rfc_keypair(seed, public_key);
            let message = hex::decode(message).expect("hex");
            let expected: Signature = array(signature);

            let signed = keypair
                .sign_with_defaults(message.as_slice())
                .expect("signing failed");
            assert_eq!(signed.signature, expected);
            assert_eq!(signed.message, message);
            signed.verify(&keypair.public_key).expect("verify failed");

            let mut wire = expected.to_vec();
            wire.extend_from_slice(&message);
            assert_eq!(signed.to_vec(), wire);
            let parsed = VecSignedMessage::from_bytes(&wire).expect("parse");
            assert_eq!(parsed, signed);
            parsed.verify(&keypair.public_key).expect("verify failed");

            let (parsed_signature, parsed_message) = parsed.into_parts();
            assert_eq!(parsed_signature, expected);
            assert_eq!(parsed_message, message);
            let rebuilt = VecSignedMessage::from_parts(parsed_signature, parsed_message);
            assert_eq!(rebuilt.to_bytes::<Vec<u8>>(), wire);
            rebuilt.verify(&keypair.public_key).expect("verify failed");

            // `sign` with an explicit message type agrees with the Vec wrapper.
            let signed_array: SignedMessage<Signature, Vec<u8>> =
                keypair.sign(message.clone()).expect("signing failed");
            assert_eq!(signed_array, signed);

            // The secret key embeds the public key.
            assert_eq!(keypair.to_public_key::<PublicKey>(), keypair.public_key);
            assert_eq!(
                SigningKeyPair::from_secret_key(keypair.secret_key.clone()),
                keypair
            );
        }
    }

    #[test]
    fn rfc8032_ed25519ph_vector_through_incremental_signer() {
        let (seed, public_key, message, signature) = RFC8032_ED25519PH;
        let keypair = rfc_keypair(seed, public_key);
        let message = hex::decode(message).expect("hex");
        let expected: Signature = array(signature);

        let splits: [&[&[u8]]; 4] = [
            &[&message],
            &[&message[..1], &message[1..]],
            &[&[], &message[..2], &message[2..], &[]],
            &[&message[..1], &message[1..2], &message[2..]],
        ];
        for parts in splits {
            let mut signer = IncrementalSigner::new();
            for part in parts {
                signer.update(part);
            }
            let actual: Signature = signer
                .finalize(&keypair.secret_key)
                .expect("signing failed");
            assert_eq!(actual, expected, "split {parts:?}");

            let mut verifier = IncrementalSigner::default();
            for part in parts {
                verifier.update(part);
            }
            verifier
                .verify(&expected, &keypair.public_key)
                .expect("verify failed");
        }

        // Ed25519ph and pure Ed25519 signatures are distinct and not
        // interchangeable.
        let pure = keypair
            .sign_with_defaults(message.as_slice())
            .expect("signing failed");
        assert_ne!(pure.signature, expected);
        let mut verifier = IncrementalSigner::new();
        verifier.update(&message);
        assert!(matches!(
            verifier.verify(&pure.signature, &keypair.public_key),
            Err(Error::AuthenticationFailed)
        ));
        assert!(matches!(
            VecSignedMessage::from_parts(expected, message).verify(&keypair.public_key),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_signatures_messages_and_wrong_keys_are_rejected() {
        let (seed, public_key, message, _) = RFC8032_ED25519[2];
        let keypair = rfc_keypair(seed, public_key);
        let other = rfc_keypair(RFC8032_ED25519[1].0, RFC8032_ED25519[1].1);
        let message = hex::decode(message).expect("hex");
        let signed = keypair
            .sign_with_defaults(message.as_slice())
            .expect("signing failed");

        assert!(matches!(
            signed.verify(&other.public_key),
            Err(Error::AuthenticationFailed)
        ));

        for index in [0, 31, 32, CRYPTO_SIGN_BYTES - 1] {
            let mut tampered = signed.clone();
            tampered.signature[index] ^= 0x01;
            assert!(matches!(
                tampered.verify(&keypair.public_key),
                Err(Error::AuthenticationFailed)
            ));
        }

        let mut tampered = signed.clone();
        tampered.message[0] ^= 0x80;
        assert!(matches!(
            tampered.verify(&keypair.public_key),
            Err(Error::AuthenticationFailed)
        ));
        let mut truncated = signed.clone();
        truncated.message.pop();
        assert!(truncated.verify(&keypair.public_key).is_err());
        let mut extended = signed.clone();
        extended.message.push(0);
        assert!(extended.verify(&keypair.public_key).is_err());

        // Incremental verification rejects a signature over a different split
        // message, and a wrong key.
        let ph: Signature = {
            let mut signer = IncrementalSigner::new();
            signer.update(&message);
            signer
                .finalize(&keypair.secret_key)
                .expect("signing failed")
        };
        let mut verifier = IncrementalSigner::new();
        verifier.update(&&message[..1]);
        assert!(verifier.verify(&ph, &keypair.public_key).is_err());
        let mut verifier = IncrementalSigner::new();
        verifier.update(&message);
        assert!(matches!(
            verifier.verify(&ph, &other.public_key),
            Err(Error::AuthenticationFailed)
        ));

        // The original is still valid after all rejections.
        signed.verify(&keypair.public_key).expect("verify failed");
    }

    #[test]
    fn signed_message_from_bytes_requires_a_full_signature() {
        for len in [0, 1, CRYPTO_SIGN_BYTES - 1] {
            assert!(matches!(
                VecSignedMessage::from_bytes(&vec![0u8; len]),
                Err(Error::InvalidLength {
                    context: ErrorContext::SignedMessage,
                    actual,
                    ..
                }) if actual == len
            ));
        }
        let bare = VecSignedMessage::from_bytes(&[0x5au8; CRYPTO_SIGN_BYTES])
            .expect("a lone signature is an empty message");
        assert!(bare.message.is_empty());
        assert_eq!(bare.signature.as_slice(), &[0x5au8; CRYPTO_SIGN_BYTES]);
    }

    #[test]
    fn from_slices_accepts_exact_lengths_and_reports_the_short_side() {
        let (seed, public_key, message, signature) = RFC8032_ED25519[0];
        let keypair = rfc_keypair(seed, public_key);
        let rebuilt = SigningKeyPair::<PublicKey, SecretKey>::from_slices(
            keypair.public_key.as_slice(),
            keypair.secret_key.as_slice(),
        )
        .expect("from_slices failed");
        assert_eq!(rebuilt, keypair);
        let signed = rebuilt
            .sign_with_defaults(hex::decode(message).expect("hex").as_slice())
            .expect("signing failed");
        assert_eq!(signed.signature, array::<CRYPTO_SIGN_BYTES>(signature));

        for len in [
            0,
            CRYPTO_SIGN_PUBLICKEYBYTES - 1,
            CRYPTO_SIGN_PUBLICKEYBYTES + 1,
        ] {
            assert!(matches!(
                SigningKeyPair::<PublicKey, SecretKey>::from_slices(
                    &vec![0u8; len],
                    keypair.secret_key.as_slice(),
                ),
                Err(Error::InvalidLength {
                    context: ErrorContext::PublicKey,
                    actual,
                    ..
                }) if actual == len
            ));
        }
        for len in [
            0,
            CRYPTO_SIGN_SECRETKEYBYTES - 1,
            CRYPTO_SIGN_SECRETKEYBYTES + 1,
        ] {
            assert!(matches!(
                SigningKeyPair::<PublicKey, SecretKey>::from_slices(
                    keypair.public_key.as_slice(),
                    &vec![0u8; len],
                ),
                Err(Error::InvalidLength {
                    context: ErrorContext::SecretKey,
                    actual,
                    ..
                }) if actual == len
            ));
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_reproduce_rfc8032_signatures() {
        let (seed, public_key, message, signature) = RFC8032_ED25519[1];
        let keypair = rfc_keypair(seed, public_key);
        let message = hex::decode(message).expect("hex");
        let expected: Signature = array(signature);

        let json = serde_json::to_string(&keypair).expect("serialize keypair");
        let decoded: SigningKeyPair<PublicKey, SecretKey> =
            serde_json::from_str(&json).expect("deserialize keypair");
        assert_eq!(decoded, keypair);
        let signed = decoded
            .sign_with_defaults(message.as_slice())
            .expect("signing failed");
        assert_eq!(signed.signature, expected);

        let json = serde_json::to_string(&signed).expect("serialize signed message");
        let decoded: VecSignedMessage =
            serde_json::from_str(&json).expect("deserialize signed message");
        assert_eq!(decoded, signed);
        decoded.verify(&keypair.public_key).expect("verify failed");

        // A field-level change in the encoding is caught by verification.
        let tampered = json.replacen(
            &format!("{}", expected[0]),
            &format!("{}", expected[0] ^ 1),
            1,
        );
        let decoded: VecSignedMessage = serde_json::from_str(&tampered).expect("deserialize");
        assert!(decoded.verify(&keypair.public_key).is_err());
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;
        use crate::native_test_util as sodium;
        use crate::utils::test_util::XorShift64;

        #[test]
        fn incremental_signer_matches_libsodium_ed25519ph_for_split_updates() {
            let mut rng = XorShift64::new(0x6564_3235_3531_3970);
            for round in 0..8 {
                let keypair =
                    SigningKeyPair::<PublicKey, SecretKey>::from_seed(&rng.next_bytes32());
                let message: Vec<u8> = (0..(round * 97) % 1023)
                    .map(|_| rng.next_u64() as u8)
                    .collect();
                let split = message.len() / 3;
                let parts: [&[u8]; 3] = [
                    &message[..split],
                    &message[split..2 * split],
                    &message[2 * split..],
                ];

                let mut signer = IncrementalSigner::new();
                for part in parts {
                    signer.update(&part);
                }
                let signature: Signature = signer
                    .finalize(&keypair.secret_key)
                    .expect("signing failed");
                assert_eq!(
                    signature.as_array(),
                    &sodium::sign_ed25519ph(&parts, &keypair.secret_key)
                );
                assert!(sodium::sign_ed25519ph_verify(
                    &[&message],
                    &signature,
                    &keypair.public_key
                ));

                let mut verifier = IncrementalSigner::new();
                verifier.update(&message);
                verifier
                    .verify(&signature, &keypair.public_key)
                    .expect("verify failed");
            }
        }

        #[test]
        fn detached_signatures_interoperate_with_libsodium() {
            let (seed, public_key, _, _) = RFC8032_ED25519PH;
            let keypair = rfc_keypair(seed, public_key);
            let (so_pk, so_sk) =
                sodium::sign_ed25519_seed_keypair(&hex::decode(seed).expect("hex"));
            assert_eq!(so_pk.as_slice(), keypair.public_key.as_slice());
            assert_eq!(so_sk.as_slice(), keypair.secret_key.as_slice());

            let mut rng = XorShift64::new(0x7369_676e_6564_2121);
            for len in [0, 1, 63, 64, 65, 1023] {
                let message: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
                let signed = keypair
                    .sign_with_defaults(message.as_slice())
                    .expect("signing failed");
                let so_signature = sodium::sign_ed25519_detached(&message, &so_sk);
                assert_eq!(signed.signature.as_slice(), so_signature.as_slice());
                assert!(sodium::sign_ed25519_verify_detached(
                    signed.signature.as_slice(),
                    &message,
                    &so_pk
                ));

                let so_signed = sodium::sign_ed25519(&message, &so_sk);
                let parsed = VecSignedMessage::from_bytes(&so_signed).expect("parse");
                assert_eq!(parsed, signed);
                parsed.verify(&keypair.public_key).expect("verify failed");
                assert_eq!(
                    sodium::sign_ed25519_open(&signed.to_vec(), &so_pk)
                        .expect("sodium verify failed"),
                    message
                );
            }
        }
    }
}

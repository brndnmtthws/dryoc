//! # Key encapsulation
//!
//! A key encapsulation mechanism (KEM) lets a sender create a fresh shared
//! secret for the holder of a public key: [`encapsulate`] returns the shared
//! secret and a ciphertext, and the recipient recovers the same secret with
//! [`KeyPair::decapsulate`]. Only the recipient needs a key pair. Feed the
//! shared secret to a key-derivation function such as [`crate::hkdf`] before
//! using it as an encryption key. A KEM does not authenticate the sender;
//! combine it with [`crate::sign`] or an authenticated protocol when that
//! matters.
//!
//! The items at the top of this module are [`xwing`], the hybrid of
//! ML-KEM-768 and X25519 that libsodium's `crypto_kem_*` functions use. It
//! stays secure if either component does, so it protects against quantum
//! computers without giving up the security of elliptic-curve cryptography.
//! [`mlkem768`] offers ML-KEM-768 alone for protocols that require it.
//!
//! # Example
//!
//! ```
//! use dryoc::kem::*;
//!
//! let recipient = KeyPair::generate_with_defaults();
//!
//! // The sender needs only the recipient's public key.
//! let (ciphertext, sender_secret): (Ciphertext, SharedSecret) =
//!     encapsulate(&recipient.public_key).expect("encapsulation failed");
//!
//! let recipient_secret: SharedSecret = recipient
//!     .decapsulate(&ciphertext)
//!     .expect("decapsulation failed");
//! assert_eq!(sender_secret, recipient_secret);
//! ```
//!
//! # Protected memory
//!
//! Every function is generic over its key, ciphertext and secret types, so
//! secret keys and shared secrets can live in locked memory; see
//! [`protected`] (with the `protected` feature).

/// Generates one algorithm's typed API from its Classic functions.
macro_rules! kem_api {
    (
        algorithm:
        $algo:literal,classic:
        $classic:ident,public_key_bytes:
        $pk_bytes:expr,secret_key_bytes:
        $sk_bytes:expr,ciphertext_bytes:
        $ct_bytes:expr,shared_secret_bytes:
        $ss_bytes:expr,seed_bytes:
        $seed_bytes:expr,seed_keypair:
        $seed_keypair:ident,enc:
        $enc:ident,public_key_of: |
        $sk:ident,
        $pk:ident |
        $public_key_of:expr,dec: |
        $dec_ss:ident,
        $dec_ct:ident,
        $dec_sk:ident |
        $dec:expr $(,)?
    ) => {
        use std::fmt;

        #[cfg(feature = "serde")]
        use serde::{Deserialize, Serialize};
        use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

        use crate::classic::$classic::{$enc, $seed_keypair};
        use crate::error::Error;
        use crate::rng::copy_randombytes;
        pub use crate::types::*;

        #[doc = concat!("Stack-allocated ", $algo, " public key.")]
        pub type PublicKey = StackByteArray<{ $pk_bytes }>;
        #[doc = concat!("Stack-allocated ", $algo, " secret key.")]
        pub type SecretKey = StackByteArray<{ $sk_bytes }>;
        #[doc = concat!("Stack-allocated ", $algo, " ciphertext.")]
        pub type Ciphertext = StackByteArray<{ $ct_bytes }>;
        #[doc = concat!("Stack-allocated ", $algo, " shared secret.")]
        pub type SharedSecret = StackByteArray<{ $ss_bytes }>;
        #[doc = concat!("Stack-allocated ", $algo, " key-generation seed.")]
        pub type Seed = StackByteArray<{ $seed_bytes }>;
        /// Stack-allocated key pair.
        pub type StackKeyPair = KeyPair<PublicKey, SecretKey>;

        #[cfg_attr(
            feature = "serde",
            derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone)
        )]
        #[cfg_attr(not(feature = "serde"), derive(Zeroize, ZeroizeOnDrop, Clone))]
        #[doc = concat!("An ", $algo, " key pair.")]
        pub struct KeyPair<
            PublicKey: ByteArray<{ $pk_bytes }> + Zeroize,
            SecretKey: ByteArray<{ $sk_bytes }> + Zeroize,
        > {
            /// Public key, shared with senders.
            pub public_key: PublicKey,
            /// Secret key.
            pub secret_key: SecretKey,
        }

        impl<
            PublicKey: ByteArray<{ $pk_bytes }> + Zeroize,
            SecretKey: ByteArray<{ $sk_bytes }> + Zeroize,
        > fmt::Debug for KeyPair<PublicKey, SecretKey>
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("KeyPair")
                    .field("public_key", &"[REDACTED]")
                    .field("secret_key", &"[REDACTED]")
                    .finish()
            }
        }

        impl<
            PublicKey: NewByteArray<{ $pk_bytes }> + Zeroize,
            SecretKey: NewByteArray<{ $sk_bytes }> + Zeroize,
        > KeyPair<PublicKey, SecretKey>
        {
            /// Generates a random key pair.
            pub fn generate() -> Self {
                let mut seed = Zeroizing::new([0u8; $seed_bytes]);
                copy_randombytes(seed.as_mut_slice());
                Self::from_seed(&*seed)
            }

            /// Deterministically derives a key pair from `seed`.
            pub fn from_seed<Seed: ByteArray<{ $seed_bytes }>>(seed: &Seed) -> Self {
                let mut public_key = PublicKey::new_byte_array();
                let mut secret_key = SecretKey::new_byte_array();
                $seed_keypair(
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
            PublicKey: NewByteArray<{ $pk_bytes }> + Zeroize,
            SecretKey: ByteArray<{ $sk_bytes }> + Zeroize,
        > KeyPair<PublicKey, SecretKey>
        {
            /// Returns the key pair for `secret_key`, deriving its public key.
            pub fn from_secret_key(secret_key: SecretKey) -> Self {
                let mut public_key = PublicKey::new_byte_array();
                {
                    let $sk = secret_key.as_array();
                    let $pk = public_key.as_mut_array();
                    $public_key_of;
                }
                Self {
                    public_key,
                    secret_key,
                }
            }
        }

        impl KeyPair<PublicKey, SecretKey> {
            /// Generates a random key pair of stack-allocated arrays.
            /// Provided for convenience.
            pub fn generate_with_defaults() -> Self {
                Self::generate()
            }
        }

        impl<
            PublicKey: ByteArray<{ $pk_bytes }> + Zeroize,
            SecretKey: ByteArray<{ $sk_bytes }> + Zeroize,
        > KeyPair<PublicKey, SecretKey>
        {
            /// Recovers the shared secret that `ciphertext` encapsulates for
            /// this key pair.
            ///
            /// A ciphertext that was not created for this key pair yields an
            /// unrelated pseudorandom secret rather than an error, so the
            /// result reveals nothing about why it differs.
            ///
            /// # Errors
            ///
            /// For X-Wing, returns [`Error::InvalidKey`] if the X25519 part
            /// of `ciphertext` is a low-order point. ML-KEM-768 decapsulation
            /// does not fail.
            pub fn decapsulate<
                Ciphertext: ByteArray<{ $ct_bytes }>,
                SharedSecret: NewByteArray<{ $ss_bytes }>,
            >(
                &self,
                ciphertext: &Ciphertext,
            ) -> Result<SharedSecret, Error> {
                let mut shared_secret = SharedSecret::new_byte_array();
                {
                    let $dec_ss = shared_secret.as_mut_array();
                    let $dec_ct = ciphertext.as_array();
                    let $dec_sk = self.secret_key.as_array();
                    $dec?;
                }
                Ok(shared_secret)
            }
        }

        #[doc = concat!(
                    "Creates a random shared secret for `public_key`, returning the ", $algo,
                    "\nciphertext to send to its owner and the shared secret."
                )]
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidKey`] if `public_key` is not a valid public
        /// key.
        pub fn encapsulate<
            PublicKey: ByteArray<{ $pk_bytes }>,
            Ciphertext: NewByteArray<{ $ct_bytes }>,
            SharedSecret: NewByteArray<{ $ss_bytes }>,
        >(
            public_key: &PublicKey,
        ) -> Result<(Ciphertext, SharedSecret), Error> {
            let mut ciphertext = Ciphertext::new_byte_array();
            let mut shared_secret = SharedSecret::new_byte_array();
            $enc(
                ciphertext.as_mut_array(),
                shared_secret.as_mut_array(),
                public_key.as_array(),
            )?;
            Ok((ciphertext, shared_secret))
        }

        #[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
        #[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
        pub mod protected {
            //! # Protected memory type aliases
            //!
            //! Heap-allocated, page-aligned keys and secrets for use with
            //! protected memory. [`encapsulate`](super::encapsulate) and
            //! [`KeyPair::decapsulate`](super::KeyPair::decapsulate) return
            //! any of these output types.
            use super::*;
            pub use crate::protected::*;

            /// Heap-allocated public key.
            pub type PublicKey = HeapByteArray<{ $pk_bytes }>;
            /// Heap-allocated secret key.
            pub type SecretKey = HeapByteArray<{ $sk_bytes }>;
            /// Heap-allocated shared secret.
            pub type SharedSecret = HeapByteArray<{ $ss_bytes }>;
            /// Locked key pair.
            pub type LockedKeyPair = KeyPair<Locked<PublicKey>, Locked<SecretKey>>;
            /// Locked, read-only key pair.
            pub type LockedROKeyPair = KeyPair<LockedRO<PublicKey>, LockedRO<SecretKey>>;

            /// Returns a locked, randomly generated public and secret key.
            fn generate_locked_parts() -> Result<(Locked<PublicKey>, Locked<SecretKey>), Error> {
                let mut seed = HeapByteArray::<{ $seed_bytes }>::new_locked()?;
                copy_randombytes(seed.as_mut_slice());
                let mut public_key = PublicKey::new_locked()?;
                let mut secret_key = SecretKey::new_locked()?;
                $seed_keypair(
                    public_key.as_mut_array(),
                    secret_key.as_mut_array(),
                    seed.as_array(),
                );
                Ok((public_key, secret_key))
            }

            impl LockedKeyPair {
                /// Returns a new randomly generated locked key pair.
                ///
                /// # Errors
                ///
                /// Returns [`Error::Io`] if an allocation cannot be locked.
                pub fn generate_locked_keypair() -> Result<Self, Error> {
                    let (public_key, secret_key) = generate_locked_parts()?;
                    Ok(Self {
                        public_key,
                        secret_key,
                    })
                }
            }

            impl LockedROKeyPair {
                /// Returns a new randomly generated locked, read-only key pair.
                ///
                /// # Errors
                ///
                /// Returns [`Error::Io`] if an allocation cannot be locked or
                /// made read-only.
                pub fn generate_readonly_locked_keypair() -> Result<Self, Error> {
                    let (public_key, secret_key) = generate_locked_parts()?;
                    Ok(Self {
                        public_key: public_key.mprotect_readonly()?,
                        secret_key: secret_key.mprotect_readonly()?,
                    })
                }
            }
        }
    };
}

pub mod xwing {
    //! # X-Wing (ML-KEM-768 + X25519)
    //!
    //! The hybrid KEM behind libsodium's `crypto_kem_*` functions; see
    //! [`crate::classic::crypto_kem_xwing`] for the construction. The secret
    //! key is a 32-byte seed.
    use crate::classic::crypto_kem_xwing::crypto_kem_xwing_dec;
    use crate::constants::{
        CRYPTO_KEM_XWING_CIPHERTEXTBYTES, CRYPTO_KEM_XWING_PUBLICKEYBYTES,
        CRYPTO_KEM_XWING_SECRETKEYBYTES, CRYPTO_KEM_XWING_SEEDBYTES,
        CRYPTO_KEM_XWING_SHAREDSECRETBYTES,
    };

    kem_api! {
        algorithm: "X-Wing",
        classic: crypto_kem_xwing,
        public_key_bytes: CRYPTO_KEM_XWING_PUBLICKEYBYTES,
        secret_key_bytes: CRYPTO_KEM_XWING_SECRETKEYBYTES,
        ciphertext_bytes: CRYPTO_KEM_XWING_CIPHERTEXTBYTES,
        shared_secret_bytes: CRYPTO_KEM_XWING_SHAREDSECRETBYTES,
        seed_bytes: CRYPTO_KEM_XWING_SEEDBYTES,
        seed_keypair: crypto_kem_xwing_seed_keypair_inplace,
        enc: crypto_kem_xwing_enc,
        // The secret key is the seed.
        public_key_of: |sk, pk| crypto_kem_xwing_seed_keypair_inplace(
            pk,
            &mut Zeroizing::new([0u8; CRYPTO_KEM_XWING_SECRETKEYBYTES]),
            sk,
        ),
        dec: |ss, ct, sk| crypto_kem_xwing_dec(ss, ct, sk),
    }
}

pub mod mlkem768 {
    //! # ML-KEM-768
    //!
    //! FIPS 203 ML-KEM-768 alone; see [`crate::classic::crypto_kem_mlkem768`].
    //! Prefer [`super::xwing`] unless a protocol requires ML-KEM-768. The
    //! secret key is FIPS 203's expanded decapsulation key, which contains
    //! the public key.
    use crate::classic::crypto_kem_mlkem768::crypto_kem_mlkem768_dec;
    use crate::constants::{
        CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
        CRYPTO_KEM_MLKEM768_SECRETKEYBYTES, CRYPTO_KEM_MLKEM768_SEEDBYTES,
        CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
    };

    /// Where the public key sits inside the expanded secret key.
    const PUBLIC_KEY_OFFSET: usize =
        CRYPTO_KEM_MLKEM768_SECRETKEYBYTES - CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES - 64;

    kem_api! {
        algorithm: "ML-KEM-768",
        classic: crypto_kem_mlkem768,
        public_key_bytes: CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
        secret_key_bytes: CRYPTO_KEM_MLKEM768_SECRETKEYBYTES,
        ciphertext_bytes: CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES,
        shared_secret_bytes: CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
        seed_bytes: CRYPTO_KEM_MLKEM768_SEEDBYTES,
        seed_keypair: crypto_kem_mlkem768_seed_keypair_inplace,
        enc: crypto_kem_mlkem768_enc,
        public_key_of: |sk, pk| pk.copy_from_slice(
            &sk[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES]
        ),
        dec: |ss, ct, sk| {
            crypto_kem_mlkem768_dec(ss, ct, sk);
            Ok::<(), Error>(())
        },
    }
}

pub use xwing::*;

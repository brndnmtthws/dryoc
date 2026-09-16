//! # Key derivation functions
//!
//! [`Kdf`] implements libsodium's key derivation functions, based on the
//! Blake2b hash function.
//!
//! You should use [`Kdf`] when you want to:
//!
//! * create many subkeys from a main key, without having to risk leaking the
//!   main key
//! * ensure that if a subkey were to become compromised, one could not derive
//!   the main key
//!
//! # Rustaceous API example
//!
//! ```
//! use base64::Engine as _;
//! use base64::engine::general_purpose;
//! use dryoc::kdf::*;
//!
//! // Randomly generate a main key and context, using the default stack-allocated
//! // types
//! let key = StackKdf::generate();
//! let subkey_id = 0;
//!
//! let subkey = key
//!     .derive_subkey_to_vec(subkey_id, 32)
//!     .expect("derive failed");
//! println!(
//!     "Subkey {}: {}",
//!     subkey_id,
//!     general_purpose::STANDARD.encode(&subkey)
//! );
//! ```
//!
//! ## Additional resources
//!
//! * See <https://doc.libsodium.org/key_derivation> for additional details on
//!   key derivation

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::classic::crypto_kdf::{crypto_kdf_derive_from_key, validate_subkey_length};
use crate::constants::{CRYPTO_KDF_CONTEXTBYTES, CRYPTO_KDF_KEYBYTES};
use crate::error::Error;
use crate::types::*;

/// Stack-allocated key type alias for key derivation with [`Kdf`].
pub type Key = StackByteArray<CRYPTO_KDF_KEYBYTES>;
/// Stack-allocated context type alias for key derivation with [`Kdf`].
pub type Context = StackByteArray<CRYPTO_KDF_CONTEXTBYTES>;

#[cfg_attr(feature = "serde", derive(Zeroize, Clone, Serialize, Deserialize))]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone))]
/// Key derivation implementation based on Blake2b, compatible with libsodium's
/// `crypto_kdf_*` functions.
///
/// The main-key type must implement [`ZeroizeOnDrop`] so keys remain
/// self-wiping after [`Kdf::into_parts`] transfers ownership to the caller.
pub struct Kdf<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> {
    main_key: Key,
    context: Context,
}

impl<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> fmt::Debug for Kdf<Key, Context>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kdf")
            .field("main_key", &"[REDACTED]")
            .field("context", &self.context.as_slice())
            .finish()
    }
}

/// Stack-allocated type alias for [`Kdf`]. Provided for convenience.
pub type StackKdf = Kdf<Key, Context>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`Kdf`]
    //!
    //! Protected-memory aliases for key derivation.
    //!
    //! ## Example
    //!
    //! ```
    //! use base64::Engine as _;
    //! use base64::engine::general_purpose;
    //! use dryoc::kdf::Kdf;
    //! use dryoc::kdf::protected::*;
    //!
    //! // Randomly generate a main key and context, using locked memory
    //! let key: LockedKdf = Kdf::generate();
    //! let subkey_id = 0;
    //!
    //! let subkey: Locked<Key> = key.derive_subkey(subkey_id).expect("derive failed");
    //! println!(
    //!     "Subkey {}: {}",
    //!     subkey_id,
    //!     general_purpose::STANDARD.encode(&subkey)
    //! );
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned key type alias for key derivation with
    /// [`Kdf`].
    pub type Key = HeapByteArray<CRYPTO_KDF_KEYBYTES>;
    /// Heap-allocated, page-aligned context type alias for key derivation with
    /// [`Kdf`].
    pub type Context = HeapByteArray<CRYPTO_KDF_CONTEXTBYTES>;

    /// Locked [`Kdf`], provided as a type alias for convenience.
    pub type LockedKdf = Kdf<Locked<Key>, Locked<Context>>;
}

impl<
    Key: NewByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: NewByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Randomly generates a new pair of main key and context.
    pub fn generate() -> Self {
        Self {
            main_key: Key::generate(),
            context: Context::generate(),
        }
    }
}

impl<
    Key: ByteArray<CRYPTO_KDF_KEYBYTES> + Zeroize + ZeroizeOnDrop,
    Context: ByteArray<CRYPTO_KDF_CONTEXTBYTES> + Zeroize,
> Kdf<Key, Context>
{
    /// Derives a subkey for `subkey_id`, returning it.
    ///
    /// # Errors
    ///
    /// Returns an error unless `LENGTH` is between
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MIN`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MIN)
    /// and
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MAX`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MAX),
    /// inclusive.
    pub fn derive_subkey<const LENGTH: usize, Subkey: NewByteArray<LENGTH>>(
        &self,
        subkey_id: u64,
    ) -> Result<Subkey, Error> {
        validate_subkey_length(LENGTH)?;
        let mut subkey = Subkey::new_byte_array();
        crypto_kdf_derive_from_key(
            subkey.as_mut_array(),
            subkey_id,
            self.context.as_array(),
            self.main_key.as_array(),
        )?;
        Ok(subkey)
    }

    /// Derives a subkey for `subkey_id`, returning it as a [`Vec`]. Provided
    /// for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error unless `length` is between
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MIN`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MIN)
    /// and
    /// [`CRYPTO_KDF_BLAKE2B_BYTES_MAX`](crate::constants::CRYPTO_KDF_BLAKE2B_BYTES_MAX),
    /// inclusive.
    pub fn derive_subkey_to_vec(&self, subkey_id: u64, length: usize) -> Result<Vec<u8>, Error> {
        validate_subkey_length(length)?;
        let mut subkey = vec![0u8; length];
        crypto_kdf_derive_from_key(
            &mut subkey,
            subkey_id,
            self.context.as_array(),
            self.main_key.as_array(),
        )?;
        Ok(subkey)
    }

    /// Constructs a new instance from `key` and `context`, consuming them both.
    pub fn from_parts(main_key: Key, context: Context) -> Self {
        Self { main_key, context }
    }

    /// Moves the key and context out of this instance, returning them as a
    /// tuple.
    pub fn into_parts(self) -> (Key, Context) {
        (self.main_key, self.context)
    }
}

impl Kdf<Key, Context> {
    /// Randomly generates a new pair of main key and context.
    pub fn generate_with_defaults() -> Self {
        Self {
            main_key: Key::generate(),
            context: Context::generate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CRYPTO_KDF_BLAKE2B_BYTES_MAX as CRYPTO_KDF_BYTES_MAX,
        CRYPTO_KDF_BLAKE2B_BYTES_MIN as CRYPTO_KDF_BYTES_MIN,
    };

    /// libsodium `test/default/kdf.c` main key (`0..32`) and context
    /// (`"KDF test"`); `(subkey_id, expected subkey)` as produced by
    /// libsodium's `crypto_kdf_derive_from_key` at 16, 32, and 64 bytes.
    /// Only the 64-byte subkey 0 appears in `kdf.c` itself; the other rows
    /// were generated with libsodium, and
    /// `matches_libsodium_derive_from_key` checks the same ids and lengths
    /// against it at runtime.
    const KAT: [(u64, [&str; 3]); 2] = [
        (
            0,
            [
                "e9136a52b9690eb4df4e9665e819a6d3",
                "c13fcc2e6cd0cd0f82d93b163a5696c5105378f8c629d36baf3ae0239de9c280",
                concat!(
                    "a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807",
                    "1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614",
                ),
            ],
        ),
        (
            u64::MAX,
            [
                "040f6b7312b53bce5d711bb9c589cdd4",
                "500c3043b2b9177ec843ecbe9f98f92d8c11fbbd10a225ab844548de89c21d55",
                concat!(
                    "6be4464350f6934d151c1bb8f555bc18e75028be95b892c6dca047101f2827a1",
                    "950b2b0fb35e996a2782db9a760e76c8b8da52e362f741bf5bcfefff0fc943fc",
                ),
            ],
        ),
    ];

    fn kat_kdf() -> StackKdf {
        let key: [u8; CRYPTO_KDF_KEYBYTES] = std::array::from_fn(|i| i as u8);
        Kdf::from_parts(Key::from(key), Context::from(*b"KDF test"))
    }

    #[test]
    fn derives_libsodium_known_answers_for_ids_zero_and_max() {
        let kdf = kat_kdf();
        for (subkey_id, expected) in KAT {
            let expected16 = hex::decode(expected[0]).expect("hex");
            let expected32 = hex::decode(expected[1]).expect("hex");
            let expected64 = hex::decode(expected[2]).expect("hex");

            let short: StackByteArray<16> = kdf.derive_subkey(subkey_id).expect("derive");
            let medium: StackByteArray<32> = kdf.derive_subkey(subkey_id).expect("derive");
            let long: StackByteArray<64> = kdf.derive_subkey(subkey_id).expect("derive");
            assert_eq!(short.as_slice(), expected16.as_slice());
            assert_eq!(medium.as_slice(), expected32.as_slice());
            assert_eq!(long.as_slice(), expected64.as_slice());

            assert_eq!(
                kdf.derive_subkey_to_vec(subkey_id, 16).expect("derive"),
                expected16
            );
            assert_eq!(
                kdf.derive_subkey_to_vec(subkey_id, 32).expect("derive"),
                expected32
            );
            assert_eq!(
                kdf.derive_subkey_to_vec(subkey_id, 64).expect("derive"),
                expected64
            );

            // Fixed-size and Vec outputs of different lengths are distinct
            // derivations, not prefixes of one another.
            assert_ne!(&expected64[..32], expected32.as_slice());
            assert_ne!(&expected32[..16], expected16.as_slice());
        }
    }

    #[test]
    fn matches_classic_derive_from_key_and_separates_key_context_and_id() {
        let kdf = kat_kdf();
        let (key, context) = kdf.clone().into_parts();
        for subkey_id in [0, 1, 2, u64::from(u32::MAX), u64::MAX - 1, u64::MAX] {
            for length in [
                CRYPTO_KDF_BYTES_MIN,
                17,
                31,
                32,
                33,
                63,
                CRYPTO_KDF_BYTES_MAX,
            ] {
                let mut classic = vec![0u8; length];
                crypto_kdf_derive_from_key(
                    &mut classic,
                    subkey_id,
                    context.as_array(),
                    key.as_array(),
                )
                .expect("classic derive");
                assert_eq!(
                    kdf.derive_subkey_to_vec(subkey_id, length).expect("derive"),
                    classic
                );
            }
        }

        let baseline = kdf.derive_subkey_to_vec(7, 32).expect("derive");
        assert_ne!(kdf.derive_subkey_to_vec(8, 32).expect("derive"), baseline);

        let mut other_key = key.clone();
        other_key[0] ^= 1;
        assert_ne!(
            Kdf::from_parts(other_key, context.clone())
                .derive_subkey_to_vec(7, 32)
                .expect("derive"),
            baseline
        );
        let mut other_context = context.clone();
        other_context[CRYPTO_KDF_CONTEXTBYTES - 1] ^= 1;
        assert_ne!(
            Kdf::from_parts(key, other_context)
                .derive_subkey_to_vec(7, 32)
                .expect("derive"),
            baseline
        );
    }

    #[test]
    fn rejects_out_of_range_subkey_lengths_and_redacts_debug_output() {
        let kdf = kat_kdf();
        assert!(format!("{kdf:?}").contains("[REDACTED]"));
        assert!(!format!("{kdf:?}").contains("KDF test"));

        for length in [
            0,
            CRYPTO_KDF_BYTES_MIN - 1,
            CRYPTO_KDF_BYTES_MAX + 1,
            usize::MAX,
        ] {
            assert!(matches!(
                kdf.derive_subkey_to_vec(0, length),
                Err(Error::InvalidLength {
                    context: crate::ErrorContext::Subkey,
                    actual,
                    ..
                }) if actual == length
            ));
        }
        assert!(matches!(
            kdf.derive_subkey::<15, StackByteArray<15>>(0),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Subkey,
                actual: 15,
                ..
            })
        ));
        assert!(matches!(
            kdf.derive_subkey::<65, StackByteArray<65>>(0),
            Err(Error::InvalidLength {
                context: crate::ErrorContext::Subkey,
                actual: 65,
                ..
            })
        ));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_derives_the_same_subkeys() {
        let kdf = kat_kdf();
        let json = serde_json::to_string(&kdf).expect("serialize");
        let decoded: StackKdf = serde_json::from_str(&json).expect("deserialize");
        for (subkey_id, expected) in KAT {
            assert_eq!(
                decoded.derive_subkey_to_vec(subkey_id, 64).expect("derive"),
                hex::decode(expected[2]).expect("hex")
            );
        }
        let (key, context) = decoded.into_parts();
        assert_eq!(context.as_slice(), b"KDF test");
        assert_eq!(key, kat_kdf().into_parts().0);
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_kdf_derives_the_same_subkeys_as_the_stack_kdf() {
        use crate::kdf::protected::*;

        let (key, context) = kat_kdf().into_parts();
        let locked: LockedKdf = Kdf::from_parts(
            protected::Key::from_slice_into_locked(key.as_slice()).expect("lock key"),
            protected::Context::from_slice_into_locked(context.as_slice()).expect("lock context"),
        );
        for (subkey_id, expected) in KAT {
            let locked_subkey: Locked<HeapByteArray<64>> =
                locked.derive_subkey(subkey_id).expect("derive");
            assert_eq!(
                locked_subkey.as_slice(),
                hex::decode(expected[2]).expect("hex").as_slice()
            );
            assert_eq!(
                locked.derive_subkey_to_vec(subkey_id, 16).expect("derive"),
                hex::decode(expected[0]).expect("hex")
            );
        }
    }

    #[cfg(dryoc_native_tests)]
    #[test]
    fn matches_libsodium_derive_from_key() {
        use crate::utils::test_util::XorShift64;

        let mut rng = XorShift64::new(0x6b64_665f_7465_7374);
        for _ in 0..8 {
            let key = Key::from(rng.next_bytes32());
            let context =
                Context::try_from(&rng.next_bytes32()[..CRYPTO_KDF_CONTEXTBYTES]).expect("context");
            let kdf = Kdf::from_parts(key.clone(), context.clone());
            for subkey_id in [0, rng.next_u64(), u64::MAX] {
                for length in [CRYPTO_KDF_BYTES_MIN, 32, CRYPTO_KDF_BYTES_MAX] {
                    let mut sodium = vec![0u8; length];
                    let rc = unsafe {
                        libsodium_sys::crypto_kdf_derive_from_key(
                            sodium.as_mut_ptr(),
                            length,
                            subkey_id,
                            context.as_ptr().cast(),
                            key.as_ptr(),
                        )
                    };
                    assert_eq!(rc, 0);
                    assert_eq!(
                        kdf.derive_subkey_to_vec(subkey_id, length).expect("derive"),
                        sodium
                    );
                }
            }
        }
    }
}

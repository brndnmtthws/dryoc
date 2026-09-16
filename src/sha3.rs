//! # SHA-3 hash algorithms
//!
//! Provides implementations of the SHA3-256 and SHA3-512 hash algorithms.
//!
//! SHA-3 hashes are unkeyed cryptographic hash functions. They turn arbitrary
//! input bytes into fixed-size digests. Hashes are useful for fingerprints and
//! compatibility with protocols that require SHA-3, but they do not
//! authenticate messages by themselves. Use [`crate::auth`] or [`crate::hmac`]
//! when a secret key must be involved.
//!
//! ## Example
//!
//! ```
//! use dryoc::sha3::Sha3256;
//!
//! let mut state = Sha3256::new();
//! state.update(b"The web of our life is of a mingled yarn.");
//! let hash = state.finalize_to_vec();
//! assert_eq!(hash.len(), 32);
//! ```
use sha3_impl::{Digest as DigestImpl, Sha3_256 as Sha3256Impl, Sha3_512 as Sha3512Impl};

use crate::constants::{CRYPTO_HASH_SHA3256_BYTES, CRYPTO_HASH_SHA3512_BYTES};
use crate::types::*;

/// Type alias for SHA3-256 digest, provided for convenience.
pub type Sha3256Digest = StackByteArray<CRYPTO_HASH_SHA3256_BYTES>;
/// Type alias for SHA3-512 digest, provided for convenience.
pub type Sha3512Digest = StackByteArray<CRYPTO_HASH_SHA3512_BYTES>;

/// Defines a SHA-3 hasher wrapping a `sha3_impl` digest.
///
/// - `$name`: the wrapper type; leading attributes (docs) are applied to it.
/// - `$algo`: the algorithm name for the generated method docs.
/// - `$inner`: the `sha3_impl` hasher.
/// - `$digest_bytes`: the digest size constant.
macro_rules! sha3_hasher {
    (
        $(#[$meta:meta])*
        $name:ident,
        $algo:literal,
        $inner:ty,
        $digest_bytes:expr,
    ) => {
        $(#[$meta])*
        pub struct $name {
            hasher: $inner,
        }

        impl $name {
            #[doc = concat!("Returns a new ", $algo, " hasher instance.")]
            pub fn new() -> Self {
                Self {
                    hasher: <$inner>::new(),
                }
            }

            #[doc = concat!(
                "One-time interface to compute ",
                $algo,
                " digest for `input`, copying\nresult into `output`."
            )]
            pub fn compute_into_bytes<Input: Bytes + ?Sized, Output: MutByteArray<$digest_bytes>>(
                output: &mut Output,
                input: &Input,
            ) {
                let mut hasher = Self::new();
                hasher.update(input);
                hasher.finalize_into_bytes(output)
            }

            #[doc = concat!(
                "One-time interface to compute ",
                $algo,
                " digest for `input`."
            )]
            pub fn compute<Input: Bytes + ?Sized, Output: NewByteArray<$digest_bytes>>(
                input: &Input,
            ) -> Output {
                let mut hasher = Self::new();
                hasher.update(input);
                hasher.finalize()
            }

            #[doc = concat!(
                "Wrapper around [`",
                stringify!($name),
                "::compute`], returning a [`Vec`]. Provided for\nconvenience."
            )]
            pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input) -> Vec<u8> {
                Self::compute(input)
            }

            #[doc = concat!("Updates ", $algo, " hash state with `input`.")]
            pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
                self.hasher.update(input.as_slice())
            }

            /// Consumes hasher and return final computed hash.
            pub fn finalize<Output: NewByteArray<$digest_bytes>>(self) -> Output {
                let mut hash = Output::new_byte_array();
                self.finalize_into_bytes(&mut hash);
                hash
            }

            /// Consumes hasher and writes final computed hash into `output`.
            pub fn finalize_into_bytes<Output: MutByteArray<$digest_bytes>>(
                self,
                output: &mut Output,
            ) {
                let digest = self.hasher.finalize();
                output.as_mut_slice().copy_from_slice(&digest);
            }

            /// Consumes hasher and returns final computed hash as a [`Vec`].
            pub fn finalize_to_vec(self) -> Vec<u8> {
                self.finalize()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

sha3_hasher! {
    /// SHA3-256 wrapper, provided for convenience.
    Sha3256,
    "SHA3-256",
    Sha3256Impl,
    CRYPTO_HASH_SHA3256_BYTES,
}

sha3_hasher! {
    /// SHA3-512 wrapper, provided for convenience.
    Sha3512,
    "SHA3-512",
    Sha3512Impl,
    CRYPTO_HASH_SHA3512_BYTES,
}

/// FIPS 202 known answers shared with the classic `crypto_hash_sha3*` tests.
///
/// The rate-boundary messages (rate-1, rate, rate+1 and, for SHA3-512, twice
/// the rate) are the Keccak team's `ShortMsgKAT` entries at those byte
/// lengths, as vendored by the RustCrypto `sha3` crate; every digest was
/// cross-checked against Python's `hashlib` (OpenSSL) and a from-scratch
/// Keccak-f[1600]. The 272-byte SHA3-256 message (twice its rate) is the
/// `(i * 31 % 251)` pattern used by the SHA-2 tests, checked the same way.
/// The million-`a` digests are the NIST SHA-3 example values.
#[cfg(test)]
pub(crate) mod test_vectors {
    /// SHA3-256 absorbs 136 bytes per permutation.
    pub(crate) const SHA3_256_RATE: usize = 136;
    /// SHA3-512 absorbs 72 bytes per permutation.
    pub(crate) const SHA3_512_RATE: usize = 72;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex failed")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// `(message, digest)` pairs for SHA3-256 at lengths 0, 3, 135, 136,
    /// 137, 272 and 1,000,000.
    pub(crate) fn sha3_256() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![],
                hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            ),
            (
                b"abc".to_vec(),
                hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            ),
            (
                hex(concat!(
                    "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732",
                    "bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e7",
                    "93f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215",
                    "ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3",
                    "b0fed6a8052fbb",
                )),
                hex("a19eee92bb2097b64e823d597798aa18be9b7c736b8059abfd6779ac35ac81b5"),
            ),
            (
                hex(concat!(
                    "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f8",
                    "35d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622",
                    "780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd",
                    "015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb",
                    "37674c6f8e380c04",
                )),
                hex("df673f4105379ff6b755eeab20ceb0dc77b5286364fe16c59cc8a907aff07732"),
            ),
            (
                hex(concat!(
                    "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00",
                    "dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31b",
                    "d0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5",
                    "f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3",
                    "f22da873c601016a0d",
                )),
                hex("d52432cf3b6b4b949aa848e058dcd62d735e0177279222e7ac0af8504762faa0"),
            ),
            (
                pattern(2 * SHA3_256_RATE),
                hex("eff96935ef1690d1f7140a486ef18e2d193baa080205e2a69f3b4a184ca03b7f"),
            ),
            (
                vec![b'a'; 1_000_000],
                hex("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
            ),
        ]
    }

    /// `(message, digest)` pairs for SHA3-512 at lengths 0, 3, 71, 72, 73,
    /// 144 and 1,000,000.
    pub(crate) fn sha3_512() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![],
                hex(concat!(
                    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
                    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                )),
            ),
            (
                b"abc".to_vec(),
                hex(concat!(
                    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
                    "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                )),
            ),
            (
                hex(concat!(
                    "13bd2811f6ed2b6f04ff3895aceed7bef8dcd45eb121791bc194a0f806206bff",
                    "c3b9281c2b308b1a729ce008119dd3066e9378acdcc50a98a82e20738800b6cd",
                    "dbe5fe9694ad6d",
                )),
                hex(concat!(
                    "def4ab6cda8839729a03e000846604b17f03c5d5d7ec23c483670a13e11573c1",
                    "e9347a63ec69a5abb21305f9382ecdaaabc6850f92840e86f88f4dabfcd93cc0",
                )),
            ),
            (
                hex(concat!(
                    "1eed9cba179a009ec2ec5508773dd305477ca117e6d569e66b5f64c6bc64801c",
                    "e25a8424ce4a26d575b8a6fb10ead3fd1992edddeec2ebe7150dc98f63adc323",
                    "7ef57b91397aa8a7",
                )),
                hex(concat!(
                    "a3e168b0d6c143ee9e17eae92930b97e6600356b73aebb5d68005dd1d0749445",
                    "1a37052f7b39ff030c1ae1d7efc4e0c3667eb7a76c627ec14354c4f6a796e2c6",
                )),
            ),
            (
                hex(concat!(
                    "ba5b67b5ec3a3ffae2c19dd8176a2ef75c0cd903725d45c9cb7009a900c0b0ca",
                    "7a2967a95ae68269a6dbf8466c7b6844a1d608ac661f7eff00538e323db5f2c6",
                    "44b78b2d48de1a08aa",
                )),
                hex(concat!(
                    "635741b37f66cd5ce4dbd1f78accd907f96146e770b239046afb9181910b612d",
                    "0e65841ff866806eed83c3ae7012fc55e42c3ffc9c6e3d03ce2870442f293ab4",
                )),
            ),
            (
                hex(concat!(
                    "157d5b7e4507f66d9a267476d33831e7bb768d4d04cc3438da12f9010263ea5f",
                    "cafbde2579db2f6b58f911d593d5f79fb05fe3596e3fa80ff2f761d1b0e57080",
                    "055c118c53e53cdb63055261d7c9b2b39bd90acc32520cbbdbda2c4fd8856dbc",
                    "ee173132a2679198daf83007a9b5c51511ae49766c792a29520388444ebefe28",
                    "256fb33d4260439cba73a9479ee00c63",
                )),
                hex(concat!(
                    "fe45289874879720ce2a844ae34bb73522775dcb6019dcd22b8885994672a088",
                    "9c69e8115c641dc8b83e39f7311815a164dc46e0ba2fca344d86d4bc2ef2532c",
                )),
            ),
            (
                vec![b'a'; 1_000_000],
                hex(concat!(
                    "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859",
                    "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
                )),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::test_vectors::*;
    use super::*;

    /// Every vector: one-shot, and streamed in rate-sized pieces so each
    /// update ends exactly on a permutation, with the last (partial or empty)
    /// piece left for `finalize`.
    #[test]
    fn test_sha3256_known_answers() {
        for (message, expected) in sha3_256() {
            let len = message.len();
            assert_eq!(Sha3256::compute_to_vec(&message), expected, "len {len}");
            let mut digest = Sha3256Digest::default();
            Sha3256::compute_into_bytes(&mut digest, &message);
            assert_eq!(digest.as_slice(), expected, "len {len}");

            let mut state = Sha3256::new();
            for chunk in message.chunks(SHA3_256_RATE) {
                state.update(chunk);
            }
            assert_eq!(state.finalize_to_vec(), expected, "rate chunks, len {len}");
        }
    }

    #[test]
    fn test_sha3512_known_answers() {
        for (message, expected) in sha3_512() {
            let len = message.len();
            assert_eq!(Sha3512::compute_to_vec(&message), expected, "len {len}");
            let mut digest = Sha3512Digest::default();
            Sha3512::compute_into_bytes(&mut digest, &message);
            assert_eq!(digest.as_slice(), expected, "len {len}");

            let mut state = Sha3512::new();
            for chunk in message.chunks(SHA3_512_RATE) {
                state.update(chunk);
            }
            assert_eq!(state.finalize_to_vec(), expected, "rate chunks, len {len}");
        }
    }

    /// One byte at a time, with an empty update before and after each byte,
    /// so the absorb buffer crosses the rate boundary from every fill level.
    #[test]
    fn test_byte_and_empty_updates_match_known_answers() {
        for (message, expected) in sha3_256()
            .into_iter()
            .filter(|(m, _)| m.len() <= 2 * SHA3_256_RATE)
        {
            let mut state = Sha3256::new();
            state.update(b"");
            for byte in &message {
                state.update(std::slice::from_ref(byte));
                state.update(b"");
            }
            assert_eq!(state.finalize_to_vec(), expected, "len {}", message.len());
        }
        for (message, expected) in sha3_512()
            .into_iter()
            .filter(|(m, _)| m.len() <= 2 * SHA3_512_RATE)
        {
            let mut state = Sha3512::new();
            state.update(b"");
            for byte in &message {
                state.update(std::slice::from_ref(byte));
                state.update(b"");
            }
            assert_eq!(state.finalize_to_vec(), expected, "len {}", message.len());
        }
    }
}

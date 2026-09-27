use subtle::ConstantTimeEq;

use crate::constants::{CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA512_BYTES};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::sha256::Sha256;
use crate::sha512::Sha512;
use crate::utils::zeroize_bytes;

/// The hash behind an HMAC. The key-pad chaining states are key-equivalent,
/// so they are absorbed and finalized in place inside the [`HmacState`]:
/// constructing or consuming hashers by value would leave moved-from copies
/// of them on the stack.
pub(crate) trait HmacHash<const OUT_BYTES: usize>: Sized + Clone {
    fn new() -> Self;
    /// Absorbs exactly one block (the HMAC key pad) into a fresh hasher.
    fn absorb_key_block(&mut self, block: &[u8]);
    /// Absorbs `a` into the fresh hasher `self` and `b` into the fresh
    /// hasher `other` (the inner and outer key pads), compressed together
    /// where the hash can interleave them.
    fn absorb_key_blocks(&mut self, a: &[u8], other: &mut Self, b: &[u8]);
    fn compute_into_bytes(output: &mut [u8; OUT_BYTES], input: &[u8]);
    fn update(&mut self, input: &[u8]);
    /// Writes the digest; the hasher is spent afterwards and only dropped.
    fn finalize_in_place(&mut self, output: &mut [u8; OUT_BYTES]);
}

macro_rules! impl_hmac_hash {
    ($hash:ty, $out_bytes:expr) => {
        impl HmacHash<$out_bytes> for $hash {
            #[inline]
            fn new() -> Self {
                <$hash>::new()
            }

            #[inline]
            fn absorb_key_block(&mut self, block: &[u8]) {
                <$hash>::absorb_key_block(self, block.try_into().expect("one hash block"));
            }

            #[inline]
            fn absorb_key_blocks(&mut self, a: &[u8], other: &mut Self, b: &[u8]) {
                <Self as HmacHash<$out_bytes>>::absorb_key_block(self, a);
                <Self as HmacHash<$out_bytes>>::absorb_key_block(other, b);
            }

            fn compute_into_bytes(output: &mut [u8; $out_bytes], input: &[u8]) {
                <$hash>::compute_into_bytes(output, input);
            }

            fn update(&mut self, input: &[u8]) {
                <$hash>::update(self, input);
            }

            fn finalize_in_place(&mut self, output: &mut [u8; $out_bytes]) {
                <$hash>::finalize_in_place(self, output);
            }
        }
    };
}

impl_hmac_hash!(Sha256, CRYPTO_AUTH_HMACSHA256_BYTES);

impl HmacHash<CRYPTO_AUTH_HMACSHA512_BYTES> for Sha512 {
    #[inline]
    fn new() -> Self {
        Sha512::new()
    }

    #[inline]
    fn absorb_key_block(&mut self, block: &[u8]) {
        Sha512::absorb_key_block(self, block.try_into().expect("one hash block"));
    }

    #[inline]
    fn absorb_key_blocks(&mut self, a: &[u8], other: &mut Self, b: &[u8]) {
        Sha512::absorb_key_blocks(
            self,
            a.try_into().expect("one hash block"),
            other,
            b.try_into().expect("one hash block"),
        );
    }

    fn compute_into_bytes(output: &mut [u8; CRYPTO_AUTH_HMACSHA512_BYTES], input: &[u8]) {
        Sha512::compute_into_bytes(output, input);
    }

    fn update(&mut self, input: &[u8]) {
        Sha512::update(self, input);
    }

    fn finalize_in_place(&mut self, output: &mut [u8; CRYPTO_AUTH_HMACSHA512_BYTES]) {
        Sha512::finalize_in_place(self, output);
    }
}

#[derive(Clone)]
pub(crate) struct HmacState<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize> {
    octx: H,
    ictx: H,
}

impl<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize> HmacState<H, BLOCK_BYTES, OUT_BYTES>
where
    H: HmacHash<OUT_BYTES>,
{
    fn new() -> Self {
        Self {
            octx: H::new(),
            ictx: H::new(),
        }
    }
}

pub(crate) fn hmac_init<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    key: &[u8],
) -> HmacState<H, BLOCK_BYTES, OUT_BYTES>
where
    H: HmacHash<OUT_BYTES>,
{
    // The returned state is copied out of this frame, whose local the
    // compression functions wrote through; that one moved-from copy is left
    // behind, as wiping it (dropping a swapped-in fresh state) costs 15-20%
    // of an init. The one-shot `hmac` initializes its state in place.
    let mut state = HmacState::new();
    hmac_init_in_place(&mut state, key);
    state
}

/// [`hmac_init`] into a fresh state the caller owns, so the key-pad states
/// are compressed where they will stay.
fn hmac_init_in_place<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    state: &mut HmacState<H, BLOCK_BYTES, OUT_BYTES>,
    key: &[u8],
) where
    H: HmacHash<OUT_BYTES>,
{
    let mut khash = [0u8; OUT_BYTES];
    let hashed_key = key.len() > BLOCK_BYTES;
    let key = if hashed_key {
        H::compute_into_bytes(&mut khash, key);
        khash.as_slice()
    } else {
        key
    };

    let mut ipad = [0x36u8; BLOCK_BYTES];
    let mut opad = [0x5cu8; BLOCK_BYTES];
    for (dst, src) in ipad.iter_mut().zip(key) {
        *dst ^= src;
    }
    for (dst, src) in opad.iter_mut().zip(key) {
        *dst ^= src;
    }

    state.ictx.absorb_key_blocks(&ipad, &mut state.octx, &opad);

    if hashed_key {
        zeroize_bytes(&mut khash);
    }
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);
}

pub(crate) fn hmac_update<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    state: &mut HmacState<H, BLOCK_BYTES, OUT_BYTES>,
    input: &[u8],
) where
    H: HmacHash<OUT_BYTES>,
{
    state.ictx.update(input);
}

pub(crate) fn hmac_final<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    mut state: HmacState<H, BLOCK_BYTES, OUT_BYTES>,
    output: &mut [u8; OUT_BYTES],
) where
    H: HmacHash<OUT_BYTES>,
{
    hmac_final_in_place(&mut state, output);
}

/// [`hmac_final`] on a state the caller keeps, and drops (wiping it)
/// afterwards; finishing in place moves no copy of the key-pad states.
/// Out of line at opt-level `z` and `s` (as are the hashers' `update` and
/// `finalize_in_place`), which adds no copy: they only get `&mut` to that
/// state and to the wiped `ihash`.
fn hmac_final_in_place<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    state: &mut HmacState<H, BLOCK_BYTES, OUT_BYTES>,
    output: &mut [u8; OUT_BYTES],
) where
    H: HmacHash<OUT_BYTES>,
{
    let mut ihash = [0u8; OUT_BYTES];
    state.ictx.finalize_in_place(&mut ihash);
    state.octx.update(&ihash);
    zeroize_bytes(&mut ihash);
    state.octx.finalize_in_place(output);
}

pub(crate) fn hmac<H, const KEY_BYTES: usize, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    mac: &mut [u8; OUT_BYTES],
    message: &[u8],
    key: &[u8; KEY_BYTES],
) where
    H: HmacHash<OUT_BYTES>,
{
    let mut state = HmacState::<H, BLOCK_BYTES, OUT_BYTES>::new();
    hmac_init_in_place(&mut state, key);
    hmac_update(&mut state, message);
    hmac_final_in_place(&mut state, mac);
}

pub(crate) fn hmac_verify<
    H,
    const KEY_BYTES: usize,
    const BLOCK_BYTES: usize,
    const OUT_BYTES: usize,
>(
    mac: &[u8; OUT_BYTES],
    input: &[u8],
    key: &[u8; KEY_BYTES],
) -> Result<(), Error>
where
    H: HmacHash<OUT_BYTES>,
{
    let mut computed_mac = [0u8; OUT_BYTES];
    hmac::<H, KEY_BYTES, BLOCK_BYTES, OUT_BYTES>(&mut computed_mac, input, key);
    let valid = mac.ct_eq(&computed_mac).unwrap_u8();
    zeroize_bytes(&mut computed_mac);
    if valid == 1 {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

pub(crate) fn hmac_keygen<const KEY_BYTES: usize>() -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    copy_randombytes(&mut key);
    key
}

/// An independent HMAC, the RFC 4231 vectors and the shared tests of the
/// `crypto_auth_hmacsha*` modules and the Rustaceous HMAC types.
#[cfg(test)]
pub(crate) mod test_util {
    use sha2::Digest;

    use crate::test_prelude::*;

    /// One RFC 4231 section 4 test case: the key, the data and the full
    /// HMAC-SHA-256 and HMAC-SHA-512 tags as hex. HMAC-SHA-512-256 is the
    /// 32-byte truncation of the HMAC-SHA-512 tag.
    pub(crate) struct Rfc4231Case {
        pub(crate) key: &'static [u8],
        pub(crate) data: &'static [u8],
        sha256: &'static str,
        sha512: &'static str,
    }

    impl Rfc4231Case {
        pub(crate) fn sha256(&self) -> Vec<u8> {
            hex::decode(self.sha256).expect("hex")
        }

        pub(crate) fn sha512(&self) -> Vec<u8> {
            hex::decode(self.sha512).expect("hex")
        }

        pub(crate) fn sha512256(&self) -> Vec<u8> {
            hex::decode(&self.sha512[..64]).expect("hex")
        }
    }

    pub(crate) const RFC4231_CASE_1: Rfc4231Case = Rfc4231Case {
        key: &[0x0b; 20],
        data: b"Hi There",
        sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        sha512: concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
    };

    /// A key shorter than the tag.
    pub(crate) const RFC4231_CASE_2: Rfc4231Case = Rfc4231Case {
        key: b"Jefe",
        data: b"what do ya want for nothing?",
        sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        sha512: concat!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
    };

    /// Combined key and data longer than 64 bytes.
    pub(crate) const RFC4231_CASE_3: Rfc4231Case = Rfc4231Case {
        key: &[0xaa; 20],
        data: &[0xdd; 50],
        sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        sha512: concat!(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
            "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
    };

    /// Combined key and data longer than 64 bytes, with a 25-byte key.
    pub(crate) const RFC4231_CASE_4: Rfc4231Case = Rfc4231Case {
        key: &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        data: &[0xcd; 50],
        sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        sha512: concat!(
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db",
            "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
    };

    /// A 131-byte key, longer than both block sizes, so it is hashed first.
    pub(crate) const RFC4231_CASE_6: Rfc4231Case = Rfc4231Case {
        key: &[0xaa; 131],
        data: b"Test Using Larger Than Block-Size Key - Hash Key First",
        sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        sha512: concat!(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
    };

    /// A 131-byte key and data longer than a block.
    pub(crate) const RFC4231_CASE_7: Rfc4231Case = Rfc4231Case {
        key: &[0xaa; 131],
        data:
            b"This is a test using a larger than block-size key and a larger than block-size data. \
                The key needs to be hashed before being used by the HMAC algorithm.",
        sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        sha512: concat!(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944",
            "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    };

    /// The cases whose keys (at most 25 bytes) zero-pad to the fixed 32-byte
    /// keys of the one-shot and Rustaceous APIs, which HMAC defines to give
    /// the same tag. Used by the `alloc`-gated Rustaceous HMAC tests.
    #[cfg(feature = "alloc")]
    pub(crate) const RFC4231_PADDABLE_KEYS: [&Rfc4231Case; 4] = [
        &RFC4231_CASE_1,
        &RFC4231_CASE_2,
        &RFC4231_CASE_3,
        &RFC4231_CASE_4,
    ];

    /// RFC 2104 HMAC over the RustCrypto hash `D`, spelled out so it shares
    /// nothing with the crate's implementation: a key longer than the
    /// `BLOCK_BYTES` block is hashed first, a shorter one is zero-padded, and
    /// the tag is the first `OUT_BYTES` bytes of the outer digest (all of it,
    /// or the 32-byte truncation of HMAC-SHA-512-256).
    pub(crate) fn reference_hmac<D: Digest, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
        key: &[u8],
        message: &[u8],
    ) -> [u8; OUT_BYTES] {
        let mut normalized = [0u8; BLOCK_BYTES];
        if key.len() > BLOCK_BYTES {
            let digest = D::digest(key);
            assert!(
                digest.len() <= BLOCK_BYTES,
                "a hashed key must fit the block"
            );
            normalized[..digest.len()].copy_from_slice(&digest);
        } else {
            normalized[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_BYTES];
        let mut opad = [0x5cu8; BLOCK_BYTES];
        for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(normalized) {
            *i ^= k;
            *o ^= k;
        }
        let mut inner = D::new();
        inner.update(ipad);
        inner.update(message);
        let inner = inner.finalize();
        let mut outer = D::new();
        outer.update(opad);
        outer.update(inner);
        let outer = outer.finalize();
        assert!(OUT_BYTES <= outer.len(), "a tag must fit the digest");
        outer[..OUT_BYTES]
            .try_into()
            .expect("tag no longer than the digest")
    }

    /// Generates the tests one `crypto_auth_hmacsha*` module shares with the
    /// others, over that module's Classic functions:
    ///
    /// - one `#[test]` per listed RFC 4231 case, through the incremental API;
    /// - `keybytes_test`: the one-shot function agrees with the incremental API
    ///   for a `KEYBYTES` key;
    /// - `test_libsodium_compatibility` (native): libsodium's one-shot tag
    ///   matches the one-shot, verify and incremental paths;
    /// - `test_key_and_message_block_boundaries`: empty and block-boundary keys
    ///   and messages (including the key-hashing transition at B+1), fed in
    ///   `chunk`-byte pieces with empty updates between them, against
    ///   [`reference_hmac`] and, natively, libsodium's variable-key incremental
    ///   API.
    macro_rules! hmac_classic_tests {
        (
            hash: $hash:ty,
            block: $block:expr,
            bytes: $bytes:expr,
            keybytes: $keybytes:expr,
            tag: $tag:ident,
            chunk: $chunk:expr,
            one_shot: $one_shot:ident,
            verify: $verify:ident,
            keygen: $keygen:ident,
            init: $init:ident,
            update: $update:ident,
            finalize: $final:ident,
            sodium_one_shot: $sodium_one_shot:ident,
            sodium_state: $sodium_state:ident,
            keybytes_test: $keybytes_test:ident($keybytes_message:expr),
            rfc4231: { $($case_test:ident => $case:ident),+ $(,)? } $(,)?
        ) => {
            fn compute_hmac(key: &[u8], message: &[u8]) -> [u8; $bytes] {
                let mut mac = [0u8; $bytes];
                let mut state = $init(key);
                $update(&mut state, message);
                $final(state, &mut mac);
                mac
            }

            $(
                #[test]
                fn $case_test() {
                    let case = &$crate::classic::crypto_auth_hmac_impl::test_util::$case;
                    let expected = case.$tag();
                    assert_eq!(compute_hmac(case.key, case.data).as_slice(), expected.as_slice());
                }
            )+

            #[test]
            fn $keybytes_test() {
                let key = [0x0bu8; $keybytes];
                let message: &[u8] = $keybytes_message;
                let mut one_shot = [0u8; $bytes];
                $one_shot(&mut one_shot, message, &key);
                assert_eq!(one_shot, compute_hmac(&key, message));
            }

            #[cfg(dryoc_native_tests)]
            #[test]
            fn test_libsodium_compatibility() {
                let key = $keygen();
                let message = b"message to authenticate";
                let so_mac = $crate::native_test_util::$sodium_one_shot(message, &key);

                let mut mac = [0u8; $bytes];
                $one_shot(&mut mac, message, &key);
                assert_eq!(mac.as_slice(), so_mac.as_slice());
                $verify(&mac, message, &key).expect("verify failed");

                let mut state = $init(&key);
                $update(&mut state, b"message ");
                $update(&mut state, b"to authenticate");
                let mut state_mac = [0u8; $bytes];
                $final(state, &mut state_mac);
                assert_eq!(state_mac.as_slice(), so_mac.as_slice());
            }

            #[test]
            fn test_key_and_message_block_boundaries() {
                use $crate::test_prelude::Vec;

                const BLOCK: usize = $block;
                for key_len in [0usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                    let key: Vec<u8> = (0..key_len as u32).map(|i| (i * 37 % 251) as u8).collect();
                    for message_len in [0usize, BLOCK - 1, BLOCK, BLOCK + 1] {
                        let message: Vec<u8> = (0..message_len as u32)
                            .map(|i| (i * 31 % 251) as u8)
                            .collect();
                        let expected =
                            $crate::classic::crypto_auth_hmac_impl::test_util::reference_hmac::<
                                $hash,
                                BLOCK,
                                { $bytes },
                            >(&key, &message);
                        let mut state = $init(&key);
                        $update(&mut state, b"");
                        for chunk in message.chunks($chunk) {
                            $update(&mut state, chunk);
                            $update(&mut state, b"");
                        }
                        let mut actual = [0u8; $bytes];
                        $final(state, &mut actual);
                        assert_eq!(actual, expected, "key {key_len}, message {message_len}");
                        #[cfg(dryoc_native_tests)]
                        {
                            let mut sodium = $crate::native_test_util::$sodium_state::new(&key);
                            sodium.update(&[]);
                            for chunk in message.chunks($chunk) {
                                sodium.update(chunk);
                            }
                            assert_eq!(
                                actual,
                                sodium.finalize(),
                                "libsodium, key {key_len}, message {message_len}"
                            );
                        }
                    }
                }
            }
        };
    }

    pub(crate) use hmac_classic_tests;
}

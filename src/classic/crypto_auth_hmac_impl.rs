use subtle::ConstantTimeEq;

use crate::constants::{CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA512_BYTES};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::sha256::Sha256;
use crate::sha512::Sha512;
use crate::utils::zeroize_bytes;

pub(crate) trait HmacHash<const OUT_BYTES: usize>: Sized + Clone {
    /// A hasher that has absorbed exactly one block (the HMAC key pad).
    fn from_block(block: &[u8]) -> Self;
    /// Whether [`HmacHash::from_blocks`] is cheaper than two
    /// [`HmacHash::from_block`] calls (the hash has an interleaved two-block
    /// compression).
    const PAIRED_BLOCKS: bool;
    /// Two hashers that have absorbed one block each (the inner and outer
    /// key pads), compressed together where the hash can interleave them.
    fn from_blocks(a: &[u8], b: &[u8]) -> (Self, Self);
    fn compute_into_bytes(output: &mut [u8; OUT_BYTES], input: &[u8]);
    fn update(&mut self, input: &[u8]);
    fn finalize_into_bytes(self, output: &mut [u8; OUT_BYTES]);
}

macro_rules! impl_hmac_hash {
    ($hash:ty, $out_bytes:expr) => {
        impl HmacHash<$out_bytes> for $hash {
            const PAIRED_BLOCKS: bool = false;

            #[inline]
            fn from_block(block: &[u8]) -> Self {
                <$hash>::from_block(block.try_into().expect("one hash block"))
            }

            #[inline]
            fn from_blocks(a: &[u8], b: &[u8]) -> (Self, Self) {
                (
                    <Self as HmacHash<$out_bytes>>::from_block(a),
                    <Self as HmacHash<$out_bytes>>::from_block(b),
                )
            }

            fn compute_into_bytes(output: &mut [u8; $out_bytes], input: &[u8]) {
                <$hash>::compute_into_bytes(output, input);
            }

            fn update(&mut self, input: &[u8]) {
                <$hash>::update(self, input);
            }

            fn finalize_into_bytes(self, output: &mut [u8; $out_bytes]) {
                <$hash>::finalize_into_bytes(self, output);
            }
        }
    };
}

impl_hmac_hash!(Sha256, CRYPTO_AUTH_HMACSHA256_BYTES);

impl HmacHash<CRYPTO_AUTH_HMACSHA512_BYTES> for Sha512 {
    const PAIRED_BLOCKS: bool = true;

    #[inline]
    fn from_block(block: &[u8]) -> Self {
        Sha512::from_block(block.try_into().expect("one hash block"))
    }

    #[inline]
    fn from_blocks(a: &[u8], b: &[u8]) -> (Self, Self) {
        Sha512::from_blocks(
            a.try_into().expect("one hash block"),
            b.try_into().expect("one hash block"),
        )
    }

    fn compute_into_bytes(output: &mut [u8; CRYPTO_AUTH_HMACSHA512_BYTES], input: &[u8]) {
        Sha512::compute_into_bytes(output, input);
    }

    fn update(&mut self, input: &[u8]) {
        Sha512::update(self, input);
    }

    fn finalize_into_bytes(self, output: &mut [u8; CRYPTO_AUTH_HMACSHA512_BYTES]) {
        Sha512::finalize_into_bytes(self, output);
    }
}

#[derive(Clone)]
pub(crate) struct HmacState<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize> {
    octx: H,
    ictx: H,
}

pub(crate) fn hmac_init<H, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    key: &[u8],
) -> HmacState<H, BLOCK_BYTES, OUT_BYTES>
where
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

    let state = if H::PAIRED_BLOCKS {
        let (ictx, octx) = H::from_blocks(&ipad, &opad);
        HmacState { octx, ictx }
    } else {
        let ictx = H::from_block(&ipad);
        let octx = H::from_block(&opad);
        HmacState { octx, ictx }
    };

    if hashed_key {
        zeroize_bytes(&mut khash);
    }
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);

    state
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
    let mut ihash = [0u8; OUT_BYTES];
    state.ictx.finalize_into_bytes(&mut ihash);
    state.octx.update(&ihash);
    zeroize_bytes(&mut ihash);
    state.octx.finalize_into_bytes(output);
}

pub(crate) fn hmac<H, const KEY_BYTES: usize, const BLOCK_BYTES: usize, const OUT_BYTES: usize>(
    mac: &mut [u8; OUT_BYTES],
    message: &[u8],
    key: &[u8; KEY_BYTES],
) where
    H: HmacHash<OUT_BYTES>,
{
    let mut state = hmac_init::<H, BLOCK_BYTES, OUT_BYTES>(key);
    hmac_update(&mut state, message);
    hmac_final(state, mac);
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

/// An independent HMAC for the tests of the `crypto_auth_hmacsha*` modules.
#[cfg(test)]
pub(crate) mod test_util {
    use sha2::Digest;

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
}

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::constants::{CRYPTO_AUTH_HMACSHA256_BYTES, CRYPTO_AUTH_HMACSHA512_BYTES};
use crate::error::Error;
use crate::rng::copy_randombytes;
use crate::sha256::Sha256;
use crate::sha512::Sha512;

pub(crate) trait HmacHash<const OUT_BYTES: usize>: Sized {
    fn new() -> Self;
    fn compute_into_bytes(output: &mut [u8; OUT_BYTES], input: &[u8]);
    fn update(&mut self, input: &[u8]);
    fn finalize_into_bytes(self, output: &mut [u8; OUT_BYTES]);
}

macro_rules! impl_hmac_hash {
    ($hash:ty, $out_bytes:expr) => {
        impl HmacHash<$out_bytes> for $hash {
            fn new() -> Self {
                <$hash>::new()
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
impl_hmac_hash!(Sha512, CRYPTO_AUTH_HMACSHA512_BYTES);

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
    let key = if key.len() > BLOCK_BYTES {
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

    let mut ictx = H::new();
    ictx.update(&ipad);
    let mut octx = H::new();
    octx.update(&opad);

    khash.zeroize();
    ipad.zeroize();
    opad.zeroize();

    HmacState { octx, ictx }
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
    ihash.zeroize();
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
    computed_mac.zeroize();
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

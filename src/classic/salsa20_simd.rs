use std::ptr;
use std::simd::{Simd, simd_swizzle};
use std::sync::atomic::{Ordering, compiler_fence};

use zeroize::Zeroize;

use crate::classic::crypto_core::crypto_core_hsalsa20;
use crate::classic::crypto_secretbox::{Key, Nonce};
use crate::poly1305::Key as Poly1305Key;
use crate::utils::load_u32_le;

type U32x4 = Simd<u32, 4>;

const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline]
fn rotl32(x: U32x4, n: u32) -> U32x4 {
    (x << U32x4::splat(n)) | (x >> U32x4::splat(32 - n))
}

#[inline]
fn rotl_sum(y0: U32x4, y1: U32x4, rot: u32) -> U32x4 {
    rotl32(y0 + y1, rot)
}

#[inline]
fn salsa20_rounds(x: &mut [U32x4; 16]) {
    for _ in (0..20).step_by(2) {
        x[4] ^= rotl_sum(x[0], x[12], 7);
        x[8] ^= rotl_sum(x[4], x[0], 9);
        x[12] ^= rotl_sum(x[8], x[4], 13);
        x[0] ^= rotl_sum(x[12], x[8], 18);
        x[9] ^= rotl_sum(x[5], x[1], 7);
        x[13] ^= rotl_sum(x[9], x[5], 9);
        x[1] ^= rotl_sum(x[13], x[9], 13);
        x[5] ^= rotl_sum(x[1], x[13], 18);
        x[14] ^= rotl_sum(x[10], x[6], 7);
        x[2] ^= rotl_sum(x[14], x[10], 9);
        x[6] ^= rotl_sum(x[2], x[14], 13);
        x[10] ^= rotl_sum(x[6], x[2], 18);
        x[3] ^= rotl_sum(x[15], x[11], 7);
        x[7] ^= rotl_sum(x[3], x[15], 9);
        x[11] ^= rotl_sum(x[7], x[3], 13);
        x[15] ^= rotl_sum(x[11], x[7], 18);
        x[1] ^= rotl_sum(x[0], x[3], 7);
        x[2] ^= rotl_sum(x[1], x[0], 9);
        x[3] ^= rotl_sum(x[2], x[1], 13);
        x[0] ^= rotl_sum(x[3], x[2], 18);
        x[6] ^= rotl_sum(x[5], x[4], 7);
        x[7] ^= rotl_sum(x[6], x[5], 9);
        x[4] ^= rotl_sum(x[7], x[6], 13);
        x[5] ^= rotl_sum(x[4], x[7], 18);
        x[11] ^= rotl_sum(x[10], x[9], 7);
        x[8] ^= rotl_sum(x[11], x[10], 9);
        x[9] ^= rotl_sum(x[8], x[11], 13);
        x[10] ^= rotl_sum(x[9], x[8], 18);
        x[12] ^= rotl_sum(x[15], x[14], 7);
        x[13] ^= rotl_sum(x[12], x[15], 9);
        x[14] ^= rotl_sum(x[13], x[12], 13);
        x[15] ^= rotl_sum(x[14], x[13], 18);
    }
}

fn salsa20_block(input: &[u32; 16], counter: u64) -> [u8; 64] {
    let mut state = *input;
    state[8] = counter as u32;
    state[9] = (counter >> 32) as u32;
    let orig = state;

    for _ in (0..20).step_by(2) {
        state[4] ^= state[0].wrapping_add(state[12]).rotate_left(7);
        state[8] ^= state[4].wrapping_add(state[0]).rotate_left(9);
        state[12] ^= state[8].wrapping_add(state[4]).rotate_left(13);
        state[0] ^= state[12].wrapping_add(state[8]).rotate_left(18);
        state[9] ^= state[5].wrapping_add(state[1]).rotate_left(7);
        state[13] ^= state[9].wrapping_add(state[5]).rotate_left(9);
        state[1] ^= state[13].wrapping_add(state[9]).rotate_left(13);
        state[5] ^= state[1].wrapping_add(state[13]).rotate_left(18);
        state[14] ^= state[10].wrapping_add(state[6]).rotate_left(7);
        state[2] ^= state[14].wrapping_add(state[10]).rotate_left(9);
        state[6] ^= state[2].wrapping_add(state[14]).rotate_left(13);
        state[10] ^= state[6].wrapping_add(state[2]).rotate_left(18);
        state[3] ^= state[15].wrapping_add(state[11]).rotate_left(7);
        state[7] ^= state[3].wrapping_add(state[15]).rotate_left(9);
        state[11] ^= state[7].wrapping_add(state[3]).rotate_left(13);
        state[15] ^= state[11].wrapping_add(state[7]).rotate_left(18);
        state[1] ^= state[0].wrapping_add(state[3]).rotate_left(7);
        state[2] ^= state[1].wrapping_add(state[0]).rotate_left(9);
        state[3] ^= state[2].wrapping_add(state[1]).rotate_left(13);
        state[0] ^= state[3].wrapping_add(state[2]).rotate_left(18);
        state[6] ^= state[5].wrapping_add(state[4]).rotate_left(7);
        state[7] ^= state[6].wrapping_add(state[5]).rotate_left(9);
        state[4] ^= state[7].wrapping_add(state[6]).rotate_left(13);
        state[5] ^= state[4].wrapping_add(state[7]).rotate_left(18);
        state[11] ^= state[10].wrapping_add(state[9]).rotate_left(7);
        state[8] ^= state[11].wrapping_add(state[10]).rotate_left(9);
        state[9] ^= state[8].wrapping_add(state[11]).rotate_left(13);
        state[10] ^= state[9].wrapping_add(state[8]).rotate_left(18);
        state[12] ^= state[15].wrapping_add(state[14]).rotate_left(7);
        state[13] ^= state[12].wrapping_add(state[15]).rotate_left(9);
        state[14] ^= state[13].wrapping_add(state[12]).rotate_left(13);
        state[15] ^= state[14].wrapping_add(state[13]).rotate_left(18);
    }

    let mut output = [0u8; 64];
    for (i, word) in state.iter_mut().enumerate() {
        *word = word.wrapping_add(orig[i]);
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    state.zeroize();
    output
}

#[inline]
fn counter_lanes(counter: u64) -> (U32x4, U32x4) {
    let counters = [
        counter,
        counter.wrapping_add(1),
        counter.wrapping_add(2),
        counter.wrapping_add(3),
    ];
    (
        U32x4::from([
            counters[0] as u32,
            counters[1] as u32,
            counters[2] as u32,
            counters[3] as u32,
        ]),
        U32x4::from([
            (counters[0] >> 32) as u32,
            (counters[1] >> 32) as u32,
            (counters[2] >> 32) as u32,
            (counters[3] >> 32) as u32,
        ]),
    )
}

#[inline]
fn input_lanes(input: &[u32; 16]) -> [U32x4; 16] {
    let mut lanes = input.map(U32x4::splat);
    lanes[8] = U32x4::splat(0);
    lanes[9] = U32x4::splat(0);
    lanes
}

#[inline]
fn xor_4words(data: &mut [u8], offset: usize, words: U32x4) {
    let data_words = U32x4::from([
        load_u32_le(&data[offset..offset + 4]),
        load_u32_le(&data[offset + 4..offset + 8]),
        load_u32_le(&data[offset + 8..offset + 12]),
        load_u32_le(&data[offset + 12..offset + 16]),
    ]);
    for (i, word) in (data_words ^ words).to_array().iter().enumerate() {
        data[offset + i * 4..offset + (i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
}

#[inline]
fn transpose_and_xor_4words(
    data: &mut [u8],
    word_offset: usize,
    w0: U32x4,
    w1: U32x4,
    w2: U32x4,
    w3: U32x4,
) {
    let b01_lo = simd_swizzle!(w0, w1, [0, 4, 1, 5]);
    let b01_hi = simd_swizzle!(w0, w1, [2, 6, 3, 7]);
    let b23_lo = simd_swizzle!(w2, w3, [0, 4, 1, 5]);
    let b23_hi = simd_swizzle!(w2, w3, [2, 6, 3, 7]);

    xor_4words(
        data,
        word_offset,
        simd_swizzle!(b01_lo, b23_lo, [0, 1, 4, 5]),
    );
    xor_4words(
        data,
        64 + word_offset,
        simd_swizzle!(b01_lo, b23_lo, [2, 3, 6, 7]),
    );
    xor_4words(
        data,
        128 + word_offset,
        simd_swizzle!(b01_hi, b23_hi, [0, 1, 4, 5]),
    );
    xor_4words(
        data,
        192 + word_offset,
        simd_swizzle!(b01_hi, b23_hi, [2, 3, 6, 7]),
    );
}

fn salsa20_xor_4blocks(data: &mut [u8], input_lanes: &[U32x4; 16], counter: u64) {
    debug_assert_eq!(data.len(), 256);

    let mut state = *input_lanes;
    let (counter_low, counter_high) = counter_lanes(counter);
    state[8] = counter_low;
    state[9] = counter_high;

    let orig = state;
    salsa20_rounds(&mut state);

    for word_offset in (0..16).step_by(4) {
        transpose_and_xor_4words(
            data,
            word_offset * 4,
            state[word_offset] + orig[word_offset],
            state[word_offset + 1] + orig[word_offset + 1],
            state[word_offset + 2] + orig[word_offset + 2],
            state[word_offset + 3] + orig[word_offset + 3],
        );
    }
}

pub(crate) struct XSalsa20 {
    input: [u32; 16],
    input_lanes: [U32x4; 16],
}

pub(crate) struct FirstBlock {
    block: [u8; 64],
}

impl FirstBlock {
    pub(crate) fn poly1305_key(&self, mac_key: &mut Poly1305Key) {
        mac_key.copy_from_slice(&self.block[..32]);
    }
}

impl XSalsa20 {
    pub(crate) fn new(nonce: &Nonce, key: &Key) -> Self {
        let mut hsalsa20_input = [0u8; 16];
        hsalsa20_input.copy_from_slice(&nonce[..16]);

        let mut subkey = [0u8; 32];
        crypto_core_hsalsa20(&mut subkey, &hsalsa20_input, key, None);

        let input = [
            SIGMA[0],
            load_u32_le(&subkey[0..4]),
            load_u32_le(&subkey[4..8]),
            load_u32_le(&subkey[8..12]),
            load_u32_le(&subkey[12..16]),
            SIGMA[1],
            load_u32_le(&nonce[16..20]),
            load_u32_le(&nonce[20..24]),
            0,
            0,
            SIGMA[2],
            load_u32_le(&subkey[16..20]),
            load_u32_le(&subkey[20..24]),
            load_u32_le(&subkey[24..28]),
            load_u32_le(&subkey[28..32]),
            SIGMA[3],
        ];

        hsalsa20_input.zeroize();
        subkey.zeroize();

        let input_lanes = input_lanes(&input);

        Self { input, input_lanes }
    }

    pub(crate) fn first_block(&self) -> FirstBlock {
        FirstBlock {
            block: salsa20_block(&self.input, 0),
        }
    }

    pub(crate) fn xor_after_first_block(&self, data: &mut [u8], first_block: &FirstBlock) {
        let first_xor_len = data.len().min(32);
        for (byte, keystream) in data
            .iter_mut()
            .take(first_xor_len)
            .zip(first_block.block[32..].iter())
        {
            *byte ^= keystream;
        }

        let mut remaining = &mut data[first_xor_len..];
        let mut counter = 1u64;
        while remaining.len() >= 256 {
            let (chunk, rest) = remaining.split_at_mut(256);
            salsa20_xor_4blocks(chunk, &self.input_lanes, counter);
            counter = counter.wrapping_add(4);
            remaining = rest;
        }
        while !remaining.is_empty() {
            let mut block = salsa20_block(&self.input, counter);
            let xor_len = remaining.len().min(64);
            for (byte, keystream) in remaining.iter_mut().take(xor_len).zip(block.iter()) {
                *byte ^= keystream;
            }
            block.zeroize();
            counter = counter.wrapping_add(1);
            remaining = &mut remaining[xor_len..];
        }
    }
}

impl Drop for XSalsa20 {
    fn drop(&mut self) {
        self.input.zeroize();
        zeroize_lanes(&mut self.input_lanes);
    }
}

impl Drop for FirstBlock {
    fn drop(&mut self) {
        self.block.zeroize();
    }
}

fn zeroize_lanes(lanes: &mut [U32x4; 16]) {
    for lane in lanes.iter_mut() {
        // SAFETY: `lane` is a valid, aligned, unique pointer derived from
        // `&mut lanes`. A volatile write is used so duplicated subkey material
        // in the SIMD lane cache is cleared even if the value is not read again.
        unsafe { ptr::write_volatile(lane, U32x4::splat(0)) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    use salsa20::{Key as SalsaKey, XNonce, XSalsa20 as RustCryptoXSalsa20};

    use super::*;
    use crate::classic::crypto_secretbox::{
        crypto_secretbox_detached, crypto_secretbox_open_detached,
    };

    fn rustcrypto_xsalsa20_poly1305_key_and_xor(
        data: &mut [u8],
        mac_key: &mut Poly1305Key,
        nonce: &Nonce,
        key: &Key,
    ) {
        let mut cipher = RustCryptoXSalsa20::new(&SalsaKey::from(*key), &XNonce::from(*nonce));
        cipher.apply_keystream(mac_key);
        cipher.apply_keystream(data);
    }

    fn simd_xsalsa20_poly1305_key_and_xor(
        data: &mut [u8],
        mac_key: &mut Poly1305Key,
        nonce: &Nonce,
        key: &Key,
    ) {
        let cipher = super::XSalsa20::new(nonce, key);
        let first_block = cipher.first_block();
        first_block.poly1305_key(mac_key);
        cipher.xor_after_first_block(data, &first_block);
    }

    fn key_strategy() -> impl Strategy<Value = Key> {
        any::<[u8; 32]>()
    }

    fn nonce_strategy() -> impl Strategy<Value = Nonce> {
        any::<[u8; 24]>()
    }

    fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(0usize),
            Just(1),
            Just(31),
            Just(32),
            Just(33),
            Just(63),
            Just(64),
            Just(65),
            Just(255),
            Just(256),
            Just(257),
            Just(511),
            Just(512),
            Just(513),
            0usize..4096,
        ]
        .prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
    }

    proptest! {
        #[test]
        fn test_xsalsa20_simd_matches_rustcrypto_for_random_inputs(
            key in key_strategy(),
            nonce in nonce_strategy(),
            message in message_strategy(),
        ) {
            let mut simd_data = message.clone();
            let mut rustcrypto_data = message;
            let mut simd_mac_key = Poly1305Key::new();
            let mut rustcrypto_mac_key = Poly1305Key::new();

            simd_xsalsa20_poly1305_key_and_xor(&mut simd_data, &mut simd_mac_key, &nonce, &key);
            rustcrypto_xsalsa20_poly1305_key_and_xor(
                &mut rustcrypto_data,
                &mut rustcrypto_mac_key,
                &nonce,
                &key,
            );

            prop_assert_eq!(simd_mac_key, rustcrypto_mac_key);
            prop_assert_eq!(simd_data, rustcrypto_data);
        }

        #[test]
        fn test_secretbox_simd_matches_rustcrypto_for_random_inputs(
            key in key_strategy(),
            nonce in nonce_strategy(),
            message in message_strategy(),
        ) {
            let mut simd_ciphertext = message.clone();
            let mut simd_mac = [0u8; 16];
            crypto_secretbox_detached(&mut simd_ciphertext, &mut simd_mac, &message, &nonce, &key);

            let mut rustcrypto_ciphertext = message.clone();
            let mut rustcrypto_mac_key = Poly1305Key::new();
            rustcrypto_xsalsa20_poly1305_key_and_xor(
                &mut rustcrypto_ciphertext,
                &mut rustcrypto_mac_key,
                &nonce,
                &key,
            );
            let mut poly1305 = crate::poly1305::Poly1305::new(&rustcrypto_mac_key);
            poly1305.update(&rustcrypto_ciphertext);
            let rustcrypto_mac = poly1305.finalize_to_array();

            prop_assert_eq!(simd_mac, rustcrypto_mac);
            prop_assert_eq!(&simd_ciphertext, &rustcrypto_ciphertext);

            let mut decrypted = vec![0u8; rustcrypto_ciphertext.len()];
            crypto_secretbox_open_detached(&mut decrypted, &simd_mac, &rustcrypto_ciphertext, &nonce, &key)
                .expect("valid generated secretbox should decrypt");
            prop_assert_eq!(decrypted, message);
        }
    }
}

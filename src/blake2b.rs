use zeroize::Zeroize;

use crate::error::Error;
use crate::utils::load64_le;

const BLOCKBYTES: usize = 128;
const OUTBYTES: usize = 64;
const KEYBYTES: usize = 64;
const SALTBYTES: usize = 16;
const PERSONALBYTES: usize = 16;

#[repr(packed)]
struct Params {
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: [u8; 4],
    node_offset: [u8; 8],
    node_depth: u8,
    inner_length: u8,
    reserved: [u8; 14],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
}

impl Default for Params {
    fn default() -> Self {
        Self {
            digest_length: 0,
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: [0u8; 4],
            node_offset: [0u8; 8],
            node_depth: 0,
            inner_length: 0,
            reserved: [0u8; 14],
            salt: [0u8; SALTBYTES],
            personal: [0u8; PERSONALBYTES],
        }
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct State {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    last_node: u8,
    buf: Vec<u8>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: vec![],
            last_node: 0,
        }
    }
}

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[inline]
fn rotr64(x: u64, b: u64) -> u64 {
    (x >> b) | (x << (64 - b))
}

fn compress(state: &mut State) {
    let mut m = [0u64; 16];
    let mut v = [0u64; 16];

    let block = &state.buf[..BLOCKBYTES];

    for i in 0..16 {
        m[i] = load64_le(&block[(i * 8)..(i * 8 + 8)]);
    }
    for i in 0..8 {
        v[i] = state.h[i];
    }
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = state.t[0] ^ IV[4];
    v[13] = state.t[1] ^ IV[5];
    v[14] = state.f[0] ^ IV[6];
    v[15] = state.f[1] ^ IV[7];

    let mut g = |r: usize, i: usize, a: usize, b: usize, c: usize, d: usize| {
        v[a] = v[a].wrapping_add(v[b].wrapping_add(m[(SIGMA[r] as [usize; 16])[2 * i + 0]]));
        v[d] = rotr64(v[d] ^ v[a], 32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = rotr64(v[b] ^ v[c], 24);
        v[a] = v[a].wrapping_add(v[b].wrapping_add(m[(SIGMA[r] as [usize; 16])[2 * i + 1]]));
        v[d] = rotr64(v[d] ^ v[a], 16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = rotr64(v[b] ^ v[c], 63);
    };
    let mut round = |r| {
        g(r, 0, 0, 4, 8, 12);
        g(r, 1, 1, 5, 9, 13);
        g(r, 2, 2, 6, 10, 14);
        g(r, 3, 3, 7, 11, 15);
        g(r, 4, 0, 5, 10, 15);
        g(r, 5, 1, 6, 11, 12);
        g(r, 6, 2, 7, 8, 13);
        g(r, 7, 3, 4, 9, 14);
    };
    round(0);
    round(1);
    round(2);
    round(3);
    round(4);
    round(5);
    round(6);
    round(7);
    round(8);
    round(9);
    round(10);
    round(11);

    for i in 0..8 {
        state.h[i] = state.h[i] ^ v[i] ^ v[i + 8];
    }
}

fn init0(state: &mut State) {
    for i in 0..8 {
        state.h[i] = IV[i];
    }
}

fn init(outlen: u8) -> Result<State, Error> {
    if outlen == 0 || outlen as usize > OUTBYTES {
        return Err(dryoc_error!(format!("invalid blake2b outlen: {}", outlen)));
    }
    let mut state = State::default();
    let mut params = Params::default();
    params.digest_length = outlen;

    init_param(state, &params)
}

fn init_param(mut state: State, params: &Params) -> Result<State, Error> {
    init0(&mut state);

    let pslice = unsafe {
        std::slice::from_raw_parts(
            (params as *const Params) as *const u8,
            std::mem::size_of::<Params>(),
        )
    };

    for i in 0..8 {
        state.h[i] ^= load64_le(&pslice[(8 * i)..(8 * i + 8)]);
    }

    Ok(state)
}

fn init_key(outlen: u8, key: &[u8]) -> Result<State, Error> {
    if outlen == 0 || outlen as usize > OUTBYTES {
        return Err(dryoc_error!(format!("invalid blake2b outlen: {}", outlen)));
    }
    let state = State::default();
    let mut params = Params::default();
    params.digest_length = outlen;

    let mut state = init_param(state, &params)?;

    let mut block = [0u8; BLOCKBYTES];
    block[..key.len()].copy_from_slice(key);
    update(&mut state, &block);
    block.zeroize();

    Ok(state)
}

fn increment_counter(state: &mut State, inc: usize) {
    let mut t: u128 = ((state.t[1] as u128) << 64) | state.t[0] as u128;
    t += inc as u128;
    state.t[0] = (t >> 0) as u64;
    state.t[1] = (t >> 64) as u64;
}

fn update(state: &mut State, input: &[u8]) {
    for chunk in input.chunks(BLOCKBYTES) {
        state.buf.extend_from_slice(chunk);

        if state.buf.len() > BLOCKBYTES {
            increment_counter(state, BLOCKBYTES);
            compress(state);
            state.buf.rotate_left(BLOCKBYTES);
            state.buf.resize(state.buf.len() - BLOCKBYTES, 0);
        }
    }
}

fn set_lastnode(state: &mut State) {
    state.f[1] = -1i64 as u64;
}

fn is_lastblock(state: &State) -> bool {
    state.f[0] != 0
}

fn set_lastblock(state: &mut State) {
    if state.last_node != 0 {
        set_lastnode(state);
    }
    state.f[0] = -1i64 as u64;
}

fn finalize(state: &mut State, output: &mut [u8]) -> Result<(), Error> {
    if output.is_empty() || output.len() > OUTBYTES {
        return Err(dryoc_error!(format!(
            "invalid output length {}, should be <= {}",
            output.len(),
            OUTBYTES
        )));
    }

    if is_lastblock(state) {
        return Err(dryoc_error!("already on last block"));
    }

    if state.buf.len() > BLOCKBYTES {
        increment_counter(state, BLOCKBYTES);
        compress(state);
        state.buf.rotate_left(BLOCKBYTES);
        state.buf.resize(state.buf.len() - BLOCKBYTES, 0);
    }

    increment_counter(state, state.buf.len());
    set_lastblock(state);

    // fill last block with zero padding
    state.buf.resize(BLOCKBYTES, 0);

    compress(state);

    let mut buffer = [0u8; OUTBYTES];
    buffer[0..8].copy_from_slice(&state.h[0].to_le_bytes());
    buffer[8..16].copy_from_slice(&state.h[1].to_le_bytes());
    buffer[16..24].copy_from_slice(&state.h[2].to_le_bytes());
    buffer[24..32].copy_from_slice(&state.h[3].to_le_bytes());
    buffer[32..40].copy_from_slice(&state.h[4].to_le_bytes());
    buffer[40..48].copy_from_slice(&state.h[5].to_le_bytes());
    buffer[48..56].copy_from_slice(&state.h[6].to_le_bytes());
    buffer[56..64].copy_from_slice(&state.h[7].to_le_bytes());
    output.copy_from_slice(&buffer[..output.len()]);

    state.h.zeroize();
    state.buf.zeroize();

    Ok(())
}

pub(crate) fn hash(output: &mut [u8], input: &[u8], key: &[u8]) -> Result<(), Error> {
    if output.len() > OUTBYTES {
        return Err(dryoc_error!(format!(
            "output length {} greater than max {}",
            output.len(),
            OUTBYTES
        )));
    }

    let mut state = if key.is_empty() {
        init(output.len() as u8)?
    } else {
        init_key(output.len() as u8, key)?
    };

    update(&mut state, input);
    finalize(&mut state, output)
}

#[cfg(test)]
mod tests {
    use libc::*;

    use super::*;

    #[repr(C)]
    #[derive(Debug)]
    struct B2state {
        h: [u64; 8],
        t: [u64; 2],
        f: [u64; 2],
        buf: [c_uchar; 256],
        buflen: size_t,
        last_node: u8,
    }

    extern "C" {
        fn blake2b_init(S: *mut B2state, outlen: c_uchar);
        fn blake2b_update(S: *mut B2state, input: *const u8, inlen: u64);
        fn blake2b_final(S: *mut B2state, output: *mut u8, outlen: u64);
    }

    #[test]
    fn test_b2() {
        use crate::rng::copy_randombytes;

        let mut s = B2state {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: [0u8; 256],
            buflen: 0,
            last_node: 0,
        };

        unsafe { blake2b_init(&mut s, 64) };

        let mut state = init(64).expect("init");

        println!("{:?}", state);
        println!("{:?}", s);

        let mut block = [0u8; 256];
        // copy_randombytes(&mut block);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        update(&mut state, &block);

        println!("{:?}", state);
        println!("{:?}", s);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        update(&mut state, &block);

        println!("{:?}", state);
        println!("{:?}", s);

        let mut output = [0u8; 64];
        let mut so_output = [0u8; 64];

        unsafe { blake2b_final(&mut s, &mut so_output as *mut u8, so_output.len() as u64) };

        finalize(&mut state, &mut output).ok();

        println!("{:?}", state);
        println!("{:?}", s);

        println!("{:?}", output);
        println!("{:?}", so_output);

        assert_eq!(output, so_output);
    }
}

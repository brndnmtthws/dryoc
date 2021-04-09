use zeroize::Zeroize;

use crate::error::Error;
use crate::utils::load64_le;

const BLOCKBYTES: usize = 128;
const OUTBYTES: usize = 64;
const KEYBYTES: usize = 64;
const SALTBYTES: usize = 16;
const PERSONALBYTES: usize = 16;

#[repr(packed)]
#[allow(dead_code)]
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
pub(crate) struct State {
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

fn compress(sh: &mut [u64; 8], st: &mut [u64; 2], sf: &mut [u64; 2], block: &[u8]) {
    let mut tm = [0u64; 16];
    let mut tv = [0u64; 16];

    for i in 0..16 {
        tm[i] = load64_le(&block[(i * 8)..(i * 8 + 8)]);
    }
    tv[..8].copy_from_slice(sh);
    tv[8] = IV[0];
    tv[9] = IV[1];
    tv[10] = IV[2];
    tv[11] = IV[3];
    tv[12] = st[0] ^ IV[4];
    tv[13] = st[1] ^ IV[5];
    tv[14] = sf[0] ^ IV[6];
    tv[15] = sf[1] ^ IV[7];

    let mut g = |r: usize, i: usize, a: usize, b: usize, c: usize, d: usize| {
        tv[a] = tv[a].wrapping_add(tv[b].wrapping_add(tm[(SIGMA[r] as [usize; 16])[2 * i]]));
        tv[d] = rotr64(tv[d] ^ tv[a], 32);
        tv[c] = tv[c].wrapping_add(tv[d]);
        tv[b] = rotr64(tv[b] ^ tv[c], 24);
        tv[a] = tv[a].wrapping_add(tv[b].wrapping_add(tm[(SIGMA[r] as [usize; 16])[2 * i + 1]]));
        tv[d] = rotr64(tv[d] ^ tv[a], 16);
        tv[c] = tv[c].wrapping_add(tv[d]);
        tv[b] = rotr64(tv[b] ^ tv[c], 63);
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
        sh[i] = sh[i] ^ tv[i] ^ tv[i + 8];
    }
}

fn increment_counter(t: &mut [u64; 2], inc: usize) {
    let mut c: u128 = ((t[1] as u128) << 64) | t[0] as u128;
    c += inc as u128;
    t[0] = c as u64;
    t[1] = (c >> 64) as u64;
}

impl State {
    fn init_param(params: &Params) -> Self {
        let mut state = Self::default();
        state.init0();

        let pslice = unsafe {
            std::slice::from_raw_parts(
                (params as *const Params) as *const u8,
                std::mem::size_of::<Params>(),
            )
        };

        for i in 0..8 {
            state.h[i] ^= load64_le(&pslice[(8 * i)..(8 * i + 8)]);
        }

        state
    }

    fn init0(&mut self) {
        self.h[..8].copy_from_slice(&IV);
    }

    pub(crate) fn init(outlen: u8) -> Result<Self, Error> {
        if outlen == 0 || outlen as usize > OUTBYTES {
            return Err(dryoc_error!(format!("invalid blake2b outlen: {}", outlen)));
        }

        let params = Params {
            digest_length: outlen,
            ..Default::default()
        };

        Ok(Self::init_param(&params))
    }

    pub(crate) fn init_key(outlen: u8, key: &[u8]) -> Result<State, Error> {
        if outlen == 0 || outlen as usize > OUTBYTES {
            return Err(dryoc_error!(format!("invalid blake2b outlen: {}", outlen)));
        }
        if key.is_empty() || key.len() > KEYBYTES {
            return Err(dryoc_error!(format!(
                "invalid blake2b key length: {}",
                outlen
            )));
        }

        let params = Params {
            digest_length: outlen,
            key_length: key.len() as u8,
            ..Default::default()
        };

        let mut state = Self::init_param(&params);

        let mut block = [0u8; BLOCKBYTES];
        block[..key.len()].copy_from_slice(key);
        state.update(&block);
        block.zeroize();

        Ok(state)
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            // return early if the input is empty
            return;
        }
        let start = if !self.buf.is_empty() && self.buf.len() < BLOCKBYTES {
            // the buffer should have at least BLOCKBYTES bytes in it; fill the buffer first
            // up to BLOCKBYTES
            if input.len() + self.buf.len() < BLOCKBYTES {
                // the combined length of input and buff is less than BLOCKBYTES, we just
                // fill the buff, and then we're done
                let buflen = self.buf.len();
                self.buf.resize(buflen + input.len(), 0);
                self.buf[buflen..].copy_from_slice(input);
                return; // return early
            } else {
                // fill the buf with the first N bytes of input until there are BLOCKBYTES bytes
                // in the buf
                let start = BLOCKBYTES - self.buf.len();
                let buf_start = self.buf.len();

                self.buf.resize(BLOCKBYTES, 0);
                self.buf[buf_start..].copy_from_slice(&input[..start]);

                start
            }
        } else if !self.buf.is_empty() {
            // if the buf is not empty, and there are at least BLOCKBYTES bytes in
            // the buf, we need to fill the buf so it's aligned to BLOCKBYTES
            // (assuming it's not already)
            if self.buf.len() % BLOCKBYTES != 0 {
                let additional_bytes = BLOCKBYTES - self.buf.len() % BLOCKBYTES;
                self.buf.copy_from_slice(&input[..additional_bytes]);
                additional_bytes
            } else {
                0
            }
        } else {
            // the state buf is empty, so we can ignore it
            0
        };
        let slen = input.len() - start; // the length from start
        let end = if slen % BLOCKBYTES == 0 {
            // it's already bound to the block size, just take everything minus one block
            input.len() - BLOCKBYTES
        } else {
            // take whatever is left over after blocks are consumed
            input.len() - slen % BLOCKBYTES
        };

        let h = &mut self.h;
        let t = &mut self.t;
        let f = &mut self.f;

        for chunk in self.buf.chunks(BLOCKBYTES) {
            increment_counter(t, BLOCKBYTES);
            compress(h, t, f, chunk);
        }
        for chunk in input[start..end].chunks(BLOCKBYTES) {
            increment_counter(t, BLOCKBYTES);
            compress(h, t, f, chunk);
        }

        // finally, copy whatever's leftover from input into buf
        self.buf.resize(input.len() - end, 0);
        self.buf.copy_from_slice(&input[end..]);
    }

    pub(crate) fn finalize(mut self, output: &mut [u8]) -> Result<(), Error> {
        if output.is_empty() || output.len() > OUTBYTES {
            return Err(dryoc_error!(format!(
                "invalid output length {}, should be <= {}",
                output.len(),
                OUTBYTES
            )));
        }

        if self.is_lastblock() {
            return Err(dryoc_error!("already on last block"));
        }

        if self.buf.len() > BLOCKBYTES {
            increment_counter(&mut self.t, BLOCKBYTES);
            compress(
                &mut self.h,
                &mut self.t,
                &mut self.f,
                &self.buf[..BLOCKBYTES],
            );

            increment_counter(&mut self.t, self.buf.len() - BLOCKBYTES);
            self.set_lastblock();

            // fill last block with zero padding
            self.buf.resize(2 * BLOCKBYTES, 0);

            compress(
                &mut self.h,
                &mut self.t,
                &mut self.f,
                &self.buf[BLOCKBYTES..],
            );
        } else {
            increment_counter(&mut self.t, self.buf.len());
            self.set_lastblock();

            // fill last block with zero padding
            self.buf.resize(BLOCKBYTES, 0);

            compress(&mut self.h, &mut self.t, &mut self.f, &self.buf);
        }
        self.buf.zeroize();

        let mut buffer = [0u8; OUTBYTES];
        buffer[0..8].copy_from_slice(&self.h[0].to_le_bytes());
        buffer[8..16].copy_from_slice(&self.h[1].to_le_bytes());
        buffer[16..24].copy_from_slice(&self.h[2].to_le_bytes());
        buffer[24..32].copy_from_slice(&self.h[3].to_le_bytes());
        buffer[32..40].copy_from_slice(&self.h[4].to_le_bytes());
        buffer[40..48].copy_from_slice(&self.h[5].to_le_bytes());
        buffer[48..56].copy_from_slice(&self.h[6].to_le_bytes());
        buffer[56..64].copy_from_slice(&self.h[7].to_le_bytes());
        output.copy_from_slice(&buffer[..output.len()]);

        self.h.zeroize();
        self.buf.zeroize();

        Ok(())
    }

    fn set_lastnode(&mut self) {
        self.f[1] = -1i64 as u64;
    }

    fn is_lastblock(&self) -> bool {
        self.f[0] != 0
    }

    fn set_lastblock(&mut self) {
        if self.last_node != 0 {
            self.set_lastnode();
        }
        self.f[0] = -1i64 as u64;
    }
}

pub(crate) fn hash(output: &mut [u8], input: &[u8], key: Option<&[u8]>) -> Result<(), Error> {
    if output.len() > OUTBYTES {
        return Err(dryoc_error!(format!(
            "output length {} greater than max {}",
            output.len(),
            OUTBYTES
        )));
    }

    let mut state = match key {
        Some(key) => State::init_key(output.len() as u8, key)?,
        None => State::init(output.len() as u8)?,
    };

    state.update(input);
    state.finalize(output)
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
        fn blake2b_init_key(S: *mut B2state, outlen: c_uchar, key: *const u8, keylen: c_uchar);
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

        let mut state = State::init(64).expect("init");

        let mut block = [0u8; 256];
        copy_randombytes(&mut block);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        let mut output = [0u8; 64];
        let mut so_output = [0u8; 64];

        unsafe {
            blake2b_final(
                &mut s,
                so_output.as_mut_ptr() as *mut u8,
                so_output.len() as u64,
            )
        };

        state.finalize(&mut output).ok();

        assert_eq!(output, so_output);
    }

    #[test]
    fn test_b2_key() {
        use crate::rng::copy_randombytes;

        let mut s = B2state {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: [0u8; 256],
            buflen: 0,
            last_node: 0,
        };

        let mut key = [0u8; 32];
        copy_randombytes(&mut key);
        let mut block = [0u8; 256];
        copy_randombytes(&mut block);

        unsafe { blake2b_init_key(&mut s, 64, &key as *const u8, key.len() as u8) };

        let mut state = State::init_key(64, &key).expect("init");

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        unsafe { blake2b_update(&mut s, &block as *const u8, block.len() as u64) };

        state.update(&block);

        let mut output = [0u8; 64];
        let mut so_output = [0u8; 64];

        unsafe {
            blake2b_final(
                &mut s,
                so_output.as_mut_ptr() as *mut u8,
                so_output.len() as u64,
            )
        };

        state.finalize(&mut output).ok();

        assert_eq!(output, so_output);
    }
}

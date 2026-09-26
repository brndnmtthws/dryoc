//! ML-KEM-768 (FIPS 203) key encapsulation.
//!
//! [`keypair`], [`encapsulate`] and [`decapsulate`] are FIPS 203's
//! `ML-KEM.KeyGen_internal`, `ML-KEM.Encaps_internal` and
//! `ML-KEM.Decaps_internal` with libsodium's byte formats: the 64-byte seed
//! is `d || z`, the secret key is the expanded FIPS 203 decapsulation key
//! `dk_pke || ek || H(ek) || z`, and encapsulation rejects an encapsulation
//! key whose coefficients are not reduced modulo `q` (FIPS 203 section
//! 7.2). Like libsodium, decapsulation does not check `H(ek)`.
//!
//! Polynomials are 256 signed 16-bit coefficients modulo `q = 3329`. The
//! three costly polynomial operations (forward NTT, inverse NTT and the
//! NTT-domain multiply-add) and the bulk of the matrix's rejection sampling
//! go through [`Arith`], which picks a vector backend at runtime when the
//! CPU has one (NEON, AVX2), or at compile time on WebAssembly builds with
//! `simd128` enabled. Every backend computes exactly the values of the
//! portable code in `mlkem_soft.rs` (and of [`rej_uniform`]). Everything
//! else (noise sampling, compression, encoding) is shared. Secret-dependent
//! code has no secret-dependent branches or memory indices: compression
//! uses multiplications instead of division, and the decapsulation
//! comparison and key selection are constant-time. Rejection sampling
//! branches on and indexes by its candidates, which come from the public
//! matrix seed.
//!
//! Zeroization: secret polynomials, seeds and hash outputs live in
//! `WideZeroizing` buffers or are wiped explicitly, and the helpers work in
//! place on them through references. At opt-level `z`, `s` or `2` several
//! helpers are out of line (the [`Arith`] methods and backend kernels,
//! `poly_reduce`, `poly_add_assign`, `encode12_vec`, `decode12_vec`, `g`,
//! `h`), which adds no copy: they get only `&`/`&mut` to that storage or
//! public data. `gen_matrix` and `rej_uniform` see only public data, and
//! the `array::map` calls left in `gen_matrix` and `cbd2` map references,
//! not secret values.

use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::constants::{
    CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_ENCSEEDBYTES,
    CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES, CRYPTO_KEM_MLKEM768_SECRETKEYBYTES,
    CRYPTO_KEM_MLKEM768_SEEDBYTES, CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
};
use crate::error::{Error, ErrorContext};
use crate::keccak::{
    Chain, Companion, DOMAIN_SHA3, DOMAIN_SHAKE, ParSponge, RATE_128, RATE_256, RATE_512,
    ROUNDS_FULL, hash,
};
use crate::utils::{WideZeroizing, zeroize_bytes};

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
mod mlkem_neon;
mod mlkem_soft;
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod mlkem_wasm32;
#[cfg(target_arch = "x86_64")]
mod mlkem_x86_64;

/// Coefficients per polynomial.
pub(crate) const N: usize = 256;
/// The modulus.
pub(crate) const Q: i16 = 3329;
/// Module rank for ML-KEM-768.
const K: usize = 3;
/// Bytes of one polynomial encoded with 12 bits per coefficient.
const POLYBYTES: usize = 384;
/// Bytes of the vector `u` compressed to 10 bits per coefficient.
const POLYVEC_COMPRESSEDBYTES: usize = K * 320;

pub(crate) const PUBLICKEYBYTES: usize = CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES;
pub(crate) const SECRETKEYBYTES: usize = CRYPTO_KEM_MLKEM768_SECRETKEYBYTES;
pub(crate) const CIPHERTEXTBYTES: usize = CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES;
pub(crate) const SHAREDSECRETBYTES: usize = CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES;
pub(crate) const SEEDBYTES: usize = CRYPTO_KEM_MLKEM768_SEEDBYTES;
pub(crate) const ENCSEEDBYTES: usize = CRYPTO_KEM_MLKEM768_ENCSEEDBYTES;

const _: () = {
    assert!(PUBLICKEYBYTES == K * POLYBYTES + 32);
    assert!(SECRETKEYBYTES == 2 * K * POLYBYTES + 3 * 32);
    assert!(CIPHERTEXTBYTES == POLYVEC_COMPRESSEDBYTES + 128);
};

/// One polynomial, in natural or NTT order.
pub(crate) type Poly = [i16; N];
type PolyVec = [Poly; K];

/// The polynomial arithmetic backend, chosen once per KEM operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arith {
    /// The portable code in `mlkem_soft.rs`.
    Soft,
    /// The NEON kernels in `mlkem_neon.rs`.
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    Neon(mlkem_neon::Kernel),
    /// The runtime-detected AVX2 kernels in `mlkem_x86_64.rs`.
    #[cfg(target_arch = "x86_64")]
    X86_64(mlkem_x86_64::Kernel),
    /// The `simd128` kernels in `mlkem_wasm32.rs`.
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    Wasm32(mlkem_wasm32::Kernel),
}

impl Arith {
    /// The fastest backend the running CPU supports.
    #[inline]
    pub(crate) fn detect() -> Self {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Some(kernel) = mlkem_neon::detect() {
            return Self::Neon(kernel);
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = mlkem_x86_64::detect() {
            return Self::X86_64(kernel);
        }
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        if let Some(kernel) = mlkem_wasm32::detect() {
            return Self::Wasm32(kernel);
        }
        Self::Soft
    }

    /// Every backend the running CPU supports, portable first.
    #[cfg(test)]
    pub(crate) fn all() -> alloc::vec::Vec<Self> {
        let all = core::iter::once(Self::Soft);
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        let all = all.chain(mlkem_neon::Kernel::all().into_iter().map(Self::Neon));
        #[cfg(target_arch = "x86_64")]
        let all = all.chain(mlkem_x86_64::Kernel::all().into_iter().map(Self::X86_64));
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        let all = all.chain(mlkem_wasm32::Kernel::all().into_iter().map(Self::Wasm32));
        all.collect()
    }

    #[inline]
    fn ntt(self, r: &mut Poly) {
        match self {
            Self::Soft => mlkem_soft::ntt(r),
            #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
            Self::Neon(kernel) => kernel.ntt(r),
            #[cfg(target_arch = "x86_64")]
            Self::X86_64(kernel) => kernel.ntt(r),
            #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
            Self::Wasm32(kernel) => kernel.ntt(r),
        }
    }

    #[inline]
    fn invntt_tomont(self, r: &mut Poly) {
        match self {
            Self::Soft => mlkem_soft::invntt_tomont(r),
            #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
            Self::Neon(kernel) => kernel.invntt_tomont(r),
            #[cfg(target_arch = "x86_64")]
            Self::X86_64(kernel) => kernel.invntt_tomont(r),
            #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
            Self::Wasm32(kernel) => kernel.invntt_tomont(r),
        }
    }

    #[inline]
    fn basemul_acc(self, r: &mut Poly, a: &PolyVec, b: &PolyVec) {
        match self {
            Self::Soft => mlkem_soft::basemul_acc(r, a, b),
            #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
            Self::Neon(kernel) => kernel.basemul_acc(r, a, b),
            #[cfg(target_arch = "x86_64")]
            Self::X86_64(kernel) => kernel.basemul_acc(r, a, b),
            #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
            Self::Wasm32(kernel) => kernel.basemul_acc(r, a, b),
        }
    }

    /// `basemul_acc(r[i], a[i], b)` for every row `i`; the NEON kernel forms
    /// `b`'s share of the products once for all rows.
    #[inline]
    fn basemul_rows<const R: usize>(self, r: [&mut Poly; R], a: [&PolyVec; R], b: &PolyVec) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Self::Neon(kernel) = self {
            kernel.basemul_rows(r, a, b);
            return;
        }
        for (r, a) in r.into_iter().zip(a) {
            self.basemul_acc(r, a, b);
        }
    }

    /// [`poly_add_assign`] of each of `addends`, then [`poly_reduce`]; one pass
    /// with the NEON kernel.
    #[inline]
    fn add_reduce<const M: usize>(self, r: &mut Poly, addends: [&Poly; M]) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Self::Neon(kernel) = self {
            kernel.add_reduce(r, addends);
            return;
        }
        for a in addends {
            poly_add_assign(r, a);
        }
        self.reduce(r);
    }

    /// [`poly_tomont`], [`poly_add_assign`] of `a`, then [`poly_reduce`]; one
    /// pass with the NEON kernel.
    #[inline]
    fn tomont_add_reduce(self, r: &mut Poly, a: &Poly) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Self::Neon(kernel) = self {
            kernel.tomont_add_reduce(r, a);
            return;
        }
        poly_tomont(r);
        poly_add_assign(r, a);
        self.reduce(r);
    }

    /// [`poly_to_msg`], with the NEON kernel where there is one.
    #[inline]
    fn poly_to_msg(self, m: &mut [u8; 32], a: &Poly) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Self::Neon(kernel) = self {
            kernel.poly_to_msg(m, a);
            return;
        }
        poly_to_msg(m, a);
    }

    /// [`decompress_u`], with the NEON kernel where there is one.
    #[inline]
    fn decompress_u(self, u: &mut PolyVec, bytes: &[u8]) {
        #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
        if let Self::Neon(kernel) = self {
            kernel.decompress10(u.as_flattened_mut().as_chunks_mut::<8>().0, bytes);
            return;
        }
        decompress_u(u, bytes);
    }

    /// [`poly_reduce`], with the NEON kernel where there is one.
    #[inline]
    fn reduce(self, r: &mut Poly) {
        match self {
            #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
            Self::Neon(kernel) => kernel.reduce(r),
            #[allow(unreachable_patterns)]
            _ => poly_reduce(r),
        }
    }

    fn ntt_vec(self, v: &mut PolyVec) {
        for p in v {
            self.ntt(p);
        }
    }

    /// [`rej_uniform`], with the bulk of `bytes` sampled by the vector
    /// backend where it has a kernel for it.
    #[inline]
    fn rej_uniform(self, poly: &mut Poly, filled: &mut usize, bytes: &[u8]) {
        let used = match self {
            #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
            Self::Neon(kernel) => kernel.rej_uniform(poly, filled, bytes),
            #[allow(unreachable_patterns)]
            _ => 0,
        };
        rej_uniform(poly, filled, &bytes[used..]);
    }
}

/// Maps a Barrett-reduced coefficient in `[0, q]` to `[0, q)`.
#[inline(always)]
fn canonical(x: i16) -> u16 {
    let x = x - Q;
    (x + ((x >> 15) & Q)) as u16
}

fn poly_reduce(r: &mut Poly) {
    for c in r {
        *c = mlkem_soft::barrett_reduce(*c);
    }
}

fn poly_add_assign(r: &mut Poly, a: &Poly) {
    for (r, a) in r.iter_mut().zip(a) {
        *r = r.wrapping_add(*a);
    }
}

/// Multiplies by `R` (enters the Montgomery domain).
fn poly_tomont(r: &mut Poly) {
    for c in r {
        *c = mlkem_soft::fqmul(*c, mlkem_soft::R2);
    }
}

/// SHA3-512 of the concatenated `parts` (FIPS 203 `G`), written as its two
/// 32-byte halves into the caller's (zeroizing) buffer.
fn g(output: &mut [[u8; 32]; 2], parts: &[&[u8]]) {
    hash::<RATE_512>(output.as_flattened_mut(), DOMAIN_SHA3, parts);
}

/// SHA3-256 (FIPS 203 `H`) of public data.
fn h(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    hash::<RATE_256>(&mut output, DOMAIN_SHA3, &[bytes]);
    output
}

/// SHAKE128 blocks squeezed for every matrix entry before sampling starts:
/// 504 bytes give 336 candidates, of which 256 are accepted in all but a
/// small fraction of entries.
const MATRIX_BLOCKS: usize = 3;

/// Appends the coefficients below `q` among the 12-bit candidates in
/// `bytes` to `poly[*filled..]` (FIPS 203 `SampleNTT`'s rejection step).
/// The matrix seed is public, so the data-dependent loop leaks nothing
/// secret. Every candidate is stored at the next free slot and the slot
/// advances only when it is accepted, so the one in five rejections is not
/// a mispredicted branch; a rejected value is overwritten by the next
/// candidate, and the only branch is the rarely taken full-polynomial exit.
fn rej_uniform(poly: &mut Poly, filled: &mut usize, bytes: &[u8]) {
    let mut n = *filled;
    'fill: for bytes in bytes.as_chunks::<3>().0 {
        let d1 = u16::from(bytes[0]) | (u16::from(bytes[1] & 0x0f) << 8);
        let d2 = u16::from(bytes[1] >> 4) | (u16::from(bytes[2]) << 4);
        for d in [d1, d2] {
            let Some(slot) = poly.get_mut(n) else {
                break 'fill;
            };
            *slot = d as i16;
            n += usize::from(d < Q as u16);
        }
    }
    *filled = n;
}

/// The matrix `A` in the NTT domain, or its transpose: entry `(i, j)` of
/// `A` is `SampleNTT(rho || j || i)`. The nine SHAKE128 streams are
/// squeezed together, then one more block at a time for the entries that
/// still need coefficients. `companion`'s permutations take slots in the
/// streams' multi-state calls (see [`Companion`]).
fn gen_matrix(
    arith: Arith,
    rho: &[u8],
    transposed: bool,
    mut companion: Option<&mut dyn Companion>,
) -> [PolyVec; K] {
    let indices: [[u8; 2]; K * K] = core::array::from_fn(|n| {
        let (i, j) = ((n / K) as u8, (n % K) as u8);
        if transposed { [i, j] } else { [j, i] }
    });
    let mut xof = ParSponge::<RATE_128, ROUNDS_FULL, { K * K }>::new();
    xof.absorb([rho; K * K]);
    xof.absorb(indices.each_ref().map(|x| &x[..]));
    xof.pad_with(DOMAIN_SHAKE, companion.as_deref_mut());

    let mut a = [[[0i16; N]; K]; K];
    let mut filled = [0; K * K];
    let mut blocks = [[0u8; MATRIX_BLOCKS * RATE_128]; K * K];
    xof.squeeze_with(
        blocks.each_mut().map(|b| &mut b[..]),
        companion.as_deref_mut(),
    );
    for ((poly, filled), block) in a
        .as_flattened_mut()
        .iter_mut()
        .zip(&mut filled)
        .zip(&blocks)
    {
        arith.rej_uniform(poly, filled, block);
    }
    while filled.iter().any(|&f| f < N) {
        let mut blocks = [[0u8; RATE_128]; K * K];
        let mut outputs = blocks.each_mut().map(|b| &mut b[..]);
        for (output, &filled) in outputs.iter_mut().zip(&filled) {
            if filled == N {
                *output = &mut [];
            }
        }
        xof.squeeze_with(outputs, companion.as_deref_mut());
        for ((poly, filled), block) in a
            .as_flattened_mut()
            .iter_mut()
            .zip(&mut filled)
            .zip(&blocks)
        {
            arith.rej_uniform(poly, filled, block);
        }
    }
    a
}

/// Samples `M` polynomials with coefficients from the centered binomial
/// distribution with `eta = 2`, polynomial `i` from `PRF(seed, nonces[i])`
/// = SHAKE256 of `seed || nonces[i]` (FIPS 203 `SamplePolyCBD`), with the
/// `M` streams computed together (with `companion` as in [`gen_matrix`]).
/// ML-KEM-768 uses `eta = 2` for all three noise vectors.
fn cbd2<const M: usize>(
    polys: &mut [Poly; M],
    seed: &[u8; 32],
    nonces: [u8; M],
    companion: Option<&mut dyn Companion>,
) {
    let mut prf = ParSponge::<RATE_256, ROUNDS_FULL, M>::new();
    prf.absorb([&seed[..]; M]);
    prf.absorb(nonces.each_ref().map(core::slice::from_ref));
    prf.pad_with(DOMAIN_SHAKE, companion);
    let mut buf = WideZeroizing::new([[0u8; 64 * 2]; M]);
    prf.squeeze(buf.each_mut().map(|b| &mut b[..]));

    // Byte `k` of the stream gives coefficients `2k` (low nibble) and `2k +
    // 1` (high nibble); LLVM vectorizes this byte-to-pair loop (`usubl`,
    // `st2`).
    for (poly, buf) in polys.iter_mut().zip(buf.iter()) {
        for (pair, &byte) in poly.as_chunks_mut::<2>().0.iter_mut().zip(buf) {
            let d = (byte & 0x55) + ((byte >> 1) & 0x55);
            let lo = i16::from(d & 3) - i16::from((d >> 2) & 3);
            let hi = i16::from((d >> 4) & 3) - i16::from(d >> 6);
            *pair = [lo, hi];
        }
    }
}

/// `ByteEncode_12` of a Barrett-reduced polynomial.
fn encode12(r: &mut [u8], a: &Poly) {
    for (bytes, pair) in r
        .as_chunks_mut::<3>()
        .0
        .iter_mut()
        .zip(a.as_chunks::<2>().0)
    {
        let t0 = canonical(pair[0]);
        let t1 = canonical(pair[1]);
        *bytes = [t0 as u8, ((t0 >> 8) | (t1 << 4)) as u8, (t1 >> 4) as u8];
    }
}

/// `ByteDecode_12` without the reduction modulo `q`: coefficients are in
/// `[0, 4096)`. Returns whether every coefficient was already below `q`
/// (the FIPS 203 encapsulation-key modulus check). Only public keys are
/// checked, so the flag need not be computed in constant time; it is
/// anyway, as the same code decodes secret keys.
fn decode12(a: &mut Poly, bytes: &[u8]) -> bool {
    let mut above = 0u16;
    for (pair, b) in a
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(bytes.as_chunks::<3>().0)
    {
        let t0 = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
        let t1 = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
        // The top bit of `q - 1 - t` is set exactly when `t >= q`.
        above |= (Q as u16 - 1).wrapping_sub(t0) | (Q as u16 - 1).wrapping_sub(t1);
        *pair = [t0 as i16, t1 as i16];
    }
    above >> 15 == 0
}

fn encode12_vec(r: &mut [u8], v: &PolyVec) {
    for (bytes, p) in r.as_chunks_mut::<POLYBYTES>().0.iter_mut().zip(v) {
        encode12(bytes, p);
    }
}

fn decode12_vec(v: &mut PolyVec, bytes: &[u8]) -> bool {
    let mut valid = true;
    for (p, bytes) in v.iter_mut().zip(bytes.as_chunks::<POLYBYTES>().0) {
        valid &= decode12(p, bytes);
    }
    valid
}

/// `Compress_10` of one coefficient, rounding by multiplication with `2^32
/// / q` rather than division.
#[inline(always)]
fn compress10(x: i16) -> u16 {
    let d = ((u64::from(canonical(x)) << 10) + 1665) * 1_290_167;
    ((d >> 32) & 0x3ff) as u16
}

/// `Compress_10` then `ByteEncode_10` of `u` (FIPS 203 section 4.2.1).
///
/// Spelled out: `array::map` with a closure copies the (secret, in
/// decapsulation's re-encryption) coefficients into an iterator, and at
/// opt-level `z` and `s` its `try_map` is out of line, which puts that copy
/// in memory.
fn compress_u(r: &mut [u8], u: &PolyVec) {
    let mut out = r.as_chunks_mut::<5>().0.iter_mut();
    for p in u {
        for c in p.as_chunks::<4>().0 {
            let t = [
                compress10(c[0]),
                compress10(c[1]),
                compress10(c[2]),
                compress10(c[3]),
            ];
            *out.next().expect("sized buffer") = [
                t[0] as u8,
                ((t[0] >> 8) | (t[1] << 2)) as u8,
                ((t[1] >> 6) | (t[2] << 4)) as u8,
                ((t[2] >> 4) | (t[3] << 6)) as u8,
                (t[3] >> 2) as u8,
            ];
        }
    }
}

/// `ByteDecode_10` then `Decompress_10`: coefficients in `[0, q)`.
///
/// The `array::map` calls are out of line at opt-level `z`, which adds no
/// secret copy: only the public ciphertext is decompressed.
fn decompress_u(u: &mut PolyVec, bytes: &[u8]) {
    let mut chunks = bytes.as_chunks::<5>().0.iter();
    for p in u {
        for c in p.as_chunks_mut::<4>().0 {
            decompress10(c, chunks.next().expect("sized buffer"));
        }
    }
}

/// Four coefficients of [`decompress_u`] from five bytes.
#[inline(always)]
fn decompress10(c: &mut [i16; 4], b: &[u8; 5]) {
    let b = b.map(u32::from);
    let t = [
        b[0] | (b[1] << 8),
        (b[1] >> 2) | (b[2] << 6),
        (b[2] >> 4) | (b[3] << 4),
        (b[3] >> 6) | (b[4] << 2),
    ];
    *c = t.map(|t| (((t & 0x3ff) * Q as u32 + 512) >> 10) as i16);
}

/// `Compress_4` of one coefficient.
#[inline(always)]
fn compress4(x: i16) -> u8 {
    let d = ((u32::from(canonical(x)) << 4) + 1665).wrapping_mul(80635);
    (d >> 28) as u8 & 0x0f
}

/// `Compress_4` then `ByteEncode_4` of `v`, spelled out like
/// [`compress_u`].
fn compress_v(r: &mut [u8], v: &Poly) {
    for (byte, pair) in r.iter_mut().zip(v.as_chunks::<2>().0) {
        *byte = compress4(pair[0]) | (compress4(pair[1]) << 4);
    }
}

/// `ByteDecode_4` then `Decompress_4`.
fn decompress_v(v: &mut Poly, bytes: &[u8]) {
    for (pair, &byte) in v.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        let nibble = |t: u8| ((u32::from(t) * Q as u32 + 8) >> 4) as i16;
        *pair = [nibble(byte & 0x0f), nibble(byte >> 4)];
    }
}

/// `Decompress_1(ByteDecode_1(m))`: each bit becomes `0` or `(q + 1) / 2`.
fn poly_from_msg(r: &mut Poly, m: &[u8; 32]) {
    for (coeffs, &byte) in r.as_chunks_mut::<8>().0.iter_mut().zip(m) {
        for (j, c) in coeffs.iter_mut().enumerate() {
            let mask = -(i16::from((byte >> j) & 1));
            *c = mask & ((Q + 1) / 2);
        }
    }
}

/// `ByteEncode_1(Compress_1(a))`.
fn poly_to_msg(m: &mut [u8; 32], a: &Poly) {
    for (byte, coeffs) in m.iter_mut().zip(a.as_chunks::<8>().0) {
        *byte = 0;
        for (j, &x) in coeffs.iter().enumerate() {
            let t = ((u32::from(canonical(x)) << 1) + 1665).wrapping_mul(80635) >> 28;
            *byte |= ((t & 1) as u8) << j;
        }
    }
}

/// A decoded encapsulation key: `t_hat` and the matrix seed `rho`.
struct PublicKey<'a> {
    t_hat: PolyVec,
    rho: &'a [u8],
}

impl<'a> PublicKey<'a> {
    /// Decodes `ek`, returning `None` if the modulus check fails.
    fn decode(ek: &'a [u8; PUBLICKEYBYTES]) -> Option<Self> {
        let (t_bytes, rho) = ek.split_at(K * POLYBYTES);
        let mut t_hat = [[0; N]; K];
        decode12_vec(&mut t_hat, t_bytes).then_some(Self { t_hat, rho })
    }

    /// K-PKE.Encrypt of `m` with randomness `coins`, given the transposed
    /// matrix `at` from [`gen_matrix`]; `companion` as in [`cbd2`].
    fn encrypt(
        &self,
        arith: Arith,
        at: &[PolyVec; K],
        ct: &mut [u8; CIPHERTEXTBYTES],
        m: &[u8; 32],
        coins: &[u8; 32],
        companion: Option<&mut dyn Companion>,
    ) {
        // `y`, `e1` and `e2` use nonces `0..2K + 1`, then comes `mu`.
        let mut polys = WideZeroizing::new([[0i16; N]; 2 * K + 2]);
        let (noise, mu) = polys.split_at_mut(2 * K + 1);
        let noise: &mut [Poly; 2 * K + 1] = noise.try_into().expect("2K + 1 polynomials");
        cbd2(noise, coins, core::array::from_fn(|i| i as u8), companion);
        poly_from_msg(&mut mu[0], m);
        let (y, rest) = noise
            .split_first_chunk_mut::<K>()
            .expect("K + K + 1 polynomials");
        let (e1, e2) = rest.split_at(K);
        arith.ntt_vec(y);

        let mut u = WideZeroizing::new([[0i16; N]; K]);
        let mut v = WideZeroizing::new([0i16; N]);
        let [u0, u1, u2] = &mut *u;
        arith.basemul_rows(
            [u0, u1, u2, &mut *v],
            [&at[0], &at[1], &at[2], &self.t_hat],
            y,
        );
        for ui in u.iter_mut() {
            arith.invntt_tomont(ui);
        }
        arith.invntt_tomont(&mut v);

        for (ui, e1i) in u.iter_mut().zip(e1.iter()) {
            arith.add_reduce(ui, [e1i]);
        }
        arith.add_reduce(&mut v, [&e2[0], &mu[0]]);

        let (ct_u, ct_v) = ct.split_at_mut(POLYVEC_COMPRESSEDBYTES);
        compress_u(ct_u, &u);
        compress_v(ct_v, &v);
    }
}

/// K-PKE.KeyGen from `d` (FIPS 203 `K-PKE.KeyGen`, before encoding):
/// writes the noise `s_hat || e_hat` (NTT domain) to `noise` and `t_hat`
/// (reduced) to `t_hat`, and returns the matrix `A` (not transposed) and
/// `rho`.
#[inline(always)]
fn pke_keygen(
    arith: Arith,
    d: &[u8],
    noise: &mut [Poly; 2 * K],
    t_hat: &mut PolyVec,
) -> ([PolyVec; K], [u8; 32]) {
    let mut rho_sigma = WideZeroizing::new([[0u8; 32]; 2]);
    g(&mut rho_sigma, &[d, &[K as u8]]);
    let [rho, sigma] = &*rho_sigma;

    let a = gen_matrix(arith, rho, false, None);
    // `s` and `e` use nonces `0..2K`.
    cbd2(noise, sigma, core::array::from_fn(|i| i as u8), None);
    let [s, e]: &mut [PolyVec; 2] = noise
        .as_chunks_mut::<K>()
        .0
        .try_into()
        .expect("two vectors");
    arith.ntt_vec(s);
    arith.ntt_vec(e);

    let [t0, t1, t2] = &mut *t_hat;
    arith.basemul_rows([t0, t1, t2], [&a[0], &a[1], &a[2]], s);
    for (t, e) in t_hat.iter_mut().zip(e.iter()) {
        arith.tomont_add_reduce(t, e);
    }
    (a, *rho)
}

/// Encodes `ek = ByteEncode_12(t_hat) || rho`.
fn encode_ek(pk: &mut [u8; PUBLICKEYBYTES], t_hat: &PolyVec, rho: &[u8; 32]) {
    let (t_bytes, pk_rho) = pk.split_at_mut(K * POLYBYTES);
    encode12_vec(t_bytes, t_hat);
    pk_rho.copy_from_slice(rho);
}

/// `ML-KEM.KeyGen_internal(d, z)` for `seed = d || z`.
pub(crate) fn keypair(
    arith: Arith,
    pk: &mut [u8; PUBLICKEYBYTES],
    sk: &mut [u8; SECRETKEYBYTES],
    seed: &[u8; SEEDBYTES],
) {
    let (d, z) = seed.split_at(32);
    let mut noise = WideZeroizing::new([[0i16; N]; 2 * K]);
    let mut t_hat = [[0i16; N]; K];
    let (_, rho) = pke_keygen(arith, d, &mut noise, &mut t_hat);
    encode_ek(pk, &t_hat, &rho);

    let (sk_s, rest) = sk.split_at_mut(K * POLYBYTES);
    let (sk_pk, rest) = rest.split_at_mut(PUBLICKEYBYTES);
    let (sk_h, sk_z) = rest.split_at_mut(32);
    let s: &PolyVec = noise.first_chunk::<K>().expect("K polynomials");
    encode12_vec(sk_s, s);
    sk_pk.copy_from_slice(pk);
    sk_h.copy_from_slice(&h(pk));
    sk_z.copy_from_slice(z);
}

/// `ML-KEM.Encaps_internal(ek, m)`, with the FIPS 203 encapsulation-key
/// check.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `pk` encodes a coefficient that is not
/// reduced modulo `q`.
pub(crate) fn encapsulate(
    arith: Arith,
    ct: &mut [u8; CIPHERTEXTBYTES],
    ss: &mut [u8; SHAREDSECRETBYTES],
    pk: &[u8; PUBLICKEYBYTES],
    m: &[u8; ENCSEEDBYTES],
) -> Result<(), Error> {
    let key = PublicKey::decode(pk).ok_or(Error::invalid_key(ErrorContext::PublicKey))?;
    // `H(ek)` is needed before the coins, the matrix only needs `rho`: the
    // hash's permutations ride along with the matrix's streams, spread over
    // its `MATRIX_BLOCKS` steps over all nine.
    let pk_parts = [&pk[..]];
    let mut pk_hash = Chain::<RATE_256>::new(DOMAIN_SHA3, &pk_parts, MATRIX_BLOCKS);
    let at = gen_matrix(arith, key.rho, true, Some(&mut pk_hash));
    let mut h = [0u8; 32];
    pk_hash.finish(&mut h);
    let mut k_r = WideZeroizing::new([[0u8; 32]; 2]);
    g(&mut k_r, &[m, &h]);
    let [k, r] = &*k_r;
    key.encrypt(arith, &at, ct, m, r, None);
    ss.copy_from_slice(k);
    Ok(())
}

/// The implicit-rejection key `J(z || c)` of [`decaps_with`]: still to be
/// finished (its remaining permutations riding along with the
/// re-encryption's noise sampling), or already computed into the caller's
/// wiped buffer.
enum Rejection<'a, 'b> {
    Pending(&'a mut Chain<'b, RATE_256>),
    Ready(&'a [u8; SHAREDSECRETBYTES]),
}

/// The Fujisaki-Okamoto part of `ML-KEM.Decaps_internal` shared by
/// [`decapsulate`] and [`decapsulate_seed`]: K-PKE.Decrypt with `s_hat`
/// (reduced), re-encryption under `key` with the transposed matrix `at`,
/// and the constant-time choice between `K` and the implicit-rejection key
/// `rejection`.
#[allow(clippy::too_many_arguments)]
fn decaps_with(
    arith: Arith,
    ss: &mut [u8; SHAREDSECRETBYTES],
    ct: &[u8; CIPHERTEXTBYTES],
    s_hat: &PolyVec,
    key: &PublicKey<'_>,
    at: &[PolyVec; K],
    pk_hash: &[u8],
    rejection: Rejection<'_, '_>,
) {
    // K-PKE.Decrypt.
    let mut polys = WideZeroizing::new([[0i16; N]; K + 2]);
    let (u, rest) = polys
        .split_first_chunk_mut::<K>()
        .expect("K + 2 polynomials");
    let [v, w]: &mut [Poly; 2] = rest.try_into().expect("two polynomials");
    let (ct_u, ct_v) = ct.split_at(POLYVEC_COMPRESSEDBYTES);
    arith.decompress_u(u, ct_u);
    decompress_v(v, ct_v);
    arith.ntt_vec(u);
    arith.basemul_acc(w, s_hat, u);
    arith.invntt_tomont(w);
    for (v, w) in v.iter_mut().zip(w.iter_mut()) {
        *w = v.wrapping_sub(*w);
    }
    arith.reduce(w);
    let mut m = WideZeroizing::new([0u8; 32]);
    arith.poly_to_msg(&mut m, w);

    let mut k_r = WideZeroizing::new([[0u8; 32]; 2]);
    g(&mut k_r, &[&m[..], pk_hash]);
    let [k, r] = &*k_r;
    let mut ct_prime = [0u8; CIPHERTEXTBYTES];
    let mut finished = WideZeroizing::new([0u8; SHAREDSECRETBYTES]);
    let reject: &[u8; SHAREDSECRETBYTES] = match rejection {
        Rejection::Pending(chain) => {
            key.encrypt(arith, at, &mut ct_prime, &m, r, Some(&mut *chain));
            chain.finish(&mut *finished);
            &finished
        }
        Rejection::Ready(reject) => {
            key.encrypt(arith, at, &mut ct_prime, &m, r, None);
            reject
        }
    };
    let matches = ct_eq_ciphertext(ct, &ct_prime);
    for ((out, &k), &reject) in ss.iter_mut().zip(k).zip(reject.iter()) {
        *out = u8::conditional_select(&reject, &k, matches);
    }
    zeroize_bytes(&mut ct_prime);
}

/// `ML-KEM.Decaps_internal(dk, c)`. A ciphertext that does not re-encrypt
/// to itself yields the implicit-rejection key `J(z || c)`; the choice is
/// made without branching on secret data.
pub(crate) fn decapsulate(
    arith: Arith,
    ss: &mut [u8; SHAREDSECRETBYTES],
    ct: &[u8; CIPHERTEXTBYTES],
    sk: &[u8; SECRETKEYBYTES],
) {
    let (sk_s, rest) = sk.split_at(K * POLYBYTES);
    let (pk, rest) = rest.split_at(PUBLICKEYBYTES);
    let (pk_hash, z) = rest.split_at(32);

    let mut s_hat = WideZeroizing::new([[0i16; N]; K]);
    decode12_vec(&mut s_hat, sk_s);
    // Re-encrypt under the embedded key; it was checked when stored, and
    // libsodium does not re-check it here, so neither do we.
    let mut t_hat = [[0; N]; K];
    decode12_vec(&mut t_hat, &pk[..K * POLYBYTES]);
    let key = PublicKey {
        t_hat,
        rho: &pk[K * POLYBYTES..],
    };
    // `J(z || c)` depends on nothing computed here: its permutations ride
    // along with the streams of the matrix's `MATRIX_BLOCKS` steps over all
    // nine and of the noise sampling's step over all seven, spread over
    // those steps.
    let rejection_parts = [z, &ct[..]];
    let mut rejection = Chain::<RATE_256>::new(DOMAIN_SHAKE, &rejection_parts, MATRIX_BLOCKS + 1);
    let at = gen_matrix(arith, key.rho, true, Some(&mut rejection));
    decaps_with(
        arith,
        ss,
        ct,
        &s_hat,
        &key,
        &at,
        pk_hash,
        Rejection::Pending(&mut rejection),
    );
}

/// [`decapsulate`] under the key pair [`keypair`] derives from `seed`,
/// without encoding the decapsulation key: the key generation's matrix `A`,
/// transposed, serves the re-encryption, so the matrix is sampled once
/// instead of twice, and `s_hat` and `t_hat` are used as computed rather
/// than encoded and decoded. The result is exactly `decapsulate` of
/// `keypair(seed)`'s secret key: every value is the same modulo `q`, and
/// the outputs are canonical encodings of those values.
pub(crate) fn decapsulate_seed(
    arith: Arith,
    ss: &mut [u8; SHAREDSECRETBYTES],
    ct: &[u8; CIPHERTEXTBYTES],
    seed: &[u8; SEEDBYTES],
) {
    let (d, z) = seed.split_at(32);
    let mut noise = WideZeroizing::new([[0i16; N]; 2 * K]);
    let mut t_hat = [[0i16; N]; K];
    let (a, rho) = pke_keygen(arith, d, &mut noise, &mut t_hat);
    let mut pk = [0u8; PUBLICKEYBYTES];
    encode_ek(&mut pk, &t_hat, &rho);
    // `H(ek)` and `J(z || c)` both take nine blocks, so they run as the two
    // lanes of one sponge; `ek`'s first 32 bytes go in with `z` so the lanes
    // fill their blocks in step.
    let mut pk_hash = [0u8; 32];
    let mut reject = WideZeroizing::new([0u8; SHAREDSECRETBYTES]);
    {
        let mut sponge = ParSponge::<RATE_256, ROUNDS_FULL, 2>::new();
        let (pk_head, pk_tail) = pk.split_at(32);
        sponge.absorb([pk_head, z]);
        sponge.absorb([pk_tail, &ct[..]]);
        sponge.pad_lanes([DOMAIN_SHA3, DOMAIN_SHAKE]);
        sponge.squeeze([&mut pk_hash, &mut *reject]);
    }

    // Decryption takes `s_hat` reduced, as decoding would give it.
    let s_hat: &mut PolyVec = noise.first_chunk_mut::<K>().expect("K polynomials");
    for p in s_hat.iter_mut() {
        arith.reduce(p);
    }
    let at: [PolyVec; K] = core::array::from_fn(|i| core::array::from_fn(|j| a[j][i]));
    let key = PublicKey { t_hat, rho: &rho };
    decaps_with(
        arith,
        ss,
        ct,
        s_hat,
        &key,
        &at,
        &pk_hash,
        Rejection::Ready(&reject),
    );
}

/// `a == b` in constant time: the XORs of the 136 eight-byte words are ORed
/// together without a branch and only the total goes through `subtle`,
/// whose slice comparison passes each of the 1,088 bytes through its
/// optimization barrier (measured at 8% of a decapsulation).
fn ct_eq_ciphertext(a: &[u8; CIPHERTEXTBYTES], b: &[u8; CIPHERTEXTBYTES]) -> subtle::Choice {
    let (a, b) = (a.as_chunks::<8>().0, b.as_chunks::<8>().0);
    let diff = a.iter().zip(b).fold(0u64, |diff, (x, y)| {
        diff | (u64::from_ne_bytes(*x) ^ u64::from_ne_bytes(*y))
    });
    diff.ct_eq(&0)
}

#[cfg(test)]
pub(crate) mod tests;

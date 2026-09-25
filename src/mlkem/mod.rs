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
//! NTT-domain multiply-add) go through [`Arith`], which picks a vector
//! backend at runtime when the CPU has one. Every backend computes exactly
//! the values of the portable code in `mlkem_soft.rs`. Everything else
//! (sampling, compression, encoding) is shared. Secret-dependent code has
//! no secret-dependent branches or memory indices: compression uses
//! multiplications instead of division, and the decapsulation comparison
//! and key selection are constant-time.

use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_ENCSEEDBYTES,
    CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES, CRYPTO_KEM_MLKEM768_SECRETKEYBYTES,
    CRYPTO_KEM_MLKEM768_SEEDBYTES, CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES,
};
use crate::error::{Error, ErrorContext};
use crate::keccak::{
    DOMAIN_SHA3, DOMAIN_SHAKE, ParSponge, RATE_128, RATE_256, RATE_512, ROUNDS_FULL, hash,
};

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
mod mlkem_neon;
mod mlkem_soft;
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
        }
    }

    fn ntt_vec(self, v: &mut PolyVec) {
        for p in v {
            self.ntt(p);
        }
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
/// secret.
fn rej_uniform(poly: &mut Poly, filled: &mut usize, bytes: &[u8]) {
    for bytes in bytes.as_chunks::<3>().0 {
        let d1 = u16::from(bytes[0]) | (u16::from(bytes[1] & 0x0f) << 8);
        let d2 = u16::from(bytes[1] >> 4) | (u16::from(bytes[2]) << 4);
        for d in [d1, d2] {
            if d < Q as u16 && *filled < N {
                poly[*filled] = d as i16;
                *filled += 1;
            }
        }
    }
}

/// The matrix `A` in the NTT domain, or its transpose: entry `(i, j)` of
/// `A` is `SampleNTT(rho || j || i)`. The nine SHAKE128 streams are
/// squeezed together, then one more block at a time for the entries that
/// still need coefficients.
fn gen_matrix(rho: &[u8], transposed: bool) -> [PolyVec; K] {
    let indices: [[u8; 2]; K * K] = core::array::from_fn(|n| {
        let (i, j) = ((n / K) as u8, (n % K) as u8);
        if transposed { [i, j] } else { [j, i] }
    });
    let mut xof = ParSponge::<RATE_128, ROUNDS_FULL, { K * K }>::new();
    xof.absorb([rho; K * K]);
    xof.absorb(indices.each_ref().map(|x| &x[..]));
    xof.pad(DOMAIN_SHAKE);

    let mut a = [[[0i16; N]; K]; K];
    let mut filled = [0; K * K];
    let mut blocks = [[0u8; MATRIX_BLOCKS * RATE_128]; K * K];
    xof.squeeze(blocks.each_mut().map(|b| &mut b[..]));
    for ((poly, filled), block) in a
        .as_flattened_mut()
        .iter_mut()
        .zip(&mut filled)
        .zip(&blocks)
    {
        rej_uniform(poly, filled, block);
    }
    while filled.iter().any(|&f| f < N) {
        let mut blocks = [[0u8; RATE_128]; K * K];
        let mut outputs = blocks.each_mut().map(|b| &mut b[..]);
        for (output, &filled) in outputs.iter_mut().zip(&filled) {
            if filled == N {
                *output = &mut [];
            }
        }
        xof.squeeze(outputs);
        for ((poly, filled), block) in a
            .as_flattened_mut()
            .iter_mut()
            .zip(&mut filled)
            .zip(&blocks)
        {
            rej_uniform(poly, filled, block);
        }
    }
    a
}

/// Samples `M` polynomials with coefficients from the centered binomial
/// distribution with `eta = 2`, polynomial `i` from `PRF(seed, nonces[i])`
/// = SHAKE256 of `seed || nonces[i]` (FIPS 203 `SamplePolyCBD`), with the
/// `M` streams computed together. ML-KEM-768 uses `eta = 2` for all three
/// noise vectors.
fn cbd2<const M: usize>(polys: &mut [Poly; M], seed: &[u8; 32], nonces: [u8; M]) {
    let mut prf = ParSponge::<RATE_256, ROUNDS_FULL, M>::new();
    prf.absorb([&seed[..]; M]);
    prf.absorb(nonces.each_ref().map(core::slice::from_ref));
    prf.pad(DOMAIN_SHAKE);
    let mut buf = Zeroizing::new([[0u8; 64 * 2]; M]);
    prf.squeeze(buf.each_mut().map(|b| &mut b[..]));

    for (poly, buf) in polys.iter_mut().zip(buf.iter()) {
        for (coeffs, word) in poly
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(buf.as_chunks::<4>().0)
        {
            let t = u32::from_le_bytes(*word);
            let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
            for (j, c) in coeffs.iter_mut().enumerate() {
                let a = ((d >> (4 * j)) & 3) as i16;
                let b = ((d >> (4 * j + 2)) & 3) as i16;
                *c = a - b;
            }
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

/// `Compress_10` then `ByteEncode_10` of `u` (FIPS 203 section 4.2.1),
/// rounding by multiplication with `2^32 / q` rather than division.
fn compress_u(r: &mut [u8], u: &PolyVec) {
    let mut out = r.as_chunks_mut::<5>().0.iter_mut();
    for p in u {
        for c in p.as_chunks::<4>().0 {
            let t = c.map(|x| {
                let d = ((u64::from(canonical(x)) << 10) + 1665) * 1_290_167;
                ((d >> 32) & 0x3ff) as u16
            });
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
fn decompress_u(u: &mut PolyVec, bytes: &[u8]) {
    let mut chunks = bytes.as_chunks::<5>().0.iter();
    for p in u {
        for c in p.as_chunks_mut::<4>().0 {
            let b = chunks.next().expect("sized buffer").map(u32::from);
            let t = [
                b[0] | (b[1] << 8),
                (b[1] >> 2) | (b[2] << 6),
                (b[2] >> 4) | (b[3] << 4),
                (b[3] >> 6) | (b[4] << 2),
            ];
            *c = t.map(|t| (((t & 0x3ff) * Q as u32 + 512) >> 10) as i16);
        }
    }
}

/// `Compress_4` then `ByteEncode_4` of `v`.
fn compress_v(r: &mut [u8], v: &Poly) {
    for (byte, pair) in r.iter_mut().zip(v.as_chunks::<2>().0) {
        let t = pair.map(|x| {
            let d = ((u32::from(canonical(x)) << 4) + 1665).wrapping_mul(80635);
            (d >> 28) as u8 & 0x0f
        });
        *byte = t[0] | (t[1] << 4);
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

    /// K-PKE.Encrypt of `m` with randomness `coins`.
    fn encrypt(
        &self,
        arith: Arith,
        ct: &mut [u8; CIPHERTEXTBYTES],
        m: &[u8; 32],
        coins: &[u8; 32],
    ) {
        let at = gen_matrix(self.rho, true);
        // `y`, `e1` and `e2` use nonces `0..2K + 1`, then comes `mu`.
        let mut polys = Zeroizing::new([[0i16; N]; 2 * K + 2]);
        let (noise, mu) = polys.split_at_mut(2 * K + 1);
        let noise: &mut [Poly; 2 * K + 1] = noise.try_into().expect("2K + 1 polynomials");
        cbd2(noise, coins, core::array::from_fn(|i| i as u8));
        poly_from_msg(&mut mu[0], m);
        let (y, rest) = noise
            .split_first_chunk_mut::<K>()
            .expect("K + K + 1 polynomials");
        let (e1, e2) = rest.split_at(K);
        arith.ntt_vec(y);

        let mut u = Zeroizing::new([[0i16; N]; K]);
        for (ui, row) in u.iter_mut().zip(&at) {
            arith.basemul_acc(ui, row, y);
            arith.invntt_tomont(ui);
        }
        let mut v = Zeroizing::new([0i16; N]);
        arith.basemul_acc(&mut v, &self.t_hat, y);
        arith.invntt_tomont(&mut v);

        for (ui, e1i) in u.iter_mut().zip(e1.iter()) {
            poly_add_assign(ui, e1i);
            poly_reduce(ui);
        }
        poly_add_assign(&mut v, &e2[0]);
        poly_add_assign(&mut v, &mu[0]);
        poly_reduce(&mut v);

        let (ct_u, ct_v) = ct.split_at_mut(POLYVEC_COMPRESSEDBYTES);
        compress_u(ct_u, &u);
        compress_v(ct_v, &v);
    }
}

/// `ML-KEM.KeyGen_internal(d, z)` for `seed = d || z`.
pub(crate) fn keypair(
    arith: Arith,
    pk: &mut [u8; PUBLICKEYBYTES],
    sk: &mut [u8; SECRETKEYBYTES],
    seed: &[u8; SEEDBYTES],
) {
    let (d, z) = seed.split_at(32);
    let mut rho_sigma = Zeroizing::new([[0u8; 32]; 2]);
    g(&mut rho_sigma, &[d, &[K as u8]]);
    let [rho, sigma] = &*rho_sigma;

    let a = gen_matrix(rho, false);
    // `s` and `e` use nonces `0..2K`.
    let mut noise = Zeroizing::new([[0i16; N]; 2 * K]);
    cbd2(&mut noise, sigma, core::array::from_fn(|i| i as u8));
    let [s, e]: &mut [PolyVec; 2] = noise
        .as_chunks_mut::<K>()
        .0
        .try_into()
        .expect("two vectors");
    arith.ntt_vec(s);
    arith.ntt_vec(e);

    let mut t_hat = [[0i16; N]; K];
    for ((t, row), e) in t_hat.iter_mut().zip(&a).zip(e.iter()) {
        arith.basemul_acc(t, row, s);
        poly_tomont(t);
        poly_add_assign(t, e);
        poly_reduce(t);
    }

    let (t_bytes, pk_rho) = pk.split_at_mut(K * POLYBYTES);
    encode12_vec(t_bytes, &t_hat);
    pk_rho.copy_from_slice(rho);

    let (sk_s, rest) = sk.split_at_mut(K * POLYBYTES);
    let (sk_pk, rest) = rest.split_at_mut(PUBLICKEYBYTES);
    let (sk_h, sk_z) = rest.split_at_mut(32);
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
    let mut k_r = Zeroizing::new([[0u8; 32]; 2]);
    g(&mut k_r, &[m, &h(pk)]);
    let [k, r] = &*k_r;
    key.encrypt(arith, ct, m, r);
    ss.copy_from_slice(k);
    Ok(())
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
    let pk: &[u8; PUBLICKEYBYTES] = pk.try_into().expect("sized public key");

    // K-PKE.Decrypt.
    let mut polys = Zeroizing::new(([[0i16; N]; K], [[0i16; N]; K], [0i16; N], [0i16; N]));
    let (s_hat, u, v, w) = &mut *polys;
    decode12_vec(s_hat, sk_s);
    let (ct_u, ct_v) = ct.split_at(POLYVEC_COMPRESSEDBYTES);
    decompress_u(u, ct_u);
    decompress_v(v, ct_v);
    arith.ntt_vec(u);
    arith.basemul_acc(w, s_hat, u);
    arith.invntt_tomont(w);
    for (v, w) in v.iter_mut().zip(w.iter_mut()) {
        *w = v.wrapping_sub(*w);
    }
    poly_reduce(w);
    let mut m = Zeroizing::new([0u8; 32]);
    poly_to_msg(&mut m, w);

    // Re-encrypt under the embedded key; it was checked when stored, and
    // libsodium does not re-check it here, so neither do we.
    let mut t_hat = [[0; N]; K];
    decode12_vec(&mut t_hat, &pk[..K * POLYBYTES]);
    let key = PublicKey {
        t_hat,
        rho: &pk[K * POLYBYTES..],
    };
    let mut k_r = Zeroizing::new([[0u8; 32]; 2]);
    g(&mut k_r, &[&m[..], pk_hash]);
    let [k, r] = &*k_r;
    let mut ct_prime = [0u8; CIPHERTEXTBYTES];
    key.encrypt(arith, &mut ct_prime, &m, r);

    let mut reject = Zeroizing::new([0u8; SHAREDSECRETBYTES]);
    hash::<RATE_256>(&mut *reject, DOMAIN_SHAKE, &[z, ct]);
    let matches = ct.ct_eq(&ct_prime);
    for ((out, &k), &reject) in ss.iter_mut().zip(k).zip(reject.iter()) {
        *out = u8::conditional_select(&reject, &k, matches);
    }
    ct_prime.zeroize();
}

#[cfg(test)]
pub(crate) mod tests;

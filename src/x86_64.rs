//! AVX2 and AVX-512 helpers shared by the x86-64 kernels (`chacha20`,
//! `salsa20`, `blake2b`, `argon2`, `mlkem`, `keccak`): the kernel variants
//! and their detection, vector loads and stores, the lane-set input, counter
//! and transposes, the keystream XOR into a [`Dest`], the feed-forward XOR
//! of a scalar block, the 64-bit lane rotations, and the BMI2 check behind
//! the Curve25519 field-arithmetic roots.

use std::arch::x86_64::{
    __m256i, __m512i, _mm256_add_epi32, _mm256_add_epi64, _mm256_cmpgt_epi32, _mm256_loadu_si256,
    _mm256_or_si256, _mm256_permute2x128_si256, _mm256_set1_epi32, _mm256_setr_epi8,
    _mm256_setr_epi32, _mm256_shuffle_epi32, _mm256_srli_epi64, _mm256_storeu_si256,
    _mm256_sub_epi32, _mm256_unpackhi_epi32, _mm256_unpackhi_epi64, _mm256_unpacklo_epi32,
    _mm256_unpacklo_epi64, _mm256_xor_si256, _mm512_add_epi32, _mm512_cmplt_epu32_mask,
    _mm512_loadu_si512, _mm512_mask_add_epi32, _mm512_set1_epi32, _mm512_setr_epi32,
    _mm512_shuffle_i32x4, _mm512_storeu_si512, _mm512_unpackhi_epi32, _mm512_unpackhi_epi64,
    _mm512_unpacklo_epi32, _mm512_unpacklo_epi64, _mm512_xor_si512,
};

pub(crate) use crate::stream::Dest;

/// Byte permutation (per 128-bit half) rotating every 64-bit lane right by
/// 24 bits.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn ror24_table() -> __m256i {
    _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13,
        14, 15, 8, 9, 10,
    )
}

/// Byte permutation (per 128-bit half) rotating every 64-bit lane right by
/// 16 bits.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn ror16_table() -> __m256i {
    _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12,
        13, 14, 15, 8, 9,
    )
}

/// Rotates every 64-bit lane right by 32 bits (a dword swap).
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn ror32(v: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<0xB1>(v)
}

// `ror24` and `ror16` are only used by the BLAKE2b kernels, which are compiled
// out when the portable-SIMD BLAKE2b backend is selected; Argon2 uses the
// tables directly.
/// Rotates every 64-bit lane right by 24 bits.
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
pub(crate) fn ror24(v: __m256i) -> __m256i {
    std::arch::x86_64::_mm256_shuffle_epi8(v, ror24_table())
}

/// Rotates every 64-bit lane right by 16 bits.
#[inline]
#[target_feature(enable = "avx2")]
#[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
pub(crate) fn ror16(v: __m256i) -> __m256i {
    std::arch::x86_64::_mm256_shuffle_epi8(v, ror16_table())
}

/// Rotates every 64-bit lane right by 63 bits (left by one).
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn ror63(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_add_epi64(v, v), _mm256_srli_epi64::<63>(v))
}

/// Blocks per 8-lane (256-bit) vector set.
pub(crate) const LANES: usize = 8;
/// Blocks per 16-lane (512-bit) vector set.
pub(crate) const LANES512: usize = 16;

/// The lane-set kernel variants of the x86-64 stream ciphers. Values are
/// only created by [`LaneSet::detect`] (and, in tests, [`LaneSet::all`])
/// after checking the CPU features the variant's kernels are compiled for,
/// which is what makes the ciphers' `xor_chunk` dispatch safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaneSet {
    /// AVX2: one 8-block lane set in the 16 `ymm` registers.
    Avx2,
    /// AVX-512F: one 16-block lane set in `zmm` registers, with `vprold` for
    /// the rotations.
    Avx512,
    /// AVX-512F with VL: [`LaneSet::Avx512`], and runs of at most [`LANES`]
    /// slots on an 8-block `ymm` lane set with `vprold` rotations and the 32
    /// EVEX registers, which finishes in about 80% of the 16-block set's
    /// time.
    Avx512Vl,
}

impl LaneSet {
    /// The best variant the running CPU supports.
    #[inline]
    pub(crate) fn detect() -> Option<Self> {
        if std::arch::is_x86_feature_detected!("avx512f") {
            if Self::has_avx512vl() {
                Some(Self::Avx512Vl)
            } else {
                Some(Self::Avx512)
            }
        } else if std::arch::is_x86_feature_detected!("avx2") {
            Some(Self::Avx2)
        } else {
            None
        }
    }

    /// Every variant the running CPU supports.
    #[cfg(test)]
    pub(crate) fn all() -> Vec<Self> {
        let mut variants = Vec::new();
        if std::arch::is_x86_feature_detected!("avx2") {
            variants.push(Self::Avx2);
        }
        if std::arch::is_x86_feature_detected!("avx512f") {
            variants.push(Self::Avx512);
            if Self::has_avx512vl() {
                variants.push(Self::Avx512Vl);
            }
        }
        variants
    }

    /// The `ymm` kernels of [`LaneSet::Avx512Vl`] are compiled for `avx2`
    /// as well as `avx512f,avx512vl`.
    #[inline]
    fn has_avx512vl() -> bool {
        std::arch::is_x86_feature_detected!("avx512vl")
            && std::arch::is_x86_feature_detected!("avx2")
    }

    /// Blocks produced per run.
    #[inline]
    pub(crate) fn blocks(self) -> usize {
        match self {
            Self::Avx2 => LANES,
            Self::Avx512 | Self::Avx512Vl => LANES512,
        }
    }

    /// Whether the AVX-512 kernels' fused companion block is available: the
    /// 16-lane set leaves the integer ports idle for a scalar block's rounds.
    #[inline]
    pub(crate) fn fuses_extra_block(self) -> bool {
        match self {
            Self::Avx2 => false,
            Self::Avx512 | Self::Avx512Vl => true,
        }
    }

    /// Whether a run of `output_len` bytes of whole blocks plus the partial
    /// slot (when `has_partial`) fits one 8-block `ymm` lane set, which
    /// [`LaneSet::Avx512Vl`] serves with its short kernel.
    #[inline]
    pub(crate) fn fits_ymm(output_len: usize, has_partial: bool) -> bool {
        output_len / 64 + usize::from(has_partial) <= LANES
    }
}

/// Whether the CPU has BMI2, whose `mulx` lets the compiler schedule the
/// `u128` products of the Curve25519 field arithmetic without the fixed
/// `rdx:rax` registers of `mul`; the check is cached by `std`.
#[inline]
pub(crate) fn has_bmi2() -> bool {
    std::arch::is_x86_feature_detected!("bmi2")
}

/// Loads 32 bytes as a vector.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn load(bytes: &[u8; 32]) -> __m256i {
    // SAFETY: `bytes` is a valid reference to exactly 32 readable bytes;
    // `_mm256_loadu_si256` has no alignment requirement.
    unsafe { _mm256_loadu_si256(bytes.as_ptr().cast()) }
}

/// Stores a vector as 32 bytes.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn store(bytes: &mut [u8; 32], v: __m256i) {
    // SAFETY: `bytes` is a valid exclusive reference to exactly 32 writable
    // bytes; `_mm256_storeu_si256` has no alignment requirement.
    unsafe { _mm256_storeu_si256(bytes.as_mut_ptr().cast(), v) }
}

/// Loads four `u64` words as a vector, word 0 in lane 0.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn load_words(words: &[u64; 4]) -> __m256i {
    // SAFETY: `words` is a valid reference to exactly 32 readable bytes;
    // `_mm256_loadu_si256` has no alignment requirement.
    unsafe { _mm256_loadu_si256(words.as_ptr().cast()) }
}

/// Stores a vector as four `u64` words, lane 0 in word 0.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn store_words(words: &mut [u64; 4], v: __m256i) {
    // SAFETY: `words` is a valid exclusive reference to exactly 32 writable
    // bytes; `_mm256_storeu_si256` has no alignment requirement.
    unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast(), v) }
}

/// Loads sixteen `i16` lanes as a vector, element 0 in lane 0.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn load_i16s(lanes: &[i16; 16]) -> __m256i {
    // SAFETY: `lanes` is a valid reference to exactly 32 readable bytes;
    // `_mm256_loadu_si256` has no alignment requirement.
    unsafe { _mm256_loadu_si256(lanes.as_ptr().cast()) }
}

/// Stores a vector as sixteen `i16` lanes, lane 0 in element 0.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn store_i16s(lanes: &mut [i16; 16], v: __m256i) {
    // SAFETY: `lanes` is a valid exclusive reference to exactly 32 writable
    // bytes; `_mm256_storeu_si256` has no alignment requirement.
    unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), v) }
}

/// Loads eight `u64` words as a vector, word 0 in lane 0.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn load_words512(words: &[u64; 8]) -> __m512i {
    // SAFETY: `words` is a valid reference to exactly 64 readable bytes;
    // `_mm512_loadu_si512` has no alignment requirement.
    unsafe { _mm512_loadu_si512(words.as_ptr().cast()) }
}

/// Stores a vector as eight `u64` words, lane 0 in word 0.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn store_words512(words: &mut [u64; 8], v: __m512i) {
    // SAFETY: `words` is a valid exclusive reference to exactly 64 writable
    // bytes; `_mm512_storeu_si512` has no alignment requirement.
    unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), v) }
}

/// The 32-bit lanes `counter + 0 .. counter + 8` of a 64-bit block counter
/// split into low and high words, `(lo, hi)`, the high word carrying where
/// the low word wrapped.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn counter_lanes(counter: u64) -> (__m256i, __m256i) {
    let lo = _mm256_set1_epi32(counter as u32 as i32);
    let lo_lanes = _mm256_add_epi32(lo, _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    // A lane whose low word wrapped compares below the base. AVX2 has only a
    // signed compare, so both sides have their sign bit flipped first; the
    // all-ones lanes are then subtracted to carry into the high word.
    let sign = _mm256_set1_epi32(i32::MIN);
    let carry = _mm256_cmpgt_epi32(_mm256_xor_si256(lo, sign), _mm256_xor_si256(lo_lanes, sign));
    let hi_lanes = _mm256_sub_epi32(_mm256_set1_epi32((counter >> 32) as u32 as i32), carry);
    (lo_lanes, hi_lanes)
}

/// The cipher input for blocks `counter .. counter + 8`, one block per
/// lane: every word of `state` broadcast, with the low and high halves of
/// the block counter in words `LO` and `HI`.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn input_lanes<const LO: usize, const HI: usize>(
    state: &[u32; 16],
    counter: u64,
) -> [__m256i; 16] {
    let mut x = [_mm256_set1_epi32(0); 16];
    for (lane, &word) in x.iter_mut().zip(state) {
        *lane = _mm256_set1_epi32(word as i32);
    }
    (x[LO], x[HI]) = counter_lanes(counter);
    x
}

/// Transposes the 8x8 word matrix held in `r` (vector `i` = word `i` of
/// blocks `0..8`) so that vector `j` of the result holds words `0..8` of block
/// `j`.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn transpose(r: [__m256i; 8]) -> [__m256i; 8] {
    // Pairs of words interleaved within each 128-bit half.
    let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
    let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
    let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
    let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
    let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
    let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
    let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
    let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
    // Each half of `u<k>` now holds words `0..4` (`k < 4`) or `4..8` (`k >=
    // 4`) of one block: the low half of block `k % 4`, the high half of block
    // `k % 4 + 4`.
    let u0 = _mm256_unpacklo_epi64(t0, t2);
    let u1 = _mm256_unpackhi_epi64(t0, t2);
    let u2 = _mm256_unpacklo_epi64(t1, t3);
    let u3 = _mm256_unpackhi_epi64(t1, t3);
    let u4 = _mm256_unpacklo_epi64(t4, t6);
    let u5 = _mm256_unpackhi_epi64(t4, t6);
    let u6 = _mm256_unpacklo_epi64(t5, t7);
    let u7 = _mm256_unpackhi_epi64(t5, t7);
    [
        _mm256_permute2x128_si256::<0x20>(u0, u4),
        _mm256_permute2x128_si256::<0x20>(u1, u5),
        _mm256_permute2x128_si256::<0x20>(u2, u6),
        _mm256_permute2x128_si256::<0x20>(u3, u7),
        _mm256_permute2x128_si256::<0x31>(u0, u4),
        _mm256_permute2x128_si256::<0x31>(u1, u5),
        _mm256_permute2x128_si256::<0x31>(u2, u6),
        _mm256_permute2x128_si256::<0x31>(u3, u7),
    ]
}

/// Transposes the 4x4 matrix of 64-bit words held in `r`: word `j` of
/// vector `i` becomes word `i` of vector `j`. The transpose is its own
/// inverse.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn transpose_words(r: [__m256i; 4]) -> [__m256i; 4] {
    // Words `0` and `2` (`lo`) or `1` and `3` (`hi`) of two vectors.
    let t0 = _mm256_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm256_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm256_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm256_unpackhi_epi64(r[2], r[3]);
    [
        _mm256_permute2x128_si256::<0x20>(t0, t2),
        _mm256_permute2x128_si256::<0x20>(t1, t3),
        _mm256_permute2x128_si256::<0x31>(t0, t2),
        _mm256_permute2x128_si256::<0x31>(t1, t3),
    ]
}

/// XORs the two 32-byte keystream halves `$lo`, `$hi` into block `$index`
/// of `$dest`. A macro for the same reason as [`finish_lanes`]: out of line,
/// the halves would be passed through the stack.
macro_rules! xor_block {
    ($lo:expr, $hi:expr, $index:expr, $dest:expr) => {
        if let Some((source, out)) = $dest.block($index) {
            let out = out.as_chunks_mut::<32>().0;
            let (data_lo, data_hi) = match source {
                Some(source) => {
                    let source = source.as_chunks::<32>().0;
                    (
                        $crate::x86_64::load(&source[0]),
                        $crate::x86_64::load(&source[1]),
                    )
                }
                None => ($crate::x86_64::load(&out[0]), $crate::x86_64::load(&out[1])),
            };
            $crate::x86_64::store(
                &mut out[0],
                ::std::arch::x86_64::_mm256_xor_si256(data_lo, $lo),
            );
            $crate::x86_64::store(
                &mut out[1],
                ::std::arch::x86_64::_mm256_xor_si256(data_hi, $hi),
            );
        }
    };
}
pub(crate) use xor_block;

/// Finalises an 8-block lane set held in the 16 vectors `$x` (lane = block):
/// adds the input `$initial` back, transposes into block order and XORs the
/// keystream into blocks `0..8` of `$dest`.
///
/// A macro rather than a function so it expands inside each kernel: a
/// `#[target_feature]` function cannot be `#[inline(always)]`, and as an
/// `#[inline]` function the compiler kept it out of line, so every kernel
/// handed it stack copies of the lane state and the input words.
macro_rules! finish_lanes {
    ($x:expr, $initial:expr, $dest:expr) => {{
        let mut x: [::std::arch::x86_64::__m256i; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = ::std::arch::x86_64::_mm256_add_epi32(*word, *init);
        }
        // `lo[block]` holds words `0..8` of `block`, `hi[block]` words
        // `8..16`.
        let lo = $crate::x86_64::transpose([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]);
        let hi = $crate::x86_64::transpose([x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]]);
        $crate::x86_64::xor_block!(lo[0], hi[0], 0, $dest);
        $crate::x86_64::xor_block!(lo[1], hi[1], 1, $dest);
        $crate::x86_64::xor_block!(lo[2], hi[2], 2, $dest);
        $crate::x86_64::xor_block!(lo[3], hi[3], 3, $dest);
        $crate::x86_64::xor_block!(lo[4], hi[4], 4, $dest);
        $crate::x86_64::xor_block!(lo[5], hi[5], 5, $dest);
        $crate::x86_64::xor_block!(lo[6], hi[6], 6, $dest);
        $crate::x86_64::xor_block!(lo[7], hi[7], 7, $dest);
    }};
}
pub(crate) use finish_lanes;

/// Loads 64 bytes as a vector.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn load512(bytes: &[u8; 64]) -> __m512i {
    // SAFETY: `bytes` is a valid reference to exactly 64 readable bytes;
    // `_mm512_loadu_si512` has no alignment requirement.
    unsafe { _mm512_loadu_si512(bytes.as_ptr().cast()) }
}

/// Stores a vector as 64 bytes.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn store512(bytes: &mut [u8; 64], v: __m512i) {
    // SAFETY: `bytes` is a valid exclusive reference to exactly 64 writable
    // bytes; `_mm512_storeu_si512` has no alignment requirement.
    unsafe { _mm512_storeu_si512(bytes.as_mut_ptr().cast(), v) }
}

/// The 32-bit lanes `counter + 0 .. counter + 16` of a 64-bit block counter
/// split into low and high words, `(lo, hi)`, the high word carrying where
/// the low word wrapped.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn counter_lanes512(counter: u64) -> (__m512i, __m512i) {
    let lo = _mm512_set1_epi32(counter as u32 as i32);
    let lo_lanes = _mm512_add_epi32(
        lo,
        _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    );
    // A lane whose low word wrapped compares below the base; the mask of
    // those lanes selects where one is added to the high word.
    let carry = _mm512_cmplt_epu32_mask(lo_lanes, lo);
    let hi = _mm512_set1_epi32((counter >> 32) as u32 as i32);
    let hi_lanes = _mm512_mask_add_epi32(hi, carry, hi, _mm512_set1_epi32(1));
    (lo_lanes, hi_lanes)
}

/// The cipher input for blocks `counter .. counter + 16`, one block per
/// lane: every word of `state` broadcast, with the low and high halves of
/// the block counter in words `LO` and `HI`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn input_lanes512<const LO: usize, const HI: usize>(
    state: &[u32; 16],
    counter: u64,
) -> [__m512i; 16] {
    let mut x = [_mm512_set1_epi32(0); 16];
    for (lane, &word) in x.iter_mut().zip(state) {
        *lane = _mm512_set1_epi32(word as i32);
    }
    (x[LO], x[HI]) = counter_lanes512(counter);
    x
}

/// Transposes the 16x16 word matrix held in `r` (vector `i` = word `i` of
/// blocks `0..16`) so that vector `j` of the result holds words `0..16` of
/// block `j`, i.e. the whole keystream block.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn transpose512(r: [__m512i; 16]) -> [__m512i; 16] {
    // Pairs of words interleaved within each 128-bit lane, then quads: after
    // this, 128-bit lane `l` of `u[4 * g + k]` holds words `4 * g .. 4 * g +
    // 4` of block `4 * l + k`.
    let mut u = r;
    for g in 0..4 {
        let t0 = _mm512_unpacklo_epi32(r[4 * g], r[4 * g + 1]);
        let t1 = _mm512_unpackhi_epi32(r[4 * g], r[4 * g + 1]);
        let t2 = _mm512_unpacklo_epi32(r[4 * g + 2], r[4 * g + 3]);
        let t3 = _mm512_unpackhi_epi32(r[4 * g + 2], r[4 * g + 3]);
        u[4 * g] = _mm512_unpacklo_epi64(t0, t2);
        u[4 * g + 1] = _mm512_unpackhi_epi64(t0, t2);
        u[4 * g + 2] = _mm512_unpacklo_epi64(t1, t3);
        u[4 * g + 3] = _mm512_unpackhi_epi64(t1, t3);
    }
    // Gather the four word quads of each block into one vector: first the
    // quads `0..8` and `8..16` of blocks `k` and `k + 8` side by side, then
    // the halves of one block together. `0x88` picks 128-bit lanes 0 and 2
    // of both operands, `0xDD` lanes 1 and 3.
    let mut out = r;
    for k in 0..4 {
        let v0 = _mm512_shuffle_i32x4::<0x88>(u[k], u[4 + k]);
        let v1 = _mm512_shuffle_i32x4::<0xDD>(u[k], u[4 + k]);
        let v2 = _mm512_shuffle_i32x4::<0x88>(u[8 + k], u[12 + k]);
        let v3 = _mm512_shuffle_i32x4::<0xDD>(u[8 + k], u[12 + k]);
        out[k] = _mm512_shuffle_i32x4::<0x88>(v0, v2);
        out[k + 8] = _mm512_shuffle_i32x4::<0xDD>(v0, v2);
        out[k + 4] = _mm512_shuffle_i32x4::<0x88>(v1, v3);
        out[k + 12] = _mm512_shuffle_i32x4::<0xDD>(v1, v3);
    }
    out
}

/// XORs the 64-byte `keystream` into block `index` of `dest`.
#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) fn xor_block512(keystream: __m512i, index: usize, dest: &mut Dest<'_>) {
    let Some((source, out)) = dest.block(index) else {
        return;
    };
    let data = match source {
        Some(source) => _mm512_xor_si512(load512(source), keystream),
        None => _mm512_xor_si512(load512(out), keystream),
    };
    store512(out, data);
}

/// Finalises a 16-block lane set held in the 16 vectors `$x` (lane =
/// block): adds the input `$initial` back, transposes into block order and
/// XORs the keystream into blocks `0..16` of `$dest`. A macro for the same
/// reason as [`finish_lanes`].
macro_rules! finish_lanes512 {
    ($x:expr, $initial:expr, $dest:expr) => {{
        let mut x: [::std::arch::x86_64::__m512i; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = ::std::arch::x86_64::_mm512_add_epi32(*word, *init);
        }
        let blocks = $crate::x86_64::transpose512(x);
        for (index, keystream) in blocks.iter().enumerate() {
            $crate::x86_64::xor_block512(*keystream, index, $dest);
        }
    }};
}
pub(crate) use finish_lanes512;

/// XORs the keystream of a finished scalar block into `extra`: `x` holds
/// the words after the rounds and `initial` the block's input, added back
/// word by word (the feed-forward) before the XOR.
#[inline(always)]
pub(crate) fn xor_scalar_words(x: &[u32; 16], initial: &[u32; 16], extra: &mut [u8; 64]) {
    for ((chunk, word), init) in extra.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(initial) {
        *chunk = (u32::from_le_bytes(*chunk) ^ word.wrapping_add(*init)).to_le_bytes();
    }
}

//! AVX2 and AVX-512 helpers shared by the x86-64 kernels (`chacha20`,
//! `salsa20`, `blake2b`, `argon2`, `mlkem`, `keccak`, `poly1305`,
//! `edwards25519`): the CPU feature tokens, the stream ciphers' kernel
//! variants, vector loads and stores, the lane-set input, counter and
//! transposes, the keystream XOR into a [`Dest`], the feed-forward XOR of a
//! scalar block, and the 64-bit lane rotations.
//!
//! # Feature tokens
//!
//! [`Avx2`], [`Avx512`], [`Avx512Vl`], [`Avx512Ifma`] and [`Bmi2`] are
//! zero-sized proofs of CPU feature detection: their field is private to
//! this module and their only constructors are the `new` functions, which
//! return a token only when `has_x86_feature!` reports every feature it
//! names (detected at runtime with `std`, taken from the compile-time target
//! features without it), and the `avx512vl` refinements, which detect the
//! features an [`Avx512Vl`] adds to the token they are called on. A kernel
//! compiled with `#[target_feature(enable = ...)]` for a token's features is
//! reached through a safe wrapper that takes the token by value, so holding
//! one is what makes that wrapper's single `unsafe` call sound.

use core::arch::x86_64::{
    __m256i, __m512i, _mm256_add_epi32, _mm256_cmpgt_epi32, _mm256_loadu_si256,
    _mm256_permute2x128_si256, _mm256_set1_epi32, _mm256_setr_epi32, _mm256_storeu_si256,
    _mm256_sub_epi32, _mm256_unpackhi_epi64, _mm256_unpacklo_epi64, _mm256_xor_si256,
    _mm512_add_epi32, _mm512_cmplt_epu32_mask, _mm512_loadu_si512, _mm512_mask_add_epi32,
    _mm512_set1_epi32, _mm512_setr_epi32, _mm512_storeu_si512,
};

// The 64-bit lane rotations serve the Argon2 kernels, which need `alloc`, and
// the BLAKE2b kernels, which are compiled out (except in tests) when the
// portable-SIMD BLAKE2b backend is selected. They are gated on the union of
// those cfgs.
#[cfg(any(
    feature = "alloc",
    test,
    not(all(feature = "simd_backend", feature = "nightly"))
))]
pub(crate) use lane_rotations::*;

pub(crate) use crate::stream::Dest;

#[cfg(any(
    feature = "alloc",
    test,
    not(all(feature = "simd_backend", feature = "nightly"))
))]
mod lane_rotations {
    use core::arch::x86_64::{
        __m256i, _mm256_add_epi64, _mm256_or_si256, _mm256_setr_epi8, _mm256_shuffle_epi32,
        _mm256_srli_epi64,
    };

    /// Byte permutation (per 128-bit half) rotating every 64-bit lane right
    /// by 24 bits.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub(crate) fn ror24_table() -> __m256i {
        _mm256_setr_epi8(
            3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12,
            13, 14, 15, 8, 9, 10,
        )
    }

    /// Byte permutation (per 128-bit half) rotating every 64-bit lane right
    /// by 16 bits.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub(crate) fn ror16_table() -> __m256i {
        _mm256_setr_epi8(
            2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11,
            12, 13, 14, 15, 8, 9,
        )
    }

    /// Rotates every 64-bit lane right by 32 bits (a dword swap).
    #[inline]
    #[target_feature(enable = "avx2")]
    pub(crate) fn ror32(v: __m256i) -> __m256i {
        _mm256_shuffle_epi32::<0xB1>(v)
    }

    // `ror24` and `ror16` are only used by the BLAKE2b kernels; Argon2 uses
    // the tables directly.
    /// Rotates every 64-bit lane right by 24 bits.
    #[inline]
    #[target_feature(enable = "avx2")]
    #[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
    pub(crate) fn ror24(v: __m256i) -> __m256i {
        core::arch::x86_64::_mm256_shuffle_epi8(v, ror24_table())
    }

    /// Rotates every 64-bit lane right by 16 bits.
    #[inline]
    #[target_feature(enable = "avx2")]
    #[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
    pub(crate) fn ror16(v: __m256i) -> __m256i {
        core::arch::x86_64::_mm256_shuffle_epi8(v, ror16_table())
    }

    /// Rotates every 64-bit lane right by 63 bits (left by one).
    #[inline]
    #[target_feature(enable = "avx2")]
    pub(crate) fn ror63(v: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_add_epi64(v, v), _mm256_srli_epi64::<63>(v))
    }
}

/// Blocks per 8-lane (256-bit) vector set.
pub(crate) const LANES: usize = 8;
/// Blocks per 16-lane (512-bit) vector set.
pub(crate) const LANES512: usize = 16;

/// Proof that the running CPU supports AVX2 (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Avx2(());

impl Avx2 {
    /// The token, if the CPU has `avx2`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_x86_feature!("avx2").then_some(Self(()))
    }

    /// The [`Avx512Vl`] token, if the CPU also has `avx512f` and
    /// `avx512vl`. Only the BLAKE2b kernels, which the portable-SIMD backend
    /// replaces, detect in this order.
    #[inline]
    #[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
    pub(crate) fn avx512vl(self) -> Option<Avx512Vl> {
        (has_x86_feature!("avx512f") && has_x86_feature!("avx512vl")).then_some(Avx512Vl(()))
    }
}

/// Proof that the running CPU supports AVX-512F and AVX2 (see the module
/// docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Avx512(());

impl Avx512 {
    /// The token, if the CPU has `avx512f` and `avx2`. rustc's `avx512f`
    /// target feature implies `avx2` (and `fma` and `f16c`), so an `avx512f`
    /// kernel may contain AVX2 instructions and call `avx2` helpers. std's
    /// detection reports `avx512f` only together with `fma` and `f16c`, but
    /// it does not check the CPUID `avx2` bit, so this checks it as well.
    /// Every AVX-512F dispatch goes through this token.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        (has_x86_feature!("avx512f") && has_x86_feature!("avx2")).then_some(Self(()))
    }

    /// The [`Avx512Vl`] token, if the CPU also has `avx512vl` and `avx2`.
    #[inline]
    pub(crate) fn avx512vl(self) -> Option<Avx512Vl> {
        (has_x86_feature!("avx512vl") && has_x86_feature!("avx2")).then_some(Avx512Vl(()))
    }
}

/// Proof that the running CPU supports AVX-512F with AVX-512VL, and AVX2,
/// the set the `ymm` EVEX kernels are compiled for (see the module docs).
/// Obtained from an [`Avx2`] or [`Avx512`] token by detecting the rest of
/// the set, so each caller keeps its detection order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Avx512Vl(());

/// Proof that the running CPU supports AVX-512F with AVX-512IFMA, and AVX2
/// (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Avx512Ifma(());

impl Avx512Ifma {
    /// The token, if the CPU has `avx512f` (with the `avx2` it implies, as
    /// for [`Avx512`]) and `avx512ifma`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        (has_x86_feature!("avx512f") && has_x86_feature!("avx2") && has_x86_feature!("avx512ifma"))
            .then_some(Self(()))
    }
}

/// Proof that the running CPU supports BMI2, whose `mulx` lets the compiler
/// schedule the `u128` products of the Curve25519 field arithmetic without
/// the fixed `rdx:rax` registers of `mul` (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bmi2(());

impl Bmi2 {
    /// The token, if the CPU has `bmi2`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_x86_feature!("bmi2").then_some(Self(()))
    }
}

/// The lane-set kernel variants of the x86-64 stream ciphers, each holding
/// the token for the CPU features its kernels are compiled for, which is
/// what makes the ciphers' `xor_chunk` dispatch safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaneSet {
    /// AVX2: one 8-block lane set in the 16 `ymm` registers.
    Avx2(Avx2),
    /// AVX-512F: one 16-block lane set in `zmm` registers, with `vprold` for
    /// the rotations.
    Avx512(Avx512),
    /// AVX-512F with VL: [`LaneSet::Avx512`], and runs of at most [`LANES`]
    /// slots on an 8-block `ymm` lane set with `vprold` rotations and the 32
    /// EVEX registers, which finishes in about 80% of the 16-block set's
    /// time. Holds the [`Avx512`] token for the 16-block kernels as well.
    Avx512Vl(Avx512, Avx512Vl),
}

impl LaneSet {
    /// The best variant the running CPU supports.
    #[inline]
    pub(crate) fn detect() -> Option<Self> {
        if let Some(avx512) = Avx512::new() {
            match avx512.avx512vl() {
                Some(avx512vl) => Some(Self::Avx512Vl(avx512, avx512vl)),
                None => Some(Self::Avx512(avx512)),
            }
        } else {
            Avx2::new().map(Self::Avx2)
        }
    }

    /// Every variant the running CPU supports.
    #[cfg(test)]
    pub(crate) fn all() -> alloc::vec::Vec<Self> {
        let mut variants = alloc::vec::Vec::new();
        if let Some(avx2) = Avx2::new() {
            variants.push(Self::Avx2(avx2));
        }
        if let Some(avx512) = Avx512::new() {
            variants.push(Self::Avx512(avx512));
            if let Some(avx512vl) = avx512.avx512vl() {
                variants.push(Self::Avx512Vl(avx512, avx512vl));
            }
        }
        variants
    }

    /// Blocks produced per run.
    #[inline]
    pub(crate) fn blocks(self) -> usize {
        match self {
            Self::Avx2(_) => LANES,
            Self::Avx512(_) | Self::Avx512Vl(..) => LANES512,
        }
    }

    /// Whether the AVX-512 kernels' fused companion block is available: the
    /// 16-lane set leaves the integer ports idle for a scalar block's rounds.
    #[inline]
    pub(crate) fn fuses_extra_block(self) -> bool {
        match self {
            Self::Avx2(_) => false,
            Self::Avx512(_) | Self::Avx512Vl(..) => true,
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
/// the low word wrapped. Out of line at opt-level `z`, which adds no copy:
/// it only sees the block counter.
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

/// Every word of the `&[u32; 16]` `$state` broadcast with `$set1`
/// (`_mm256_set1_epi32` or `_mm512_set1_epi32`), spelled out: a `zip` over
/// `state` built the lanes in a stack array behind an out-of-line
/// `Iter::size` at opt-level `z` and `s`.
macro_rules! broadcast_words {
    ($set1:path, $state:expr) => {{
        let state: &[u32; 16] = $state;
        [
            $set1(state[0] as i32),
            $set1(state[1] as i32),
            $set1(state[2] as i32),
            $set1(state[3] as i32),
            $set1(state[4] as i32),
            $set1(state[5] as i32),
            $set1(state[6] as i32),
            $set1(state[7] as i32),
            $set1(state[8] as i32),
            $set1(state[9] as i32),
            $set1(state[10] as i32),
            $set1(state[11] as i32),
            $set1(state[12] as i32),
            $set1(state[13] as i32),
            $set1(state[14] as i32),
            $set1(state[15] as i32),
        ]
    }};
}
pub(crate) use broadcast_words;

/// The cipher input for blocks `$counter .. $counter + 8`, one block per
/// lane (a `[__m256i; 16]`): every word of `$state` broadcast, with the low
/// and high halves of the block counter in words `$lo` and `$hi`.
///
/// A macro rather than a function so it expands inside each kernel: as a
/// `#[target_feature]` function (which cannot be `#[inline(always)]`) it was
/// out of line at opt-level `z` and returned the broadcast key words through
/// a stack buffer.
macro_rules! input_lanes {
    ($state:expr, $counter:expr, $lo:literal, $hi:literal) => {{
        let mut x =
            $crate::x86_64::broadcast_words!(::core::arch::x86_64::_mm256_set1_epi32, $state);
        (x[$lo], x[$hi]) = $crate::x86_64::counter_lanes($counter);
        x
    }};
}
pub(crate) use input_lanes;

/// Transposes the 8x8 word matrix held in the `[__m256i; 8]` `$r` (vector
/// `i` = word `i` of blocks `0..8`) so that vector `j` of the result holds
/// words `0..8` of block `j`. A macro for the same reason as
/// [`input_lanes`]: out of line at opt-level `z`, the keystream went in and
/// out through the stack.
macro_rules! transpose {
    ($r:expr) => {{
        use ::core::arch::x86_64::{
            __m256i, _mm256_permute2x128_si256, _mm256_unpackhi_epi32, _mm256_unpackhi_epi64,
            _mm256_unpacklo_epi32, _mm256_unpacklo_epi64,
        };
        let r: [__m256i; 8] = $r;
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
        // 4`) of one block: the low half of block `k % 4`, the high half of
        // block `k % 4 + 4`.
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
    }};
}
pub(crate) use transpose;

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
                ::core::arch::x86_64::_mm256_xor_si256(data_lo, $lo),
            );
            $crate::x86_64::store(
                &mut out[1],
                ::core::arch::x86_64::_mm256_xor_si256(data_hi, $hi),
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
        let mut x: [::core::arch::x86_64::__m256i; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = ::core::arch::x86_64::_mm256_add_epi32(*word, *init);
        }
        // `lo[block]` holds words `0..8` of `block`, `hi[block]` words
        // `8..16`.
        let lo = $crate::x86_64::transpose!([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]);
        let hi = $crate::x86_64::transpose!([x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]]);
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
/// the low word wrapped. Out of line at opt-level `z`, which adds no copy:
/// it only sees the block counter.
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

/// The cipher input for blocks `$counter .. $counter + 16`, one block per
/// lane (a `[__m512i; 16]`): every word of `$state` broadcast, with the low
/// and high halves of the block counter in words `$lo` and `$hi`. A macro
/// for the same reason as [`input_lanes`].
macro_rules! input_lanes512 {
    ($state:expr, $counter:expr, $lo:literal, $hi:literal) => {{
        let mut x =
            $crate::x86_64::broadcast_words!(::core::arch::x86_64::_mm512_set1_epi32, $state);
        (x[$lo], x[$hi]) = $crate::x86_64::counter_lanes512($counter);
        x
    }};
}
pub(crate) use input_lanes512;

/// One word-quad step of [`transpose512`]: pairs of words of `$a, $b` and
/// `$c, $d` interleaved within each 128-bit lane, then quads, as a tuple of
/// four vectors.
macro_rules! transpose512_quads {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        use ::core::arch::x86_64::{
            _mm512_unpackhi_epi32, _mm512_unpackhi_epi64, _mm512_unpacklo_epi32,
            _mm512_unpacklo_epi64,
        };
        let t0 = _mm512_unpacklo_epi32($a, $b);
        let t1 = _mm512_unpackhi_epi32($a, $b);
        let t2 = _mm512_unpacklo_epi32($c, $d);
        let t3 = _mm512_unpackhi_epi32($c, $d);
        (
            _mm512_unpacklo_epi64(t0, t2),
            _mm512_unpackhi_epi64(t0, t2),
            _mm512_unpacklo_epi64(t1, t3),
            _mm512_unpackhi_epi64(t1, t3),
        )
    }};
}
pub(crate) use transpose512_quads;

/// One gather step of [`transpose512`]: from the quad vectors `u[k]`,
/// `u[4 + k]`, `u[8 + k]` and `u[12 + k]`, the blocks `k`, `k + 4`, `k + 8`
/// and `k + 12`, as a tuple in that order.
macro_rules! transpose512_gather {
    ($uk:expr, $uk4:expr, $uk8:expr, $uk12:expr) => {{
        use ::core::arch::x86_64::_mm512_shuffle_i32x4;
        let v0 = _mm512_shuffle_i32x4::<0x88>($uk, $uk4);
        let v1 = _mm512_shuffle_i32x4::<0xDD>($uk, $uk4);
        let v2 = _mm512_shuffle_i32x4::<0x88>($uk8, $uk12);
        let v3 = _mm512_shuffle_i32x4::<0xDD>($uk8, $uk12);
        (
            _mm512_shuffle_i32x4::<0x88>(v0, v2),
            _mm512_shuffle_i32x4::<0x88>(v1, v3),
            _mm512_shuffle_i32x4::<0xDD>(v0, v2),
            _mm512_shuffle_i32x4::<0xDD>(v1, v3),
        )
    }};
}
pub(crate) use transpose512_gather;

/// Transposes the 16x16 word matrix held in the `[__m512i; 16]` `$r`
/// (vector `i` = word `i` of blocks `0..16`) so that vector `j` of the
/// result holds words `0..16` of block `j`, i.e. the whole keystream block.
/// A macro for the same reason as [`transpose`]. Spelled out: indexed loops
/// over working arrays copied from `$r` made opt-level `s` pass the 1 KiB of
/// keystream to out-of-line `memcpy` calls.
macro_rules! transpose512 {
    ($r:expr) => {{
        let [
            r0,
            r1,
            r2,
            r3,
            r4,
            r5,
            r6,
            r7,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
        ]: [::core::arch::x86_64::__m512i; 16] = $r;
        // Pairs of words interleaved within each 128-bit lane, then quads:
        // after this, 128-bit lane `l` of `u<4 * g + k>` holds words `4 * g ..
        // 4 * g + 4` of block `4 * l + k`.
        let (u0, u1, u2, u3) = $crate::x86_64::transpose512_quads!(r0, r1, r2, r3);
        let (u4, u5, u6, u7) = $crate::x86_64::transpose512_quads!(r4, r5, r6, r7);
        let (u8, u9, u10, u11) = $crate::x86_64::transpose512_quads!(r8, r9, r10, r11);
        let (u12, u13, u14, u15) = $crate::x86_64::transpose512_quads!(r12, r13, r14, r15);
        // Gather the four word quads of each block into one vector: first the
        // quads `0..8` and `8..16` of blocks `k` and `k + 8` side by side, then
        // the halves of one block together. `0x88` picks 128-bit lanes 0 and 2
        // of both operands, `0xDD` lanes 1 and 3.
        let (o0, o4, o8, o12) = $crate::x86_64::transpose512_gather!(u0, u4, u8, u12);
        let (o1, o5, o9, o13) = $crate::x86_64::transpose512_gather!(u1, u5, u9, u13);
        let (o2, o6, o10, o14) = $crate::x86_64::transpose512_gather!(u2, u6, u10, u14);
        let (o3, o7, o11, o15) = $crate::x86_64::transpose512_gather!(u3, u7, u11, u15);
        [
            o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15,
        ]
    }};
}
pub(crate) use transpose512;

/// XORs the 64-byte keystream `$keystream` (an `__m512i`) into block
/// `$index` of `$dest`. A macro for the same reason as [`input_lanes`]: out
/// of line at opt-level `z`, the keystream was passed through a stack copy.
macro_rules! xor_block512 {
    ($keystream:expr, $index:expr, $dest:expr) => {{
        let keystream: ::core::arch::x86_64::__m512i = $keystream;
        if let Some((source, out)) = $dest.block($index) {
            let data = match source {
                Some(source) => ::core::arch::x86_64::_mm512_xor_si512(
                    $crate::x86_64::load512(source),
                    keystream,
                ),
                None => {
                    ::core::arch::x86_64::_mm512_xor_si512($crate::x86_64::load512(out), keystream)
                }
            };
            $crate::x86_64::store512(out, data);
        }
    }};
}
pub(crate) use xor_block512;

/// Finalises a 16-block lane set held in the 16 vectors `$x` (lane =
/// block): adds the input `$initial` back, transposes into block order and
/// XORs the keystream into blocks `0..16` of `$dest`. A macro for the same
/// reason as [`finish_lanes`].
macro_rules! finish_lanes512 {
    ($x:expr, $initial:expr, $dest:expr) => {{
        let mut x: [::core::arch::x86_64::__m512i; 16] = $x;
        for (word, init) in x.iter_mut().zip($initial) {
            *word = ::core::arch::x86_64::_mm512_add_epi32(*word, *init);
        }
        let blocks = $crate::x86_64::transpose512!(x);
        // Spelled out per block, like [`finish_lanes`]: an iterator over
        // `blocks` would take the keystream's address.
        $crate::x86_64::xor_block512!(blocks[0], 0, $dest);
        $crate::x86_64::xor_block512!(blocks[1], 1, $dest);
        $crate::x86_64::xor_block512!(blocks[2], 2, $dest);
        $crate::x86_64::xor_block512!(blocks[3], 3, $dest);
        $crate::x86_64::xor_block512!(blocks[4], 4, $dest);
        $crate::x86_64::xor_block512!(blocks[5], 5, $dest);
        $crate::x86_64::xor_block512!(blocks[6], 6, $dest);
        $crate::x86_64::xor_block512!(blocks[7], 7, $dest);
        $crate::x86_64::xor_block512!(blocks[8], 8, $dest);
        $crate::x86_64::xor_block512!(blocks[9], 9, $dest);
        $crate::x86_64::xor_block512!(blocks[10], 10, $dest);
        $crate::x86_64::xor_block512!(blocks[11], 11, $dest);
        $crate::x86_64::xor_block512!(blocks[12], 12, $dest);
        $crate::x86_64::xor_block512!(blocks[13], 13, $dest);
        $crate::x86_64::xor_block512!(blocks[14], 14, $dest);
        $crate::x86_64::xor_block512!(blocks[15], 15, $dest);
    }};
}
pub(crate) use finish_lanes512;

/// XORs the keystream of a finished scalar block into `extra`: `x` holds
/// the words after the rounds and `initial` the block's input, added back
/// word by word (the feed-forward) before the XOR. Spelled out with
/// [`each_word`](crate::stream::each_word): at opt-level `z` a three-way
/// `zip` over them was out of line and took both blocks' addresses.
#[inline(always)]
pub(crate) fn xor_scalar_words(x: &[u32; 16], initial: &[u32; 16], extra: &mut [u8; 64]) {
    let extra = extra.as_chunks_mut::<4>().0;
    crate::stream::each_word!(I, {
        extra[I] = (u32::from_le_bytes(extra[I]) ^ x[I].wrapping_add(initial[I])).to_le_bytes();
    });
}

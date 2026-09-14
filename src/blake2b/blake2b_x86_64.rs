//! AVX2 and AVX-512VL BLAKE2b compression, chosen at runtime by [`detect`]
//! and used by the soft backend on x86-64.
//!
//! The 16-word working state is four `ymm` rows: `a = v[0..4]`,
//! `b = v[4..8]`, `c = v[8..12]`, `d = v[12..16]`. The four `G` mixings of a
//! column step are then one lane-wise `G`; for the diagonal step `a`, `c`
//! and `d` are rotated by one, three and two lanes so the diagonals line up
//! in columns, and rotated back afterwards. Each round's four message
//! vectors are assembled from `m0..m7` (the block's eight 16-byte word pairs,
//! each broadcast to both 128-bit halves) with one unpack, byte-align or
//! blend per half and a blend to join them, the schedule of the BLAKE2
//! reference AVX2 implementation.
//!
//! The two kernels differ only in the lane rotations. AVX2 has no 64-bit
//! rotate: 32 is a dword shuffle, 24 and 16 are a `vpshufb`, 63 an add plus
//! shift, all but the last competing with the message shuffles for the
//! shuffle port. AVX-512VL rotates `ymm` lanes with one `vprorq` on another
//! port, which is what makes it faster on the same 256-bit lane set.
//!
//! Control flow and memory access are independent of the data.

use std::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_alignr_epi8, _mm256_blend_epi32, _mm256_or_si256,
    _mm256_permute4x64_epi64, _mm256_ror_epi64, _mm256_setr_epi8, _mm256_setr_epi64x,
    _mm256_shuffle_epi8, _mm256_shuffle_epi32, _mm256_srli_epi64, _mm256_unpackhi_epi64,
    _mm256_unpacklo_epi64, _mm256_xor_si256,
};

use super::{BLOCKBYTES, IV};
use crate::x86_64::{load, load_words, store_words};

/// A vector kernel the running CPU has been verified to support.
///
/// Values are only created by [`detect`] after checking the CPU features the
/// kernel is compiled for, which is what makes [`Kernel::compress`] safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kernel {
    /// AVX2: shuffle-based lane rotations.
    Avx2,
    /// AVX-512VL on `ymm` registers: `vprorq` lane rotations.
    Avx512Vl,
}

/// The best kernel the running CPU supports.
#[inline]
pub(super) fn detect() -> Option<Kernel> {
    if std::arch::is_x86_feature_detected!("avx2") {
        if std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512vl")
        {
            Some(Kernel::Avx512Vl)
        } else {
            Some(Kernel::Avx2)
        }
    } else {
        None
    }
}

impl Kernel {
    /// Every kernel the running CPU supports.
    #[cfg(test)]
    pub(super) fn all() -> Vec<Kernel> {
        let mut kernels = Vec::new();
        if std::arch::is_x86_feature_detected!("avx2") {
            kernels.push(Kernel::Avx2);
            if std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512vl")
            {
                kernels.push(Kernel::Avx512Vl);
            }
        }
        kernels
    }

    /// One BLAKE2b compression of `block` into the chaining state `h` with
    /// the byte counter `t` and finalization flags `f`.
    #[inline]
    pub(super) fn compress(
        self,
        h: &mut [u64; 8],
        t: &[u64; 2],
        f: &[u64; 2],
        block: &[u8; BLOCKBYTES],
    ) {
        match self {
            // SAFETY: `Kernel::Avx2` is only constructed after
            // `is_x86_feature_detected!("avx2")` succeeded.
            Kernel::Avx2 => unsafe { avx2::compress(h, t, f, block) },
            // SAFETY: `Kernel::Avx512Vl` is only constructed after
            // `is_x86_feature_detected!` confirmed `avx2`, `avx512f` and
            // `avx512vl`.
            Kernel::Avx512Vl => unsafe { avx512vl::compress(h, t, f, block) },
        }
    }
}

const IV_LO: [u64; 4] = [IV[0], IV[1], IV[2], IV[3]];
const IV_HI: [u64; 4] = [IV[4], IV[5], IV[6], IV[7]];

/// Byte permutation (per 128-bit half) rotating every 64-bit lane right by
/// 24 bits.
#[inline]
#[target_feature(enable = "avx2")]
fn ror24_table() -> __m256i {
    _mm256_setr_epi8(
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13,
        14, 15, 8, 9, 10,
    )
}

/// Byte permutation (per 128-bit half) rotating every 64-bit lane right by
/// 16 bits.
#[inline]
#[target_feature(enable = "avx2")]
fn ror16_table() -> __m256i {
    _mm256_setr_epi8(
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12,
        13, 14, 15, 8, 9,
    )
}

/// Rotates every 64-bit lane right by 32 bits (a dword swap).
#[inline]
#[target_feature(enable = "avx2")]
fn ror32_avx2(v: __m256i) -> __m256i {
    _mm256_shuffle_epi32::<0xB1>(v)
}

/// Rotates every 64-bit lane right by 24 bits.
#[inline]
#[target_feature(enable = "avx2")]
fn ror24_avx2(v: __m256i) -> __m256i {
    _mm256_shuffle_epi8(v, ror24_table())
}

/// Rotates every 64-bit lane right by 16 bits.
#[inline]
#[target_feature(enable = "avx2")]
fn ror16_avx2(v: __m256i) -> __m256i {
    _mm256_shuffle_epi8(v, ror16_table())
}

/// Rotates every 64-bit lane right by 63 bits (left by one).
#[inline]
#[target_feature(enable = "avx2")]
fn ror63_avx2(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_add_epi64(v, v), _mm256_srli_epi64::<63>(v))
}

/// Rotates every 64-bit lane right by `N` bits with one `vprorq`.
#[inline]
#[target_feature(enable = "avx512f,avx512vl")]
fn ror_avx512vl<const N: i32>(v: __m256i) -> __m256i {
    _mm256_ror_epi64::<N>(v)
}

/// Joins the low 128-bit half of `lo` and the high half of `hi` into one
/// message vector.
#[inline]
#[target_feature(enable = "avx2")]
fn msg(lo: __m256i, hi: __m256i) -> __m256i {
    _mm256_blend_epi32::<0xF0>(lo, hi)
}

/// Defines the module `$name` holding one kernel compiled for `$features`,
/// with the four lane rotations `$ror32`, `$ror24`, `$ror16` and `$ror63`.
macro_rules! kernel {
    ($name:ident, $features:literal, $ror32:expr, $ror24:expr, $ror16:expr, $ror63:expr) => {
        mod $name {
            use super::*;

            /// The working state as four rows.
            struct Rows {
                a: __m256i,
                b: __m256i,
                c: __m256i,
                d: __m256i,
            }

            impl Rows {
                /// The first half of `G` on every column: `a += b + m`,
                /// `d = (d ^ a) >>> 32`, `c += d`, `b = (b ^ c) >>> 24`.
                #[inline]
                #[target_feature(enable = $features)]
                fn g1(&mut self, m: __m256i) {
                    self.a = _mm256_add_epi64(_mm256_add_epi64(self.a, self.b), m);
                    self.d = $ror32(_mm256_xor_si256(self.d, self.a));
                    self.c = _mm256_add_epi64(self.c, self.d);
                    self.b = $ror24(_mm256_xor_si256(self.b, self.c));
                }

                /// The second half of `G` on every column: `a += b + m`,
                /// `d = (d ^ a) >>> 16`, `c += d`, `b = (b ^ c) >>> 63`.
                #[inline]
                #[target_feature(enable = $features)]
                fn g2(&mut self, m: __m256i) {
                    self.a = _mm256_add_epi64(_mm256_add_epi64(self.a, self.b), m);
                    self.d = $ror16(_mm256_xor_si256(self.d, self.a));
                    self.c = _mm256_add_epi64(self.c, self.d);
                    self.b = $ror63(_mm256_xor_si256(self.b, self.c));
                }

                /// Lines the diagonals up in columns: `a` rotated right by
                /// one lane, `d` by two, `c` by three (`b` stays).
                #[inline]
                #[target_feature(enable = $features)]
                fn diagonalize(&mut self) {
                    self.a = _mm256_permute4x64_epi64::<0x93>(self.a);
                    self.d = _mm256_permute4x64_epi64::<0x4E>(self.d);
                    self.c = _mm256_permute4x64_epi64::<0x39>(self.c);
                }

                /// Undoes [`Rows::diagonalize`].
                #[inline]
                #[target_feature(enable = $features)]
                fn undiagonalize(&mut self) {
                    self.a = _mm256_permute4x64_epi64::<0x39>(self.a);
                    self.d = _mm256_permute4x64_epi64::<0x4E>(self.d);
                    self.c = _mm256_permute4x64_epi64::<0x93>(self.c);
                }

                /// One round: a column step and a diagonal step, with the
                /// round's four message vectors.
                #[inline]
                #[target_feature(enable = $features)]
                fn round(&mut self, m1: __m256i, m2: __m256i, m3: __m256i, m4: __m256i) {
                    self.g1(m1);
                    self.g2(m2);
                    self.diagonalize();
                    self.g1(m3);
                    self.g2(m4);
                    self.undiagonalize();
                }
            }

            /// One BLAKE2b compression of `block` into the chaining state
            /// `h` with the byte counter `t` and finalization flags `f`.
            #[target_feature(enable = $features)]
            pub(super) fn compress(
                h: &mut [u64; 8],
                t: &[u64; 2],
                f: &[u64; 2],
                block: &[u8; BLOCKBYTES],
            ) {
                let [h_lo, h_hi] = h.as_chunks_mut::<4>().0 else {
                    unreachable!("h is eight words");
                };
                let [q0, q1, q2, q3] = block.as_chunks::<32>().0 else {
                    unreachable!("block is 128 bytes");
                };

                // `m[2i]` and `m[2i + 1]` are the block's word pair `i`,
                // broadcast to both 128-bit halves.
                let (w0, w1, w2, w3) = (load(q0), load(q1), load(q2), load(q3));
                let m0 = _mm256_permute4x64_epi64::<0x44>(w0);
                let m1 = _mm256_permute4x64_epi64::<0xEE>(w0);
                let m2 = _mm256_permute4x64_epi64::<0x44>(w1);
                let m3 = _mm256_permute4x64_epi64::<0xEE>(w1);
                let m4 = _mm256_permute4x64_epi64::<0x44>(w2);
                let m5 = _mm256_permute4x64_epi64::<0xEE>(w2);
                let m6 = _mm256_permute4x64_epi64::<0x44>(w3);
                let m7 = _mm256_permute4x64_epi64::<0xEE>(w3);

                let iv0 = load_words(h_lo);
                let iv1 = load_words(h_hi);
                let mut v = Rows {
                    a: iv0,
                    b: iv1,
                    c: load_words(&IV_LO),
                    d: _mm256_xor_si256(
                        load_words(&IV_HI),
                        _mm256_setr_epi64x(t[0] as i64, t[1] as i64, f[0] as i64, f[1] as i64),
                    ),
                };

                // round 1
                v.round(
                    msg(_mm256_unpacklo_epi64(m0, m1), _mm256_unpacklo_epi64(m2, m3)),
                    msg(_mm256_unpackhi_epi64(m0, m1), _mm256_unpackhi_epi64(m2, m3)),
                    msg(_mm256_unpacklo_epi64(m7, m4), _mm256_unpacklo_epi64(m5, m6)),
                    msg(_mm256_unpackhi_epi64(m7, m4), _mm256_unpackhi_epi64(m5, m6)),
                );
                // round 2
                v.round(
                    msg(_mm256_unpacklo_epi64(m7, m2), _mm256_unpackhi_epi64(m4, m6)),
                    msg(
                        _mm256_unpacklo_epi64(m5, m4),
                        _mm256_alignr_epi8::<8>(m3, m7),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m2, m0),
                        _mm256_blend_epi32::<0x33>(m5, m0),
                    ),
                    msg(
                        _mm256_alignr_epi8::<8>(m6, m1),
                        _mm256_blend_epi32::<0x33>(m3, m1),
                    ),
                );
                // round 3
                v.round(
                    msg(
                        _mm256_alignr_epi8::<8>(m6, m5),
                        _mm256_unpackhi_epi64(m2, m7),
                    ),
                    msg(
                        _mm256_unpacklo_epi64(m4, m0),
                        _mm256_blend_epi32::<0x33>(m6, m1),
                    ),
                    msg(
                        _mm256_alignr_epi8::<8>(m5, m4),
                        _mm256_unpackhi_epi64(m1, m3),
                    ),
                    msg(
                        _mm256_unpacklo_epi64(m2, m7),
                        _mm256_blend_epi32::<0x33>(m0, m3),
                    ),
                );
                // round 4
                v.round(
                    msg(_mm256_unpackhi_epi64(m3, m1), _mm256_unpackhi_epi64(m6, m5)),
                    msg(_mm256_unpackhi_epi64(m4, m0), _mm256_unpacklo_epi64(m6, m7)),
                    msg(
                        _mm256_alignr_epi8::<8>(m1, m7),
                        _mm256_shuffle_epi32::<0x4E>(m2),
                    ),
                    msg(_mm256_unpacklo_epi64(m4, m3), _mm256_unpacklo_epi64(m5, m0)),
                );
                // round 5
                v.round(
                    msg(_mm256_unpackhi_epi64(m4, m2), _mm256_unpacklo_epi64(m1, m5)),
                    msg(
                        _mm256_blend_epi32::<0x33>(m3, m0),
                        _mm256_blend_epi32::<0x33>(m7, m2),
                    ),
                    msg(
                        _mm256_alignr_epi8::<8>(m7, m1),
                        _mm256_alignr_epi8::<8>(m3, m5),
                    ),
                    msg(_mm256_unpackhi_epi64(m6, m0), _mm256_unpacklo_epi64(m6, m4)),
                );
                // round 6
                v.round(
                    msg(_mm256_unpacklo_epi64(m1, m3), _mm256_unpacklo_epi64(m0, m4)),
                    msg(_mm256_unpacklo_epi64(m6, m5), _mm256_unpackhi_epi64(m5, m1)),
                    msg(
                        _mm256_alignr_epi8::<8>(m2, m0),
                        _mm256_unpackhi_epi64(m3, m7),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m4, m6),
                        _mm256_alignr_epi8::<8>(m7, m2),
                    ),
                );
                // round 7
                v.round(
                    msg(
                        _mm256_blend_epi32::<0x33>(m0, m6),
                        _mm256_unpacklo_epi64(m7, m2),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m2, m7),
                        _mm256_alignr_epi8::<8>(m5, m6),
                    ),
                    msg(
                        _mm256_unpacklo_epi64(m4, m0),
                        _mm256_blend_epi32::<0x33>(m4, m3),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m5, m3),
                        _mm256_shuffle_epi32::<0x4E>(m1),
                    ),
                );
                // round 8
                v.round(
                    msg(
                        _mm256_unpackhi_epi64(m6, m3),
                        _mm256_blend_epi32::<0x33>(m1, m6),
                    ),
                    msg(
                        _mm256_alignr_epi8::<8>(m7, m5),
                        _mm256_unpackhi_epi64(m0, m4),
                    ),
                    msg(
                        _mm256_blend_epi32::<0x33>(m2, m1),
                        _mm256_alignr_epi8::<8>(m4, m7),
                    ),
                    msg(_mm256_unpacklo_epi64(m5, m0), _mm256_unpacklo_epi64(m2, m3)),
                );
                // round 9
                v.round(
                    msg(
                        _mm256_unpacklo_epi64(m3, m7),
                        _mm256_alignr_epi8::<8>(m0, m5),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m7, m4),
                        _mm256_alignr_epi8::<8>(m4, m1),
                    ),
                    msg(_mm256_unpacklo_epi64(m5, m6), _mm256_unpackhi_epi64(m6, m0)),
                    msg(
                        _mm256_alignr_epi8::<8>(m1, m2),
                        _mm256_alignr_epi8::<8>(m2, m3),
                    ),
                );
                // round 10
                v.round(
                    msg(_mm256_unpacklo_epi64(m5, m4), _mm256_unpackhi_epi64(m3, m0)),
                    msg(
                        _mm256_unpacklo_epi64(m1, m2),
                        _mm256_blend_epi32::<0x33>(m2, m3),
                    ),
                    msg(_mm256_unpackhi_epi64(m6, m7), _mm256_unpackhi_epi64(m4, m1)),
                    msg(
                        _mm256_blend_epi32::<0x33>(m5, m0),
                        _mm256_unpacklo_epi64(m7, m6),
                    ),
                );
                // round 11
                v.round(
                    msg(_mm256_unpacklo_epi64(m0, m1), _mm256_unpacklo_epi64(m2, m3)),
                    msg(_mm256_unpackhi_epi64(m0, m1), _mm256_unpackhi_epi64(m2, m3)),
                    msg(_mm256_unpacklo_epi64(m7, m4), _mm256_unpacklo_epi64(m5, m6)),
                    msg(_mm256_unpackhi_epi64(m7, m4), _mm256_unpackhi_epi64(m5, m6)),
                );
                // round 12
                v.round(
                    msg(_mm256_unpacklo_epi64(m7, m2), _mm256_unpackhi_epi64(m4, m6)),
                    msg(
                        _mm256_unpacklo_epi64(m5, m4),
                        _mm256_alignr_epi8::<8>(m3, m7),
                    ),
                    msg(
                        _mm256_unpackhi_epi64(m2, m0),
                        _mm256_blend_epi32::<0x33>(m5, m0),
                    ),
                    msg(
                        _mm256_alignr_epi8::<8>(m6, m1),
                        _mm256_blend_epi32::<0x33>(m3, m1),
                    ),
                );

                store_words(h_lo, _mm256_xor_si256(iv0, _mm256_xor_si256(v.a, v.c)));
                store_words(h_hi, _mm256_xor_si256(iv1, _mm256_xor_si256(v.b, v.d)));
            }
        }
    };
}

kernel!(avx2, "avx2", ror32_avx2, ror24_avx2, ror16_avx2, ror63_avx2);
kernel!(
    avx512vl,
    "avx2,avx512f,avx512vl",
    ror_avx512vl::<32>,
    ror_avx512vl::<24>,
    ror_avx512vl::<16>,
    ror_avx512vl::<63>
);

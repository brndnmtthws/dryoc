//! SHA-256 compression on AArch64 cores with the `sha2` extension.
//!
//! One `asm!` block runs the whole message loop so the round instructions keep
//! the schedule the hardware likes: each `sha256h`/`sha256h2` pair is issued as
//! soon as its round constant sum exists, with the message-schedule update for
//! the block four groups ahead interleaved between the pairs and the next
//! constant load ahead of both. LLVM reorders the intrinsic form into a
//! dependency chain that runs ~15% slower on Neoverse V-class cores.

use crate::aarch64::Sha2;

/// SHA-256 round constants (FIPS 180-4 section 4.2.2).
const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compresses `blocks` into `state` using the `sha2` instructions.
#[target_feature(enable = "sha2")]
fn compress_unchecked(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    if blocks.is_empty() {
        return;
    }
    // SAFETY: `state` is a valid 32-byte in/out buffer and `blocks` holds
    // `blocks.len()` readable 64-byte blocks; the loop reads exactly those
    // bytes and `K32` (256 bytes) through `x3`. Only the declared
    // registers and the two pointer/counter operands are written; the
    // block touches no stack and no memory other than `state`.
    unsafe {
        core::arch::asm!(
            "ld1 {{v22.4s, v23.4s}}, [{st}]",
            "2:",
            "ld1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [{blk}], #64",
            "mov x3, {k}",
            "ld1 {{v0.4s}}, [x3], #16",
            "rev32 v16.16b, v16.16b",
            "rev32 v17.16b, v17.16b",
            "rev32 v18.16b, v18.16b",
            "rev32 v19.16b, v19.16b",
            "mov v20.16b, v22.16b",
            "mov v21.16b, v23.16b",
            "add v4.4s, v16.4s, v0.4s",
        // round group 0
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v16.4s, v17.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v17.4s, v1.4s",
        "sha256su1 v16.4s, v18.4s, v19.4s",
        // round group 1
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v17.4s, v18.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v18.4s, v1.4s",
        "sha256su1 v17.4s, v19.4s, v16.4s",
        // round group 2
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v18.4s, v19.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v19.4s, v1.4s",
        "sha256su1 v18.4s, v16.4s, v17.4s",
        // round group 3
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v19.4s, v16.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v16.4s, v1.4s",
        "sha256su1 v19.4s, v17.4s, v18.4s",
        // round group 4
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v16.4s, v17.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v17.4s, v1.4s",
        "sha256su1 v16.4s, v18.4s, v19.4s",
        // round group 5
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v17.4s, v18.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v18.4s, v1.4s",
        "sha256su1 v17.4s, v19.4s, v16.4s",
        // round group 6
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v18.4s, v19.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v19.4s, v1.4s",
        "sha256su1 v18.4s, v16.4s, v17.4s",
        // round group 7
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v19.4s, v16.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v16.4s, v1.4s",
        "sha256su1 v19.4s, v17.4s, v18.4s",
        // round group 8
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v16.4s, v17.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v17.4s, v1.4s",
        "sha256su1 v16.4s, v18.4s, v19.4s",
        // round group 9
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v17.4s, v18.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v18.4s, v1.4s",
        "sha256su1 v17.4s, v19.4s, v16.4s",
        // round group 10
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v18.4s, v19.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v19.4s, v1.4s",
        "sha256su1 v18.4s, v16.4s, v17.4s",
        // round group 11
        "ld1 {{v1.4s}}, [x3], #16",
        "sha256su0 v19.4s, v16.4s",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v16.4s, v1.4s",
        "sha256su1 v19.4s, v17.4s, v18.4s",
        // round group 12
        "ld1 {{v1.4s}}, [x3], #16",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v17.4s, v1.4s",
        // round group 13
        "ld1 {{v1.4s}}, [x3], #16",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
        "add v4.4s, v18.4s, v1.4s",
        // round group 14
        "ld1 {{v1.4s}}, [x3], #16",
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v4.4s",
        "sha256h2 q23, q2, v4.4s",
        "add v5.4s, v19.4s, v1.4s",
        // round group 15
        "mov v2.16b, v22.16b",
        "sha256h q22, q23, v5.4s",
        "sha256h2 q23, q2, v5.4s",
            "add v22.4s, v22.4s, v20.4s",
            "add v23.4s, v23.4s, v21.4s",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            "st1 {{v22.4s, v23.4s}}, [{st}]",
            st = in(reg) state.as_mut_ptr(),
            blk = inout(reg) blocks.as_ptr() => _,
            n = inout(reg) blocks.len() => _,
            k = in(reg) K32.as_ptr(),
            out("x3") _,
            out("v0") _, out("v1") _, out("v2") _, out("v4") _, out("v5") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack),
            );
    }
}

/// [`compress_unchecked`], safe to call with a [`Sha2`] token.
#[inline(always)]
pub(super) fn compress(_: Sha2, state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // SAFETY: a `Sha2` token exists only after detection of `sha2`,
    // the feature the compression is compiled for.
    unsafe { compress_unchecked(state, blocks) }
}

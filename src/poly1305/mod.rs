#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) mod poly1305_simd;

#[cfg(any(test, not(all(feature = "simd_backend", feature = "nightly"))))]
pub(crate) mod poly1305_soft;

const BLOCK_SIZE: usize = 16;

#[inline]
fn pad_partial_block(buffer: &[u8]) -> [u8; BLOCK_SIZE] {
    debug_assert!(buffer.len() < BLOCK_SIZE);

    let mut block = [0u8; BLOCK_SIZE];
    block[..buffer.len()].copy_from_slice(buffer);
    block[buffer.len()] = 1;
    block
}

#[cfg(all(test, feature = "nightly", not(tarpaulin)))]
mod bench_inputs {
    pub(super) const BYTES_64: usize = 64;
    pub(super) const KIB_1: usize = 1024;
    pub(super) const KIB_16: usize = 16 * 1024;
    pub(super) const MIB_1: usize = 1024 * 1024;
}

#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) use poly1305_simd::*;
#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
pub(crate) use poly1305_soft::*;

#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) mod blake2b_simd;
#[cfg(all(feature = "simd_backend", feature = "nightly"))]
pub(crate) use blake2b_simd::*;

#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
pub(crate) mod blake2b_soft;
#[cfg(not(all(feature = "simd_backend", feature = "nightly")))]
pub(crate) use blake2b_soft::*;

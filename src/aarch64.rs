//! AArch64 CPU feature tokens for the detected kernels: NEON
//! (`chacha20`, `salsa20`, `poly1305`, `mlkem`), SVE2
//! (`chacha20`, `salsa20`) and the `sha2`/`sha3` extensions (`sha256`,
//! `sha512`, `salsa20`).
//!
//! [`Neon`], [`Sve2`], [`Sha2`] and [`Sha3`] are zero-sized proofs of CPU
//! feature detection: their field is private to this module and their only
//! constructors are the `new` functions, which return a token only when
//! `has_aarch64_feature!` reports the feature it names (detected at runtime
//! with `std`, taken from the compile-time target features without it). A
//! kernel compiled with `#[target_feature(enable = ...)]` for a token's feature
//! is reached through a safe wrapper that takes the token by value, so holding
//! one is what makes that wrapper's single `unsafe` call sound.
//!
//! The kernels compiled for `"neon,sve2"` or `"neon,sha3"` take the [`Sve2`]
//! or [`Sha3`] token alone: both target features imply `neon`, so enabling
//! either at compile time enables `neon` too, and `std` reports them at
//! runtime only when it also detects `neon`.
//!
//! Like the kernels that use them, the tokens exist only on little-endian
//! AArch64 targets, and [`Neon`] and [`Sve2`] (whose kernels use the NEON
//! helpers in `neon.rs`) not under Miri.

/// Proof that the running CPU supports NEON (see the module docs).
#[cfg(not(miri))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Neon(());

#[cfg(not(miri))]
impl Neon {
    /// The token, if the CPU has `neon`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_aarch64_feature!("neon").then_some(Self(()))
    }
}

/// Proof that the running CPU supports SVE2 (see the module docs).
#[cfg(not(miri))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sve2(());

#[cfg(not(miri))]
impl Sve2 {
    /// The token, if the CPU has `sve2`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_aarch64_feature!("sve2").then_some(Self(()))
    }
}

/// Proof that the running CPU supports the SHA-256 instructions (see the
/// module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sha2(());

impl Sha2 {
    /// The token, if the CPU has `sha2`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_aarch64_feature!("sha2").then_some(Self(()))
    }
}

/// Proof that the running CPU supports the SHA-3 and SHA-512 instructions
/// (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sha3(());

impl Sha3 {
    /// The token, if the CPU has `sha3`.
    #[inline]
    pub(crate) fn new() -> Option<Self> {
        has_aarch64_feature!("sha3").then_some(Self(()))
    }
}

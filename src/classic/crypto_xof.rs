//! # Extendable-output functions
//!
//! Implements libsodium's `crypto_xof_shake128_*`, `crypto_xof_shake256_*`,
//! `crypto_xof_turboshake128_*` and `crypto_xof_turboshake256_*` functions.
//!
//! An extendable-output function (XOF) hashes input of any length into
//! output of any length. SHAKE is specified in FIPS 202; TurboSHAKE (RFC
//! 9861) uses 12 Keccak rounds instead of 24 and is about twice as fast.
//!
//! Absorb input with `update`, then call `squeeze` as many times as needed:
//! the calls continue one output stream. Once squeezing has started, `update`
//! returns an error and leaves the state unchanged. `init_with_domain`
//! selects a custom domain byte in `0x01..=0x7f`.
//!
//! libsodium documents the same rules but does not enforce them: it accepts
//! any domain byte, and an `update` after squeezing returns `-1` after
//! resetting the state and absorbing the input anyway. dryoc returns an
//! error in both cases instead.
//!
//! ```
//! use dryoc::classic::crypto_xof::*;
//!
//! let mut digest = [0u8; 32];
//! crypto_xof_turboshake128(&mut digest, b"Arbitrary data to hash");
//!
//! let mut state = crypto_xof_shake256_init();
//! crypto_xof_shake256_update(&mut state, b"Arbitrary data to hash").expect("update failed");
//! let (mut key1, mut key2) = ([0u8; 32], [0u8; 32]);
//! crypto_xof_shake256_squeeze(&mut state, &mut key1);
//! crypto_xof_shake256_squeeze(&mut state, &mut key2);
//! assert_ne!(key1, key2);
//! ```

use crate::error::Error;
use crate::keccak::{RATE_128, RATE_256, ROUNDS_FULL, ROUNDS_TURBO};
use crate::xof::XofCore;

/// Generates the `*State` struct and the one-shot, `init`,
/// `init_with_domain`, `update` and `squeeze` functions for one XOF.
macro_rules! crypto_xof {
    (
        $(#[$state_meta:meta])*
        state: $state:ident($rate:expr, $rounds:expr),
        rustaceous: $xof:ty,
        algorithm: $algo:literal,
        oneshot: $oneshot:ident,
        init: $init:ident,
        init_with_domain: $init_with_domain:ident,
        update: $update:ident,
        squeeze: $squeeze:ident $(,)?
    ) => {
        $(#[$state_meta])*
        #[derive(Clone)]
        pub struct $state {
            core: XofCore<$rate, $rounds>,
        }

        #[doc = concat!("Computes ", $algo, " of `input`, filling `output`.")]
        pub fn $oneshot(output: &mut [u8], input: &[u8]) {
            <$xof>::compute_into_bytes(output, input)
        }

        #[doc = concat!("Initializes ", $algo, " with the standard domain.")]
        pub fn $init() -> $state {
            $state {
                core: XofCore::new(),
            }
        }

        #[doc = concat!("Initializes ", $algo, " with a custom `domain` byte.")]
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidValue`] unless `domain` is in `0x01..=0x7f`.
        pub fn $init_with_domain(domain: u8) -> Result<$state, Error> {
            Ok($state {
                core: XofCore::with_domain(domain)?,
            })
        }

        #[doc = concat!("Absorbs `input` into the ", $algo, " `state`.")]
        ///
        /// # Errors
        ///
        /// Returns [`Error::InvalidState`] if squeezing has started; the
        /// state is left unchanged.
        pub fn $update(state: &mut $state, input: &[u8]) -> Result<(), Error> {
            state.core.update(input)
        }

        #[doc = concat!(
            "Fills `output` with the next bytes of the ", $algo, " output stream,\n",
            "finishing absorption on the first call."
        )]
        pub fn $squeeze(state: &mut $state, output: &mut [u8]) {
            state.core.squeeze(output)
        }
    };
}

crypto_xof! {
    /// Incremental SHAKE128 state.
    state: Shake128State(RATE_128, ROUNDS_FULL),
    rustaceous: crate::xof::Shake128,
    algorithm: "SHAKE128",
    oneshot: crypto_xof_shake128,
    init: crypto_xof_shake128_init,
    init_with_domain: crypto_xof_shake128_init_with_domain,
    update: crypto_xof_shake128_update,
    squeeze: crypto_xof_shake128_squeeze,
}

crypto_xof! {
    /// Incremental SHAKE256 state.
    state: Shake256State(RATE_256, ROUNDS_FULL),
    rustaceous: crate::xof::Shake256,
    algorithm: "SHAKE256",
    oneshot: crypto_xof_shake256,
    init: crypto_xof_shake256_init,
    init_with_domain: crypto_xof_shake256_init_with_domain,
    update: crypto_xof_shake256_update,
    squeeze: crypto_xof_shake256_squeeze,
}

crypto_xof! {
    /// Incremental TurboSHAKE128 state.
    state: TurboShake128State(RATE_128, ROUNDS_TURBO),
    rustaceous: crate::xof::TurboShake128,
    algorithm: "TurboSHAKE128",
    oneshot: crypto_xof_turboshake128,
    init: crypto_xof_turboshake128_init,
    init_with_domain: crypto_xof_turboshake128_init_with_domain,
    update: crypto_xof_turboshake128_update,
    squeeze: crypto_xof_turboshake128_squeeze,
}

crypto_xof! {
    /// Incremental TurboSHAKE256 state.
    state: TurboShake256State(RATE_256, ROUNDS_TURBO),
    rustaceous: crate::xof::TurboShake256,
    algorithm: "TurboSHAKE256",
    oneshot: crypto_xof_turboshake256,
    init: crypto_xof_turboshake256_init,
    init_with_domain: crypto_xof_turboshake256_init_with_domain,
    update: crypto_xof_turboshake256_update,
    squeeze: crypto_xof_turboshake256_squeeze,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorContext;
    use crate::xof::test_vectors::*;

    /// Checks one XOF's Classic functions against its vectors: the one-shot
    /// function for the standard domain, and `init_with_domain`, one byte
    /// per `update` with empty updates around each, and odd-sized squeezes.
    macro_rules! check_known_answers {
        ($vectors:expr, $oneshot:ident, $init_with_domain:ident, $update:ident, $squeeze:ident) => {
            for Vector {
                message,
                domain,
                skip,
                output,
            } in $vectors
            {
                let len = message.len();
                if domain == 0x1f && skip == 0 {
                    let mut out = vec![0u8; output.len()];
                    $oneshot(&mut out, &message);
                    assert_eq!(out, output, "one-shot len {len}");
                }

                let mut state = $init_with_domain(domain).expect("valid domain");
                if len <= 1024 {
                    $update(&mut state, b"").expect("update failed");
                    for byte in &message {
                        $update(&mut state, std::slice::from_ref(byte)).expect("update failed");
                        $update(&mut state, b"").expect("update failed");
                    }
                } else {
                    $update(&mut state, &message).expect("update failed");
                }
                let mut all = vec![0u8; skip + output.len()];
                for chunk in all.chunks_mut(7) {
                    $squeeze(&mut state, chunk);
                }
                assert_eq!(&all[skip..], output, "streamed len {len}");
            }
        };
    }

    #[test]
    fn test_crypto_xof_shake128_known_answers() {
        check_known_answers!(
            shake128(),
            crypto_xof_shake128,
            crypto_xof_shake128_init_with_domain,
            crypto_xof_shake128_update,
            crypto_xof_shake128_squeeze
        );
    }

    #[test]
    fn test_crypto_xof_shake256_known_answers() {
        check_known_answers!(
            shake256(),
            crypto_xof_shake256,
            crypto_xof_shake256_init_with_domain,
            crypto_xof_shake256_update,
            crypto_xof_shake256_squeeze
        );
    }

    #[test]
    fn test_crypto_xof_turboshake128_known_answers() {
        check_known_answers!(
            turboshake128(),
            crypto_xof_turboshake128,
            crypto_xof_turboshake128_init_with_domain,
            crypto_xof_turboshake128_update,
            crypto_xof_turboshake128_squeeze
        );
    }

    #[test]
    fn test_crypto_xof_turboshake256_known_answers() {
        check_known_answers!(
            turboshake256(),
            crypto_xof_turboshake256,
            crypto_xof_turboshake256_init_with_domain,
            crypto_xof_turboshake256_update,
            crypto_xof_turboshake256_squeeze
        );
    }

    /// `update` after `squeeze` is rejected without disturbing the output
    /// stream, and `init` equals `init_with_domain` with the standard domain.
    #[test]
    fn test_update_after_squeeze_is_rejected() {
        let mut state = crypto_xof_turboshake256_init();
        crypto_xof_turboshake256_update(&mut state, b"abc").expect("update failed");
        let mut first = [0u8; 16];
        crypto_xof_turboshake256_squeeze(&mut state, &mut first);
        assert!(matches!(
            crypto_xof_turboshake256_update(&mut state, b"more"),
            Err(Error::InvalidState {
                context: ErrorContext::Xof
            })
        ));
        let mut rest = [0u8; 48];
        crypto_xof_turboshake256_squeeze(&mut state, &mut rest);

        let mut expected = [0u8; 64];
        crypto_xof_turboshake256(&mut expected, b"abc");
        assert_eq!([&first[..], &rest[..]].concat(), expected);

        assert!(crypto_xof_shake128_init_with_domain(0x80).is_err());
        assert!(crypto_xof_shake128_init_with_domain(0x00).is_err());
    }
}

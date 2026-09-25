//! Random bytes come from the operating system through
//! [`getrandom`](https://docs.rs/getrandom), which does not need `std`. On
//! targets without a supported system source, such as bare-metal
//! `thumbv7em-none-eabihf` or `aarch64-unknown-none`, the application must
//! provide a
//! [getrandom custom backend](https://docs.rs/getrandom/latest/getrandom/#custom-backend).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Provides random data up to `len` from the OS's random number generator.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
#[cfg(feature = "alloc")]
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    let mut r: Vec<u8> = vec![0; len];
    copy_randombytes(r.as_mut_slice());

    r
}

/// Provides random data up to length of `data` from the OS's random number
/// generator.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
pub fn copy_randombytes(dest: &mut [u8]) {
    fill_from(getrandom::fill, dest)
}

/// Fills `dest` with `fill`, panicking on failure. The shared body of the
/// public entry points; takes the source as a parameter so tests can
/// substitute a failing one.
fn fill_from<E: core::fmt::Debug>(fill: impl FnOnce(&mut [u8]) -> Result<(), E>, dest: &mut [u8]) {
    fill(dest).expect("failed to fill random bytes");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn randombytes_buf_returns_requested_length_and_fresh_data() {
        assert!(randombytes_buf(0).is_empty());

        let first = randombytes_buf(32);
        let second = randombytes_buf(32);
        assert_eq!(first.len(), 32);
        assert_ne!(first, second, "two 32-byte draws collided");
    }

    #[test]
    fn copy_randombytes_fills_exactly_the_destination() {
        let mut buf = [0u8; 64];
        copy_randombytes(&mut buf[16..48]);

        assert_eq!(&buf[..16], &[0; 16]);
        assert_eq!(&buf[48..], &[0; 16]);
        assert_ne!(&buf[16..48], &[0; 32]);

        copy_randombytes(&mut buf[..0]);
        assert_eq!(&buf[..16], &[0; 16]);
    }

    #[test]
    #[should_panic]
    fn os_rng_failure_panics_instead_of_leaving_zeroes() {
        let mut dest = [0u8; 8];
        fill_from(|_: &mut [u8]| Err("no entropy"), &mut dest);
    }
}

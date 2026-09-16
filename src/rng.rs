/// Provides random data up to `len` from the OS's random number generator.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
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
    fill_from(&mut rand::rngs::SysRng, dest)
}

/// Fills `dest` from `rng`, panicking on failure. The shared body of the
/// public entry points; generic so tests can substitute a failing generator.
fn fill_from<R: rand::TryRng>(rng: &mut R, dest: &mut [u8]) {
    rng.try_fill_bytes(dest)
        .expect("failed to fill random bytes");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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

    struct FailingRng;

    impl rand::TryRng for FailingRng {
        type Error = std::io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(std::io::Error::other("no entropy"))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(std::io::Error::other("no entropy"))
        }

        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
            Err(std::io::Error::other("no entropy"))
        }
    }

    #[test]
    #[should_panic]
    fn os_rng_failure_panics_instead_of_leaving_zeroes() {
        let mut dest = [0u8; 8];
        fill_from(&mut FailingRng, &mut dest);
    }
}

/// Provides random data up to `len` from the OS's random number generator.
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    use rand_core::{OsRng, TryRngCore};

    let mut r: Vec<u8> = vec![0; len];
    OsRng
        .try_fill_bytes(r.as_mut_slice())
        .expect("failed to fill random bytes");

    r
}

/// Provides random data up to length of `data` from the OS's random number
/// generator.
pub fn copy_randombytes(dest: &mut [u8]) {
    use rand_core::{OsRng, TryRngCore};

    OsRng
        .try_fill_bytes(dest)
        .expect("failed to fill random bytes");
}

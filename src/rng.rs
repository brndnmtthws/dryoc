/// Provides random data up to `len` from the OS's random number generator.
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};

    let mut r: Vec<u8> = vec![0; len];
    OsRng.fill_bytes(r.as_mut_slice());

    r
}

/// Provides random data up to length of `data` from the OS's random number
/// generator.
pub fn copy_randombytes(dest: &mut [u8]) {
    use rand_core::{OsRng, RngCore};

    OsRng.fill_bytes(dest);
}

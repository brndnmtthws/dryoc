/// Provides random data up to `len` from the OS's random number generator.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
pub fn randombytes_buf(len: usize) -> Vec<u8> {
    use rand::TryRng;
    use rand::rngs::SysRng;

    let mut r: Vec<u8> = vec![0; len];
    SysRng
        .try_fill_bytes(r.as_mut_slice())
        .expect("failed to fill random bytes");

    r
}

/// Provides random data up to length of `data` from the OS's random number
/// generator.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails.
pub fn copy_randombytes(dest: &mut [u8]) {
    use rand::TryRng;
    use rand::rngs::SysRng;

    SysRng
        .try_fill_bytes(dest)
        .expect("failed to fill random bytes");
}

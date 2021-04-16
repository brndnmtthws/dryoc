/// Increments `bytes` in constant time, representing a large little-endian
/// integer; equivalent to `sodium_increment`.
#[inline]
pub fn increment_bytes(bytes: &mut [u8]) {
    let mut carry: u16 = 1;
    for b in bytes {
        carry += *b as u16;
        *b = (carry & 0xff) as u8;
        carry >>= 8;
    }
}

/// Convenience wrapper for [`increment_bytes`]. Functionally equivalent to
/// `sodium_increment`.
pub fn sodium_increment(bytes: &mut [u8]) {
    increment_bytes(bytes)
}

#[inline]
pub(crate) fn xor_buf(out: &mut [u8], in_: &[u8]) {
    let len = std::cmp::min(out.len(), in_.len());
    for i in 0..len {
        out[i] ^= in_[i];
    }
}

#[inline]
pub(crate) fn load64_le(bytes: &[u8]) -> u64 {
    let mut r = 0u64;
    for (i, &b) in bytes[0..8].iter().enumerate() {
        r |= (b as u64) << (8 * i);
    }
    r
}

#[inline]
pub(crate) fn load32_le(bytes: &[u8]) -> u32 {
    let mut r = 0u32;
    for (i, &b) in bytes[0..4].iter().enumerate() {
        r |= (b as u32) << (8 * i);
    }
    r
}

#[inline]
pub(crate) fn rotr64(x: u64, b: u64) -> u64 {
    (x >> b) | (x << (64 - b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_bytes() {
        let mut b = [0];

        increment_bytes(&mut b);
        assert_eq!(b, [1]);
        increment_bytes(&mut b);
        assert_eq!(b, [2]);

        let mut b = [0xff];

        increment_bytes(&mut b);
        assert_eq!(b, [0]);
        increment_bytes(&mut b);
        assert_eq!(b, [1]);

        let mut b = [0xff, 0];

        increment_bytes(&mut b);
        assert_eq!(b, [0, 1]);
        increment_bytes(&mut b);
        assert_eq!(b, [1, 1]);
        increment_bytes(&mut b);
        assert_eq!(b, [2, 1]);
    }

    #[test]
    fn test_xor_buf() {
        let mut a = [0];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([0], a);

        let mut a = [1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1], a);

        let mut a = [1, 1, 1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1, 1, 1], a);

        let mut a = [1, 1, 1];
        let b = [0];

        xor_buf(&mut a, &b);
        assert_eq!([1, 1, 1], a);

        let mut a = [1, 1, 1];
        let b = [0, 1, 1];

        xor_buf(&mut a, &b);
        assert_eq!([1, 0, 0], a);
    }

    #[test]
    fn test_sodium_increment() {
        use libsodium_sys::sodium_increment as so_sodium_increment;
        use rand_core::{OsRng, RngCore};

        use crate::rng::copy_randombytes;

        for _ in 0..20 {
            let rand_usize = (OsRng.next_u32() % 1000) as usize;
            let mut data = vec![0u8; rand_usize];
            copy_randombytes(&mut data);

            let mut data_copy = data.clone();

            sodium_increment(&mut data);

            unsafe { so_sodium_increment(data_copy.as_mut_ptr(), data_copy.len()) };

            assert_eq!(data, data_copy);
        }
    }
}

/// Increments `bytes` representing a large integer as if they were encoded as
/// little-endian, equivalent to `sodium_increment`.
pub fn increment_bytes(bytes: &mut [u8]) {
    let mut carry: u16 = 1;
    for b in bytes {
        carry = carry + *b as u16;
        *b = carry as u8;
        carry = carry >> 8;
    }
}

pub(crate) fn xor_buf(out: &mut [u8], in_: &[u8]) {
    let len = std::cmp::min(out.len(), in_.len());
    let out = &mut out[..len];
    let in_ = &in_[..len];
    for i in 0..len {
        out[i] = out[i] ^ in_[i];
    }
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
}

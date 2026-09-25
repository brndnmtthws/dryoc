use subtle::ConstantTimeEq;

use crate::constants::{
    CRYPTO_CORE_ED25519_BYTES, CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_CORE_HCHACHA20_KEYBYTES,
    CRYPTO_CORE_HCHACHA20_OUTPUTBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES,
    CRYPTO_CORE_HSALSA20_KEYBYTES, CRYPTO_CORE_HSALSA20_OUTPUTBYTES, CRYPTO_SCALARMULT_BYTES,
    CRYPTO_SCALARMULT_SCALARBYTES,
};
use crate::edwards25519::Point;
use crate::error::Error;
use crate::scalarmult_curve25519::{
    crypto_scalarmult_curve25519, crypto_scalarmult_curve25519_base,
};
use crate::types::*;
use crate::utils::{SIGMA, load_u32_le};

/// Stack-allocated HChaCha20 input.
pub type HChaCha20Input = [u8; CRYPTO_CORE_HCHACHA20_INPUTBYTES];
/// Stack-allocated HChaCha20 key.
pub type HChaCha20Key = [u8; CRYPTO_CORE_HCHACHA20_KEYBYTES];
/// Stack-allocated HChaCha20 output.
pub type HChaCha20Output = [u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
/// Stack-allocated HSalsa20 input.
pub type HSalsa20Input = [u8; CRYPTO_CORE_HSALSA20_INPUTBYTES];
/// Stack-allocated HSalsa20 key.
pub type HSalsa20Key = [u8; CRYPTO_CORE_HSALSA20_KEYBYTES];
/// Stack-allocated HSalsa20 output.
pub type HSalsa20Output = [u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
/// Stack-allocated Ed25519 point.
pub type Ed25519Point = [u8; CRYPTO_CORE_ED25519_BYTES];

/// Computes the public key for a previously generated secret key.
///
/// Compatible with libsodium's `crypto_scalarmult_base`.
pub fn crypto_scalarmult_base(
    q: &mut [u8; CRYPTO_SCALARMULT_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
) {
    crypto_scalarmult_curve25519_base(q, n)
}

/// Computes a shared secret `q`, given `n`, our secret key, and `p`, their
/// public key, using a Diffie-Hellman key exchange.
///
/// Compatible with libsodium's `crypto_scalarmult`.
///
/// # Errors
///
/// Returns an error if `p` is an unacceptable low-order public key that
/// produces an all-zero shared secret.
pub fn crypto_scalarmult(
    q: &mut [u8; CRYPTO_SCALARMULT_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_BYTES],
) -> Result<(), Error> {
    crypto_scalarmult_curve25519(q, n, p);

    if q.ct_eq(&[0u8; CRYPTO_SCALARMULT_BYTES]).into() {
        Err(Error::invalid_key(crate::ErrorContext::Curve25519PublicKey))
    } else {
        Ok(())
    }
}

/// Implements the HChaCha20 function.
///
/// Compatible with libsodium's `crypto_core_hchacha20`.
pub fn crypto_core_hchacha20(
    output: &mut HChaCha20Output,
    input: &HChaCha20Input,
    key: &HChaCha20Key,
    constants: Option<(u32, u32, u32, u32)>,
) {
    let input = input.as_array();
    let key = key.as_array();
    let (c0, c1, c2, c3) = constants.unwrap_or((SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3]));
    let mut x = [c0, c1, c2, c3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (word, bytes) in x[4..12].iter_mut().zip(key.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    for (word, bytes) in x[12..].iter_mut().zip(input.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    crate::chacha20::rounds(&mut x);

    // Words 0..4 and 12..16 of the permuted state, read by reference rather
    // than gathered into a by-value copy.
    let (head, tail) = output.as_chunks_mut::<4>().0.split_at_mut(4);
    for (chunk, word) in head.iter_mut().zip(&x[..4]) {
        *chunk = word.to_le_bytes();
    }
    for (chunk, word) in tail.iter_mut().zip(&x[12..]) {
        *chunk = word.to_le_bytes();
    }
}

/// Checks whether `p` is a valid prime-order Ed25519 point.
///
/// This validates the canonical compressed encoding, rejects points that are
/// not on the curve or have small order, and requires membership in the main
/// subgroup. The high bit is the sign of the x-coordinate and may legitimately
/// be set.
///
/// # Example
///
/// ```
/// use dryoc::classic::crypto_core::crypto_core_ed25519_is_valid_point;
/// use dryoc::classic::crypto_sign::crypto_sign_keypair;
///
/// let (pk, _) = crypto_sign_keypair();
/// assert!(crypto_core_ed25519_is_valid_point(&pk));
/// ```
///
/// # Compatibility
///
/// This matches `crypto_core_ed25519_is_valid_point` in libsodium 1.0.21 and
/// later. Libsodium versions through 1.0.20 incorrectly accepted some
/// mixed-order points; this function rejects them.
pub fn crypto_core_ed25519_is_valid_point(p: &Ed25519Point) -> bool {
    decompress_prime_order_ed25519_point(p).is_some()
}

/// Decompresses `p` only if it is a canonical encoding of a point in the
/// prime-order subgroup: not small order and torsion free.
pub(crate) fn decompress_prime_order_ed25519_point(p: &Ed25519Point) -> Option<Point> {
    decompress_canonical_ed25519_point(p)
        .filter(|point| !point.is_small_order() && ed25519_is_torsion_free(point))
}

/// Whether `point` lies in the prime-order subgroup, i.e. `[L]P` is the
/// identity for the basepoint order `L`.
///
/// The multiplication runs in variable time with respect to the scalar: `L`
/// is a public constant and the points checked here are public keys and
/// encodings, so nothing secret is involved, and the NAF form of `L` needs a
/// third fewer point additions than a constant-time fixed-window
/// multiplication.
pub(crate) fn ed25519_is_torsion_free(point: &Point) -> bool {
    point.is_torsion_free_vartime()
}

/// Decompresses an Ed25519 point only if its encoding is canonical.
///
/// Decompression reduces the encoded y-coordinate modulo the field prime, and
/// any sign bit decodes when `x == 0`. Checking the encoding first rejects
/// alternate encodings of the same point without recompressing the result,
/// which would cost a field inversion.
pub(crate) fn decompress_canonical_ed25519_point(p: &Ed25519Point) -> Option<Point> {
    if !is_canonical_ed25519_encoding(p) {
        return None;
    }
    Point::decompress(p)
}

/// Whether `p` is the unique encoding of the point it decodes to (if any):
/// its y-coordinate is below the field prime `2^255 - 19`, and its sign bit
/// is clear when `y` is `1` or `-1`, the only y-coordinates with `x == 0`.
///
/// This is the byte-level equivalent of decompressing and recompressing the
/// point, which is how a non-canonical encoding would otherwise be detected.
fn is_canonical_ed25519_encoding(p: &Ed25519Point) -> bool {
    let sign = p[31] >> 7;
    let y_top = p[31] & 0x7f;
    let y_middle_all_ones = p[1..31].iter().all(|&b| b == 0xff);
    let y_middle_all_zero = p[1..31].iter().all(|&b| b == 0);

    // y >= p: bits 8..255 all set (p = 2^255 - 19 has them set) and the low
    // byte at least 0xed.
    let y_at_least_p = y_top == 0x7f && y_middle_all_ones && p[0] >= 0xed;
    let y_is_one = y_top == 0 && y_middle_all_zero && p[0] == 1;
    let y_is_minus_one = y_top == 0x7f && y_middle_all_ones && p[0] == 0xec;

    !y_at_least_p && !(sign == 1 && (y_is_one || y_is_minus_one))
}

#[inline]
fn salsa20_rotl32(x: u32, y: u32, rot: u32) -> u32 {
    x.wrapping_add(y).rotate_left(rot)
}

/// Implements the HSalsa20 function.
///
/// Compatible with libsodium's `crypto_core_hsalsa20`.
pub fn crypto_core_hsalsa20(
    output: &mut HSalsa20Output,
    input: &HSalsa20Input,
    key: &HSalsa20Key,
    constants: Option<(u32, u32, u32, u32)>,
) {
    let (mut x0, mut x5, mut x10, mut x15) =
        constants.unwrap_or((SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3]));
    let (
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
    ) = (
        load_u32_le(&key[0..4]),
        load_u32_le(&key[4..8]),
        load_u32_le(&key[8..12]),
        load_u32_le(&key[12..16]),
        load_u32_le(&key[16..20]),
        load_u32_le(&key[20..24]),
        load_u32_le(&key[24..28]),
        load_u32_le(&key[28..32]),
        load_u32_le(&input[0..4]),
        load_u32_le(&input[4..8]),
        load_u32_le(&input[8..12]),
        load_u32_le(&input[12..16]),
    );

    for _ in (0..20).step_by(2) {
        x4 ^= salsa20_rotl32(x0, x12, 7);
        x8 ^= salsa20_rotl32(x4, x0, 9);
        x12 ^= salsa20_rotl32(x8, x4, 13);
        x0 ^= salsa20_rotl32(x12, x8, 18);
        x9 ^= salsa20_rotl32(x5, x1, 7);
        x13 ^= salsa20_rotl32(x9, x5, 9);
        x1 ^= salsa20_rotl32(x13, x9, 13);
        x5 ^= salsa20_rotl32(x1, x13, 18);
        x14 ^= salsa20_rotl32(x10, x6, 7);
        x2 ^= salsa20_rotl32(x14, x10, 9);
        x6 ^= salsa20_rotl32(x2, x14, 13);
        x10 ^= salsa20_rotl32(x6, x2, 18);
        x3 ^= salsa20_rotl32(x15, x11, 7);
        x7 ^= salsa20_rotl32(x3, x15, 9);
        x11 ^= salsa20_rotl32(x7, x3, 13);
        x15 ^= salsa20_rotl32(x11, x7, 18);
        x1 ^= salsa20_rotl32(x0, x3, 7);
        x2 ^= salsa20_rotl32(x1, x0, 9);
        x3 ^= salsa20_rotl32(x2, x1, 13);
        x0 ^= salsa20_rotl32(x3, x2, 18);
        x6 ^= salsa20_rotl32(x5, x4, 7);
        x7 ^= salsa20_rotl32(x6, x5, 9);
        x4 ^= salsa20_rotl32(x7, x6, 13);
        x5 ^= salsa20_rotl32(x4, x7, 18);
        x11 ^= salsa20_rotl32(x10, x9, 7);
        x8 ^= salsa20_rotl32(x11, x10, 9);
        x9 ^= salsa20_rotl32(x8, x11, 13);
        x10 ^= salsa20_rotl32(x9, x8, 18);
        x12 ^= salsa20_rotl32(x15, x14, 7);
        x13 ^= salsa20_rotl32(x12, x15, 9);
        x14 ^= salsa20_rotl32(x13, x12, 13);
        x15 ^= salsa20_rotl32(x14, x13, 18);
    }

    output[0..4].copy_from_slice(&x0.to_le_bytes());
    output[4..8].copy_from_slice(&x5.to_le_bytes());
    output[8..12].copy_from_slice(&x10.to_le_bytes());
    output[12..16].copy_from_slice(&x15.to_le_bytes());
    output[16..20].copy_from_slice(&x6.to_le_bytes());
    output[20..24].copy_from_slice(&x7.to_le_bytes());
    output[24..28].copy_from_slice(&x8.to_le_bytes());
    output[28..32].copy_from_slice(&x9.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    use super::*;
    use crate::classic::crypto_sign::crypto_sign_keypair;
    use crate::scalarmult_curve25519::test_vectors::low_order_u_encodings;
    use crate::test_prelude::*;

    #[test]
    fn test_crypto_core_ed25519_is_valid_point() {
        let basepoint = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        assert!(crypto_core_ed25519_is_valid_point(&basepoint));

        let mut negative_basepoint = basepoint;
        negative_basepoint[31] |= 0x80;
        assert!(
            crypto_core_ed25519_is_valid_point(&negative_basepoint),
            "the high bit is a valid x-coordinate sign bit"
        );

        let identity = {
            let mut point = [0u8; CRYPTO_CORE_ED25519_BYTES];
            point[0] = 1;
            point
        };
        assert!(!crypto_core_ed25519_is_valid_point(&identity));

        let noncanonical_identity = {
            let mut point = [0xff; CRYPTO_CORE_ED25519_BYTES];
            point[0] = 0xee;
            point[31] = 0x7f;
            point
        };
        assert!(
            decompress_canonical_ed25519_point(&noncanonical_identity).is_none(),
            "p + 1 must not be accepted as an alternate encoding of the identity"
        );
        assert!(!crypto_core_ed25519_is_valid_point(&noncanonical_identity));

        let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
        assert!(torsion.is_small_order());
        assert!(!crypto_core_ed25519_is_valid_point(
            &torsion.compress().to_bytes()
        ));

        let mixed_order = curve25519_dalek::constants::ED25519_BASEPOINT_POINT + torsion;
        assert!(!mixed_order.is_small_order());
        assert!(!mixed_order.is_torsion_free());
        assert!(!crypto_core_ed25519_is_valid_point(
            &mixed_order.compress().to_bytes()
        ));

        let mut point_not_on_curve = [0u8; CRYPTO_CORE_ED25519_BYTES];
        point_not_on_curve[0] = 2;
        assert!(!crypto_core_ed25519_is_valid_point(&point_not_on_curve));
        assert!(!crypto_core_ed25519_is_valid_point(
            &[0u8; CRYPTO_CORE_ED25519_BYTES]
        ));
    }

    #[test]
    fn test_generated_ed25519_keys_are_valid_points() {
        for _ in 0..25 {
            let (ed25519_pk, _) = crypto_sign_keypair();
            assert!(crypto_core_ed25519_is_valid_point(&ed25519_pk));
        }
    }

    /// The variable-time subgroup check must agree with dalek's constant-time
    /// one on prime-order, small-order and mixed-order points.
    #[test]
    fn test_torsion_check_matches_dalek() {
        let mut points = vec![curve25519_dalek::constants::ED25519_BASEPOINT_POINT];
        // Every torsion class is retained; fewer generated prime-order
        // points keep the interpreted cross-product bounded.
        for _ in 0..if cfg!(miri) { 2 } else { 32 } {
            let (pk, _) = crypto_sign_keypair();
            points.push(CompressedEdwardsY(pk).decompress().unwrap());
        }
        let prime_order = points.clone();
        for torsion in curve25519_dalek::constants::EIGHT_TORSION {
            points.push(torsion);
            for point in &prime_order {
                points.push(point + torsion);
            }
        }
        for point in points {
            let ours = Point::decompress(&point.compress().to_bytes()).unwrap();
            assert_eq!(ed25519_is_torsion_free(&ours), point.is_torsion_free());
        }
    }

    /// The byte-level canonical check must accept exactly the encodings that
    /// survive a decompress/recompress round trip.
    #[test]
    fn test_canonical_encoding_check_matches_recompression() {
        let round_trip = |p: &Ed25519Point| {
            let compressed = CompressedEdwardsY(*p);
            compressed
                .decompress()
                .is_some_and(|point| point.compress() == compressed)
        };
        let mut cases = Vec::new();
        // Every y in p - 2 ..= 2^255 - 1 (canonical, then the 19 non-canonical
        // encodings of 0..18), and small y, each with both sign bits.
        for low in 0xebu8..=0xff {
            let mut point = [0xff; CRYPTO_CORE_ED25519_BYTES];
            point[0] = low;
            point[31] = 0x7f;
            cases.push(point);
        }
        for low in 0u8..=20 {
            let mut point = [0; CRYPTO_CORE_ED25519_BYTES];
            point[0] = low;
            cases.push(point);
        }
        cases.push(curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes());
        for torsion in curve25519_dalek::constants::EIGHT_TORSION {
            cases.push(torsion.compress().to_bytes());
        }
        for _ in 0..if cfg!(miri) { 4 } else { 64 } {
            cases.push(crypto_sign_keypair().0);
            let mut random = [0u8; CRYPTO_CORE_ED25519_BYTES];
            crate::rng::copy_randombytes(&mut random);
            cases.push(random);
        }
        for mut point in cases {
            for sign in [0u8, 0x80] {
                point[31] = (point[31] & 0x7f) | sign;
                assert_eq!(
                    decompress_canonical_ed25519_point(&point).is_some(),
                    round_trip(&point),
                    "{point:02x?}"
                );
            }
        }
    }

    /// Mixed-order points that libsodium through 1.0.20 accepted: `y = 9`,
    /// and the regression vector added when libsodium fixed its main
    /// subgroup check (a prime-order point plus order-two torsion).
    fn legacy_libsodium_mixed_order_points() -> [[u8; CRYPTO_CORE_ED25519_BYTES]; 2] {
        let mut y_is_nine = [0u8; CRYPTO_CORE_ED25519_BYTES];
        y_is_nine[0] = 9;
        let mut order_two_coset = [0x99; CRYPTO_CORE_ED25519_BYTES];
        order_two_coset[0] = 0x95;
        [y_is_nine, order_two_coset]
    }

    #[test]
    fn test_crypto_core_ed25519_rejects_legacy_libsodium_mixed_order_points() {
        for point in legacy_libsodium_mixed_order_points() {
            let decoded = decompress_canonical_ed25519_point(&point)
                .expect("regression vector must be a canonical curve point");
            assert!(!decoded.is_small_order());
            assert!(!ed25519_is_torsion_free(&decoded));
            assert!(!crypto_core_ed25519_is_valid_point(&point));
        }
    }

    /// Every low-order `u` (libsodium's blacklist, with and without bit 255)
    /// is rejected, and the all-zero shared secret it produces is what the
    /// caller's buffer holds afterwards.
    #[test]
    fn test_crypto_scalarmult_rejects_low_order_points() {
        let scalar = [0x42; CRYPTO_SCALARMULT_SCALARBYTES];

        for public_key in low_order_u_encodings() {
            let mut shared_secret = [0xa5; CRYPTO_SCALARMULT_BYTES];
            assert!(
                matches!(
                    crypto_scalarmult(&mut shared_secret, &scalar, &public_key),
                    Err(Error::InvalidKey {
                        context: crate::ErrorContext::Curve25519PublicKey,
                    })
                ),
                "{public_key:02x?}"
            );
            assert_eq!(shared_secret, [0u8; CRYPTO_SCALARMULT_BYTES]);
        }
    }

    #[test]
    fn test_crypto_scalarmult_ignores_public_key_high_bit() {
        let scalar = [0x42; CRYPTO_SCALARMULT_SCALARBYTES];
        let mut canonical = [0u8; CRYPTO_SCALARMULT_BYTES];
        canonical[0] = 9;
        let mut high_bit_set = canonical;
        high_bit_set[CRYPTO_SCALARMULT_BYTES - 1] = 0x80;
        let mut canonical_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
        let mut high_bit_secret = [0u8; CRYPTO_SCALARMULT_BYTES];

        crypto_scalarmult(&mut canonical_secret, &scalar, &canonical).unwrap();
        crypto_scalarmult(&mut high_bit_secret, &scalar, &high_bit_set).unwrap();

        assert_eq!(canonical_secret, high_bit_secret);
    }

    /// Non-default constants that differ in every word, so a constant in the
    /// wrong position or order changes the output.
    const CUSTOM_CONSTANTS: Constants = (0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210);

    /// The default constants passed explicitly.
    const SIGMA_CONSTANTS: Constants = (SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3]);

    /// The `constants` argument of the HChaCha20 and HSalsa20 functions.
    type Constants = (u32, u32, u32, u32);

    /// HChaCha20 test vector of draft-irtf-cfrg-xchacha-03 section 2.2.1 with
    /// the default constants, implied and explicit, and the same key and
    /// input with [`CUSTOM_CONSTANTS`] (expected output from libsodium
    /// 1.0.22's `crypto_core_hchacha20`).
    #[test]
    fn test_crypto_core_hchacha20_known_answers() {
        let key: HChaCha20Key = core::array::from_fn(|i| i as u8);
        let input: HChaCha20Input = hex::decode("000000090000004a0000000031415927")
            .unwrap()
            .try_into()
            .unwrap();
        let default = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
        for (constants, expected) in [
            (None, default),
            (Some(SIGMA_CONSTANTS), default),
            (
                Some(CUSTOM_CONSTANTS),
                "e887f97849587bad0f41aa2b5596fe9967e2785acc6ecc13c7c4e4a02016bd76",
            ),
        ] {
            let mut output = HChaCha20Output::default();
            crypto_core_hchacha20(&mut output, &input, &key, constants);
            assert_eq!(hex::encode(output), expected, "{constants:x?}");
        }
    }

    /// HSalsa20 test vectors of NaCl's `tests/core1.c` and `tests/core2.c`
    /// (the XSalsa20 subkeys of the crypto_box example) with the default
    /// constants, implied and explicit, and the `core1` key and input with
    /// [`CUSTOM_CONSTANTS`] (expected output from libsodium 1.0.22's
    /// `crypto_core_hsalsa20`).
    #[test]
    fn test_crypto_core_hsalsa20_known_answers() {
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        let firstkey = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
        let nonce_prefix = "69696ee955b62b73cd62bda875fc73d6";
        let zero = "00000000000000000000000000000000";
        for (key, input, constants, expected) in [
            (shared, zero, None, firstkey),
            (shared, zero, Some(SIGMA_CONSTANTS), firstkey),
            (
                firstkey,
                nonce_prefix,
                None,
                "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4",
            ),
            (
                shared,
                zero,
                Some(CUSTOM_CONSTANTS),
                "7ee2bcfe4eec7e4e59e64a4e7b0a97a001f2ad95c10247115f0d261afa7c092c",
            ),
        ] {
            let key: HSalsa20Key = hex::decode(key).unwrap().try_into().unwrap();
            let input: HSalsa20Input = hex::decode(input).unwrap().try_into().unwrap();
            let mut output = HSalsa20Output::default();
            crypto_core_hsalsa20(&mut output, &input, &key, constants);
            assert_eq!(hex::encode(output), expected, "{constants:x?}");
        }
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;
        use crate::classic::crypto_box::*;
        use crate::scalarmult_curve25519::test_vectors::field_prime_plus;

        #[test]
        fn test_crypto_core_ed25519_is_valid_point_matches_libsodium() {
            use libsodium_sys::crypto_core_ed25519_is_valid_point as sodium_is_valid_point;

            crate::native_test_util::init();

            let basepoint = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
            let mut negative_basepoint = basepoint;
            negative_basepoint[31] |= 0x80;
            let identity = {
                let mut point = [0u8; CRYPTO_CORE_ED25519_BYTES];
                point[0] = 1;
                point
            };
            let noncanonical_identity = {
                let mut point = [0xff; CRYPTO_CORE_ED25519_BYTES];
                point[0] = 0xee;
                point[31] = 0x7f;
                point
            };
            let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
            let mixed_order = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT + torsion)
                .compress()
                .to_bytes();

            for point in [
                basepoint,
                negative_basepoint,
                identity,
                noncanonical_identity,
                torsion.compress().to_bytes(),
                mixed_order,
                [0u8; CRYPTO_CORE_ED25519_BYTES],
            ]
            .into_iter()
            .chain(legacy_libsodium_mixed_order_points())
            {
                let dryoc_result = crypto_core_ed25519_is_valid_point(&point);
                let sodium_result = unsafe { sodium_is_valid_point(point.as_ptr()) } == 1;
                assert_eq!(dryoc_result, sodium_result, "point: {point:02x?}");
            }

            for _ in 0..20 {
                let (public_key, _) = crypto_sign_keypair();
                let sodium_result = unsafe { sodium_is_valid_point(public_key.as_ptr()) } == 1;
                assert!(sodium_result);
                assert_eq!(
                    crypto_core_ed25519_is_valid_point(&public_key),
                    sodium_result
                );
            }
        }

        #[test]
        fn test_crypto_scalarmult_base() {
            use base64::Engine as _;
            use base64::engine::general_purpose;
            for _ in 0..20 {
                use crate::native_test_util::scalarmult_curve25519_base;

                let (pk, sk) = crypto_box_keypair();

                let mut public_key = [0u8; CRYPTO_SCALARMULT_BYTES];
                crypto_scalarmult_base(&mut public_key, &sk);

                assert_eq!(&pk, &public_key);

                let ge = scalarmult_curve25519_base(&sk);

                assert_eq!(
                    general_purpose::STANDARD.encode(ge),
                    general_purpose::STANDARD.encode(public_key)
                );
            }
        }

        #[test]
        fn test_crypto_scalarmult() {
            use base64::Engine as _;
            use base64::engine::general_purpose;
            for _ in 0..20 {
                use crate::native_test_util::scalarmult_curve25519;

                let (_our_pk, our_sk) = crypto_box_keypair();
                let (their_pk, _their_sk) = crypto_box_keypair();

                let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
                crypto_scalarmult(&mut shared_secret, &our_sk, &their_pk)
                    .expect("scalarmult failed");

                let ge = scalarmult_curve25519(&our_sk, &their_pk).expect("scalarmult failed");

                assert_eq!(
                    general_purpose::STANDARD.encode(ge),
                    general_purpose::STANDARD.encode(shared_secret)
                );
            }
        }

        /// libsodium refuses the same fourteen low-order encodings (its
        /// `has_small_order` blacklist compares with bit 255 masked), and
        /// both sides reject them for every scalar tried.
        #[test]
        fn test_crypto_scalarmult_low_order_compatibility() {
            use libsodium_sys::crypto_scalarmult as sodium_scalarmult;

            crate::native_test_util::init();

            let mut rng = crate::utils::test_util::XorShift64::new(0x3c6e_f372_fe94_f82b);
            let scalars = [[0u8; 32], [0xff; 32], [0x42; 32], rng.next_bytes32()];

            for public_key in low_order_u_encodings() {
                for scalar in scalars {
                    let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
                    assert!(
                        crypto_scalarmult(&mut shared_secret, &scalar, &public_key).is_err(),
                        "{public_key:02x?}"
                    );
                    let mut sodium_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
                    let sodium_result = unsafe {
                        sodium_scalarmult(
                            sodium_secret.as_mut_ptr(),
                            scalar.as_ptr(),
                            public_key.as_ptr(),
                        )
                    };
                    assert_eq!(sodium_result, -1, "{public_key:02x?}");
                }
            }
        }

        /// Non-canonical `u` encodings (`p + j`, with and without bit 255)
        /// are accepted and give libsodium's output, which is the output for
        /// the reduced `j`.
        #[test]
        fn test_crypto_scalarmult_noncanonical_compatibility() {
            use libsodium_sys::crypto_scalarmult as sodium_scalarmult;

            crate::native_test_util::init();

            let mut rng = crate::utils::test_util::XorShift64::new(0xa54f_f53a_5f1d_36f1);
            // 0 and 1 are low order (tested above); 2..=18 reach 2^255 - 1.
            for j in 2..=18u8 {
                let scalar = rng.next_bytes32();
                let mut canonical = [0u8; CRYPTO_SCALARMULT_BYTES];
                canonical[0] = j;
                let mut expected = [0u8; CRYPTO_SCALARMULT_BYTES];
                crypto_scalarmult(&mut expected, &scalar, &canonical).unwrap();

                let unreduced = field_prime_plus(j as i8);
                let mut unreduced_high = unreduced;
                unreduced_high[31] |= 0x80;
                for public_key in [unreduced, unreduced_high] {
                    let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
                    crypto_scalarmult(&mut shared_secret, &scalar, &public_key).unwrap();
                    let mut sodium_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
                    let sodium_result = unsafe {
                        sodium_scalarmult(
                            sodium_secret.as_mut_ptr(),
                            scalar.as_ptr(),
                            public_key.as_ptr(),
                        )
                    };
                    assert_eq!(sodium_result, 0, "j {j}");
                    assert_eq!(shared_secret, sodium_secret, "j {j}");
                    assert_eq!(shared_secret, expected, "j {j}");
                }
            }
        }

        /// Constants for the libsodium comparisons: the defaults implied
        /// (`None`, a null `c`), the defaults passed explicitly, and random
        /// ones, each with the 16 little-endian bytes libsodium's `c` takes.
        fn constant_cases() -> [(Option<Constants>, Option<[u8; 16]>); 3] {
            fn le_bytes((c0, c1, c2, c3): Constants) -> [u8; 16] {
                let mut bytes = [0u8; 16];
                for (chunk, word) in bytes
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip([c0, c1, c2, c3])
                {
                    *chunk = word.to_le_bytes();
                }
                bytes
            }

            let mut random = [0u8; 16];
            crate::rng::copy_randombytes(&mut random);
            let word = |i: usize| load_u32_le(&random[4 * i..4 * i + 4]);
            let random = (word(0), word(1), word(2), word(3));
            let sigma = (SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3]);
            [
                (None, None),
                (Some(sigma), Some(le_bytes(sigma))),
                (Some(random), Some(le_bytes(random))),
            ]
        }

        #[test]
        fn test_crypto_core_hchacha20() {
            use libsodium_sys::crypto_core_hchacha20 as so_crypto_core_hchacha20;

            use crate::rng::copy_randombytes;

            crate::native_test_util::init();

            for _ in 0..10 {
                let mut key = [0u8; CRYPTO_CORE_HCHACHA20_KEYBYTES];
                let mut data = [0u8; CRYPTO_CORE_HCHACHA20_INPUTBYTES];
                copy_randombytes(&mut key);
                copy_randombytes(&mut data);

                for (constants, c) in constant_cases() {
                    let mut out = [0u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
                    crypto_core_hchacha20(&mut out, &data, &key, constants);

                    let mut so_out = [0u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
                    let ret = unsafe {
                        so_crypto_core_hchacha20(
                            so_out.as_mut_ptr(),
                            data.as_ptr(),
                            key.as_ptr(),
                            c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()),
                        )
                    };
                    assert_eq!(ret, 0);
                    assert_eq!(out, so_out, "{constants:x?}");
                }
            }
        }

        #[test]
        fn test_crypto_core_hsalsa20() {
            use libsodium_sys::crypto_core_hsalsa20 as so_crypto_core_hsalsa20;

            use crate::rng::copy_randombytes;

            crate::native_test_util::init();

            for _ in 0..10 {
                let mut key = [0u8; CRYPTO_CORE_HSALSA20_KEYBYTES];
                let mut data = [0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES];
                copy_randombytes(&mut key);
                copy_randombytes(&mut data);

                for (constants, c) in constant_cases() {
                    let mut out = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
                    crypto_core_hsalsa20(&mut out, &data, &key, constants);

                    let mut so_out = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
                    let ret = unsafe {
                        so_crypto_core_hsalsa20(
                            so_out.as_mut_ptr(),
                            data.as_ptr(),
                            key.as_ptr(),
                            c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()),
                        )
                    };
                    assert_eq!(ret, 0);
                    assert_eq!(out, so_out, "{constants:x?}");
                }
            }
        }
    }
}

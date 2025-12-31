use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::constants::{
    CRYPTO_CORE_ED25519_BYTES, CRYPTO_CORE_HCHACHA20_INPUTBYTES, CRYPTO_CORE_HCHACHA20_KEYBYTES,
    CRYPTO_CORE_HCHACHA20_OUTPUTBYTES, CRYPTO_CORE_HSALSA20_INPUTBYTES,
    CRYPTO_CORE_HSALSA20_KEYBYTES, CRYPTO_CORE_HSALSA20_OUTPUTBYTES, CRYPTO_SCALARMULT_BYTES,
    CRYPTO_SCALARMULT_SCALARBYTES,
};
use crate::scalarmult_curve25519::{
    crypto_scalarmult_curve25519, crypto_scalarmult_curve25519_base,
};
use crate::types::*;
use crate::utils::load_u32_le;

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
pub fn crypto_scalarmult(
    q: &mut [u8; CRYPTO_SCALARMULT_BYTES],
    n: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
    p: &[u8; CRYPTO_SCALARMULT_BYTES],
) {
    crypto_scalarmult_curve25519(q, n, p)
}

#[inline]
fn chacha20_round(x: &mut u32, y: &u32, z: &mut u32, rot: u32) {
    *x = x.wrapping_add(*y);
    *z = (*z ^ *x).rotate_left(rot);
}

#[inline]
fn chacha20_quarterround(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    chacha20_round(a, b, d, 16);
    chacha20_round(c, d, b, 12);
    chacha20_round(a, b, d, 8);
    chacha20_round(c, d, b, 7);
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
    assert_eq!(input.len(), 16);
    assert_eq!(key.len(), 32);
    let (mut x0, mut x1, mut x2, mut x3) =
        constants.unwrap_or((0x61707865, 0x3320646e, 0x79622d32, 0x6b206574));
    let (
        mut x4,
        mut x5,
        mut x6,
        mut x7,
        mut x8,
        mut x9,
        mut x10,
        mut x11,
        mut x12,
        mut x13,
        mut x14,
        mut x15,
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

    for _ in 0..10 {
        chacha20_quarterround(&mut x0, &mut x4, &mut x8, &mut x12);
        chacha20_quarterround(&mut x1, &mut x5, &mut x9, &mut x13);
        chacha20_quarterround(&mut x2, &mut x6, &mut x10, &mut x14);
        chacha20_quarterround(&mut x3, &mut x7, &mut x11, &mut x15);
        chacha20_quarterround(&mut x0, &mut x5, &mut x10, &mut x15);
        chacha20_quarterround(&mut x1, &mut x6, &mut x11, &mut x12);
        chacha20_quarterround(&mut x2, &mut x7, &mut x8, &mut x13);
        chacha20_quarterround(&mut x3, &mut x4, &mut x9, &mut x14);
    }

    output[0..4].copy_from_slice(&x0.to_le_bytes());
    output[4..8].copy_from_slice(&x1.to_le_bytes());
    output[8..12].copy_from_slice(&x2.to_le_bytes());
    output[12..16].copy_from_slice(&x3.to_le_bytes());
    output[16..20].copy_from_slice(&x12.to_le_bytes());
    output[20..24].copy_from_slice(&x13.to_le_bytes());
    output[24..28].copy_from_slice(&x14.to_le_bytes());
    output[28..32].copy_from_slice(&x15.to_le_bytes());
}

/// Checks if a given point is on the Ed25519 curve.
///
/// This function determines if a given point is a valid point on the Ed25519
/// curve that can be safely used for cryptographic operations.
///
/// # Security Note
///
/// This implementation uses `curve25519-dalek` for validation and is stricter
/// than libsodium's `crypto_core_ed25519_is_valid_point`. Specifically, it may
/// reject certain points, such as small-order points (e.g., the point
/// represented by `[1, 0, ..., 0]`), which libsodium might accept. While
/// libsodium's behavior provides compatibility, using points rejected by this
/// function can lead to security vulnerabilities in certain protocols. Relying
/// on this stricter check is generally recommended for new applications.
///
/// By default, this function enforces canonical encoding by requiring the high
/// bit of the last byte to be 0. If you're working with Ed25519 keys generated
/// by [`crypto_sign_keypair`](`crate::classic::crypto_sign::crypto_sign_keypair`)
/// that might have the high bit set, you should use
/// [`crypto_core_ed25519_is_valid_point_relaxed`] instead.
///
/// # Example
///
/// ```
/// use dryoc::classic::crypto_core::{
///     Ed25519Point, crypto_core_ed25519_is_valid_point,
///     crypto_core_ed25519_is_valid_point_relaxed,
/// };
/// use dryoc::classic::crypto_sign::crypto_sign_keypair;
///
/// // Get a valid Ed25519 public key (valid point)
/// let (pk, _) = crypto_sign_keypair();
///
/// // For keys from crypto_sign_keypair(), use the relaxed validation
/// // as they may have the high bit set
/// assert!(crypto_core_ed25519_is_valid_point_relaxed(&pk));
///
/// // Strict validation for a manually constructed point
/// let mut invalid_point = [0u8; 32];
/// invalid_point[31] = 0x80; // Set high bit, making it invalid
/// assert!(!crypto_core_ed25519_is_valid_point(&invalid_point));
/// ```
///
/// Not fully compatible with libsodium's `crypto_core_ed25519_is_valid_point`
/// due to stricter checks.
pub fn crypto_core_ed25519_is_valid_point(p: &Ed25519Point) -> bool {
    crypto_core_ed25519_is_valid_point_internal(p, false)
}

/// Version of [`crypto_core_ed25519_is_valid_point`] that optionally ignores
/// the high bit check.
///
/// This is particularly useful when validating Ed25519 public keys generated by
/// [`crypto_sign_keypair`](`crate::classic::crypto_sign::crypto_sign_keypair`),
/// which may have the high bit set.
pub fn crypto_core_ed25519_is_valid_point_relaxed(p: &Ed25519Point) -> bool {
    crypto_core_ed25519_is_valid_point_internal(p, true)
}

/// Internal implementation for point validation that can optionally ignore the
/// high bit check.
fn crypto_core_ed25519_is_valid_point_internal(p: &Ed25519Point, ignore_high_bit: bool) -> bool {
    // Check 1: Canonical encoding. The high bit of the last byte must be 0, unless
    // ignore_high_bit is true.
    let last_byte = p[CRYPTO_CORE_ED25519_BYTES - 1];
    if !ignore_high_bit && last_byte & 0x80 != 0 {
        return false;
    }

    // Check 2: Reject the all-zero point, which is invalid.
    const ZERO_POINT: Ed25519Point = [0u8; CRYPTO_CORE_ED25519_BYTES];
    if p == &ZERO_POINT {
        return false;
    }

    // Check 3: Reject the identity element ([1, 0, ..., 0]) which is a small-order
    // point.
    const SMALL_ORDER_POINT_IDENTITY: Ed25519Point = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    if p == &SMALL_ORDER_POINT_IDENTITY {
        return false;
    }

    // Check 4: Use curve25519-dalek decompression for point-on-curve check and
    // reject points with a torsion component (not in the main subgroup).
    match CompressedEdwardsY::from_slice(p) {
        Ok(compressed) => match compressed.decompress() {
            Some(point) => point.is_torsion_free(),
            None => false,
        },
        Err(_) => false, // Should not happen if length is correct, but handle defensively.
    }
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
        constants.unwrap_or((0x61707865, 0x3320646e, 0x79622d32, 0x6b206574));
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
    use super::*;
    use crate::classic::crypto_box::*;
    use crate::classic::crypto_sign::crypto_sign_keypair;
    use crate::keypair::{KeyPair, PublicKey, SecretKey};

    #[test]
    fn test_crypto_scalarmult_base() {
        use base64::Engine as _;
        use base64::engine::general_purpose;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{Scalar, scalarmult_base};

            let (pk, sk) = crypto_box_keypair();

            let mut public_key = [0u8; CRYPTO_SCALARMULT_BYTES];
            crypto_scalarmult_base(&mut public_key, &sk);

            assert_eq!(&pk, &public_key);

            let ge = scalarmult_base(&Scalar::from_slice(&sk).unwrap());

            assert_eq!(
                general_purpose::STANDARD.encode(ge.as_ref()),
                general_purpose::STANDARD.encode(public_key)
            );
        }
    }

    #[test]
    fn test_crypto_scalarmult() {
        use base64::Engine as _;
        use base64::engine::general_purpose;
        for _ in 0..20 {
            use sodiumoxide::crypto::scalarmult::curve25519::{GroupElement, Scalar, scalarmult};

            let (_our_pk, our_sk) = crypto_box_keypair();
            let (their_pk, _their_sk) = crypto_box_keypair();

            let mut shared_secret = [0u8; CRYPTO_SCALARMULT_BYTES];
            crypto_scalarmult(&mut shared_secret, &our_sk, &their_pk);

            let ge = scalarmult(
                &Scalar::from_slice(&our_sk).unwrap(),
                &GroupElement::from_slice(&their_pk).unwrap(),
            )
            .expect("scalarmult failed");

            assert_eq!(
                general_purpose::STANDARD.encode(ge.as_ref()),
                general_purpose::STANDARD.encode(shared_secret)
            );
        }
    }

    #[test]
    fn test_crypto_core_hchacha20() {
        use base64::Engine as _;
        use base64::engine::general_purpose;
        use libsodium_sys::crypto_core_hchacha20 as so_crypto_core_hchacha20;

        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let mut key = [0u8; 32];
            let mut data = [0u8; 16];
            copy_randombytes(&mut key);
            copy_randombytes(&mut data);

            let mut out = [0u8; CRYPTO_CORE_HCHACHA20_OUTPUTBYTES];
            crypto_core_hchacha20(&mut out, &data, &key, None);

            let mut so_out = [0u8; 32];
            unsafe {
                let ret = so_crypto_core_hchacha20(
                    so_out.as_mut_ptr(),
                    data.as_ptr(),
                    key.as_ptr(),
                    std::ptr::null(),
                );
                assert_eq!(ret, 0);
            }
            assert_eq!(
                general_purpose::STANDARD.encode(out),
                general_purpose::STANDARD.encode(so_out)
            );
        }
    }

    #[test]
    fn test_crypto_core_hsalsa20() {
        use base64::Engine as _;
        use base64::engine::general_purpose;
        use libsodium_sys::crypto_core_hsalsa20 as so_crypto_core_hsalsa20;

        use crate::rng::copy_randombytes;

        for _ in 0..10 {
            let mut key = [0u8; CRYPTO_CORE_HSALSA20_KEYBYTES];
            let mut data = [0u8; CRYPTO_CORE_HSALSA20_INPUTBYTES];
            copy_randombytes(&mut key);
            copy_randombytes(&mut data);

            let mut out = [0u8; CRYPTO_CORE_HSALSA20_OUTPUTBYTES];
            crypto_core_hsalsa20(&mut out, &data, &key, None);

            let mut so_out = [0u8; 32];
            unsafe {
                let ret = so_crypto_core_hsalsa20(
                    so_out.as_mut_ptr(),
                    data.as_ptr(),
                    key.as_ptr(),
                    std::ptr::null(),
                );
                assert_eq!(ret, 0);
            }
            assert_eq!(
                general_purpose::STANDARD.encode(out),
                general_purpose::STANDARD.encode(so_out)
            );
        }
    }

    #[test]
    fn test_crypto_core_ed25519_is_valid_point() {
        // Test with a known valid public key (from one of the crypto_sign test vectors)
        // This point is on the curve and correctly encoded.
        let valid_pk = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        assert!(
            crypto_core_ed25519_is_valid_point(&valid_pk),
            "Known valid Ed25519 public key should be considered valid"
        );

        // Test a point with the high bit set (invalid compressed format)
        // Standard Ed25519 compression requires the high bit of the last byte to be 0.
        let mut invalid_point_high_bit = [0u8; CRYPTO_CORE_ED25519_BYTES];
        invalid_point_high_bit[31] = 0x80; // Set high bit, making it invalid
        assert!(
            !crypto_core_ed25519_is_valid_point(&invalid_point_high_bit),
            "Point with high bit set in last byte should be invalid"
        );

        // Test the identity element (0, 1), which is a valid point.
        // Its compressed form is [1, 0, ..., 0].
        // While mathematically valid, this is a small-order point that can cause
        // security issues in certain cryptographic protocols, such as enabling
        // invalid curve attacks. Stricter implementations (like curve25519-dalek)
        // reject small-order points for this reason, whereas Libsodium accepts them.
        let small_order_point_identity = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert!(
            !crypto_core_ed25519_is_valid_point(&small_order_point_identity),
            "Small-order point (identity element) should be rejected by stricter validation"
        );

        // Test torsion points and mixed-order points to ensure we reject anything
        // outside the main subgroup.
        use curve25519_dalek::traits::IsIdentity;

        let torsion_point = curve25519_dalek::constants::EIGHT_TORSION
            .iter()
            .find(|point| {
                let torsion_bytes = point.compress().to_bytes();
                let mixed_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT + *point;
                let mixed_bytes = mixed_point.compress().to_bytes();
                torsion_bytes[31] & 0x80 == 0
                    && mixed_bytes[31] & 0x80 == 0
                    && !point.is_identity()
                    && !mixed_point.is_torsion_free()
            })
            .copied()
            .expect("expected a non-identity torsion point with canonical encoding");

        let torsion_bytes = torsion_point.compress().to_bytes();
        assert!(
            !crypto_core_ed25519_is_valid_point(&torsion_bytes),
            "Torsion point should be rejected"
        );
        assert!(
            !crypto_core_ed25519_is_valid_point_relaxed(&torsion_bytes),
            "Torsion point should be rejected even with relaxed validation"
        );

        let mixed_bytes =
            (curve25519_dalek::constants::ED25519_BASEPOINT_POINT + torsion_point)
                .compress()
                .to_bytes();
        assert!(
            !crypto_core_ed25519_is_valid_point(&mixed_bytes),
            "Mixed-order point should be rejected"
        );
        assert!(
            !crypto_core_ed25519_is_valid_point_relaxed(&mixed_bytes),
            "Mixed-order point should be rejected even with relaxed validation"
        );

        // Test a point that is not on the curve (but is canonically encoded)
        // Example: A point generated randomly is unlikely to be on the curve.
        // We expect this to be rejected by the decompression check.
        let mut point_not_on_curve = [0u8; CRYPTO_CORE_ED25519_BYTES];
        // Fill with some non-zero value that's unlikely to form a valid point
        // but is canonically encoded (last byte < 128)
        point_not_on_curve[0] = 2; // Example modification
        assert!(
            !crypto_core_ed25519_is_valid_point(&point_not_on_curve),
            "Point not on the curve should be invalid"
        );

        // Test the zero point [0, ..., 0], which is invalid encoding.
        let zero_point = [0u8; CRYPTO_CORE_ED25519_BYTES];
        assert!(
            !crypto_core_ed25519_is_valid_point(&zero_point),
            "Zero point represents invalid encoding"
        );
    }

    #[test]
    fn test_keypair_on_curve() {
        // Run multiple attempts to ensure we catch any potential issues
        let iterations = 25;
        let mut strict_failures = 0;
        let mut relaxed_failures = 0;

        println!(
            "\n=== Testing Ed25519 key validation across {} iterations ===",
            iterations
        );

        for i in 0..iterations {
            // Generate an Ed25519 keypair
            let (ed25519_pk, _) = crypto_sign_keypair();

            // Check with strict validation (may fail due to high bit)
            let strict_valid = crypto_core_ed25519_is_valid_point(&ed25519_pk);

            // Check with relaxed validation (should always pass for generated keys)
            let relaxed_valid = crypto_core_ed25519_is_valid_point_relaxed(&ed25519_pk);

            if !strict_valid {
                strict_failures += 1;
                // Only check the reason when strict validation fails
                let high_bit_set = ed25519_pk[CRYPTO_CORE_ED25519_BYTES - 1] & 0x80 != 0;
                println!("Iteration {}: Ed25519 key strict validation failed:", i);
                println!("  High bit set: {}", high_bit_set);
            }

            if !relaxed_valid {
                relaxed_failures += 1;
                // This shouldn't happen for properly generated keys
                println!(
                    "ERROR: Iteration {}: Ed25519 key failed relaxed validation",
                    i
                );

                // Check all conditions to see why it failed
                const ZERO_POINT: Ed25519Point = [0u8; CRYPTO_CORE_ED25519_BYTES];
                let is_zero = ed25519_pk == ZERO_POINT;

                const SMALL_ORDER_POINT_IDENTITY: Ed25519Point = [
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ];
                let is_identity = ed25519_pk == SMALL_ORDER_POINT_IDENTITY;

                let on_curve = match CompressedEdwardsY::from_slice(&ed25519_pk) {
                    Ok(compressed) => compressed.decompress().is_some(),
                    Err(_) => false,
                };

                println!("  Zero point: {}", is_zero);
                println!("  Identity element: {}", is_identity);
                println!("  On curve: {}", on_curve);
                println!("  Key: {:?}", ed25519_pk);
            }

            // We should always be able to verify keys with relaxed validation
            assert!(
                relaxed_valid,
                "Generated Ed25519 key failed relaxed validation"
            );
        }

        println!(
            "\nSummary: {} of {} Ed25519 keys failed strict validation",
            strict_failures, iterations
        );
        println!(
            "Summary: {} of {} Ed25519 keys failed relaxed validation",
            relaxed_failures, iterations
        );

        // X25519 keys should be valid with standard validation (they're generated
        // clamped)
        println!("\n=== Testing X25519 key validation ===");
        let (x25519_pk, _) = crypto_box_keypair();

        assert!(
            KeyPair::<PublicKey, SecretKey>::is_valid_public_key(&x25519_pk),
            "X25519 public key should be valid according to X25519 rules"
        );

        println!("X25519 key validation: Success");
    }
}

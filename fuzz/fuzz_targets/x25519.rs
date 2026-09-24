//! X25519 edge-case inputs shared by the fuzz targets that exercise X25519,
//! pulled in per target with `#[path]` like `common.rs`.
use curve25519_dalek::constants::EIGHT_TORSION;

/// `p + k` for `p = 2^255 - 19` and a small `k`, little-endian.
pub fn p_plus(k: i8) -> [u8; 32] {
    let mut bytes = [0xffu8; 32];
    bytes[0] = (0xedi16 + i16::from(k)) as u8;
    bytes[31] = 0x7f;
    bytes
}

/// Every X25519 input libsodium blacklists: the Montgomery `u` of each
/// Ed25519 torsion point (0, 1 and the two order-8 values, from dalek) and the
/// noncanonical `p - 1`, `p`, `p + 1` encodings, each with and without bit
/// 255.
pub fn low_order_points() -> Vec<[u8; 32]> {
    let mut points: Vec<[u8; 32]> = EIGHT_TORSION
        .iter()
        .map(|point| point.to_montgomery().to_bytes())
        .collect();
    points.extend([p_plus(-1), p_plus(0), p_plus(1)]);
    points.sort_unstable();
    points.dedup();
    let flipped: Vec<[u8; 32]> = points
        .iter()
        .map(|point| {
            let mut flipped = *point;
            flipped[31] ^= 0x80;
            flipped
        })
        .collect();
    points.extend(flipped);
    points
}

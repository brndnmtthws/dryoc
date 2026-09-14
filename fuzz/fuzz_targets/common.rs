//! Input-splitting helpers shared by the fuzz targets. Each target is its own
//! `[[bin]]`, so this file is pulled in per target with `#[path]`.

/// Takes the next `N` bytes of `data` as a fixed-size array, zero-padding when
/// the input runs out, and advances `data` past them.
pub fn fill<const N: usize>(data: &mut &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = out.len().min(data.len());
    out[..n].copy_from_slice(&data[..n]);
    *data = &data[n..];
    out
}

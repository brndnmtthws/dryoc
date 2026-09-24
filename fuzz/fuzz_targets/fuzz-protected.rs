#![no_main]
//! Protected memory against a plain `Vec<u8>` model: `HeapBytes` resizing,
//! cloning and indexing; locked/unlocked and read-write/read-only/no-access
//! typestate transitions, explicit zeroization in every protect mode, and the
//! fixed-size `HeapByteArray` conversions. Locking may legitimately be refused
//! by host limits, so a refused `mlock` ends the sequence instead of being
//! reported as an input-dependent crash; protection changes and unlocking of
//! an existing allocation have no such excuse and must succeed.

#[cfg(any(unix, windows))]
use dryoc::protected::*;
use libfuzzer_sys::fuzz_target;
#[cfg(any(unix, windows))]
use zeroize::Zeroize;

#[cfg(any(unix, windows))]
const MAX_HEAP_BYTES_LEN: usize = 32 * 1024;
#[cfg(any(unix, windows))]
const MAX_LOCKED_LEN: usize = 4096;
#[cfg(any(unix, windows))]
const MAX_OPS: usize = 64;

#[cfg(any(unix, windows))]
fn take_u16(data: &mut &[u8]) -> usize {
    let lo = data.first().copied().unwrap_or(0);
    let hi = data.get(1).copied().unwrap_or(0);
    *data = data.get(2..).unwrap_or_default();
    u16::from_le_bytes([lo, hi]) as usize
}

#[cfg(any(unix, windows))]
fn exercise_heapbytearray(model: &[u8], byte: u8) {
    let mut array = [0u8; 32];
    let len = array.len().min(model.len());
    array[..len].copy_from_slice(&model[..len]);
    let idx = usize::from(byte) % array.len();

    let mut protected = HeapByteArray::<32>::from(&array);
    assert_eq!(protected.as_array(), &array);
    assert_eq!(protected.as_slice(), &array);

    protected.as_mut_array()[idx] ^= byte;
    let mut expected = array;
    expected[idx] ^= byte;
    assert_eq!(protected.as_array(), &expected);

    // Fixed-size locked conversion takes exactly LENGTH bytes.
    let prefix = &model[..model.len().min(33)];
    if prefix.len() == 32 {
        let Ok(locked) = HeapByteArray::<32>::from_slice_into_locked(prefix) else {
            return;
        };
        assert_eq!(locked.as_slice(), prefix);
        let readonly = locked.mprotect_readonly().expect("mprotect_readonly");
        assert_eq!(readonly.as_slice(), prefix);
    } else {
        assert!(HeapByteArray::<32>::from_slice_into_locked(prefix).is_err());
    }

    // Locking the array and reading it back through the read-only view.
    let Ok(locked) = protected.mlock() else {
        return;
    };
    assert_eq!(locked.as_slice(), &expected);
    let readonly = locked.mprotect_readonly().expect("mprotect_readonly");
    assert_eq!(readonly.as_array(), &expected);
}

/// Walks a copy of `model` through the protected-memory typestate transitions.
/// `raw_len` chooses the resized length (anywhere in `0..=MAX_LOCKED_LEN`, so
/// across the page boundary) and `byte` the fill byte.
#[cfg(any(unix, windows))]
fn exercise_locked(model: &[u8], raw_len: usize, byte: u8) {
    if model.len() > MAX_LOCKED_LEN {
        return;
    }
    let new_len = raw_len % (MAX_LOCKED_LEN + 1);

    // Lock an already-sized value so lock refusal remains a fallible operation;
    // locked `Clone` and `resize` allocate internally and panic on host limits.
    let Ok(locked) = HeapBytes::from(model).mlock() else {
        return;
    };
    assert_eq!(locked.as_slice(), model);

    // Locked, read-only. Explicit zeroization wipes it and restores its
    // protection, keeping the length.
    let mut readonly = locked.mprotect_readonly().expect("mprotect_readonly");
    assert_eq!(readonly.as_slice(), model);
    readonly.zeroize();
    assert_eq!(readonly.len(), model.len());
    assert!(readonly.as_slice().iter().all(|&b| b == 0));
    let mut readwrite = readonly.mprotect_readwrite().expect("mprotect_readwrite");
    readwrite.as_mut_slice().copy_from_slice(model);
    assert_eq!(readwrite.as_slice(), model);

    // Unlocked: no-access round trips back to read-only and read-write with
    // the bytes intact, and zeroization while inaccessible still wipes.
    let unlocked = readwrite.munlock().expect("munlock");
    assert_eq!(unlocked.as_slice(), model);
    let noaccess = unlocked.mprotect_noaccess().expect("mprotect_noaccess");
    let readonly = noaccess.mprotect_readonly().expect("mprotect_readonly");
    assert_eq!(readonly.as_slice(), model);
    let noaccess = readonly.mprotect_noaccess().expect("mprotect_noaccess");
    let readwrite = noaccess.mprotect_readwrite().expect("mprotect_readwrite");
    assert_eq!(readwrite.as_slice(), model);
    let mut noaccess = readwrite.mprotect_noaccess().expect("mprotect_noaccess");
    noaccess.zeroize();
    let mut readwrite = noaccess.mprotect_readwrite().expect("mprotect_readwrite");
    assert_eq!(readwrite.len(), model.len());
    assert!(readwrite.as_slice().iter().all(|&b| b == 0));

    // Unlocked read-write is resizable and can be locked again. Explicit
    // zeroization of both read-write states is plain.
    readwrite.resize(new_len, byte);
    assert_eq!(readwrite.len(), new_len);
    assert!(
        readwrite.as_slice()[model.len().min(new_len)..]
            .iter()
            .all(|&b| b == byte)
    );
    let Ok(mut relocked) = readwrite.mlock() else {
        return;
    };
    relocked.zeroize();
    assert_eq!(relocked.len(), new_len);
    assert!(relocked.as_slice().iter().all(|&b| b == 0));
}

#[cfg(any(unix, windows))]
fn exercise(data: &[u8]) {
    let mut cursor = data;
    let initial_len = take_u16(&mut cursor)
        .min(MAX_HEAP_BYTES_LEN)
        .min(cursor.len());
    let initial = cursor[..initial_len].to_vec();
    cursor = &cursor[initial_len..];

    let mut bytes = HeapBytes::from(initial.as_slice());
    let mut model = initial;
    assert_eq!(bytes.as_slice(), model.as_slice());

    for chunk in cursor.chunks(4).take(MAX_OPS) {
        let op = chunk.first().copied().unwrap_or(0) % 5;
        let arg = chunk.get(1).copied().unwrap_or(0);
        let wide_arg = usize::from(u16::from_le_bytes([
            arg,
            chunk.get(2).copied().unwrap_or(0),
        ]));
        let value = chunk.get(3).copied().unwrap_or(0);

        match op {
            0 => {
                let new_len = wide_arg % (MAX_HEAP_BYTES_LEN + 1);
                bytes.resize(new_len, value);
                model.resize(new_len, value);
                assert_eq!(bytes.as_slice(), model.as_slice());
            }
            1 => {
                let mut cloned = bytes.clone();
                assert_eq!(cloned, bytes);
                assert_eq!(cloned.as_slice(), model.as_slice());
                if !model.is_empty() {
                    let idx = usize::from(arg) % model.len();
                    cloned[idx] = !model[idx];
                    assert_eq!(bytes.as_slice(), model.as_slice());
                    assert_ne!(cloned, bytes);
                }
            }
            2 => {
                if !model.is_empty() {
                    let idx = wide_arg % model.len();
                    bytes[idx] = value;
                    model[idx] = value;
                    assert_eq!(bytes.as_slice(), model.as_slice());
                }
            }
            3 => exercise_locked(model.as_slice(), wide_arg, value),
            _ => exercise_heapbytearray(model.as_slice(), value),
        }
    }

    // Explicit zeroization of the plain heap value keeps its length.
    bytes.zeroize();
    assert_eq!(bytes.len(), model.len());
    assert!(bytes.as_slice().iter().all(|&b| b == 0));
}

fuzz_target!(|data: &[u8]| {
    #[cfg(any(unix, windows))]
    exercise(data);

    #[cfg(not(any(unix, windows)))]
    let _ = data;
});

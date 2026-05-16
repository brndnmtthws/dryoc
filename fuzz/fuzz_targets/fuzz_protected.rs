#![no_main]

#[cfg(any(unix, windows))]
use dryoc::protected::*;
use libfuzzer_sys::fuzz_target;

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
}

#[cfg(any(unix, windows))]
fn exercise_locked(model: &[u8]) {
    if model.len() > MAX_LOCKED_LEN {
        return;
    }

    let Ok(locked) = HeapBytes::from_slice_into_locked(model) else {
        return;
    };
    assert_eq!(locked.as_slice(), model);

    let Ok(readonly) = locked.mprotect_readonly() else {
        return;
    };
    assert_eq!(readonly.as_slice(), model);

    let Ok(readwrite) = readonly.mprotect_readwrite() else {
        return;
    };
    assert_eq!(readwrite.as_slice(), model);

    let Ok(unlocked) = readwrite.munlock() else {
        return;
    };
    assert_eq!(unlocked.as_slice(), model);
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
        let value = chunk.get(3).copied().unwrap_or(0);

        match op {
            0 => {
                let raw_len =
                    u16::from_le_bytes([arg, chunk.get(2).copied().unwrap_or(0)]) as usize;
                let new_len = raw_len % (MAX_HEAP_BYTES_LEN + 1);
                bytes.resize(new_len, value);
                model.resize(new_len, value);
                assert_eq!(bytes.as_slice(), model.as_slice());
            }
            1 => {
                let cloned = bytes.clone();
                assert_eq!(cloned, bytes);
                assert_eq!(cloned.as_slice(), model.as_slice());
            }
            2 => {
                if !model.is_empty() {
                    let raw_idx =
                        u16::from_le_bytes([arg, chunk.get(2).copied().unwrap_or(0)]) as usize;
                    let idx = raw_idx % model.len();
                    bytes[idx] = value;
                    model[idx] = value;
                    assert_eq!(bytes.as_slice(), model.as_slice());
                }
            }
            3 => exercise_locked(model.as_slice()),
            _ => exercise_heapbytearray(model.as_slice(), value),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    #[cfg(any(unix, windows))]
    exercise(data);

    #[cfg(not(any(unix, windows)))]
    let _ = data;
});

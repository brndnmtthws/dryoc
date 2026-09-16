use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::*;

/// Serializes a byte container with [`Serializer::serialize_bytes`].
macro_rules! impl_serialize_bytes {
    ([$($generics:tt)*] $ty:ty) => {
        impl<$($generics)*> Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(self.as_slice())
            }
        }
    };
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(self.as_slice())
            }
        }
    };
}

/// Implements [`Deserialize`] for a fixed-size byte container, accepting a
/// byte string or a sequence of exactly `LENGTH` bytes.
///
/// * `$ty`: the container type, mentioning `LENGTH`.
/// * `$new`: builds an empty `$ty` in `visit_seq`; may fail with `A::Error` for
///   locked allocation.
/// * `$from_slice`: converts the length-checked `v: &[u8]` into `$ty` in
///   `visit_bytes`; may fail with `E`.
macro_rules! impl_deserialize_fixed {
    ($ty:ty, $new:expr, $from_slice:expr) => {
        impl<'de, const LENGTH: usize> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct ByteArrayVisitor<const LENGTH: usize>;

                impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
                    type Value = $ty;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "exactly {LENGTH} bytes")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut arr = $new;
                        let mut idx: usize = 0;

                        while let Some(elem) = seq.next_element()? {
                            if idx >= LENGTH {
                                return Err(Error::invalid_length(idx + 1, &self));
                            }
                            arr[idx] = elem;
                            idx += 1;
                        }

                        if idx != LENGTH {
                            return Err(Error::invalid_length(idx, &self));
                        }

                        Ok(arr)
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        if v.len() != LENGTH {
                            return Err(Error::invalid_length(v.len(), &self));
                        }
                        $from_slice(v)
                    }
                }

                deserializer.deserialize_bytes(ByteArrayVisitor::<LENGTH>)
            }
        }
    };
}

/// Implements [`Deserialize`] for a variable-length byte container, accepting
/// a byte string or a sequence of bytes. Takes the same three arguments as
/// [`impl_deserialize_fixed`], minus the length checks.
// Only the `protected` module below uses this macro.
#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
macro_rules! impl_deserialize_bytes {
    ($ty:ty, $new:expr, $from_slice:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct BytesVisitor;

                impl<'de> Visitor<'de> for BytesVisitor {
                    type Value = $ty;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "bytes")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let mut arr = $new;
                        let mut idx: usize = 0;
                        let size_hint = seq.size_hint().unwrap_or(1);
                        arr.resize(size_hint, 0);

                        while let Some(elem) = seq.next_element()? {
                            if idx >= arr.len() {
                                arr.resize(idx + 1, 0);
                            }
                            arr[idx] = elem;
                            idx += 1;
                        }

                        arr.resize(idx, 0);

                        Ok(arr)
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        $from_slice(v)
                    }
                }

                deserializer.deserialize_bytes(BytesVisitor)
            }
        }
    };
}

impl_serialize_bytes!([const LENGTH: usize] StackByteArray<LENGTH>);

impl_deserialize_fixed!(
    StackByteArray<LENGTH>,
    StackByteArray::<LENGTH>::new(),
    |v| {
        let mut arr = StackByteArray::<LENGTH>::new();
        arr.copy_from_slice(v);
        Ok(arr)
    }
);

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
mod protected {
    use super::*;
    use crate::protected::*;

    impl_serialize_bytes!([const LENGTH: usize] HeapByteArray<LENGTH>);

    impl_serialize_bytes!([const LENGTH: usize] Locked<HeapByteArray<LENGTH>>);

    impl_deserialize_fixed!(
        HeapByteArray<LENGTH>,
        HeapByteArray::<LENGTH>::default(),
        |v| HeapByteArray::<LENGTH>::try_from(v).map_err(E::custom)
    );

    impl_serialize_bytes!(HeapBytes);

    impl_serialize_bytes!(LockedBytes);

    impl_serialize_bytes!(LockedRO<HeapBytes>);

    impl_deserialize_bytes!(HeapBytes, HeapBytes::default(), |v| Ok(HeapBytes::from(v)));

    impl_deserialize_bytes!(
        LockedBytes,
        HeapBytes::new_locked().map_err(A::Error::custom)?,
        |v| HeapBytes::from_slice_into_locked(v).map_err(E::custom)
    );

    impl_deserialize_fixed!(
        Locked<HeapByteArray<LENGTH>>,
        HeapByteArray::<LENGTH>::new_locked().map_err(A::Error::custom)?,
        |v| HeapByteArray::<LENGTH>::from_slice_into_locked(v).map_err(E::custom)
    );
}

#[cfg(test)]
mod tests {
    use serde::de::value::{BytesDeserializer, Error as ValueError, SeqDeserializer};

    use super::*;

    /// Iterator whose `size_hint` is wrong, so `visit_seq` cannot rely on it
    /// for the final length.
    struct LyingHint<I> {
        iter: I,
        hint: usize,
    }

    impl<I: Iterator> Iterator for LyingHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<I::Item> {
            self.iter.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.hint, Some(self.hint))
        }
    }

    /// Drives the `visit_bytes` path with a byte string.
    fn from_bytes<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, ValueError> {
        T::deserialize(BytesDeserializer::<ValueError>::new(bytes))
    }

    /// Drives the `visit_seq` path with a sequence claiming `hint` elements.
    fn from_seq<T: for<'de> Deserialize<'de>>(bytes: &[u8], hint: usize) -> Result<T, ValueError> {
        let iter = LyingHint {
            iter: bytes.iter().copied(),
            hint,
        };
        T::deserialize(SeqDeserializer::<_, ValueError>::new(iter))
    }

    /// A fixed-size container accepts exactly `LENGTH` bytes from either
    /// input form and rejects one fewer or one more.
    fn check_fixed<T: for<'de> Deserialize<'de> + Bytes>() {
        let data = [7u8, 8, 9];

        assert_eq!(
            from_bytes::<T>(&data).expect("exact bytes").as_slice(),
            &data
        );
        assert!(from_bytes::<T>(&data[..2]).is_err());
        assert!(from_bytes::<T>(&[7, 8, 9, 10]).is_err());
        assert!(from_bytes::<T>(&[]).is_err());

        for hint in [0, 3, 100] {
            assert_eq!(
                from_seq::<T>(&data, hint).expect("exact seq").as_slice(),
                &data,
                "hint {hint}"
            );
            assert!(from_seq::<T>(&data[..2], hint).is_err(), "hint {hint}");
            assert!(from_seq::<T>(&[7, 8, 9, 10], hint).is_err(), "hint {hint}");
        }
    }

    /// A variable-size container accepts any length from either input form,
    /// regardless of what the sequence claims about its length.
    #[cfg(all(feature = "protected", any(unix, windows)))]
    fn check_variable<T: for<'de> Deserialize<'de> + Bytes>() {
        for len in [0usize, 1, 5, 17] {
            let data: Vec<u8> = (1..=len as u8).collect();
            assert_eq!(from_bytes::<T>(&data).expect("bytes").as_slice(), &data);
            for hint in [0, 1, len, 100] {
                assert_eq!(
                    from_seq::<T>(&data, hint).expect("seq").as_slice(),
                    &data,
                    "len {len} hint {hint}"
                );
            }
        }
    }

    #[test]
    fn stack_byte_array_deserializes_only_exact_length() {
        check_fixed::<StackByteArray<3>>();
    }

    #[test]
    fn stack_byte_array_json_uses_byte_array_form() {
        let array = StackByteArray::from([1u8, 2, 3]);
        let json = serde_json::to_string(&array).expect("serialize");
        assert_eq!(json, "[1,2,3]");

        let decoded: StackByteArray<3> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, array);

        // A JSON string reaches the visitor as a byte string.
        let from_string: StackByteArray<3> = serde_json::from_str("\"abc\"").expect("string");
        assert_eq!(from_string.as_slice(), b"abc");
        assert!(serde_json::from_str::<StackByteArray<3>>("\"ab\"").is_err());
        assert!(serde_json::from_str::<StackByteArray<3>>("[1,2]").is_err());
        assert!(serde_json::from_str::<StackByteArray<3>>("[1,2,3,4]").is_err());
        assert!(serde_json::from_str::<StackByteArray<3>>("null").is_err());
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    mod protected {
        use super::*;
        use crate::protected::test_util::can_lock_pages;
        use crate::protected::*;

        #[test]
        fn fixed_protected_containers_deserialize_only_exact_length() {
            check_fixed::<HeapByteArray<3>>();
            if can_lock_pages(1) {
                check_fixed::<Locked<HeapByteArray<3>>>();
            }
        }

        #[test]
        fn variable_protected_containers_deserialize_any_length() {
            check_variable::<HeapBytes>();
            // A locked sequence grows by locked `resize`, which holds the old
            // and the new page at once.
            if can_lock_pages(2) {
                check_variable::<LockedBytes>();
            }
        }

        #[test]
        fn locked_deserialization_yields_locked_values() {
            if !can_lock_pages(1) {
                return;
            }
            let locked: LockedBytes = from_bytes(&[1, 2, 3]).expect("locked bytes");
            let unlocked = locked.munlock().expect("munlock");
            assert_eq!(unlocked.as_slice(), &[1, 2, 3]);

            let locked: Locked<HeapByteArray<3>> = from_seq(&[4, 5, 6], 0).expect("locked array");
            let unlocked = locked.munlock().expect("munlock");
            assert_eq!(unlocked.as_slice(), &[4, 5, 6]);
        }

        #[test]
        fn protected_containers_serialize_as_their_bytes() {
            let data = [1u8, 2, 3];
            let expected = serde_json::to_string(&data).expect("serialize array");

            let heap = HeapBytes::from(&data[..]);
            assert_eq!(serde_json::to_string(&heap).expect("heap"), expected);

            let array = HeapByteArray::<3>::from(&data);
            assert_eq!(serde_json::to_string(&array).expect("array"), expected);

            assert_eq!(
                serde_json::to_string(&HeapBytes::default()).expect("empty"),
                "[]"
            );

            // Each locked form is released before the next is created, so
            // one lockable page suffices.
            if !can_lock_pages(1) {
                return;
            }
            {
                let locked = HeapBytes::from_slice_into_locked(&data).expect("locked");
                assert_eq!(serde_json::to_string(&locked).expect("locked"), expected);
            }
            {
                // `LockedRO<HeapBytes>` is serialize-only: there is no
                // `Deserialize` impl for it, so it must serialize exactly like
                // the unlocked, read-write form it was created from.
                let readonly = HeapBytes::from_slice_into_readonly_locked(&data).expect("readonly");
                assert_eq!(
                    serde_json::to_string(&readonly).expect("readonly"),
                    expected
                );
            }
            let locked_array = HeapByteArray::<3>::from_slice_into_locked(&data).expect("locked");
            assert_eq!(
                serde_json::to_string(&locked_array).expect("locked array"),
                expected
            );
        }
    }
}

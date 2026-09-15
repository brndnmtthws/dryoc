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

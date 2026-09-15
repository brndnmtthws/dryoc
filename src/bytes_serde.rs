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

impl_serialize_bytes!([const LENGTH: usize] StackByteArray<LENGTH>);

impl<'de, const LENGTH: usize> Deserialize<'de> for StackByteArray<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArrayVisitor<const LENGTH: usize>;

        impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
            type Value = StackByteArray<LENGTH>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "exactly {LENGTH} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = StackByteArray::<LENGTH>::new();
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
                let mut arr = StackByteArray::<LENGTH>::new();
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(ByteArrayVisitor::<LENGTH>)
    }
}

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
mod protected {
    use super::*;
    use crate::protected::*;

    impl_serialize_bytes!([const LENGTH: usize] HeapByteArray<LENGTH>);

    impl_serialize_bytes!([const LENGTH: usize] Locked<HeapByteArray<LENGTH>>);

    impl<'de, const LENGTH: usize> Deserialize<'de> for HeapByteArray<LENGTH> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ByteArrayVisitor<const LENGTH: usize>;

            impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
                type Value = HeapByteArray<LENGTH>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "exactly {LENGTH} bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = HeapByteArray::<LENGTH>::default();
                    let mut idx = 0;

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
                    HeapByteArray::<LENGTH>::try_from(v).map_err(E::custom)
                }
            }

            deserializer.deserialize_bytes(ByteArrayVisitor::<LENGTH>)
        }
    }

    impl_serialize_bytes!(HeapBytes);

    impl_serialize_bytes!(LockedBytes);

    impl_serialize_bytes!(LockedRO<HeapBytes>);

    impl<'de> Deserialize<'de> for HeapBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct BytesVisitor;

            impl<'de> Visitor<'de> for BytesVisitor {
                type Value = HeapBytes;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = HeapBytes::default();
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
                    Ok(HeapBytes::from(v))
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }

    impl<'de> Deserialize<'de> for LockedBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct BytesVisitor;

            impl<'de> Visitor<'de> for BytesVisitor {
                type Value = LockedBytes;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = HeapBytes::new_locked().map_err(A::Error::custom)?;
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
                    HeapBytes::from_slice_into_locked(v).map_err(E::custom)
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }

    impl<'de, const LENGTH: usize> Deserialize<'de> for Locked<HeapByteArray<LENGTH>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct BytesVisitor<const LENGTH: usize>;

            impl<'de, const LENGTH: usize> Visitor<'de> for BytesVisitor<LENGTH> {
                type Value = Locked<HeapByteArray<LENGTH>>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "exactly {LENGTH} bytes")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr =
                        HeapByteArray::<LENGTH>::new_locked().map_err(A::Error::custom)?;
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
                        Err(Error::invalid_length(v.len(), &self))
                    } else {
                        HeapByteArray::<LENGTH>::from_slice_into_locked(v).map_err(E::custom)
                    }
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

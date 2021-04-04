use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::*;

impl<const LENGTH: usize> Serialize for StackByteArray<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de, const LENGTH: usize> Deserialize<'de> for StackByteArray<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArrayVisitor<const LENGTH: usize>;

        impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
            type Value = StackByteArray<LENGTH>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = StackByteArray::<LENGTH>::new();
                let mut idx: usize = 0;

                while let Some(elem) = seq.next_element()? {
                    if idx < LENGTH {
                        arr[idx] = elem;
                        idx += 1;
                    } else {
                        break;
                    }
                }

                Ok(arr)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() != LENGTH {
                    return Err(Error::invalid_length(v.len(), &stringify!(LENGTH)));
                }
                let mut arr = StackByteArray::<LENGTH>::new();
                arr.copy_from_slice(v);
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(ByteArrayVisitor::<LENGTH>)
    }
}

#[cfg(any(feature = "nightly", doc))]
mod protected {
    use super::*;
    use crate::protected::*;

    impl<const LENGTH: usize> Serialize for HeapByteArray<LENGTH> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bytes(self.as_slice())
        }
    }

    impl Serialize for HeapBytes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bytes(self.as_slice())
        }
    }

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
                        if idx > arr.len() {
                            arr.resize(idx, 0);
                        }
                        arr[idx] = elem;
                        idx += 1;
                    }

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
}

#[cfg(any(feature = "nightly", doc))]
pub use protected::*;

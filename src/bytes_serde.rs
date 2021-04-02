#[cfg(feature = "base64")]
mod b64 {
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::types::{Bytes, StackByteArray};

    impl<const LENGTH: usize> Serialize for StackByteArray<LENGTH> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&base64::encode(self.as_slice()))
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
                    write!(formatter, "string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    if s.len() * 4 / 3 < LENGTH {
                        return Err(Error::invalid_length(s.len(), &stringify!(LENGTH)));
                    }
                    let mut arr = StackByteArray::<LENGTH>::new();
                    arr.copy_from_slice(
                        &base64::decode(s).map_err(|err| Error::custom(err.to_string()))?,
                    );
                    Ok(arr)
                }
            }

            deserializer.deserialize_str(ByteArrayVisitor::<LENGTH>)
        }
    }
    pub(crate) fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(key.as_ref()))
    }

    pub(crate) fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|string| base64::decode(string).map_err(|err| Error::custom(err.to_string())))
    }
}

#[cfg(feature = "base64")]
pub(crate) use b64::*;

#[cfg(not(feature = "base64"))]
mod no_b64 {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::types::{Bytes, StackByteArray};

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
                    write!(formatter, "sequence")
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
}

#[cfg(not(feature = "base64"))]
pub use no_b64::*;

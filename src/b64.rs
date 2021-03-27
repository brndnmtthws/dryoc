use crate::types::ByteArray;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}

pub(crate) fn vec_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(string).map_err(|err| Error::custom(err.to_string())))
}

pub(crate) fn bytearray_from_base64<'de, D, const LENGTH: usize>(
    deserializer: D,
) -> Result<ByteArray<LENGTH>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(string).map_err(|err| Error::custom(err.to_string())))
        .map(|vec| {
            let mut out = ByteArray::<LENGTH>::new();
            out.as_mut_slice().copy_from_slice(&vec);
            out
        })
}

pub(crate) fn slice_from_base64<'de, D, const LENGTH: usize>(
    deserializer: D,
) -> Result<[u8; LENGTH], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(string).map_err(|err| Error::custom(err.to_string())))
        .map(|vec| {
            let mut out = [0u8; LENGTH];
            out.copy_from_slice(&vec);
            out
        })
}

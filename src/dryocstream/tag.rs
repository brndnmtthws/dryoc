use crate::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
};
use crate::error::{Error, ErrorContext, ValueConstraint};

/// Secret stream message tag.
///
/// Each message pushed to a [`DryocStream`](super::DryocStream) carries one
/// tag, which is encrypted and authenticated with the message. The variants
/// are exactly libsodium's four `crypto_secretstream_xchacha20poly1305_TAG_*`
/// values, and [`Tag::bits`] returns the byte stored in the stream. Convert a
/// tag byte with [`Tag::try_from`], which rejects every other byte.
///
/// `Tag` is `#[non_exhaustive]` so that a tag value libsodium may add to the
/// secretstream format later can become a new variant without a breaking
/// change; a `match` on `Tag` outside this crate therefore needs a wildcard
/// arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Tag {
    /// A normal message in a stream (`TAG_MESSAGE`, `0`).
    #[default]
    Message = 0,
    /// Marks the end of a series of messages in a stream, but not the end of
    /// the stream (`TAG_PUSH`, `1`).
    Push    = 1,
    /// Derives a new key for the stream after this message (`TAG_REKEY`, `2`).
    Rekey   = 2,
    /// Marks the end of the stream, and rekeys after this message
    /// (`TAG_FINAL`, `3`).
    Final   = 3,
}

const _: () = {
    assert!(Tag::Message as u8 == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
    assert!(Tag::Push as u8 == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH);
    assert!(Tag::Rekey as u8 == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY);
    assert!(Tag::Final as u8 == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
};

impl Tag {
    /// Returns the tag byte, as stored in the stream and used by the Classic
    /// [`crypto_secretstream_xchacha20poly1305`](crate::classic::crypto_secretstream_xchacha20poly1305)
    /// functions.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Tag {
    type Error = Error;

    /// Converts a tag byte into a [`Tag`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] with [`ErrorContext::Tag`] for any byte
    /// other than the four libsodium tag values.
    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        match bits {
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE => Ok(Self::Message),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH => Ok(Self::Push),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY => Ok(Self::Rekey),
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL => Ok(Self::Final),
            _ => Err(Error::InvalidValue {
                context: ErrorContext::Tag,
                actual: u64::from(bits),
                constraint: ValueConstraint::AllowedBits {
                    mask: u64::from(Self::Final.bits()),
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Tag;

    #[test]
    fn tag_bytes_are_libsodiums_values() {
        let cases = [
            (Tag::Message, 0u8),
            (Tag::Push, 1),
            (Tag::Rekey, 2),
            (Tag::Final, 3),
        ];
        for (tag, bits) in cases {
            assert_eq!(tag.bits(), bits);
            assert_eq!(Tag::try_from(bits).expect("known tag byte"), tag);
        }
    }

    #[test]
    fn tag_from_u8_rejects_every_unknown_byte() {
        for bits in 4..=u8::MAX {
            let error = Tag::try_from(bits).expect_err("unknown tag byte must be rejected");
            assert!(
                matches!(
                    error,
                    crate::Error::InvalidValue {
                        context: crate::ErrorContext::Tag,
                        actual,
                        constraint: crate::ValueConstraint::AllowedBits { mask: 0x3 },
                    } if actual == u64::from(bits)
                ),
                "tag byte {bits:#04x}: {error:?}"
            );
        }
    }
}

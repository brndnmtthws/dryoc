use std::fmt;
use std::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Sub, SubAssign,
};

use crate::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY,
};

/// Message tag definitions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(u8);

const TAG_ITER_FLAGS: [Tag; 2] = [Tag::PUSH, Tag::REKEY];
const TAG_ITER_NAMES: [(&str, Tag); 2] = [("PUSH", Tag::PUSH), ("REKEY", Tag::REKEY)];

impl Tag {
    /// Indicates the end of the stream.
    pub const FINAL: Self = Self(Self::PUSH.bits() | Self::REKEY.bits());
    const KNOWN_BITS: u8 = Self::MESSAGE.bits() | Self::PUSH.bits() | Self::REKEY.bits();
    /// Describes a normal message in a stream.
    pub const MESSAGE: Self = Self(CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
    /// Indicates the message marks the end of a series of messages in a
    /// stream, but not the end of the stream.
    pub const PUSH: Self = Self(CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH);
    /// Derives a new key for the stream.
    pub const REKEY: Self = Self(CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY);

    /// Get a flags value with all bits unset.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Get a flags value with all known bits set.
    #[inline]
    pub const fn all() -> Self {
        Self(Self::KNOWN_BITS)
    }

    /// Get the underlying bits value.
    #[inline]
    pub const fn bits(&self) -> u8 {
        self.0
    }

    /// Convert from a bits value, returning `None` if any unknown bits are set.
    #[inline]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Convert from a bits value, unsetting any unknown bits.
    #[inline]
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & Self::KNOWN_BITS)
    }

    /// Convert from a bits value exactly.
    ///
    /// Values containing unknown bits are rejected when passed to
    /// [`DryocStream::push`](super::DryocStream::push), and authenticated
    /// unknown tags are rejected by Rustaceous pull streams.
    #[inline]
    pub const fn from_bits_retain(bits: u8) -> Self {
        Self(bits)
    }

    /// Get a flags value with the bits of a flag with the given name set.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "MESSAGE" => Some(Self::MESSAGE),
            "PUSH" => Some(Self::PUSH),
            "REKEY" => Some(Self::REKEY),
            "FINAL" => Some(Self::FINAL),
            _ => None,
        }
    }

    /// Whether all bits in this flags value are unset.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bits() == 0
    }

    /// Whether all known bits in this flags value are set.
    #[inline]
    pub const fn is_all(&self) -> bool {
        Self::KNOWN_BITS | self.bits() == self.bits()
    }

    /// Whether any set bits in a source flags value are also set in a target
    /// flags value.
    #[inline]
    pub const fn intersects(&self, other: Self) -> bool {
        self.bits() & other.bits() != 0
    }

    /// Whether all set bits in a source flags value are also set in a target
    /// flags value.
    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        self.bits() & other.bits() == other.bits()
    }

    /// The bitwise or (`|`) of the bits in two flags values.
    #[inline]
    pub fn insert(&mut self, other: Self) {
        *self = self.union(other);
    }

    /// The intersection of a source flags value with the complement of a target
    /// flags value (`&!`).
    #[inline]
    pub fn remove(&mut self, other: Self) {
        *self = self.difference(other);
    }

    /// The bitwise exclusive-or (`^`) of the bits in two flags values.
    #[inline]
    pub fn toggle(&mut self, other: Self) {
        *self = self.symmetric_difference(other);
    }

    /// Call [`insert`](Self::insert) when `value` is `true` or
    /// [`remove`](Self::remove) when `value` is `false`.
    #[inline]
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }

    /// Unsets all bits in the flags.
    #[inline]
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// The bitwise and (`&`) of the bits in two flags values.
    #[inline]
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.bits() & other.bits())
    }

    /// The bitwise or (`|`) of the bits in two flags values.
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.bits() | other.bits())
    }

    /// The intersection of a source flags value with the complement of a target
    /// flags value (`&!`).
    #[inline]
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.bits() & !other.bits())
    }

    /// The bitwise exclusive-or (`^`) of the bits in two flags values.
    #[inline]
    #[must_use]
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self(self.bits() ^ other.bits())
    }

    /// The bitwise negation (`!`) of the bits in a flags value, truncating the
    /// result.
    #[inline]
    #[must_use]
    pub const fn complement(self) -> Self {
        Self::from_bits_truncate(!self.bits())
    }

    /// Yield a set of contained flags values.
    pub const fn iter(&self) -> TagIter {
        TagIter {
            remaining: *self,
            index: 0,
            yielded_unknown: false,
        }
    }

    /// Yield a set of contained named flags values.
    pub const fn iter_names(&self) -> TagIterNames {
        TagIterNames {
            remaining: *self,
            index: 0,
        }
    }
}

impl Default for Tag {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(")?;

        let mut first = true;
        for (name, _) in self.iter_names() {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(name)?;
        }

        let unknown = self.bits() & !Self::KNOWN_BITS;
        if unknown != 0 || first {
            if !first {
                f.write_str(" | ")?;
            }
            write!(f, "0x{unknown:x}")?;
        }

        f.write_str(")")
    }
}

impl fmt::Binary for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&self.bits(), f)
    }
}

impl fmt::Octal for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Octal::fmt(&self.bits(), f)
    }
}

impl fmt::LowerHex for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.bits(), f)
    }
}

impl fmt::UpperHex for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.bits(), f)
    }
}

impl BitOr for Tag {
    type Output = Self;

    #[inline]
    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl BitOrAssign for Tag {
    #[inline]
    fn bitor_assign(&mut self, other: Self) {
        self.insert(other);
    }
}

impl BitAnd for Tag {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self {
        self.intersection(other)
    }
}

impl BitAndAssign for Tag {
    #[inline]
    fn bitand_assign(&mut self, other: Self) {
        *self = self.intersection(other);
    }
}

impl BitXor for Tag {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self {
        self.symmetric_difference(other)
    }
}

impl BitXorAssign for Tag {
    #[inline]
    fn bitxor_assign(&mut self, other: Self) {
        self.toggle(other);
    }
}

impl Sub for Tag {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        self.difference(other)
    }
}

impl SubAssign for Tag {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        self.remove(other);
    }
}

impl Not for Tag {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        self.complement()
    }
}

impl Extend<Tag> for Tag {
    fn extend<T: IntoIterator<Item = Self>>(&mut self, iter: T) {
        for item in iter {
            self.insert(item);
        }
    }
}

impl FromIterator<Tag> for Tag {
    fn from_iter<T: IntoIterator<Item = Self>>(iter: T) -> Self {
        let mut result = Self::empty();
        result.extend(iter);
        result
    }
}

impl IntoIterator for Tag {
    type IntoIter = TagIter;
    type Item = Tag;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl TryFrom<u8> for Tag {
    type Error = crate::Error;

    fn try_from(other: u8) -> Result<Self, Self::Error> {
        Self::from_bits(other).ok_or(crate::Error::InvalidValue {
            context: crate::ErrorContext::Tag,
            actual: other as u64,
            constraint: crate::ValueConstraint::AllowedBits {
                mask: Self::KNOWN_BITS as u64,
            },
        })
    }
}

/// Iterator over contained secretstream tags.
#[derive(Clone, Debug)]
pub struct TagIter {
    remaining: Tag,
    index: usize,
    yielded_unknown: bool,
}

impl Iterator for TagIter {
    type Item = Tag;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < TAG_ITER_FLAGS.len() {
            let flag = TAG_ITER_FLAGS[self.index];
            self.index += 1;

            if self.remaining.contains(flag) {
                self.remaining.remove(flag);
                return Some(flag);
            }
        }

        let unknown = self.remaining.bits() & !Tag::KNOWN_BITS;
        if unknown != 0 && !self.yielded_unknown {
            self.yielded_unknown = true;
            self.remaining.remove(Tag::from_bits_retain(unknown));
            Some(Tag::from_bits_retain(unknown))
        } else {
            None
        }
    }
}

/// Iterator over contained named secretstream tags.
#[derive(Clone, Debug)]
pub struct TagIterNames {
    remaining: Tag,
    index: usize,
}

impl Iterator for TagIterNames {
    type Item = (&'static str, Tag);

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < TAG_ITER_NAMES.len() {
            let (name, flag) = TAG_ITER_NAMES[self.index];
            self.index += 1;

            if self.remaining.contains(flag) {
                self.remaining.remove(flag);
                return Some((name, flag));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::Tag;

    #[test]
    fn tag_constructors_and_names_cover_known_and_unknown_bits() {
        assert_eq!(Tag::default(), Tag::empty());
        assert_eq!(Tag::default(), Tag::MESSAGE);
        assert_eq!(Tag::all(), Tag::FINAL);

        for bits in 0..=u8::MAX {
            let retained = Tag::from_bits_retain(bits);
            assert_eq!(retained.bits(), bits);
            assert_eq!(Tag::from_bits_truncate(bits).bits(), bits & Tag::KNOWN_BITS);

            let expected = if bits & !Tag::KNOWN_BITS == 0 {
                Some(retained)
            } else {
                None
            };
            assert_eq!(Tag::from_bits(bits), expected);
        }

        assert_eq!(
            Tag::try_from(Tag::FINAL.bits()).expect("known tag bits should be accepted"),
            Tag::FINAL
        );
        assert_eq!(Tag::from_name("MESSAGE"), Some(Tag::MESSAGE));
        assert_eq!(Tag::from_name("PUSH"), Some(Tag::PUSH));
        assert_eq!(Tag::from_name("REKEY"), Some(Tag::REKEY));
        assert_eq!(Tag::from_name("FINAL"), Some(Tag::FINAL));
        assert_eq!(Tag::from_name("UNKNOWN"), None);
    }

    #[test]
    fn tag_from_u8_rejects_unknown_bits() {
        let error = Tag::try_from(0x80).expect_err("unknown tag bits should be rejected");

        assert!(matches!(
            error,
            crate::Error::InvalidValue {
                context: crate::ErrorContext::Tag,
                actual: 0x80,
                constraint: crate::ValueConstraint::AllowedBits { .. },
            }
        ));
    }

    #[test]
    fn tag_predicates_and_mutators_match_flag_semantics() {
        assert!(Tag::empty().is_empty());
        assert!(Tag::MESSAGE.is_empty());
        assert!(!Tag::PUSH.is_empty());
        assert!(Tag::FINAL.is_all());
        assert!(Tag::from_bits_retain(Tag::FINAL.bits() | 0x80).is_all());
        assert!(!Tag::PUSH.is_all());

        assert!(Tag::FINAL.contains(Tag::PUSH));
        assert!(Tag::PUSH.contains(Tag::MESSAGE));
        assert!(!Tag::PUSH.contains(Tag::REKEY));
        assert!(Tag::FINAL.intersects(Tag::PUSH));
        assert!(!Tag::PUSH.intersects(Tag::REKEY));

        let mut tag = Tag::empty();
        tag.insert(Tag::PUSH);
        assert_eq!(tag, Tag::PUSH);
        tag.insert(Tag::REKEY);
        assert_eq!(tag, Tag::FINAL);
        tag.remove(Tag::PUSH);
        assert_eq!(tag, Tag::REKEY);
        tag.toggle(Tag::PUSH);
        assert_eq!(tag, Tag::FINAL);
        tag.set(Tag::REKEY, false);
        assert_eq!(tag, Tag::PUSH);
        tag.set(Tag::REKEY, true);
        assert_eq!(tag, Tag::FINAL);
        tag.clear();
        assert_eq!(tag, Tag::empty());
    }

    #[test]
    fn tag_set_operations_and_operators_match_flag_semantics() {
        assert_eq!(Tag::PUSH.union(Tag::REKEY), Tag::FINAL);
        assert_eq!(Tag::FINAL.intersection(Tag::PUSH), Tag::PUSH);
        assert_eq!(Tag::FINAL.difference(Tag::PUSH), Tag::REKEY);
        assert_eq!(Tag::FINAL.symmetric_difference(Tag::PUSH), Tag::REKEY);
        assert_eq!(Tag::PUSH.complement(), Tag::REKEY);

        assert_eq!(Tag::PUSH | Tag::REKEY, Tag::FINAL);
        assert_eq!(Tag::FINAL & Tag::PUSH, Tag::PUSH);
        assert_eq!(Tag::FINAL ^ Tag::PUSH, Tag::REKEY);
        assert_eq!(Tag::FINAL - Tag::PUSH, Tag::REKEY);
        assert_eq!(!Tag::PUSH, Tag::REKEY);

        let mut tag = Tag::PUSH;
        tag |= Tag::REKEY;
        assert_eq!(tag, Tag::FINAL);
        tag &= Tag::PUSH;
        assert_eq!(tag, Tag::PUSH);
        tag ^= Tag::REKEY;
        assert_eq!(tag, Tag::FINAL);
        tag -= Tag::PUSH;
        assert_eq!(tag, Tag::REKEY);
    }

    #[test]
    fn tag_iterators_skip_zero_bit_message_and_retain_unknown_bits() {
        assert_eq!(Tag::MESSAGE.iter().collect::<Vec<_>>(), Vec::<Tag>::new());
        assert_eq!(
            Tag::FINAL.iter().collect::<Vec<_>>(),
            vec![Tag::PUSH, Tag::REKEY]
        );
        assert_eq!(
            Tag::FINAL.iter_names().collect::<Vec<_>>(),
            vec![("PUSH", Tag::PUSH), ("REKEY", Tag::REKEY)]
        );

        let unknown = Tag::from_bits_retain(0x80);
        let retained = Tag::from_bits_retain(Tag::FINAL.bits() | unknown.bits());

        assert_eq!(
            retained.iter().collect::<Vec<_>>(),
            vec![Tag::PUSH, Tag::REKEY, unknown]
        );
        assert_eq!(
            retained.iter_names().collect::<Vec<_>>(),
            vec![("PUSH", Tag::PUSH), ("REKEY", Tag::REKEY)]
        );
        assert_eq!(unknown.iter().collect::<Vec<_>>(), vec![unknown]);
        assert_eq!(unknown.iter_names().collect::<Vec<_>>(), Vec::new());
        assert_eq!(
            Tag::FINAL.into_iter().collect::<Vec<_>>(),
            vec![Tag::PUSH, Tag::REKEY]
        );
    }

    #[test]
    fn tag_formatting_matches_bitflags_style() {
        assert_eq!(format!("{:?}", Tag::empty()), "Tag(0x0)");
        assert_eq!(format!("{:?}", Tag::MESSAGE), "Tag(0x0)");
        assert_eq!(format!("{:?}", Tag::PUSH), "Tag(PUSH)");
        assert_eq!(format!("{:?}", Tag::REKEY), "Tag(REKEY)");
        assert_eq!(format!("{:?}", Tag::FINAL), "Tag(PUSH | REKEY)");

        let retained = Tag::from_bits_retain(Tag::FINAL.bits() | 0x80);
        assert_eq!(format!("{retained:?}"), "Tag(PUSH | REKEY | 0x80)");
        assert_eq!(format!("{retained:b}"), format!("{:b}", retained.bits()));
        assert_eq!(format!("{retained:o}"), format!("{:o}", retained.bits()));
        assert_eq!(format!("{retained:x}"), format!("{:x}", retained.bits()));
        assert_eq!(format!("{retained:X}"), format!("{:X}", retained.bits()));
        assert_eq!(
            format!("{retained:#04x}"),
            format!("{:#04x}", retained.bits())
        );
    }

    #[test]
    fn tag_collection_traits_accumulate_flags() {
        let mut tag = Tag::empty();
        tag.extend([Tag::PUSH, Tag::REKEY]);
        assert_eq!(tag, Tag::FINAL);

        let tag: Tag = [Tag::PUSH, Tag::REKEY].into_iter().collect();
        assert_eq!(tag, Tag::FINAL);
    }
}

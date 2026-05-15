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

impl From<u8> for Tag {
    fn from(other: u8) -> Self {
        Self::from_bits(other).expect("Unable to parse tag")
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

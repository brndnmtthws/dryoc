use std::fmt::{Display, Formatter};

/// The input, output, or operation associated with an [`Error`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorContext {
    /// Associated data supplied to an authenticated operation.
    AssociatedData,
    /// An authenticated-encryption ciphertext.
    AeadCiphertext,
    /// An authenticated-encryption envelope.
    AeadEnvelope,
    /// A message authentication tag.
    AuthenticationTag,
    /// A BLAKE2b key.
    Blake2bKey,
    /// BLAKE2b output.
    Blake2bOutput,
    /// A BLAKE2b operation or state.
    Blake2b,
    /// An authenticated public-key box.
    Box,
    /// Ciphertext input or output.
    Ciphertext,
    /// A Curve25519 public key.
    Curve25519PublicKey,
    /// An in-place data buffer.
    Data,
    /// An Ed25519 public key.
    Ed25519PublicKey,
    /// An ephemeral public key.
    EphemeralPublicKey,
    /// An Argon2 memory-cost parameter.
    MemoryCost,
    /// A password-hashing memory limit.
    MemoryLimit,
    /// Plaintext message input or output.
    Message,
    /// A nonce.
    Nonce,
    /// A password-hashing operations limit.
    OperationsLimit,
    /// A generic output buffer.
    Output,
    /// An Argon2 parallelism parameter.
    Parallelism,
    /// A password.
    Password,
    /// An encoded password hash or its hash field.
    PasswordHash,
    /// A password-hash algorithm field.
    PasswordHashAlgorithm,
    /// A password-hash memory-cost field.
    PasswordHashMemoryCost,
    /// A password-hash parallelism field.
    PasswordHashParallelism,
    /// A password-hash salt field.
    PasswordHashSalt,
    /// A password-hash time-cost field.
    PasswordHashTimeCost,
    /// A password-hash version field.
    PasswordHashVersion,
    /// A protected-memory value or operation.
    ProtectedMemory,
    /// A public key.
    PublicKey,
    /// A sealed public-key box.
    SealedBox,
    /// An Argon2 secret input.
    Secret,
    /// An authenticated secret-key box.
    SecretBox,
    /// A secret key.
    SecretKey,
    /// A signature.
    Signature,
    /// A signed message.
    SignedMessage,
    /// A byte slice.
    Slice,
    /// A derived subkey.
    Subkey,
    /// A secretstream message tag.
    Tag,
    /// An Argon2 time-cost parameter.
    TimeCost,
}

impl Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AssociatedData => "associated data",
            Self::AeadCiphertext => "AEAD ciphertext",
            Self::AeadEnvelope => "AEAD envelope",
            Self::AuthenticationTag => "authentication tag",
            Self::Blake2bKey => "BLAKE2b key",
            Self::Blake2bOutput => "BLAKE2b output",
            Self::Blake2b => "BLAKE2b",
            Self::Box => "box",
            Self::Ciphertext => "ciphertext",
            Self::Curve25519PublicKey => "Curve25519 public key",
            Self::Data => "data",
            Self::Ed25519PublicKey => "Ed25519 public key",
            Self::EphemeralPublicKey => "ephemeral public key",
            Self::MemoryCost => "memory cost",
            Self::MemoryLimit => "memory limit",
            Self::Message => "message",
            Self::Nonce => "nonce",
            Self::OperationsLimit => "operations limit",
            Self::Output => "output",
            Self::Parallelism => "parallelism",
            Self::Password => "password",
            Self::PasswordHash => "password hash",
            Self::PasswordHashAlgorithm => "password hash algorithm",
            Self::PasswordHashMemoryCost => "password hash memory cost",
            Self::PasswordHashParallelism => "password hash parallelism",
            Self::PasswordHashSalt => "password hash salt",
            Self::PasswordHashTimeCost => "password hash time cost",
            Self::PasswordHashVersion => "password hash version",
            Self::ProtectedMemory => "protected memory",
            Self::PublicKey => "public key",
            Self::SealedBox => "sealed box",
            Self::Secret => "secret",
            Self::SecretBox => "secretbox",
            Self::SecretKey => "secret key",
            Self::Signature => "signature",
            Self::SignedMessage => "signed message",
            Self::Slice => "slice",
            Self::Subkey => "subkey",
            Self::Tag => "tag",
            Self::TimeCost => "time cost",
        })
    }
}

/// A constraint on a byte or buffer length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LengthConstraint {
    /// The length must equal this value.
    Exact(usize),
    /// The length must be at least this value.
    AtLeast(usize),
    /// The length must be at most this value.
    AtMost(usize),
    /// The length must be within this inclusive range.
    Between { min: usize, max: usize },
}

impl Display for LengthConstraint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(expected) => write!(f, "exactly {expected}"),
            Self::AtLeast(min) => write!(f, "at least {min}"),
            Self::AtMost(max) => write!(f, "at most {max}"),
            Self::Between { min, max } => write!(f, "between {min} and {max} (inclusive)"),
        }
    }
}

/// A constraint on a numeric parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValueConstraint {
    /// The value must be within this inclusive range.
    Between { min: u64, max: u64 },
    /// Only bits present in this mask may be set.
    AllowedBits { mask: u64 },
}

impl Display for ValueConstraint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Between { min, max } => write!(f, "between {min} and {max} (inclusive)"),
            Self::AllowedBits { mask } => {
                write!(f, "a value containing only bits from mask 0x{mask:x}")
            }
        }
    }
}

/// Errors generated by Dryoc.
///
/// Variants are structured so callers can handle failures without parsing the
/// human-readable message. Display text is not part of the API contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication or signature verification failed.
    AuthenticationFailed,

    /// A byte string or buffer had an invalid length.
    InvalidLength {
        /// The input or output whose length was invalid.
        context: ErrorContext,
        /// The supplied length.
        actual: usize,
        /// The required length constraint.
        constraint: LengthConstraint,
    },

    /// A numeric parameter was outside its supported range.
    InvalidValue {
        /// The parameter whose value was invalid.
        context: ErrorContext,
        /// The supplied value.
        actual: u64,
        /// The required value constraint.
        constraint: ValueConstraint,
    },

    /// Encoded data was malformed or unsupported.
    InvalidEncoding {
        /// The encoded field or format that was invalid.
        context: ErrorContext,
    },

    /// A cryptographic key was invalid or unsafe to use.
    InvalidKey {
        /// The key whose value was invalid.
        context: ErrorContext,
    },

    /// Required data was absent.
    MissingData {
        /// The missing field or value.
        context: ErrorContext,
    },

    /// The requested operation was invalid for the current state.
    InvalidState {
        /// The state or operation that was invalid.
        context: ErrorContext,
    },

    /// An arithmetic operation overflowed.
    ArithmeticOverflow {
        /// The value being calculated.
        context: ErrorContext,
    },

    /// An operating-system I/O operation failed.
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::InvalidLength {
                context,
                actual,
                constraint,
            } => write!(
                f,
                "invalid {context} length: expected {constraint}, got {actual}"
            ),
            Self::InvalidValue {
                context,
                actual,
                constraint,
            } => write!(
                f,
                "invalid {context} value: expected {constraint}, got {actual}"
            ),
            Self::InvalidEncoding { context } => write!(f, "invalid {context} encoding"),
            Self::InvalidKey { context } => write!(f, "invalid {context}"),
            Self::MissingData { context } => write!(f, "missing {context}"),
            Self::InvalidState { context } => write!(f, "invalid {context} state"),
            Self::ArithmeticOverflow { context } => {
                write!(f, "arithmetic overflow while calculating {context} length")
            }
            Self::Io(error) => write!(f, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

macro_rules! length_error {
    ($context:expr_2021, $actual:expr_2021,exact $expected:expr_2021) => {
        crate::error::Error::InvalidLength {
            context: $context,
            actual: $actual,
            constraint: crate::error::LengthConstraint::Exact($expected),
        }
    };
    ($context:expr_2021, $actual:expr_2021,min $min:expr_2021) => {
        crate::error::Error::InvalidLength {
            context: $context,
            actual: $actual,
            constraint: crate::error::LengthConstraint::AtLeast($min),
        }
    };
    ($context:expr_2021, $actual:expr_2021,max $max:expr_2021) => {
        crate::error::Error::InvalidLength {
            context: $context,
            actual: $actual,
            constraint: crate::error::LengthConstraint::AtMost($max),
        }
    };
    ($context:expr_2021, $actual:expr_2021,range $min:expr_2021, $max:expr_2021) => {
        crate::error::Error::InvalidLength {
            context: $context,
            actual: $actual,
            constraint: crate::error::LengthConstraint::Between {
                min: $min,
                max: $max,
            },
        }
    };
}

macro_rules! validate {
    ($min:expr_2021, $max:expr_2021, $value:expr_2021, $context:expr_2021) => {
        if !($min..=$max).contains(&$value) {
            return Err(crate::error::Error::InvalidValue {
                context: $context,
                actual: $value as u64,
                constraint: crate::error::ValueConstraint::Between {
                    min: $min as u64,
                    max: $max as u64,
                },
            });
        }
    };
}

macro_rules! validate_length {
    ($min:expr_2021, $max:expr_2021, $value:expr_2021, $context:expr_2021) => {
        if !($min..=$max).contains(&$value) {
            return Err(length_error!($context, $value, range $min, $max));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_human_readable_without_source_locations() {
        let cases = [
            (Error::AuthenticationFailed, "authentication failed"),
            (
                Error::InvalidLength {
                    context: ErrorContext::Nonce,
                    actual: 12,
                    constraint: LengthConstraint::Exact(24),
                },
                "invalid nonce length: expected exactly 24, got 12",
            ),
            (
                Error::InvalidLength {
                    context: ErrorContext::Blake2bOutput,
                    actual: 0,
                    constraint: LengthConstraint::Between { min: 1, max: 64 },
                },
                "invalid BLAKE2b output length: expected between 1 and 64 (inclusive), got 0",
            ),
            (
                Error::InvalidValue {
                    context: ErrorContext::Parallelism,
                    actual: 8,
                    constraint: ValueConstraint::Between { min: 1, max: 4 },
                },
                "invalid parallelism value: expected between 1 and 4 (inclusive), got 8",
            ),
            (
                Error::InvalidValue {
                    context: ErrorContext::Tag,
                    actual: 128,
                    constraint: ValueConstraint::AllowedBits { mask: 3 },
                },
                "invalid tag value: expected a value containing only bits from mask 0x3, got 128",
            ),
            (
                Error::InvalidEncoding {
                    context: ErrorContext::PasswordHashSalt,
                },
                "invalid password hash salt encoding",
            ),
            (
                Error::InvalidKey {
                    context: ErrorContext::Ed25519PublicKey,
                },
                "invalid Ed25519 public key",
            ),
            (
                Error::MissingData {
                    context: ErrorContext::EphemeralPublicKey,
                },
                "missing ephemeral public key",
            ),
            (
                Error::InvalidState {
                    context: ErrorContext::Blake2b,
                },
                "invalid BLAKE2b state",
            ),
            (
                Error::ArithmeticOverflow {
                    context: ErrorContext::Ciphertext,
                },
                "arithmetic overflow while calculating ciphertext length",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn debug_is_structured_and_does_not_include_internal_source_locations() {
        let error = Error::InvalidLength {
            context: ErrorContext::Ciphertext,
            actual: 7,
            constraint: LengthConstraint::AtLeast(16),
        };

        assert_eq!(
            format!("{error:?}"),
            "InvalidLength { context: Ciphertext, actual: 7, constraint: AtLeast(16) }"
        );
    }

    #[test]
    fn wrapped_errors_preserve_their_source() {
        use std::error::Error as _;

        let error = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        assert_eq!(error.to_string(), "I/O error: access denied");
        let debug = format!("{error:?}");
        assert!(debug.contains("Io"));
        assert!(debug.contains("PermissionDenied"));
        assert!(debug.contains("access denied"));
        assert!(error.source().is_some());
    }
}

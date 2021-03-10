use crate::types::InputBase;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, PartialEq))]
#[zeroize(drop)]
/// Message container, for use with unencrypted messages
pub struct Message(pub Box<InputBase>);

impl From<Vec<u8>> for Message {
    fn from(other: Vec<u8>) -> Self {
        Self(Box::from(other.as_slice()))
    }
}

impl From<&[u8]> for Message {
    fn from(other: &[u8]) -> Self {
        Self(Box::from(other))
    }
}

impl From<String> for Message {
    fn from(other: String) -> Self {
        Self(Box::from(other.as_bytes()))
    }
}

impl From<&str> for Message {
    fn from(other: &str) -> Self {
        Self(Box::from(other.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from() {
        assert_eq!(Message::from("hey").0.as_ref(), "hey".as_bytes());
        assert_eq!(
            Message::from(String::from("hey")).0.as_ref(),
            "hey".as_bytes()
        );
        assert_eq!(Message::from(vec![1, 2, 3]).0.as_ref(), [1, 2, 3]);
        assert_eq!(
            Message::from(vec![1, 2, 3].as_slice()).0.as_ref(),
            [1, 2, 3]
        );
    }
}

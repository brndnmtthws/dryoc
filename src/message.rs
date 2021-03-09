use crate::constants::*;
use crate::traits::*;
use crate::types::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Debug, PartialEq)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Debug, PartialEq))]
#[zeroize(drop)]
pub struct Message(pub Box<InputBase>);

impl From<String> for Message {
    fn from(s: String) -> Self {
        Self(Box::from(s.as_bytes()))
    }
}
impl From<&str> for Message {
    fn from(s: &str) -> Self {
        Self(Box::from(s.as_bytes()))
    }
}

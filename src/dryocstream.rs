/*!

# Encrypted streams

_For public-key based encryption, see [crate::dryocbox]_.

_For secret-key based encryption, see [crate::dryocsecretbox]_.

# Rustaceous API example

```
use dryoc::dryocstream::*;

```
*/

use crate::crypto_secretstream_xchacha20poly1305::{
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push, crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push, crypto_secretstream_xchacha20poly1305_rekey, State,
};
use crate::types::InputBase;
use crate::{error::Error, types::OutputBase};

pub use crate::crypto_secretstream_xchacha20poly1305::{Key, Tag};

use zeroize::Zeroize;

/// Stream mode marker trait
pub trait Mode {}
/// Indicates a push stream
pub struct Push;
/// Indicates a pull stream
pub struct Pull;

impl Mode for Push {}
impl Mode for Pull {}

/// Secret-key authenticated encrypted streams
#[derive(PartialEq, Clone, Zeroize)]
pub struct DryocStream<Mode> {
    #[zeroize(drop)]
    state: State,
    phantom: std::marker::PhantomData<Mode>,
}

/// Container for stream header data
#[derive(PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
pub struct Header(Vec<u8>);

impl<M> DryocStream<M> {
    /// Manually rekeys the stream. Both the push and pull sides of the stream
    /// need to manually rekey if you use this function (i.e., it's not handled
    /// by the library).
    ///
    /// Automatic rekeying will occur normally, and you generally should need to
    /// manually rekey.
    ///
    /// Refer to the [libsodium
    /// docs](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream#rekeying)
    /// for details.
    pub fn rekey(&mut self) {
        crypto_secretstream_xchacha20poly1305_rekey(&mut self.state)
    }
}

impl DryocStream<Push> {
    /// Returns a new push stream, initialized from `key`.
    pub fn init_push(key: &Key) -> (Self, Header) {
        let mut state = State::new();
        let header = crypto_secretstream_xchacha20poly1305_init_push(&mut state, key);
        (
            Self {
                state,
                phantom: std::marker::PhantomData,
            },
            Header(header),
        )
    }
    /// Encrypts `message` for this stream with `associated_data` and `tag`,
    /// returning the ciphertext.
    pub fn encrypt(
        &mut self,
        message: &InputBase,
        associated_data: Option<&InputBase>,
        tag: Tag,
    ) -> Result<OutputBase, Error> {
        crypto_secretstream_xchacha20poly1305_push(&mut self.state, message, associated_data, tag)
    }
}

impl DryocStream<Pull> {
    /// Returns a new pull stream, initialized from `key` and `header`.
    pub fn init_pull(key: &Key, header: &Header) -> Self {
        let mut state = State::new();
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header.0, key);
        Self {
            state,
            phantom: std::marker::PhantomData,
        }
    }
    /// Decrypts `ciphertext` for this stream with `associated_data`, returning
    /// the decrypted message and tag.
    pub fn decrypt(
        &mut self,
        ciphertext: &InputBase,
        associated_data: Option<&InputBase>,
    ) -> Result<(OutputBase, Tag), Error> {
        crypto_secretstream_xchacha20poly1305_pull(&mut self.state, ciphertext, associated_data)
    }
}

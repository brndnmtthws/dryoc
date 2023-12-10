//! # Secret-key authenticated encryption
//!
//! [`DryocSecretBox`] implements libsodium's secret-key authenticated
//! encryption, also known as a _secretbox_. This implementation uses the
//! XSalsa20 stream cipher, and Poly1305 for message authentication.
//!
//! You should use a [`DryocSecretBox`] when you want to:
//!
//! * exchange messages between two or more parties
//! * use a shared secret, which could be pre-shared, or derived using one or
//!   more of:
//!   * [`Kdf`](crate::kdf)
//!   * [`Kx`](crate::kx)
//!   * a passphrase with a strong password hashing function, such as
//!     [`crypto_pwhash`](crate::classic::crypto_pwhash)
//!
//! If the `serde` feature is enabled, the [`serde::Deserialize`] and
//! [`serde::Serialize`] traits will be implemented for [`DryocSecretBox`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::dryocsecretbox::*;
//!
//! // Generate a random secret key and nonce
//! let secret_key = Key::gen();
//! let nonce = Nonce::gen();
//! let message = b"Why hello there, fren";
//!
//! // Encrypt `message`, into a Vec-based box
//! let dryocsecretbox = DryocSecretBox::encrypt_to_vecbox(message, &nonce, &secret_key);
//!
//! // Convert into a libsodium-compatible box
//! let sodium_box = dryocsecretbox.to_vec();
//!
//! // Read the same box we just made into a new DryocBox
//! let dryocsecretbox = DryocSecretBox::from_bytes(&sodium_box).expect("unable to load box");
//!
//! // Decrypt the box we previously encrypted,
//! let decrypted = dryocsecretbox
//!     .decrypt_to_vec(&nonce, &secret_key)
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```
//!
//! ## Additional resources
//!
//! * See <https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox>
//!   for additional details on secret boxes
//! * For public-key based encryption, see [`DryocBox`](crate::dryocbox)
//! * For stream encryption, see [`DryocStream`](crate::dryocstream)
//! * See the [protected] mod for an example using the protected memory features
//!   with [`DryocSecretBox`]

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use crate::error::Error;
pub use crate::types::*;

/// Stack-allocated secret for authenticated secret box.
pub type Key = StackByteArray<CRYPTO_SECRETBOX_KEYBYTES>;
/// Stack-allocated nonce for authenticated secret box.
pub type Nonce = StackByteArray<CRYPTO_SECRETBOX_NONCEBYTES>;
/// Stack-allocated secret box message authentication code.
pub type Mac = StackByteArray<CRYPTO_SECRETBOX_MACBYTES>;

#[cfg(any(feature = "nightly", all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
pub mod protected {
    //! #  Protected memory type aliases for [`DryocSecretBox`]
    //!
    //! This mod provides re-exports of type aliases for protected memory usage
    //! with [`DryocSecretBox`]. These type aliases are provided for
    //! convenience.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::dryocsecretbox::protected::*;
    //! use dryoc::dryocsecretbox::DryocSecretBox;
    //!
    //! // Generate a random secret key, lock it, protect memory as read-only
    //! let secret_key = Key::gen_readonly_locked().expect("key failed");
    //!
    //! // Generate a random secret key, lock it, protect memory as read-only
    //! let nonce = Nonce::gen_readonly_locked().expect("nonce failed");
    //!
    //! // Load a message, lock it, protect memory as read-only
    //! let message =
    //!     HeapBytes::from_slice_into_readonly_locked(b"Secret message from the tooth fairy")
    //!         .expect("message failed");
    //!
    //! // Encrypt the message, placing the result into locked memory
    //! let dryocsecretbox: LockedBox = DryocSecretBox::encrypt(&message, &nonce, &secret_key);
    //!
    //! // Decrypt the message, placing the result into locked memory
    //! let decrypted: LockedBytes = dryocsecretbox
    //!     .decrypt(&nonce, &secret_key)
    //!     .expect("decrypt failed");
    //!
    //! assert_eq!(message.as_slice(), decrypted.as_slice());
    //! ```
    use super::*;
    pub use crate::protected::*;

    /// Heap-allocated, page-aligned secret for authenticated secret box, for
    /// use with protected memory.
    pub type Key = HeapByteArray<CRYPTO_SECRETBOX_KEYBYTES>;
    /// Heap-allocated, page-aligned nonce for authenticated secret box, for use
    /// with protected memory.
    pub type Nonce = HeapByteArray<CRYPTO_SECRETBOX_NONCEBYTES>;
    /// Heap-allocated, page-aligned secret box message authentication code, for
    /// use with protected memory.
    pub type Mac = HeapByteArray<CRYPTO_SECRETBOX_MACBYTES>;

    /// Locked [`DryocSecretBox`], provided as a type alias for convenience.
    pub type LockedBox = DryocSecretBox<Locked<Mac>, LockedBytes>;
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// An authenticated secret-key encrypted box, compatible with a libsodium box.
/// Use with either [`VecBox`] or [`protected::LockedBox`] type aliases.
///
/// Refer to [crate::dryocsecretbox] for sample usage.
pub struct DryocSecretBox<
    Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize,
    Data: Bytes + Zeroize,
> {
    tag: Mac,
    data: Data,
}

/// [Vec]-based authenticated secret box.
pub type VecBox = DryocSecretBox<Mac, Vec<u8>>;

impl<
    Mac: NewByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocSecretBox<Mac, Data>
{
    /// Encrypts a message using `secret_key`, and returns a new
    /// [DryocSecretBox] with ciphertext and tag
    pub fn encrypt<
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_SECRETBOX_NONCEBYTES>,
        SecretKey: ByteArray<CRYPTO_SECRETBOX_KEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        secret_key: &SecretKey,
    ) -> Self {
        use crate::classic::crypto_secretbox::crypto_secretbox_detached;

        let mut new = Self {
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };
        new.data.resize(message.len(), 0);

        crypto_secretbox_detached(
            new.data.as_mut_slice(),
            new.tag.as_mut_array(),
            message.as_slice(),
            nonce.as_array(),
            secret_key.as_array(),
        );

        new
    }
}

impl<
    'a,
    Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + std::convert::TryFrom<&'a [u8]> + Zeroize,
    Data: Bytes + From<&'a [u8]> + Zeroize,
> DryocSecretBox<Mac, Data>
{
    /// Initializes a [`DryocSecretBox`] from a slice. Expects the first
    /// [`CRYPTO_SECRETBOX_MACBYTES`] bytes to contain the message
    /// authentication tag, with the remaining bytes containing the
    /// encrypted message.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < CRYPTO_SECRETBOX_MACBYTES {
            Err(dryoc_error!(format!(
                "bytes of len {} less than expected minimum of {}",
                bytes.len(),
                CRYPTO_SECRETBOX_MACBYTES
            )))
        } else {
            let (tag, data) = bytes.split_at(CRYPTO_SECRETBOX_MACBYTES);
            Ok(Self {
                tag: Mac::try_from(tag).map_err(|_e| dryoc_error!("invalid tag"))?,
                data: Data::from(data),
            })
        }
    }
}

impl<Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize, Data: Bytes + Zeroize>
    DryocSecretBox<Mac, Data>
{
    /// Returns a new box with `tag` and `data`, consuming both
    pub fn from_parts(tag: Mac, data: Data) -> Self {
        Self { tag, data }
    }

    /// Copies `self` into a new [`Vec`]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Moves the tag and data out of this instance, returning them as a tuple.
    pub fn into_parts(self) -> (Mac, Data) {
        (self.tag, self.data)
    }
}

impl<Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize, Data: Bytes + Zeroize>
    DryocSecretBox<Mac, Data>
{
    /// Decrypts `ciphertext` using `secret_key`, returning a new
    /// [DryocSecretBox] with decrypted message
    pub fn decrypt<
        Output: ResizableBytes + NewBytes,
        Nonce: ByteArray<CRYPTO_SECRETBOX_NONCEBYTES>,
        SecretKey: ByteArray<CRYPTO_SECRETBOX_KEYBYTES>,
    >(
        &self,
        nonce: &Nonce,
        secret_key: &SecretKey,
    ) -> Result<Output, Error> {
        use crate::classic::crypto_secretbox::crypto_secretbox_open_detached;

        let mut message = Output::new_bytes();
        message.resize(self.data.as_slice().len(), 0);

        crypto_secretbox_open_detached(
            message.as_mut_slice(),
            self.tag.as_array(),
            self.data.as_slice(),
            nonce.as_array(),
            secret_key.as_array(),
        )?;

        Ok(message)
    }

    /// Copies `self` into the target. Can be used with protected memory.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        let mut data = Bytes::new_bytes();
        data.resize(self.tag.len() + self.data.len(), 0);
        let s = data.as_mut_slice();
        s[..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(self.tag.as_slice());
        s[CRYPTO_SECRETBOX_MACBYTES..].copy_from_slice(self.data.as_slice());
        data
    }
}

impl DryocSecretBox<Mac, Vec<u8>> {
    /// Encrypts a message using `secret_key`, and returns a new
    /// [DryocSecretBox] with ciphertext and tag
    pub fn encrypt_to_vecbox<
        Message: Bytes + ?Sized,
        Nonce: ByteArray<CRYPTO_SECRETBOX_NONCEBYTES>,
        SecretKey: ByteArray<CRYPTO_SECRETBOX_KEYBYTES>,
    >(
        message: &Message,
        nonce: &Nonce,
        secret_key: &SecretKey,
    ) -> Self {
        Self::encrypt(message, nonce, secret_key)
    }

    /// Decrypts `ciphertext` using `secret_key`, returning a new
    /// [DryocSecretBox] with decrypted message
    pub fn decrypt_to_vec<
        Nonce: ByteArray<CRYPTO_SECRETBOX_NONCEBYTES>,
        SecretKey: ByteArray<CRYPTO_SECRETBOX_KEYBYTES>,
    >(
        &self,
        nonce: &Nonce,
        secret_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(nonce, secret_key)
    }

    /// Consumes this box and returns it as a Vec
    pub fn into_vec(mut self) -> Vec<u8> {
        self.data
            .resize(self.data.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
        self.data.rotate_right(CRYPTO_SECRETBOX_MACBYTES);
        self.data[0..CRYPTO_SECRETBOX_MACBYTES].copy_from_slice(self.tag.as_array());
        self.data
    }
}

impl<
    'a,
    Mac: NewByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + From<&'a [u8]> + Zeroize,
> DryocSecretBox<Mac, Data>
{
    /// Returns a box with `data` copied from slice `input`.
    pub fn with_data(input: &'a [u8]) -> Self {
        Self {
            tag: Mac::new_byte_array(),
            data: input.into(),
        }
    }
}

impl<
    'a,
    Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize,
    Data: Bytes + ResizableBytes + From<&'a [u8]> + Zeroize,
> DryocSecretBox<Mac, Data>
{
    /// Returns a new box with `data` and `tag`, with data copied from `input`
    /// and `tag` consumed.
    pub fn with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            tag,
            data: input.into(),
        }
    }
}

impl<Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize, Data: Bytes + Zeroize>
    PartialEq<DryocSecretBox<Mac, Data>> for DryocSecretBox<Mac, Data>
{
    fn eq(&self, other: &Self) -> bool {
        self.tag.as_slice().ct_eq(other.tag.as_slice()).unwrap_u8() == 1
            && self
                .data
                .as_slice()
                .ct_eq(other.data.as_slice())
                .unwrap_u8()
                == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dryocbox() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            use crate::dryocsecretbox::*;

            let secret_key = Key::gen();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ").into_bytes();
            let message_copy = message.clone();
            let dryocsecretbox: VecBox = DryocSecretBox::encrypt(&message, &nonce, &secret_key);

            let ciphertext = dryocsecretbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocsecretbox.to_vec());

            let ciphertext_copy = ciphertext.clone();

            let so_ciphertext = secretbox::seal(
                &message_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&secret_key).unwrap(),
            );
            assert_eq!(
                general_purpose::STANDARD.encode(&ciphertext),
                general_purpose::STANDARD.encode(&so_ciphertext)
            );

            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&secret_key).unwrap(),
            )
            .expect("decrypt failed");

            let m = DryocSecretBox::decrypt::<Vec<u8>, Nonce, Key>(
                &dryocsecretbox,
                &nonce,
                &secret_key,
            )
            .expect("decrypt failed");
            assert_eq!(m, message_copy);
            assert_eq!(m, so_decrypted);
        }
    }

    #[test]
    fn test_dryocbox_vec() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            use crate::dryocsecretbox::*;

            let secret_key = Key::gen();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ").into_bytes();
            let message_copy = message.clone();
            let dryocsecretbox = DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &secret_key);

            let ciphertext = dryocsecretbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocsecretbox.to_vec());

            let ciphertext_copy = ciphertext.clone();

            let so_ciphertext = secretbox::seal(
                &message_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&secret_key).unwrap(),
            );
            assert_eq!(
                general_purpose::STANDARD.encode(&ciphertext),
                general_purpose::STANDARD.encode(&so_ciphertext)
            );

            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOKey::from_slice(&secret_key).unwrap(),
            )
            .expect("decrypt failed");

            let m = dryocsecretbox
                .decrypt_to_vec(&nonce, &secret_key)
                .expect("decrypt failed");
            assert_eq!(m, message_copy);
            assert_eq!(m, so_decrypted);
        }
    }

    #[test]
    fn test_copy() {
        for _ in 0..20 {
            use std::convert::TryFrom;

            use crate::rng::*;

            let mut data1: Vec<u8> = vec![0u8; 1024];
            copy_randombytes(data1.as_mut_slice());
            let data1_copy = data1.clone();

            let dryocsecretbox: VecBox = DryocSecretBox::from_bytes(&data1).expect("ok");
            assert_eq!(
                dryocsecretbox.data.as_slice(),
                &data1_copy[CRYPTO_SECRETBOX_MACBYTES..]
            );
            assert_eq!(
                dryocsecretbox.tag.as_slice(),
                &data1_copy[..CRYPTO_SECRETBOX_MACBYTES]
            );

            let data1 = data1_copy.clone();
            let dryocsecretbox: VecBox = DryocSecretBox::with_data(&data1);
            assert_eq!(&dryocsecretbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let (tag, data) = data1.split_at(CRYPTO_SECRETBOX_MACBYTES);
            let dryocsecretbox: VecBox =
                DryocSecretBox::with_data_and_mac(Mac::try_from(tag).expect("mac"), data);
            assert_eq!(
                dryocsecretbox.data.as_slice(),
                &data1_copy[CRYPTO_SECRETBOX_MACBYTES..]
            );
            assert_eq!(
                dryocsecretbox.tag.as_array(),
                &data1_copy[..CRYPTO_SECRETBOX_MACBYTES]
            );
        }
    }

    #[cfg(any(feature = "nightly", all(doc, not(doctest))))]
    #[cfg(feature = "nightly")]
    #[test]
    fn test_dryocbox_locked() {
        for i in 0..20 {
            use base64::engine::general_purpose;
            use base64::Engine as _;
            use sodiumoxide::crypto::secretbox;
            use sodiumoxide::crypto::secretbox::{Key as SOKey, Nonce as SONonce};

            use crate::dryocsecretbox::*;
            use crate::protected::*;

            let secret_key = protected::Key::gen_locked().expect("gen failed");
            let nonce = protected::Nonce::gen_locked().expect("gen failed");
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocsecretbox: protected::LockedBox =
                DryocSecretBox::encrypt(message.as_bytes(), &nonce, &secret_key);

            let ciphertext = dryocsecretbox.to_vec();

            let ciphertext_copy = ciphertext.clone();

            let so_ciphertext = secretbox::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &SOKey::from_slice(secret_key.as_slice()).unwrap(),
            );
            assert_eq!(
                general_purpose::STANDARD.encode(&ciphertext),
                general_purpose::STANDARD.encode(&so_ciphertext)
            );

            let so_decrypted = secretbox::open(
                &ciphertext_copy,
                &SONonce::from_slice(nonce.as_slice()).unwrap(),
                &SOKey::from_slice(secret_key.as_slice()).unwrap(),
            )
            .expect("decrypt failed");

            let m: LockedBytes = dryocsecretbox
                .decrypt(&nonce, &secret_key)
                .expect("decrypt failed");

            assert_eq!(m.as_slice(), message_copy.as_bytes());
            assert_eq!(m.as_slice(), so_decrypted);
        }
    }
}

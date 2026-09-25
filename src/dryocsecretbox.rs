//! # Secret-key authenticated encryption
//!
//! [`DryocSecretBox`] provides libsodium-compatible authenticated encryption
//! with a shared secret key. It uses XSalsa20 to encrypt the message and
//! Poly1305 to detect tampering.
//!
//! Use a [`DryocSecretBox`] when all parties already share a secret key. The
//! key can be generated directly or derived with [`Kdf`](crate::kdf),
//! [`Session`](crate::kx), or a password-hashing function such as
//! [`crypto_pwhash`](crate::classic::crypto_pwhash).
//!
//! Anyone who knows the key can create valid messages. In a group, a secretbox
//! proves that a member created the message, not which member created it.
//!
//! Nonces are public, but a nonce must never repeat with the same key. Store
//! each nonce with its ciphertext, or use a counter that cannot repeat for that
//! key.
//!
//! With the `serde` feature,
//! [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) and
//! [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) are implemented
//! for [`DryocSecretBox`]. With `wincode_0_6`,
//! [`wincode::SchemaRead`](https://docs.rs/wincode/0.6/wincode/trait.SchemaRead.html) and
//! [`wincode::SchemaWrite`](https://docs.rs/wincode/0.6/wincode/trait.SchemaWrite.html) are
//! implemented for [`VecBox`].
//!
//! ## Rustaceous API example
//!
//! ```
//! use dryoc::dryocsecretbox::*;
//!
//! // Generate a random secret key and nonce
//! let secret_key = Key::generate();
//! let nonce = Nonce::generate();
//! let message = b"A message to encrypt";
//!
//! // Encrypt the message into a vector-backed box.
//! let dryocsecretbox = DryocSecretBox::encrypt_to_vecbox(message, &nonce, &secret_key);
//!
//! // Serialize the box in libsodium's wire format, then read it back.
//! let sodium_box = dryocsecretbox.to_vec();
//! let dryocsecretbox = DryocSecretBox::from_bytes(&sodium_box).expect("unable to load box");
//!
//! // Decrypt the box.
//! let decrypted = dryocsecretbox
//!     .decrypt_to_vec(&nonce, &secret_key)
//!     .expect("unable to decrypt");
//!
//! assert_eq!(message, decrypted.as_slice());
//! ```
//!
//! ## Additional resources
//!
//! * See the [libsodium documentation](https://doc.libsodium.org/secret-key_cryptography/secretbox)
//!   for more about secret boxes
//! * For public-key encryption, see [`DryocBox`](crate::dryocbox)
//! * For encrypted message streams, see [`DryocStream`](crate::dryocstream)
//! * See the [`protected`] module for an example that stores keys in protected
//!   memory

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::constants::{
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use crate::error::{Error, ErrorContext};
pub use crate::types::*;
use crate::utils::{ct_eq_bytes, split_prefix};

/// Stack-allocated secret for authenticated secret box.
pub type Key = StackByteArray<CRYPTO_SECRETBOX_KEYBYTES>;
/// Stack-allocated nonce for authenticated secret box.
pub type Nonce = StackByteArray<CRYPTO_SECRETBOX_NONCEBYTES>;
/// Stack-allocated secret box message authentication code.
pub type Mac = StackByteArray<CRYPTO_SECRETBOX_MACBYTES>;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`DryocSecretBox`]
    //!
    //! Type aliases for using [`DryocSecretBox`] with protected memory.
    //!
    //! ## Example
    //!
    //! ```
    //! use dryoc::dryocsecretbox::DryocSecretBox;
    //! use dryoc::dryocsecretbox::protected::*;
    //!
    //! // Generate a random secret key, lock it, protect memory as read-only
    //! let secret_key = Key::generate_readonly_locked().expect("key failed");
    //!
    //! // Generate a random secret key, lock it, protect memory as read-only
    //! let nonce = Nonce::generate_readonly_locked().expect("nonce failed");
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

#[cfg(feature = "wincode_0_6")]
// SAFETY: The implementation writes exactly the fields used to reconstruct
// `VecBox` below, using `wincode` schema implementations for each initialized
// field and preserving their order.
unsafe impl<C: wincode::config::Config> wincode::SchemaWrite<C> for VecBox {
    type Src = Self;

    fn size_of(src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(
            <[u8; CRYPTO_SECRETBOX_MACBYTES] as wincode::SchemaWrite<C>>::size_of(
                src.tag.as_array(),
            )? + <Vec<u8> as wincode::SchemaWrite<C>>::size_of(&src.data)?,
        )
    }

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        <[u8; CRYPTO_SECRETBOX_MACBYTES] as wincode::SchemaWrite<C>>::write(
            writer.by_ref(),
            src.tag.as_array(),
        )?;
        <Vec<u8> as wincode::SchemaWrite<C>>::write(writer, &src.data)
    }
}

#[cfg(feature = "wincode_0_6")]
// SAFETY: The implementation fully initializes `dst` with a valid `VecBox`
// after successfully reading each field in the same order as `SchemaWrite`.
unsafe impl<'de, C: wincode::config::Config> wincode::SchemaRead<'de, C> for VecBox {
    type Dst = Self;

    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let tag =
            <[u8; CRYPTO_SECRETBOX_MACBYTES] as wincode::SchemaRead<'de, C>>::get(reader.by_ref())?;
        let data = <Vec<u8> as wincode::SchemaRead<'de, C>>::get(reader)?;
        dst.write(Self {
            tag: tag.into(),
            data,
        });
        Ok(())
    }
}

impl<
    Mac: NewByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocSecretBox<Mac, Data>
{
    /// Encrypts a message using `secret_key` and returns a new
    /// [`DryocSecretBox`] with ciphertext and tag.
    ///
    /// # Panics
    ///
    /// Panics if allocation or resizing panics, the message exceeds
    /// [`CRYPTO_SECRETBOX_MESSAGEBYTES_MAX`](crate::constants::CRYPTO_SECRETBOX_MESSAGEBYTES_MAX),
    /// or a custom `Data` implementation leaves its buffer shorter than the
    /// message.
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
        )
        .expect("allocated ciphertext length matches message length");

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
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is shorter than one authentication tag or
    /// the tag cannot be converted to `Mac`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let (tag, data) = split_prefix(bytes, CRYPTO_SECRETBOX_MACBYTES, ErrorContext::SecretBox)?;
        Ok(Self {
            tag: Mac::try_from(tag)
                .map_err(|_| Error::invalid_encoding(ErrorContext::AuthenticationTag))?,
            data: Data::from(data),
        })
    }
}

impl<Mac: ByteArray<CRYPTO_SECRETBOX_MACBYTES> + Zeroize, Data: Bytes + Zeroize>
    DryocSecretBox<Mac, Data>
{
    /// Returns a new box with `tag` and `data`, consuming both.
    pub fn from_parts(tag: Mac, data: Data) -> Self {
        Self { tag, data }
    }

    /// Copies `self` into a new [`Vec`].
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
    /// Decrypts this box using `secret_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the output storage is shorter than the ciphertext
    /// or authentication fails. Authentication fails when the key, nonce, tag,
    /// or ciphertext does not match the value used during encryption.
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
        concat_bytes(self.tag.as_array(), self.data.as_slice())
    }
}

impl DryocSecretBox<Mac, Vec<u8>> {
    /// Encrypts a message using `secret_key` and returns a new
    /// [`DryocSecretBox`] with ciphertext and tag.
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

    /// Decrypts this box using `secret_key` and returns the plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails because the key, nonce, tag,
    /// or ciphertext does not match.
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

    /// Consumes this box and returns `tag || ciphertext` as a [`Vec`].
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
    /// Returns a new box with ciphertext copied from `input` and the supplied
    /// `tag`.
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
        ct_eq_bytes(self.tag.as_slice(), other.tag.as_slice())
            && ct_eq_bytes(self.data.as_slice(), other.data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NaCl `tests/secretbox.c` vector: `firstkey`, `nonce`, the 131-byte
    /// message, and the 147-byte `tag || ciphertext` output.
    const NACL_KEY: &str = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
    const NACL_NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    const NACL_MESSAGE: &str = concat!(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d4",
        "5e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a",
        "024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
    );
    const NACL_BOXED: &str = concat!(
        "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c5",
        "31a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8a",
        "b932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622",
        "a43d14a6599b1f654cb45a74e355a5",
    );

    fn nacl_vector() -> (Key, Nonce, Vec<u8>, Vec<u8>) {
        let key = Key::try_from(hex::decode(NACL_KEY).expect("key hex").as_slice()).expect("key");
        let nonce =
            Nonce::try_from(hex::decode(NACL_NONCE).expect("nonce hex").as_slice()).expect("nonce");
        (
            key,
            nonce,
            hex::decode(NACL_MESSAGE).expect("message hex"),
            hex::decode(NACL_BOXED).expect("boxed hex"),
        )
    }

    #[test]
    fn nacl_vector_encrypts_to_known_bytes_and_parses_back() {
        let (key, nonce, message, boxed) = nacl_vector();

        let dryocsecretbox = DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &key);
        assert_eq!(dryocsecretbox.to_vec(), boxed);
        assert_eq!(dryocsecretbox.clone().into_vec(), boxed);
        assert_eq!(
            dryocsecretbox.tag.as_slice(),
            &boxed[..CRYPTO_SECRETBOX_MACBYTES]
        );
        assert_eq!(dryocsecretbox.data, boxed[CRYPTO_SECRETBOX_MACBYTES..]);

        let parsed = VecBox::from_bytes(&boxed).expect("known-good box should parse");
        assert_eq!(parsed, dryocsecretbox);
        assert_eq!(
            parsed.decrypt_to_vec(&nonce, &key).expect("decrypt failed"),
            message
        );

        let (tag, data) = boxed.split_at(CRYPTO_SECRETBOX_MACBYTES);
        let rebuilt: VecBox =
            DryocSecretBox::with_data_and_mac(Mac::try_from(tag).expect("mac"), data);
        assert_eq!(rebuilt, dryocsecretbox);
        let (rebuilt_tag, rebuilt_data) = rebuilt.into_parts();
        assert_eq!(
            VecBox::from_parts(rebuilt_tag, rebuilt_data).to_vec(),
            boxed
        );

        let mut with_data: VecBox = DryocSecretBox::with_data(data);
        assert_eq!(with_data.tag, Mac::default());
        with_data.tag = Mac::try_from(tag).expect("mac");
        assert_eq!(with_data.to_vec(), boxed);
    }

    #[test]
    fn from_bytes_requires_a_full_tag() {
        for len in 0..CRYPTO_SECRETBOX_MACBYTES {
            assert!(matches!(
                VecBox::from_bytes(&vec![0u8; len]),
                Err(Error::InvalidLength {
                    context: ErrorContext::SecretBox,
                    actual,
                    ..
                }) if actual == len
            ));
        }
        let empty = VecBox::from_bytes(&[0xa5u8; CRYPTO_SECRETBOX_MACBYTES])
            .expect("a lone tag is an empty box");
        assert!(empty.data.is_empty());
        assert_eq!(empty.tag.as_slice(), &[0xa5u8; CRYPTO_SECRETBOX_MACBYTES]);
    }

    #[test]
    fn tampering_is_rejected_and_the_box_stays_usable() {
        let (key, nonce, message, boxed) = nacl_vector();
        let dryocsecretbox = VecBox::from_bytes(&boxed).expect("parse");

        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;
        assert!(matches!(
            dryocsecretbox.decrypt_to_vec(&nonce, &wrong_key),
            Err(Error::AuthenticationFailed)
        ));

        let mut wrong_nonce = nonce.clone();
        wrong_nonce[CRYPTO_SECRETBOX_NONCEBYTES - 1] ^= 1;
        assert!(matches!(
            dryocsecretbox.decrypt_to_vec(&wrong_nonce, &key),
            Err(Error::AuthenticationFailed)
        ));

        for index in [
            0,
            CRYPTO_SECRETBOX_MACBYTES - 1,
            CRYPTO_SECRETBOX_MACBYTES,
            boxed.len() - 1,
        ] {
            let mut tampered = boxed.clone();
            tampered[index] ^= 0x80;
            let tampered = VecBox::from_bytes(&tampered).expect("parse");
            assert!(matches!(
                tampered.decrypt_to_vec(&nonce, &key),
                Err(Error::AuthenticationFailed)
            ));
        }

        let truncated = VecBox::from_bytes(&boxed[..boxed.len() - 1]).expect("parse");
        assert!(truncated.decrypt_to_vec(&nonce, &key).is_err());

        // Rejections leave the box untouched and decryptable.
        assert_eq!(dryocsecretbox.to_vec(), boxed);
        assert_eq!(
            dryocsecretbox
                .decrypt_to_vec(&nonce, &key)
                .expect("decrypt"),
            message
        );
    }

    #[test]
    fn empty_message_produces_a_bare_tag_that_authenticates() {
        let (key, nonce, _, _) = nacl_vector();
        let empty = DryocSecretBox::encrypt_to_vecbox(&[], &nonce, &key);
        let bytes = empty.to_vec();
        assert_eq!(bytes.len(), CRYPTO_SECRETBOX_MACBYTES);

        let parsed = VecBox::from_bytes(&bytes).expect("parse");
        assert!(
            parsed
                .decrypt_to_vec(&nonce, &key)
                .expect("decrypt")
                .is_empty()
        );
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;
        assert!(parsed.decrypt_to_vec(&nonce, &wrong_key).is_err());
    }

    #[cfg(all(feature = "protected", any(unix, windows)))]
    #[test]
    fn locked_box_matches_stack_box_bytes() {
        use crate::protected::*;

        let (key, nonce, message, boxed) = nacl_vector();
        let locked_key =
            protected::Key::from_slice_into_readonly_locked(key.as_slice()).expect("lock key");
        let locked_nonce = protected::Nonce::from_slice_into_readonly_locked(nonce.as_slice())
            .expect("lock nonce");
        let locked_message =
            HeapBytes::from_slice_into_readonly_locked(&message).expect("lock message");

        let locked: protected::LockedBox =
            DryocSecretBox::encrypt(&locked_message, &locked_nonce, &locked_key);
        assert_eq!(locked.to_vec(), boxed);

        let decrypted: LockedBytes = locked
            .decrypt(&locked_nonce, &locked_key)
            .expect("decrypt failed");
        assert_eq!(decrypted.as_slice(), message.as_slice());

        let parsed: protected::LockedBox = DryocSecretBox::from_parts(
            protected::Mac::from_slice_into_locked(&boxed[..CRYPTO_SECRETBOX_MACBYTES])
                .expect("lock tag"),
            HeapBytes::from_slice_into_locked(&boxed[CRYPTO_SECRETBOX_MACBYTES..])
                .expect("lock data"),
        );
        let decrypted: Vec<u8> = parsed.decrypt(&nonce, &key).expect("decrypt failed");
        assert_eq!(decrypted, message);
    }

    #[cfg(dryoc_native_tests)]
    mod native_tests {
        use super::*;
        use crate::native_test_util as sodium;

        #[test]
        fn nacl_vector_matches_libsodium() {
            let (key, nonce, message, boxed) = nacl_vector();
            let so_ciphertext = sodium::secretbox_easy(&message, &nonce, &key);
            assert_eq!(so_ciphertext, boxed);
        }

        #[test]
        fn libsodium_ciphertext_parses_and_decrypts() {
            let (key, nonce, message, _) = nacl_vector();

            for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, message.len()] {
                let plaintext = &message[..len];
                let so_ciphertext = sodium::secretbox_easy(plaintext, &nonce, &key);

                let dryocsecretbox =
                    VecBox::from_bytes(&so_ciphertext).expect("sodium box should parse");
                assert_eq!(
                    dryocsecretbox
                        .decrypt_to_vec(&nonce, &key)
                        .expect("decrypt failed"),
                    plaintext
                );
                assert_eq!(dryocsecretbox.to_vec(), so_ciphertext);

                let mut wrong_key = key.clone();
                wrong_key[len % CRYPTO_SECRETBOX_KEYBYTES] ^= 1;
                assert!(dryocsecretbox.decrypt_to_vec(&nonce, &wrong_key).is_err());
            }
        }

        #[cfg(all(feature = "protected", any(unix, windows)))]
        #[test]
        fn libsodium_ciphertext_decrypts_into_locked_box() {
            use crate::protected::*;

            let (key, nonce, message, boxed) = nacl_vector();
            let locked: protected::LockedBox = DryocSecretBox::from_parts(
                protected::Mac::from_slice_into_locked(&boxed[..CRYPTO_SECRETBOX_MACBYTES])
                    .expect("lock tag"),
                HeapBytes::from_slice_into_locked(&boxed[CRYPTO_SECRETBOX_MACBYTES..])
                    .expect("lock data"),
            );
            let decrypted: LockedBytes = locked.decrypt(&nonce, &key).expect("decrypt failed");
            assert_eq!(decrypted.as_slice(), message.as_slice());

            let so_decrypted = sodium::secretbox_open_easy(&locked.to_vec(), &nonce, &key)
                .expect("sodium open failed");
            assert_eq!(so_decrypted, message);
        }

        #[test]
        fn test_dryocbox() {
            for i in 0..20 {
                use base64::Engine as _;
                use base64::engine::general_purpose;

                use crate::dryocsecretbox::*;

                let secret_key = Key::generate();
                let nonce = Nonce::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ").into_bytes();
                let message_copy = message.clone();
                let dryocsecretbox: VecBox = DryocSecretBox::encrypt(&message, &nonce, &secret_key);

                let ciphertext = dryocsecretbox.clone().into_vec();
                assert_eq!(&ciphertext, &dryocsecretbox.to_vec());

                let ciphertext_copy = ciphertext.clone();

                let so_ciphertext = sodium::secretbox_easy(&message_copy, &nonce, &secret_key);
                assert_eq!(
                    general_purpose::STANDARD.encode(&ciphertext),
                    general_purpose::STANDARD.encode(&so_ciphertext)
                );

                let so_decrypted =
                    sodium::secretbox_open_easy(&ciphertext_copy, &nonce, &secret_key)
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
                use base64::Engine as _;
                use base64::engine::general_purpose;

                use crate::dryocsecretbox::*;

                let secret_key = Key::generate();
                let nonce = Nonce::generate();
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ").into_bytes();
                let message_copy = message.clone();
                let dryocsecretbox =
                    DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &secret_key);

                let ciphertext = dryocsecretbox.clone().into_vec();
                assert_eq!(&ciphertext, &dryocsecretbox.to_vec());

                let ciphertext_copy = ciphertext.clone();

                let so_ciphertext = sodium::secretbox_easy(&message_copy, &nonce, &secret_key);
                assert_eq!(
                    general_purpose::STANDARD.encode(&ciphertext),
                    general_purpose::STANDARD.encode(&so_ciphertext)
                );

                let so_decrypted =
                    sodium::secretbox_open_easy(&ciphertext_copy, &nonce, &secret_key)
                        .expect("decrypt failed");

                let m = dryocsecretbox
                    .decrypt_to_vec(&nonce, &secret_key)
                    .expect("decrypt failed");
                assert_eq!(m, message_copy);
                assert_eq!(m, so_decrypted);
            }
        }

        #[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
        #[cfg(all(feature = "protected", any(unix, windows)))]
        #[test]
        fn test_dryocbox_locked() {
            for i in 0..20 {
                use base64::Engine as _;
                use base64::engine::general_purpose;

                use crate::dryocsecretbox::*;
                use crate::protected::*;

                let secret_key = protected::Key::generate_locked().expect("generate failed");
                let nonce = protected::Nonce::generate_locked().expect("generate failed");
                let words = vec!["hello1".to_string(); i];
                let message = words.join(" :D ");
                let message_copy = message.clone();
                let dryocsecretbox: protected::LockedBox =
                    DryocSecretBox::encrypt(message.as_bytes(), &nonce, &secret_key);

                let ciphertext = dryocsecretbox.to_vec();

                let ciphertext_copy = ciphertext.clone();

                let so_ciphertext = sodium::secretbox_easy(
                    message_copy.as_bytes(),
                    nonce.as_slice(),
                    secret_key.as_slice(),
                );
                assert_eq!(
                    general_purpose::STANDARD.encode(&ciphertext),
                    general_purpose::STANDARD.encode(&so_ciphertext)
                );

                let so_decrypted = sodium::secretbox_open_easy(
                    &ciphertext_copy,
                    nonce.as_slice(),
                    secret_key.as_slice(),
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
}

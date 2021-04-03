/*!
# Public-key authenticated encryption

_For secret-key based encryption, see [dryocsecretbox](crate::dryocsecretbox)_.

_For stream encryption, see [dryocstream](crate::dryocstream)_.

# Rustaceous API example

```
use dryoc::dryocbox::*;

let sender_keypair = KeyPair::gen();
let recipient_keypair = KeyPair::gen();
let nonce = Nonce::gen();
let message = b"hey";

let dryocbox = DryocBox::encrypt_to_vecbox(
    message,
    &nonce,
    &recipient_keypair.public_key,
    &sender_keypair.secret_key,
)
.expect("unable to encrypt");

let decrypted = dryocbox
    .decrypt_to_vec(&nonce, &sender_keypair.public_key, &recipient_keypair.secret_key)
    .expect("unable to decrypt");

assert_eq!(message, decrypted.as_slice());
```
*/

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(any(feature = "serde", feature = "base64"))]
use crate::bytes_serde::*;
use crate::constants::{
    CRYPTO_BOX_MACBYTES, CRYPTO_BOX_NONCEBYTES, CRYPTO_BOX_PUBLICKEYBYTES,
    CRYPTO_BOX_SECRETKEYBYTES,
};
use crate::error::Error;
pub use crate::keypair::KeyPair;
pub use crate::types::*;

/// A secret for authenticated secret streams.
pub type SecretKey = StackByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
/// A secret for authenticated secret streams.
pub type PublicKey = StackByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
/// A nonce for authenticated secret streams.
pub type Nonce = StackByteArray<CRYPTO_BOX_NONCEBYTES>;
/// Container for crypto secret box message authentication code.
pub type Mac = StackByteArray<CRYPTO_BOX_MACBYTES>;

#[cfg(any(feature = "nightly", doc))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "nightly")))]
/// Type aliases for using protected memory with [DryocSecretBox].
pub mod protected {
    use super::*;
    pub use crate::protected::*;

    /// A secret for authenticated secret streams.
    pub type SecretKey = HeapByteArray<CRYPTO_BOX_SECRETKEYBYTES>;
    /// A secret for authenticated secret streams.
    pub type PublicKey = HeapByteArray<CRYPTO_BOX_PUBLICKEYBYTES>;
    /// A nonce for authenticated secret streams.
    pub type Nonce = HeapByteArray<CRYPTO_BOX_NONCEBYTES>;
    /// Container for crypto secret box message authentication code.
    pub type Mac = HeapByteArray<CRYPTO_BOX_MACBYTES>;

    pub type LockedSecretKey = Protected<SecretKey, ReadWrite, Locked>;
    pub type LockedReadOnlySecretKey = Protected<SecretKey, ReadOnly, Locked>;
    pub type NoAccessSecretKey = Protected<SecretKey, NoAccess, Unlocked>;
    pub type LockedNonce = Protected<Nonce, ReadWrite, Locked>;
    pub type LockedMac = Protected<Mac, ReadWrite, Locked>;

    pub type LockedBox = DryocBox<LockedMac, LockedBytes>;
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Zeroize, Clone, Debug)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A libsodium public-key authenticated encrypted box
pub struct DryocBox<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> {
    /// libsodium box authentication tag, usually prepended to each box
    tag: Mac,
    /// libsodium box message or ciphertext, depending on state
    data: Data,
}

pub type VecBox = DryocBox<StackByteArray<CRYPTO_BOX_MACBYTES>, Vec<u8>>;

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Default, Data: Bytes + Default> DryocBox<Mac, Data> {
    /// Returns an empty box
    pub fn new() -> Self {
        Self {
            tag: Mac::default(),
            data: Data::default(),
        }
    }
}

impl<Mac: MutByteArray<CRYPTO_BOX_MACBYTES> + Default, Data: MutBytes + Default + ResizableBytes>
    DryocBox<Mac, Data>
{
    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag
    pub fn encrypt<
        Message: Bytes,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Default,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Default,
    >(
        message: Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        use crate::crypto_box::*;

        let mut dryocbox = Self::new();
        dryocbox.data.resize(message.as_slice().len(), 0);

        crypto_box_detached(
            dryocbox.data.as_mut_slice(),
            dryocbox.tag.as_mut_array(),
            message.as_slice(),
            nonce.as_array(),
            recipient_public_key.as_array(),
            sender_secret_key.as_array(),
        )?;

        Ok(dryocbox)
    }
}

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Default, Data: Bytes> DryocBox<Mac, Data> {
    /// Returns a box with an empty `tag`, and data from `data`, consuming
    /// `data`
    pub fn from_data(data: Data) -> Self {
        Self {
            tag: Mac::default(),
            data,
        }
    }
}

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> DryocBox<Mac, Data> {
    /// Returns a new box with `tag` and `data`, consuming both
    pub fn from_data_and_mac(tag: Mac, data: Data) -> Self {
        Self { tag, data }
    }
}

impl<Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes> DryocBox<Mac, Data> {
    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocBox] with decrypted message
    pub fn decrypt<
        Output: Default + ResizableBytes + MutBytes,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Default,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Default,
    >(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Output, Error> {
        use crate::crypto_box::*;

        let mut message = Output::default();
        message.resize(self.data.as_slice().len(), 0);

        crypto_box_open_detached(
            message.as_mut_slice(),
            self.tag.as_array(),
            self.data.as_slice(),
            nonce.as_array(),
            sender_public_key.as_array(),
            recipient_secret_key.as_array(),
        )?;

        Ok(message)
    }

    /// Copies this box into a new Vec
    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.tag.as_slice());
        data.extend(self.data.as_slice());
        data
    }
}

impl DryocBox<Mac, Vec<u8>> {
    pub fn new_vecbox() -> Self {
        Self::new()
    }

    /// Encrypts a message using `sender_secret_key` for `recipient_public_key`,
    /// and returns a new [DryocBox] with ciphertext and tag
    pub fn encrypt_to_vecbox<
        Message: Bytes,
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Default,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Default,
    >(
        message: Message,
        nonce: &Nonce,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<Self, Error> {
        Self::encrypt(message, nonce, recipient_public_key, sender_secret_key)
    }

    /// Decrypts `ciphertext` using `recipient_secret_key` and
    /// `sender_public_key`, returning a new [DryocBox] with decrypted message
    pub fn decrypt_to_vec<
        PublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES> + Default,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES> + Default,
    >(
        &self,
        nonce: &Nonce,
        sender_public_key: &PublicKey,
        recipient_secret_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        self.decrypt(nonce, sender_public_key, recipient_secret_key)
    }

    /// Consumes this box and returns it as a Vec
    pub fn into_vec(mut self) -> Vec<u8> {
        self.data.resize(self.data.len() + CRYPTO_BOX_MACBYTES, 0);
        self.data.rotate_right(CRYPTO_BOX_MACBYTES);
        self.data[0..CRYPTO_BOX_MACBYTES].copy_from_slice(&self.tag);
        self.data
    }
}

impl<'a, Mac: ByteArray<CRYPTO_BOX_MACBYTES> + Default, Data: Bytes + From<&'a [u8]>>
    DryocBox<Mac, Data>
{
    /// Returns a box with `data` copied from slice `input`.
    pub fn with_data(input: &'a [u8]) -> Self {
        Self {
            tag: Mac::default(),
            data: input.into(),
        }
    }
}

impl<'a, Mac: ByteArray<CRYPTO_BOX_MACBYTES>, Data: Bytes + From<&'a [u8]>> DryocBox<Mac, Data> {
    /// Returns a new box with `data` and `tag`, with data copied from `input`
    /// and `tag` consumed.
    pub fn with_data_and_mac(tag: Mac, input: &'a [u8]) -> Self {
        Self {
            tag,
            data: input.into(),
        }
    }
}

impl<Mac: MutByteArray<CRYPTO_BOX_MACBYTES> + Default, Data: MutBytes + Default + ResizableBytes>
    Default for DryocBox<Mac, Data>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_eq<T>(t: &[T], v: T) -> bool
    where
        T: PartialEq,
    {
        t.iter().fold(true, |acc, x| acc && *x == v)
    }

    #[test]
    fn test_new() {
        let dryocbox: VecBox = DryocBox::new();

        assert_eq!(all_eq(&dryocbox.tag, 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);

        let dryocbox = DryocBox::new_vecbox();

        assert_eq!(all_eq(&dryocbox.tag, 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_default() {
        let dryocbox: VecBox = DryocBox::default();

        assert_eq!(all_eq(&dryocbox.tag, 0), true);
        assert_eq!(all_eq(&dryocbox.data, 0), true);
    }

    #[test]
    fn test_dryocbox_vecbox() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{Nonce as SONonce, PublicKey, SecretKey};

            use crate::keypair::*;

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocbox = DryocBox::encrypt_to_vecbox(
                message.as_bytes(),
                &nonce,
                keypair_recipient.public_key.as_array(),
                keypair_sender.secret_key.as_array(),
            )
            .unwrap();

            let ciphertext = dryocbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocbox.to_vec());

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let keypair_sender = keypair_sender_copy.clone();
            let keypair_recipient = keypair_recipient_copy.clone();

            let m = dryocbox
                .decrypt_to_vec(
                    &nonce,
                    &keypair_sender.public_key,
                    &keypair_recipient.secret_key,
                )
                .expect("hmm");
            let so_m = box_::open(
                &ciphertext,
                &SONonce::from_slice(&nonce).unwrap(),
                &PublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                &SecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
            )
            .expect("HMMM");

            assert_eq!(m, message_copy.as_bytes());
            assert_eq!(m, so_m);
        }
    }

    #[test]
    fn test_decrypt_failure() {
        for i in 0..20 {
            use base64::encode;
            use sodiumoxide::crypto::box_;
            use sodiumoxide::crypto::box_::{
                Nonce as SONonce, PublicKey as SOPublicKey, SecretKey as SOSecretKey,
            };

            use crate::keypair::*;

            let keypair_sender = KeyPair::gen();
            let keypair_recipient = KeyPair::gen();
            let keypair_sender_copy = keypair_sender.clone();
            let keypair_recipient_copy = keypair_recipient.clone();
            let nonce = Nonce::gen();
            let words = vec!["hello1".to_string(); i];
            let message = words.join(" :D ");
            let message_copy = message.clone();
            let dryocbox = DryocBox::encrypt(
                message.as_bytes(),
                &nonce,
                &keypair_recipient.public_key,
                &keypair_sender.secret_key,
            )
            .unwrap();

            let ciphertext = dryocbox.clone().into_vec();
            assert_eq!(&ciphertext, &dryocbox.to_vec());

            let so_ciphertext = box_::seal(
                message_copy.as_bytes(),
                &SONonce::from_slice(&nonce).unwrap(),
                &SOPublicKey::from_slice(&keypair_recipient_copy.public_key).unwrap(),
                &SOSecretKey::from_slice(&keypair_sender_copy.secret_key).unwrap(),
            );

            assert_eq!(encode(&ciphertext), encode(&so_ciphertext));

            let invalid_key = KeyPair::gen();
            let invalid_key_copy_1 = invalid_key.clone();
            let invalid_key_copy_2 = invalid_key.clone();

            DryocBox::decrypt::<Vec<u8>, crate::crypto_box::PublicKey, crate::crypto_box::SecretKey>(
                &dryocbox,
                &nonce,
                &invalid_key_copy_1.public_key,
                &invalid_key_copy_2.secret_key,
            )
            .expect_err("hmm");
            box_::open(
                &ciphertext,
                &SONonce::from_slice(&nonce).unwrap(),
                &SOPublicKey::from_slice(&invalid_key.public_key).unwrap(),
                &SOSecretKey::from_slice(&invalid_key.secret_key).unwrap(),
            )
            .expect_err("HMMM");
        }
    }

    #[test]
    fn test_decrypt_failure_empty() {
        for _ in 0..20 {
            use crate::keypair::*;

            let invalid_key = KeyPair::gen();
            let invalid_key_copy_1 = invalid_key.clone();
            let invalid_key_copy_2 = invalid_key.clone();
            let nonce = Nonce::gen();

            let dryocbox: VecBox = DryocBox::from_data("lol".as_bytes().into());
            DryocBox::decrypt::<Vec<u8>, crate::crypto_box::PublicKey, crate::crypto_box::SecretKey>(
                &dryocbox,
                    &nonce,
                    &invalid_key_copy_1.public_key,
                    &invalid_key_copy_2.secret_key,
                )
                .expect_err("hmm");
        }
    }

    #[test]
    fn test_copy() {
        for _ in 0..20 {
            use crate::rng::*;

            let mut data1: Vec<u8> = vec![0u8; 1024];
            copy_randombytes(data1.as_mut_slice());
            let data1_copy = data1.clone();

            let dryocbox: VecBox = DryocBox::from_data(data1);
            assert_eq!(&dryocbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let dryocbox: VecBox = DryocBox::with_data(&data1);
            assert_eq!(&dryocbox.data, &data1_copy);

            let data1 = data1_copy.clone();
            let tag = Mac::default();
            let dryocbox: VecBox = DryocBox::with_data_and_mac(tag, &data1);
            assert_eq!(dryocbox.data.as_slice(), &data1_copy);
            assert_eq!(dryocbox.tag.as_array(), &[0u8; CRYPTO_BOX_MACBYTES]);
        }
    }
}

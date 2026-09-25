//! # Post-quantum sealed boxes
//!
//! [`DryocSealedBox`] encrypts a message to a recipient's [`kem`](crate::kem)
//! public key so that only the holder of the matching secret key can read
//! it. Like [`DryocBox::seal`](crate::dryocbox::DryocBox::seal), it is
//! anonymous: the sender needs no key pair, and the box does not identify the
//! sender. Unlike it, the key agreement uses X-Wing, the hybrid of ML-KEM-768
//! and X25519, so recorded boxes stay confidential even if a quantum computer
//! later breaks X25519.
//!
//! Moving from [`DryocBox::seal`](crate::dryocbox::DryocBox::seal) takes two
//! changes: generate the recipient's key pair with [`KeyPair`] from this
//! module (a [`kem`](crate::kem) key pair), and use [`DryocSealedBox`] in
//! place of [`DryocBox`](crate::dryocbox::DryocBox). The method names are the
//! same. Boxes are larger: 1136 bytes of overhead instead of 48.
//!
//! ## Format
//!
//! The format is dryoc's application profile of [HPKE (RFC 9180)][rfc9180],
//! which leaves the wire encoding to applications (section 10). The profile
//! is base mode, single-shot, with an empty `info`, empty associated data and
//! one fixed ciphersuite:
//!
//! * KEM `0x647A`, [X-Wing][xwing], as registered by IANA. The registry cites
//!   draft-connolly-cfrg-xwing-kem-06; the draft's test vectors are identical
//!   from -05 through -11.
//! * KDF `0x0001`, HKDF-SHA256.
//! * AEAD `0x0003`, ChaCha20-Poly1305.
//!
//! A box is HPKE's `(enc, ct)` output concatenated: `enc` (the 1120-byte
//! X-Wing ciphertext), then the AEAD ciphertext, then its 16-byte tag. The box
//! carries no suite identifier. Any HPKE implementation that supports this
//! ciphersuite can open it. The tests check the implementation against the
//! known-answer vector in [draft-ietf-hpke-pq-05][hpke-pq] Appendix A.5.
//! [draft-ietf-hpke-hpke-04][hpke-hpke], the RFC 9180 revision in IESG review,
//! is backwards-compatible with RFC 9180 for this ciphersuite.
//!
//! This byte format, written by [`DryocSealedBox::to_vec`] and read by
//! [`DryocSealedBox::from_bytes`], is stable for the 2.x series. A different
//! ciphersuite or profile would be a new type, so existing boxes stay readable.
//!
//! With the `serde` feature,
//! [`serde::Deserialize`](https://docs.rs/serde/latest/serde/trait.Deserialize.html) and
//! [`serde::Serialize`](https://docs.rs/serde/latest/serde/trait.Serialize.html) are implemented
//! for [`DryocSealedBox`] as a struct with the fields `enc`, `tag` and `data`,
//! in that order. That representation is separate from the byte format above;
//! use the byte format to exchange boxes with other HPKE implementations.
//!
//! [rfc9180]: https://www.rfc-editor.org/rfc/rfc9180.html
//! [xwing]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
//! [hpke-pq]: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/05/
//! [hpke-hpke]: https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/04/
//!
//! ## Example
//!
//! ```
//! use dryoc::dryocsealedbox::*;
//!
//! let recipient_keypair = KeyPair::generate_with_defaults();
//! let message = b"Now is the winter of our discontent.";
//!
//! let sealed = DryocSealedBox::seal_to_vecbox(message, &recipient_keypair.public_key)
//!     .expect("unable to seal");
//!
//! // Serialize, send, and read the box back.
//! let bytes = sealed.to_vec();
//! let sealed = VecBox::from_bytes(&bytes).expect("unable to read box");
//!
//! let decrypted = sealed
//!     .unseal_to_vec(&recipient_keypair)
//!     .expect("unable to unseal");
//! assert_eq!(message, decrypted.as_slice());
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::classic::crypto_aead_chacha20poly1305_ietf::{
    crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    crypto_aead_chacha20poly1305_ietf_encrypt_detached,
};
use crate::classic::crypto_kdf::{
    crypto_kdf_hkdf_sha256_expand, crypto_kdf_hkdf_sha256_extract_final,
    crypto_kdf_hkdf_sha256_extract_init, crypto_kdf_hkdf_sha256_extract_update,
};
use crate::classic::crypto_kem_xwing;
use crate::constants::{
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES,
    CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, CRYPTO_KDF_HKDF_SHA256_KEYBYTES,
    CRYPTO_KEM_XWING_CIPHERTEXTBYTES, CRYPTO_KEM_XWING_ENCSEEDBYTES,
    CRYPTO_KEM_XWING_PUBLICKEYBYTES, CRYPTO_KEM_XWING_SECRETKEYBYTES,
    CRYPTO_KEM_XWING_SHAREDSECRETBYTES,
};
use crate::error::{Error, ErrorContext};
pub use crate::kem::xwing::{KeyPair, PublicKey, SecretKey, StackKeyPair};
use crate::mlkem::Arith;
use crate::rng::copy_randombytes;
pub use crate::types::*;

/// Stack-allocated X-Wing ciphertext that carries the box's key (HPKE's
/// `enc`).
pub type EncapsulatedKey = StackByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES>;
/// Stack-allocated authentication tag.
pub type Mac = StackByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES>;

/// Bytes a sealed box adds to its message.
pub const SEALBYTES: usize =
    CRYPTO_KEM_XWING_CIPHERTEXTBYTES + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;

#[cfg(any(all(feature = "protected", any(unix, windows)), all(doc, not(doctest))))]
#[cfg_attr(all(feature = "nightly", doc), doc(cfg(feature = "protected")))]
pub mod protected {
    //! # Protected memory type aliases for [`DryocSealedBox`]
    //!
    //! ```
    //! use dryoc::dryocsealedbox::DryocSealedBox;
    //! use dryoc::dryocsealedbox::protected::*;
    //!
    //! let recipient_keypair = LockedROKeyPair::generate_readonly_locked_keypair().expect("keypair");
    //! let message = HeapBytes::from_slice_into_readonly_locked(b"Secret message").expect("message");
    //!
    //! let sealed: LockedBox =
    //!     DryocSealedBox::seal(&message, &recipient_keypair.public_key).expect("seal");
    //! let decrypted: LockedBytes = sealed.unseal(&recipient_keypair).expect("unseal");
    //! assert_eq!(message.as_slice(), decrypted.as_slice());
    //! ```
    use super::DryocSealedBox;
    use crate::constants::{
        CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES, CRYPTO_KEM_XWING_CIPHERTEXTBYTES,
    };
    pub use crate::kem::xwing::protected::*;

    /// Heap-allocated X-Wing ciphertext, for use with protected memory.
    pub type EncapsulatedKey = HeapByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES>;
    /// Heap-allocated authentication tag, for use with protected memory.
    pub type Mac = HeapByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES>;
    /// Locked [`DryocSealedBox`].
    pub type LockedBox = DryocSealedBox<Locked<EncapsulatedKey>, Locked<Mac>, LockedBytes>;
}

#[cfg_attr(
    feature = "serde",
    derive(Zeroize, Clone, Debug, Serialize, Deserialize)
)]
#[cfg_attr(not(feature = "serde"), derive(Zeroize, Clone, Debug))]
/// A post-quantum sealed box: an HPKE-encrypted message for one recipient.
///
/// Refer to [crate::dryocsealedbox] for the byte format and sample usage.
pub struct DryocSealedBox<
    EncapsulatedKey: ByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES> + Zeroize,
    Data: Bytes + Zeroize,
> {
    enc: EncapsulatedKey,
    tag: Mac,
    data: Data,
}

/// [Vec]-based sealed box.
pub type VecBox = DryocSealedBox<EncapsulatedKey, Mac, Vec<u8>>;

/// HPKE's `suite_id` for X-Wing, HKDF-SHA256 and ChaCha20-Poly1305.
const SUITE_ID: &[u8; 10] = b"HPKE\x64\x7a\x00\x01\x00\x03";

type AeadKey = [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
type AeadNonce = [u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES];

/// HPKE `LabeledExtract(salt, label, ikm)`, written to `prk`.
fn labeled_extract(prk: &mut [u8; 32], salt: &[u8], label: &[u8], ikm: &[u8]) {
    let mut state = crypto_kdf_hkdf_sha256_extract_init(Some(salt));
    for part in [b"HPKE-v1".as_slice(), SUITE_ID, label, ikm] {
        crypto_kdf_hkdf_sha256_extract_update(&mut state, part);
    }
    crypto_kdf_hkdf_sha256_extract_final(state, prk);
}

/// HPKE `LabeledExpand(prk, label, info, output.len())`.
fn labeled_expand(output: &mut [u8], prk: &[u8; 32], label: &[u8], info: &[u8]) {
    let length = u16::try_from(output.len()).expect("short HPKE output");
    let labeled_info = [&length.to_be_bytes()[..], b"HPKE-v1", SUITE_ID, label, info].concat();
    crypto_kdf_hkdf_sha256_expand(output, &labeled_info, prk)
        .expect("HPKE output lengths are within HKDF's limit");
}

/// An HPKE encryption context at sequence number 0: the AEAD key and nonce.
/// Filled in place and wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Context {
    key: AeadKey,
    nonce: AeadNonce,
}

impl Context {
    fn new() -> Self {
        Self {
            key: [0u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES],
            nonce: [0u8; CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES],
        }
    }

    /// HPKE's base-mode key schedule for `shared_secret` and `info`.
    fn schedule(&mut self, shared_secret: &[u8], info: &[u8]) {
        let mut psk_id_hash = [0u8; CRYPTO_KDF_HKDF_SHA256_KEYBYTES];
        labeled_extract(&mut psk_id_hash, b"", b"psk_id_hash", b"");
        let mut info_hash = [0u8; CRYPTO_KDF_HKDF_SHA256_KEYBYTES];
        labeled_extract(&mut info_hash, b"", b"info_hash", info);
        let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
        let mut secret = Zeroizing::new([0u8; CRYPTO_KDF_HKDF_SHA256_KEYBYTES]);
        labeled_extract(&mut secret, shared_secret, b"secret", b"");
        labeled_expand(&mut self.key, &secret, b"key", &context);
        labeled_expand(&mut self.nonce, &secret, b"base_nonce", &context);
    }

    /// HPKE `SetupBaseS`: encapsulates to `public_key` with the randomness
    /// `seed`, writing `enc`. ML-KEM arithmetic comes from `arith`.
    fn setup_sender(
        &mut self,
        arith: Arith,
        enc: &mut [u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES],
        public_key: &[u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES],
        info: &[u8],
        seed: &[u8; CRYPTO_KEM_XWING_ENCSEEDBYTES],
    ) -> Result<(), Error> {
        let mut shared_secret = Zeroizing::new([0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES]);
        crypto_kem_xwing::enc_deterministic(arith, enc, &mut shared_secret, public_key, seed)?;
        self.schedule(&*shared_secret, info);
        Ok(())
    }

    /// HPKE `SetupBaseR`: decapsulates `enc`. ML-KEM arithmetic comes from
    /// `arith`.
    fn setup_receiver(
        &mut self,
        arith: Arith,
        enc: &[u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES],
        secret_key: &[u8; CRYPTO_KEM_XWING_SECRETKEYBYTES],
        info: &[u8],
    ) -> Result<(), Error> {
        let mut shared_secret = Zeroizing::new([0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES]);
        crypto_kem_xwing::dec(arith, &mut shared_secret, enc, secret_key)?;
        self.schedule(&*shared_secret, info);
        Ok(())
    }
}

impl<
    EncapsulatedKey: NewByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES> + Zeroize,
    Mac: NewByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES> + Zeroize,
    Data: NewBytes + ResizableBytes + Zeroize,
> DryocSealedBox<EncapsulatedKey, Mac, Data>
{
    /// Encrypts `message` for `recipient_public_key`, returning a new
    /// [`DryocSealedBox`].
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too long or `recipient_public_key`
    /// is not a valid X-Wing public key.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator fails.
    pub fn seal<
        Message: Bytes + ?Sized,
        RecipientPublicKey: ByteArray<CRYPTO_KEM_XWING_PUBLICKEYBYTES>,
    >(
        message: &Message,
        recipient_public_key: &RecipientPublicKey,
    ) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; CRYPTO_KEM_XWING_ENCSEEDBYTES]);
        copy_randombytes(seed.as_mut_slice());
        let mut sealed = Self {
            enc: EncapsulatedKey::new_byte_array(),
            tag: Mac::new_byte_array(),
            data: Data::new_bytes(),
        };
        sealed.data.resize(message.as_slice().len(), 0);
        let mut context = Context::new();
        context.setup_sender(
            Arith::detect(),
            sealed.enc.as_mut_array(),
            recipient_public_key.as_array(),
            b"",
            &seed,
        )?;
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            sealed.data.as_mut_slice(),
            sealed.tag.as_mut_array(),
            message.as_slice(),
            None,
            &context.nonce,
            &context.key,
        )?;
        Ok(sealed)
    }
}

impl<
    'a,
    EncapsulatedKey: ByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES> + TryFrom<&'a [u8]> + Zeroize,
    Mac: ByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES> + TryFrom<&'a [u8]> + Zeroize,
    Data: Bytes + From<&'a [u8]> + Zeroize,
> DryocSealedBox<EncapsulatedKey, Mac, Data>
{
    /// Reads a sealed box from its wire format: the X-Wing ciphertext, the
    /// encrypted message, then the tag.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is shorter than [`SEALBYTES`] or a field
    /// cannot be converted to its target type.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        validate_length!(min SEALBYTES, bytes.len(), ErrorContext::SealedBox);
        let (enc, rest) = bytes.split_at(CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
        let (data, tag) = rest.split_at(rest.len() - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
        Ok(Self {
            enc: EncapsulatedKey::try_from(enc)
                .map_err(|_| Error::invalid_encoding(ErrorContext::Ciphertext))?,
            tag: Mac::try_from(tag)
                .map_err(|_| Error::invalid_encoding(ErrorContext::AuthenticationTag))?,
            data: Data::from(data),
        })
    }
}

impl<
    EncapsulatedKey: ByteArray<CRYPTO_KEM_XWING_CIPHERTEXTBYTES> + Zeroize,
    Mac: ByteArray<CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES> + Zeroize,
    Data: Bytes + Zeroize,
> DryocSealedBox<EncapsulatedKey, Mac, Data>
{
    /// Returns a new box from its parts, consuming each.
    pub fn from_parts(enc: EncapsulatedKey, tag: Mac, data: Data) -> Self {
        Self { enc, tag, data }
    }

    /// Moves the X-Wing ciphertext, tag and encrypted message out of this
    /// box.
    pub fn into_parts(self) -> (EncapsulatedKey, Mac, Data) {
        (self.enc, self.tag, self.data)
    }

    /// Copies the box's wire format into a new [`Vec`].
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Copies the box's wire format into new `Bytes`.
    pub fn to_bytes<Bytes: NewBytes + ResizableBytes>(&self) -> Bytes {
        let mut bytes = Bytes::new_bytes();
        bytes.resize(SEALBYTES + self.data.len(), 0);
        let (enc, rest) = bytes
            .as_mut_slice()
            .split_at_mut(CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
        let (data, tag) = rest.split_at_mut(self.data.len());
        enc.copy_from_slice(self.enc.as_array());
        data.copy_from_slice(self.data.as_slice());
        tag.copy_from_slice(self.tag.as_array());
        bytes
    }

    /// Decrypts this box with `recipient_keypair`, returning the message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationFailed`] if the box was not sealed for
    /// this key pair or was modified, or an error if the X-Wing ciphertext
    /// carries a low-order X25519 point.
    pub fn unseal<
        RecipientPublicKey: ByteArray<CRYPTO_KEM_XWING_PUBLICKEYBYTES> + Zeroize,
        RecipientSecretKey: ByteArray<CRYPTO_KEM_XWING_SECRETKEYBYTES> + Zeroize,
        Output: ResizableBytes + NewBytes + Zeroize,
    >(
        &self,
        recipient_keypair: &KeyPair<RecipientPublicKey, RecipientSecretKey>,
    ) -> Result<Output, Error> {
        let mut message = Output::new_bytes();
        message.resize(self.data.len(), 0);
        let mut context = Context::new();
        context.setup_receiver(
            Arith::detect(),
            self.enc.as_array(),
            recipient_keypair.secret_key.as_array(),
            b"",
        )?;
        crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            message.as_mut_slice(),
            self.data.as_slice(),
            self.tag.as_array(),
            None,
            &context.nonce,
            &context.key,
        )?;
        Ok(message)
    }
}

impl DryocSealedBox<EncapsulatedKey, Mac, Vec<u8>> {
    /// Encrypts `message` for `recipient_public_key` into a [`VecBox`].
    /// Provided for convenience.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`DryocSealedBox::seal`].
    pub fn seal_to_vecbox<Message: Bytes + ?Sized>(
        message: &Message,
        recipient_public_key: &PublicKey,
    ) -> Result<Self, Error> {
        Self::seal(message, recipient_public_key)
    }

    /// Decrypts this box with `recipient_keypair` into a [`Vec`]. Provided
    /// for convenience.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`DryocSealedBox::unseal`].
    pub fn unseal_to_vec<
        RecipientPublicKey: ByteArray<CRYPTO_KEM_XWING_PUBLICKEYBYTES> + Zeroize,
        RecipientSecretKey: ByteArray<CRYPTO_KEM_XWING_SECRETKEYBYTES> + Zeroize,
    >(
        &self,
        recipient_keypair: &KeyPair<RecipientPublicKey, RecipientSecretKey>,
    ) -> Result<Vec<u8>, Error> {
        self.unseal(recipient_keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::tests::{field, records};

    /// draft-ietf-hpke-pq Appendix A.5: the X-Wing encapsulation and
    /// decapsulation, the key schedule and the first encryption, through the
    /// sender and receiver setups, on every ML-KEM backend the CPU supports.
    #[test]
    fn test_hpke_known_answer() {
        use crate::classic::crypto_aead_chacha20poly1305_ietf::{
            crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_encrypt,
        };

        let record = &records(include_str!(
            "mlkem/test-vectors/hpke_xwing_hkdfsha256_chacha20poly1305.txt"
        ))[0];
        let bytes = |key| hex::decode(record[key]).expect("hex");
        let (info, aad, message) = (bytes("info"), bytes("aad"), bytes("pt"));
        let (public_key, secret_key, seed) = (
            field(record, "pkRm"),
            field(record, "skRm"),
            field(record, "ikmE"),
        );
        let expected_enc: [u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES] = field(record, "enc");
        let expected_secret: [u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES] =
            field(record, "shared_secret");

        for arith in Arith::all() {
            let mut enc = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
            let mut shared_secret = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
            crypto_kem_xwing::enc_deterministic(
                arith,
                &mut enc,
                &mut shared_secret,
                &public_key,
                &seed,
            )
            .expect("enc");
            assert_eq!(enc, expected_enc, "{arith:?}");
            assert_eq!(shared_secret, expected_secret, "{arith:?}");
            let mut shared_secret = [0u8; CRYPTO_KEM_XWING_SHAREDSECRETBYTES];
            crypto_kem_xwing::dec(arith, &mut shared_secret, &expected_enc, &secret_key)
                .expect("dec");
            assert_eq!(shared_secret, expected_secret, "{arith:?}");

            let mut enc = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
            let mut sender = Context::new();
            sender
                .setup_sender(arith, &mut enc, &public_key, &info, &seed)
                .expect("sender");
            assert_eq!(enc, expected_enc, "{arith:?}");
            assert_eq!(sender.key, field::<32>(record, "key"), "{arith:?}");
            assert_eq!(sender.nonce, field::<12>(record, "base_nonce"), "{arith:?}");
            let mut ciphertext =
                vec![0u8; message.len() + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
            crypto_aead_chacha20poly1305_ietf_encrypt(
                &mut ciphertext,
                &message,
                Some(&aad),
                &sender.nonce,
                &sender.key,
            )
            .expect("encrypt");
            assert_eq!(ciphertext, bytes("ct"), "{arith:?}");

            let mut receiver = Context::new();
            receiver
                .setup_receiver(arith, &expected_enc, &secret_key, &info)
                .expect("receiver");
            assert_eq!(receiver.key, sender.key, "{arith:?}");
            assert_eq!(receiver.nonce, sender.nonce, "{arith:?}");
            let mut opened = vec![0u8; message.len()];
            crypto_aead_chacha20poly1305_ietf_decrypt(
                &mut opened,
                &ciphertext,
                Some(&aad),
                &receiver.nonce,
                &receiver.key,
            )
            .expect("decrypt");
            assert_eq!(opened, message, "{arith:?}");
        }
    }

    /// The wire format is `enc || ciphertext || tag`, a box for another key
    /// or with any byte changed fails to open, and short inputs are rejected.
    #[test]
    fn test_wire_format_and_tampering() {
        let keypair = StackKeyPair::generate();
        let message = b"All the world's a stage";
        let sealed = VecBox::seal_to_vecbox(message, &keypair.public_key).expect("seal");
        let bytes = sealed.to_vec();
        assert_eq!(bytes.len(), SEALBYTES + message.len());
        let (enc, tag, data) = sealed.clone().into_parts();
        assert_eq!(bytes, [enc.as_slice(), &data, tag.as_slice()].concat());

        for index in [
            0,
            CRYPTO_KEM_XWING_CIPHERTEXTBYTES - 1,
            bytes.len() - 20,
            bytes.len() - 1,
        ] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            let tampered = VecBox::from_bytes(&tampered).expect("parse");
            assert!(tampered.unseal_to_vec(&keypair).is_err(), "byte {index}");
        }
        let other = StackKeyPair::generate();
        assert!(matches!(
            sealed.unseal_to_vec(&other),
            Err(Error::AuthenticationFailed)
        ));
        for short in [0, CRYPTO_KEM_XWING_CIPHERTEXTBYTES, SEALBYTES - 1] {
            assert!(matches!(
                VecBox::from_bytes(&bytes[..short]),
                Err(Error::InvalidLength {
                    context: ErrorContext::SealedBox,
                    actual,
                    constraint: crate::error::LengthConstraint::AtLeast(SEALBYTES),
                }) if actual == short
            ));
        }
        let empty = VecBox::seal_to_vecbox(b"", &keypair.public_key).expect("seal");
        let empty = VecBox::from_bytes(&empty.to_vec()).expect("parse");
        assert!(empty.unseal_to_vec(&keypair).expect("unseal").is_empty());
    }
}

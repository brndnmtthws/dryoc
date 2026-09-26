//! Shared orchestration for the ChaCha20-Poly1305-IETF and
//! XChaCha20-Poly1305-IETF AEAD constructions.
//!
//! The two constructions differ only in how the ChaCha20 stream is derived
//! from the nonce and key, and in the message size bound that follows from
//! that stream's counter width. Each public module supplies those two pieces
//! to [`impl_chacha20poly1305_aead!`]; everything that is independent of the
//! stream lives here as ordinary functions.

use zeroize::Zeroize;

use crate::chacha20::ChaCha20;
use crate::constants::{CRYPTO_ONETIMEAUTH_POLY1305_BYTES, CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES};
use crate::error::Error;
use crate::poly1305::{Key as Poly1305Key, Poly1305};
use crate::utils::{pad16, verify_ct, zeroize_bytes};

/// Poly1305 tag; the `Mac` of every ChaCha20-Poly1305 construction.
pub(crate) type Tag = [u8; CRYPTO_ONETIMEAUTH_POLY1305_BYTES];

const PAD0: [u8; 16] = [0u8; 16];

/// Takes the Poly1305 key from block 0 of `cipher`, which must be positioned
/// at block 0; the returned cipher is positioned at block 1 for the message.
pub(crate) fn poly1305_key(mut cipher: ChaCha20) -> (ChaCha20, Poly1305Key) {
    let mut mac_key = Poly1305Key::new();
    cipher.apply_keystream(&mut mac_key);
    (cipher, mac_key)
}

/// Encrypts `message` into `ciphertext` (in place when `message` is `None`)
/// with `cipher`, which must be positioned at block 0, and returns the
/// Poly1305 key from block 0. Both come out of the same keystream runs, so
/// the key costs no separate scalar block.
pub(crate) fn encrypt_with_poly1305_key(
    mut cipher: ChaCha20,
    message: Option<&[u8]>,
    ciphertext: &mut [u8],
) -> Poly1305Key {
    encrypt_with_poly1305_key_into(&mut cipher, message, ciphertext)
}

/// [`encrypt_with_poly1305_key`] leaving `cipher` positioned after
/// `ciphertext` for more.
#[inline(always)]
fn encrypt_with_poly1305_key_into(
    cipher: &mut ChaCha20,
    message: Option<&[u8]>,
    ciphertext: &mut [u8],
) -> Poly1305Key {
    let mut block0 = [0u8; 64];
    match message {
        Some(message) => cipher.apply_keystream_b2b_with_head(&mut block0, message, ciphertext),
        None => cipher.apply_keystream_with_head(&mut block0, ciphertext),
    }
    let mut mac_key = Poly1305Key::new();
    mac_key.copy_from_slice(&block0[..CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES]);
    zeroize_bytes(&mut block0);
    mac_key
}

pub(crate) fn compute_mac(mac: &mut Tag, mac_key: &mut Poly1305Key, ciphertext: &[u8], ad: &[u8]) {
    let mut state = Poly1305::new(mac_key);
    mac_key.zeroize();

    state.update(ad);
    state.update(&PAD0[..pad16(ad.len())]);
    state.update(ciphertext);
    finish_mac(mac, &mut state, ciphertext.len(), ad.len());
}

/// The ciphertext's padding and the two lengths, then the tag. Takes the
/// state by reference: moved into a call, its key-derived limbs would leave
/// an unwiped copy behind.
#[inline(always)]
fn finish_mac(mac: &mut Tag, state: &mut Poly1305, ciphertext_len: usize, ad_len: usize) {
    state.update(&PAD0[..pad16(ciphertext_len)]);
    // Both lengths as one block, so the state takes it without buffering.
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(ad_len as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext_len as u64).to_le_bytes());
    state.update(&lengths);
    state.finalize(mac);
}

/// Encrypts `message` into `ciphertext` (in place when `message` is `None`)
/// with `cipher`, positioned at block 0, and writes the tag over `ad` and
/// the ciphertext into `mac`: [`encrypt_with_poly1305_key`] then
/// [`compute_mac`], except that with the stitched AArch64 kernel (SVE2) the
/// ciphertext after the first chunk is MACed chunk by chunk inside the
/// keystream runs of the chunk after it
/// ([`ChaCha20::apply_keystream_poly`]). The tag is the same either way.
#[inline]
pub(crate) fn encrypt_and_mac(
    cipher: ChaCha20,
    message: Option<&[u8]>,
    ciphertext: &mut [u8],
    ad: &[u8],
    mac: &mut Tag,
) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if ciphertext.len() >= 2 * ChaCha20::POLY_CHUNK && ChaCha20::poly_stitched() {
        let mut cipher = cipher;
        encrypt_and_mac_stitched(&mut cipher, message, ciphertext, ad, mac);
        return;
    }
    let mut mac_key = encrypt_with_poly1305_key(cipher, message, ciphertext);
    compute_mac(mac, &mut mac_key, ciphertext, ad);
}

/// The stitched path of [`encrypt_and_mac`], for at least two chunks. Out of
/// line so that it adds nothing to the inlined short-message path; `cipher`
/// is passed by reference, so no copy of its state is left behind.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
#[inline(never)]
fn encrypt_and_mac_stitched(
    cipher: &mut ChaCha20,
    message: Option<&[u8]>,
    ciphertext: &mut [u8],
    ad: &[u8],
    mac: &mut Tag,
) {
    let first = ChaCha20::POLY_CHUNK;
    // The first chunk and the Poly1305 key block in one run, then `ad`.
    let (head, _) = ciphertext.split_at_mut(first);
    let mut mac_key = encrypt_with_poly1305_key_into(cipher, message.map(|m| &m[..first]), head);
    let mut state = Poly1305::new(&mac_key);
    mac_key.zeroize();
    state.update(ad);
    state.update(&PAD0[..pad16(ad.len())]);
    let (done, mac_done) = cipher.apply_keystream_poly(message, ciphertext, first, 0, &mut state);
    match message {
        Some(message) => cipher.apply_keystream_b2b(&message[done..], &mut ciphertext[done..]),
        None => cipher.apply_keystream(&mut ciphertext[done..]),
    }
    state.update(&ciphertext[mac_done..]);
    finish_mac(mac, &mut state, ciphertext.len(), ad.len());
}

/// Verifies `mac` over `ciphertext` and `ad` in constant time. The computed
/// tag is the valid tag for this input, so it is wiped before returning,
/// whether or not verification succeeded.
pub(crate) fn verify_mac(
    mac: &Tag,
    mac_key: &mut Poly1305Key,
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<(), Error> {
    let mut computed_mac = Tag::default();
    compute_mac(&mut computed_mac, mac_key, ciphertext, ad);

    let verified = verify_ct(mac, &computed_mac);
    zeroize_bytes(&mut computed_mac);
    verified
}

/// Generates the libsodium-shaped API of one ChaCha20-Poly1305-IETF
/// construction in the invoking module.
///
/// * `abytes` / `messagebytes_max`: the construction's `*_ABYTES` and
///   `*_MESSAGEBYTES_MAX` constants. The bound is deliberately not defaulted;
///   it must match the counter width of `stream`.
/// * `stream`: a closure `|nonce: &Nonce, key: &Key| -> ChaCha20` returning the
///   stream positioned at block 0. Block 0 becomes the Poly1305 key and the
///   message starts at block 1; `messagebytes_max` must keep the block counter
///   from wrapping over a message of that length plus block 0.
/// * `key` / `nonce` / `mac`: the module's `Key`, `Nonce`, and `Mac` aliases;
///   `mac` must be [`Tag`].
/// * The remaining entries name the generated functions. Attributes on an
///   entry, including doc comments, are applied to that function.
///
/// The invoking module must have `crate::types::*` in scope.
macro_rules! impl_chacha20poly1305_aead {
    (
        abytes: $abytes:expr,
        messagebytes_max: $messagebytes_max:expr,
        stream: $stream:expr,
        key: $key:ty,
        nonce: $nonce:ty,
        mac: $mac:ty,
        $(#[$keygen_inplace_meta:meta])*
        keygen_inplace: $keygen_inplace:ident,
        $(#[$keygen_meta:meta])*
        keygen: $keygen:ident,
        $(#[$encrypt_detached_meta:meta])*
        encrypt_detached: $encrypt_detached:ident,
        $(#[$encrypt_detached_inplace_meta:meta])*
        encrypt_detached_inplace: $encrypt_detached_inplace:ident,
        $(#[$decrypt_detached_meta:meta])*
        decrypt_detached: $decrypt_detached:ident,
        $(#[$decrypt_detached_inplace_meta:meta])*
        decrypt_detached_inplace: $decrypt_detached_inplace:ident,
        $(#[$encrypt_meta:meta])*
        encrypt: $encrypt:ident,
        $(#[$decrypt_meta:meta])*
        decrypt: $decrypt:ident,
        $(#[$encrypt_inplace_meta:meta])*
        encrypt_inplace: $encrypt_inplace:ident,
        $(#[$decrypt_inplace_meta:meta])*
        decrypt_inplace: $decrypt_inplace:ident,
    ) => {
        use $crate::classic::crypto_aead_chacha20poly1305_impl::{
            encrypt_and_mac, poly1305_key, verify_mac,
        };

        $(#[$keygen_inplace_meta])*
        pub fn $keygen_inplace(key: &mut $key) {
            $crate::rng::copy_randombytes(key)
        }

        $(#[$keygen_meta])*
        pub fn $keygen() -> $key {
            <$key>::generate()
        }

        pub(super) fn message_len_from_combined_len(
            combined_len: usize,
            context: $crate::ErrorContext,
        ) -> Result<usize, $crate::error::Error> {
            validate_length!(min $abytes, combined_len, context);
            let message_len = combined_len - $abytes;
            validate_length!(max $messagebytes_max, message_len, $crate::ErrorContext::Message);
            Ok(message_len)
        }

        $(#[$encrypt_detached_meta])*
        pub fn $encrypt_detached(
            ciphertext: &mut [u8],
            mac: &mut $mac,
            message: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_length!(max $messagebytes_max, message.len(), $crate::ErrorContext::Message);
            validate_length!(exact message.len(), ciphertext.len(), $crate::ErrorContext::Ciphertext);

            let associated_data = associated_data.unwrap_or(&[]);
            encrypt_and_mac(($stream)(nonce, key), Some(message), ciphertext, associated_data, mac);
            Ok(())
        }

        $(#[$encrypt_detached_inplace_meta])*
        pub fn $encrypt_detached_inplace(
            data: &mut [u8],
            mac: &mut $mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_length!(max $messagebytes_max, data.len(), $crate::ErrorContext::Message);

            let associated_data = associated_data.unwrap_or(&[]);
            encrypt_and_mac(($stream)(nonce, key), None, data, associated_data, mac);
            Ok(())
        }

        $(#[$decrypt_detached_meta])*
        pub fn $decrypt_detached(
            message: &mut [u8],
            ciphertext: &[u8],
            mac: &$mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_length!(max $messagebytes_max, ciphertext.len(), $crate::ErrorContext::Message);
            validate_length!(exact ciphertext.len(), message.len(), $crate::ErrorContext::Message);

            let associated_data = associated_data.unwrap_or(&[]);
            let (mut cipher, mut mac_key) = poly1305_key(($stream)(nonce, key));
            verify_mac(mac, &mut mac_key, ciphertext, associated_data)?;
            cipher.apply_keystream_b2b(ciphertext, message);
            Ok(())
        }

        $(#[$decrypt_detached_inplace_meta])*
        pub fn $decrypt_detached_inplace(
            data: &mut [u8],
            mac: &$mac,
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_length!(max $messagebytes_max, data.len(), $crate::ErrorContext::Message);

            let associated_data = associated_data.unwrap_or(&[]);
            let (mut cipher, mut mac_key) = poly1305_key(($stream)(nonce, key));
            verify_mac(mac, &mut mac_key, data, associated_data)?;
            cipher.apply_keystream(data);
            Ok(())
        }

        $(#[$encrypt_meta])*
        pub fn $encrypt(
            ciphertext: &mut [u8],
            message: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            validate_length!(max $messagebytes_max, message.len(), $crate::ErrorContext::Message);
            validate_length!(
                exact message.len() + $abytes,
                ciphertext.len(),
                $crate::ErrorContext::Ciphertext
            );

            let (ciphertext, mac) = ciphertext.split_at_mut(message.len());
            let mac = mac.try_into().expect("validated tag length");
            $encrypt_detached(ciphertext, mac, message, associated_data, nonce, key)
        }

        $(#[$decrypt_meta])*
        pub fn $decrypt(
            message: &mut [u8],
            ciphertext: &[u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(ciphertext.len(), $crate::ErrorContext::Ciphertext)?;
            validate_length!(exact message_len, message.len(), $crate::ErrorContext::Message);

            let (ciphertext, mac) = ciphertext.split_at(message_len);
            let mac = mac.try_into().expect("validated tag length");
            $decrypt_detached(message, ciphertext, mac, associated_data, nonce, key)
        }

        $(#[$encrypt_inplace_meta])*
        pub fn $encrypt_inplace(
            data: &mut [u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(data.len(), $crate::ErrorContext::Data)?;
            let (data, mac) = data.split_at_mut(message_len);
            let mac = mac.try_into().expect("validated tag length");
            $encrypt_detached_inplace(data, mac, associated_data, nonce, key)
        }

        $(#[$decrypt_inplace_meta])*
        pub fn $decrypt_inplace(
            data: &mut [u8],
            associated_data: Option<&[u8]>,
            nonce: &$nonce,
            key: &$key,
        ) -> Result<(), $crate::error::Error> {
            let message_len =
                message_len_from_combined_len(data.len(), $crate::ErrorContext::Data)?;
            let (data, mac) = data.split_at_mut(message_len);
            let mac = (&*mac).try_into().expect("validated tag length");
            $decrypt_detached_inplace(data, mac, associated_data, nonce, key)
        }
    };
}

pub(crate) use impl_chacha20poly1305_aead;

/// Checks shared by the tests of both constructions, each expressed over
/// the generated ten-function API.
#[cfg(test)]
pub(crate) mod test_util {
    use super::Tag;
    use crate::error::Error;
    use crate::test_prelude::*;

    type Key = [u8; 32];
    type Aad<'a> = Option<&'a [u8]>;
    type Res = Result<(), Error>;
    type EncryptDetached<N> = fn(&mut [u8], &mut Tag, &[u8], Aad<'_>, &N, &Key) -> Res;
    type EncryptDetachedInplace<N> = fn(&mut [u8], &mut Tag, Aad<'_>, &N, &Key) -> Res;
    type DecryptDetached<N> = fn(&mut [u8], &[u8], &Tag, Aad<'_>, &N, &Key) -> Res;
    type DecryptDetachedInplace<N> = fn(&mut [u8], &Tag, Aad<'_>, &N, &Key) -> Res;
    type Combined<N> = fn(&mut [u8], &[u8], Aad<'_>, &N, &Key) -> Res;
    type CombinedInplace<N> = fn(&mut [u8], Aad<'_>, &N, &Key) -> Res;

    /// One construction's encrypt/decrypt functions.
    pub(crate) struct Aead<N> {
        pub(crate) encrypt_detached: EncryptDetached<N>,
        pub(crate) encrypt_detached_inplace: EncryptDetachedInplace<N>,
        pub(crate) decrypt_detached: DecryptDetached<N>,
        pub(crate) decrypt_detached_inplace: DecryptDetachedInplace<N>,
        pub(crate) encrypt: Combined<N>,
        pub(crate) decrypt: Combined<N>,
        pub(crate) encrypt_inplace: CombinedInplace<N>,
        pub(crate) decrypt_inplace: CombinedInplace<N>,
    }

    const ABYTES: usize = super::CRYPTO_ONETIMEAUTH_POLY1305_BYTES;

    /// Message and associated-data lengths around the Poly1305 block and
    /// the ChaCha20 block: empty, one byte, a block less/exact/more of each.
    #[cfg(dryoc_native_tests)]
    pub(crate) const LENS: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 63, 64, 65];

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
            .collect()
    }

    /// Every failing decryption, detached and combined, buffer to buffer
    /// and in place, must return the right error and leave its output
    /// buffer exactly as it found it: a flipped MAC bit (first and last
    /// byte), a flipped ciphertext bit, the wrong key, the wrong nonce, the
    /// wrong (or missing) associated data, a truncated ciphertext, and a
    /// combined ciphertext shorter than a tag or a message buffer of the
    /// wrong length. The ciphertext under test is sealed through all four
    /// encrypt paths, which must agree.
    pub(crate) fn check_failures_leave_outputs_untouched<N: Copy + AsMut<[u8]>>(
        aead: &Aead<N>,
        key: &Key,
        nonce: &N,
    ) {
        let message = pattern(100, 3);
        let ad = pattern(20, 5);
        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = Tag::default();
        (aead.encrypt_detached)(&mut ciphertext, &mut mac, &message, Some(&ad), nonce, key)
            .expect("encrypt");

        let mut inplace = message.clone();
        let mut inplace_mac = Tag::default();
        (aead.encrypt_detached_inplace)(&mut inplace, &mut inplace_mac, Some(&ad), nonce, key)
            .expect("encrypt detached in place");
        assert_eq!((&inplace, inplace_mac), (&ciphertext, mac));
        let mut combined = vec![0u8; message.len() + ABYTES];
        (aead.encrypt)(&mut combined, &message, Some(&ad), nonce, key).expect("encrypt combined");
        assert_eq!(combined[..message.len()], ciphertext);
        assert_eq!(combined[message.len()..], mac);
        let mut inplace = message.clone();
        inplace.resize(message.len() + ABYTES, 0);
        (aead.encrypt_inplace)(&mut inplace, Some(&ad), nonce, key).expect("encrypt in place");
        assert_eq!(inplace, combined);

        let mut wrong_key = *key;
        wrong_key[31] ^= 0x80;
        let mut wrong_nonce = *nonce;
        wrong_nonce.as_mut()[0] ^= 1;
        let mut wrong_ad = ad.clone();
        wrong_ad[19] ^= 1;
        let mut mac_first = mac;
        mac_first[0] ^= 1;
        let mut mac_last = mac;
        mac_last[ABYTES - 1] ^= 0x80;
        let mut tampered = ciphertext.clone();
        tampered[64] ^= 1;

        type Case<'a, N> = (&'a str, &'a [u8], &'a Tag, Aad<'a>, &'a N, &'a Key);
        let cases: [Case<'_, N>; 8] = [
            (
                "mac first byte",
                &ciphertext,
                &mac_first,
                Some(&ad),
                nonce,
                key,
            ),
            (
                "mac last byte",
                &ciphertext,
                &mac_last,
                Some(&ad),
                nonce,
                key,
            ),
            (
                "tampered ciphertext",
                &tampered,
                &mac,
                Some(&ad),
                nonce,
                key,
            ),
            ("wrong key", &ciphertext, &mac, Some(&ad), nonce, &wrong_key),
            (
                "wrong nonce",
                &ciphertext,
                &mac,
                Some(&ad),
                &wrong_nonce,
                key,
            ),
            ("wrong ad", &ciphertext, &mac, Some(&wrong_ad), nonce, key),
            ("missing ad", &ciphertext, &mac, None, nonce, key),
            (
                "truncated ciphertext",
                &ciphertext[..message.len() - 1],
                &mac,
                Some(&ad),
                nonce,
                key,
            ),
        ];
        for (name, ciphertext, mac, ad, nonce, key) in cases {
            let mut output = vec![0xa5u8; ciphertext.len()];
            assert!(
                matches!(
                    (aead.decrypt_detached)(&mut output, ciphertext, mac, ad, nonce, key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: detached"
            );
            assert_eq!(
                output,
                vec![0xa5u8; ciphertext.len()],
                "{name}: detached output"
            );

            let mut data = ciphertext.to_vec();
            assert!(
                matches!(
                    (aead.decrypt_detached_inplace)(&mut data, mac, ad, nonce, key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: detached in place"
            );
            assert_eq!(data, ciphertext, "{name}: detached in place data");

            let mut combined = ciphertext.to_vec();
            combined.extend_from_slice(mac);
            let mut output = vec![0xa5u8; ciphertext.len()];
            assert!(
                matches!(
                    (aead.decrypt)(&mut output, &combined, ad, nonce, key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: combined"
            );
            assert_eq!(
                output,
                vec![0xa5u8; ciphertext.len()],
                "{name}: combined output"
            );

            let mut data = combined.clone();
            assert!(
                matches!(
                    (aead.decrypt_inplace)(&mut data, ad, nonce, key),
                    Err(Error::AuthenticationFailed)
                ),
                "{name}: combined in place"
            );
            assert_eq!(data, combined, "{name}: combined in place data");
        }

        // Length errors: a combined ciphertext shorter than a tag, and
        // message buffers of the wrong length for a valid ciphertext.
        let mut combined = ciphertext.clone();
        combined.extend_from_slice(&mac);
        let short = &combined[..ABYTES - 1];
        let mut output = vec![0xa5u8; 1];
        assert!(matches!(
            (aead.decrypt)(&mut output, short, Some(&ad), nonce, key),
            Err(Error::InvalidLength { .. })
        ));
        assert_eq!(output, [0xa5]);
        let mut data = short.to_vec();
        assert!(matches!(
            (aead.decrypt_inplace)(&mut data, Some(&ad), nonce, key),
            Err(Error::InvalidLength { .. })
        ));
        assert_eq!(data, short);
        for len in [message.len() - 1, message.len() + 1] {
            let mut output = vec![0xa5u8; len];
            assert!(matches!(
                (aead.decrypt)(&mut output, &combined, Some(&ad), nonce, key),
                Err(Error::InvalidLength { .. })
            ));
            assert_eq!(output, vec![0xa5u8; len], "combined into {len} bytes");
            let mut output = vec![0xa5u8; len];
            assert!(matches!(
                (aead.decrypt_detached)(&mut output, &ciphertext, &mac, Some(&ad), nonce, key),
                Err(Error::InvalidLength { .. })
            ));
            assert_eq!(output, vec![0xa5u8; len], "detached into {len} bytes");
        }
    }

    /// libsodium's `crypto_aead_*_encrypt_detached`.
    #[cfg(dryoc_native_tests)]
    pub(crate) type SodiumEncryptDetached = unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_uchar,
        *mut libc::c_ulonglong,
        *const libc::c_uchar,
        libc::c_ulonglong,
        *const libc::c_uchar,
        libc::c_ulonglong,
        *const libc::c_uchar,
        *const libc::c_uchar,
        *const libc::c_uchar,
    ) -> libc::c_int;

    /// Every encrypt function must produce libsodium's ciphertext and tag,
    /// and every decrypt function must recover the message from them, for
    /// every message and associated-data length in [`LENS`] (an empty
    /// associated data both as `None` and as `Some(&[])`).
    #[cfg(dryoc_native_tests)]
    pub(crate) fn check_matches_libsodium<N: AsRef<[u8]>>(
        aead: &Aead<N>,
        sodium_encrypt_detached: SodiumEncryptDetached,
        key: &Key,
        nonce: &N,
    ) {
        for message_len in LENS {
            for ad_len in LENS {
                let message = pattern(message_len, 7);
                let ad = pattern(ad_len, 11);
                let mut expected = vec![0u8; message_len];
                let mut expected_mac = Tag::default();
                let mut mac_len: libc::c_ulonglong = 0;
                // SAFETY: every pointer comes from a live buffer of the
                // length passed beside it; `nsec` is unused and may be null.
                let rc = unsafe {
                    sodium_encrypt_detached(
                        expected.as_mut_ptr(),
                        expected_mac.as_mut_ptr(),
                        &mut mac_len,
                        message.as_ptr(),
                        message_len as libc::c_ulonglong,
                        ad.as_ptr(),
                        ad_len as libc::c_ulonglong,
                        core::ptr::null(),
                        nonce.as_ref().as_ptr(),
                        key.as_ptr(),
                    )
                };
                assert_eq!((rc, mac_len as usize), (0, ABYTES));
                let mut expected_combined = expected.clone();
                expected_combined.extend_from_slice(&expected_mac);

                let ads: &[Option<&[u8]>] = if ad_len == 0 {
                    &[None, Some(&[])]
                } else {
                    &[Some(&ad)]
                };
                for &ad in ads {
                    let ctx = format!("message {message_len}, ad {ad:?}");

                    let mut ciphertext = vec![0u8; message_len];
                    let mut mac = Tag::default();
                    (aead.encrypt_detached)(&mut ciphertext, &mut mac, &message, ad, nonce, key)
                        .expect("encrypt detached");
                    assert_eq!(
                        (&ciphertext, mac),
                        (&expected, expected_mac),
                        "{ctx}: detached"
                    );

                    let mut data = message.clone();
                    let mut mac = Tag::default();
                    (aead.encrypt_detached_inplace)(&mut data, &mut mac, ad, nonce, key)
                        .expect("encrypt detached in place");
                    assert_eq!(
                        (&data, mac),
                        (&expected, expected_mac),
                        "{ctx}: detached in place"
                    );

                    let mut combined = vec![0u8; message_len + ABYTES];
                    (aead.encrypt)(&mut combined, &message, ad, nonce, key).expect("encrypt");
                    assert_eq!(combined, expected_combined, "{ctx}: combined");

                    let mut data = message.clone();
                    data.resize(message_len + ABYTES, 0);
                    (aead.encrypt_inplace)(&mut data, ad, nonce, key).expect("encrypt in place");
                    assert_eq!(data, expected_combined, "{ctx}: combined in place");

                    let mut output = vec![0u8; message_len];
                    (aead.decrypt_detached)(&mut output, &expected, &expected_mac, ad, nonce, key)
                        .expect("decrypt detached");
                    assert_eq!(output, message, "{ctx}: open detached");

                    let mut data = expected.clone();
                    (aead.decrypt_detached_inplace)(&mut data, &expected_mac, ad, nonce, key)
                        .expect("decrypt detached in place");
                    assert_eq!(data, message, "{ctx}: open detached in place");

                    let mut output = vec![0u8; message_len];
                    (aead.decrypt)(&mut output, &expected_combined, ad, nonce, key)
                        .expect("decrypt");
                    assert_eq!(output, message, "{ctx}: open combined");

                    let mut data = expected_combined.clone();
                    (aead.decrypt_inplace)(&mut data, ad, nonce, key).expect("decrypt in place");
                    assert_eq!(
                        &data[..message_len],
                        message,
                        "{ctx}: open combined in place"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_prelude::*;
    use crate::utils::test_util::XorShift64;

    /// [`encrypt_and_mac`] gives the ciphertext and tag of the plain
    /// keystream-then-MAC construction, buffer to buffer and in place, at
    /// lengths around whole stitched chunks (512 bytes) where the stitched
    /// path starts, runs several chunks and hands a tail back.
    #[test]
    fn test_encrypt_and_mac_matches_sequential() {
        let mut rng = XorShift64::new(0x510e_527f_ade6_82d1);
        let key = rng.next_bytes32();
        let nonce: [u8; 12] = rng.next_bytes32()[..12].try_into().unwrap();
        let lens = [
            0, 64, 511, 512, 1023, 1024, 1025, 1535, 1536, 1600, 2048, 4113, 16384,
        ];
        for len in lens {
            for ad_len in [0, 5, 16, 33] {
                let message: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
                let ad: Vec<u8> = (0..ad_len).map(|_| rng.next_u64() as u8).collect();

                let mut expected = vec![0u8; len];
                let mut mac_key = encrypt_with_poly1305_key(
                    ChaCha20::ietf(&key, &nonce, 0),
                    Some(&message),
                    &mut expected,
                );
                let mut expected_tag = Tag::default();
                compute_mac(&mut expected_tag, &mut mac_key, &expected, &ad);

                let mut ciphertext = vec![0u8; len];
                let mut tag = Tag::default();
                encrypt_and_mac(
                    ChaCha20::ietf(&key, &nonce, 0),
                    Some(&message),
                    &mut ciphertext,
                    &ad,
                    &mut tag,
                );
                assert_eq!(
                    (&ciphertext, tag),
                    (&expected, expected_tag),
                    "len {len}, ad {ad_len}"
                );

                let mut data = message.clone();
                let mut tag = Tag::default();
                encrypt_and_mac(
                    ChaCha20::ietf(&key, &nonce, 0),
                    None,
                    &mut data,
                    &ad,
                    &mut tag,
                );
                assert_eq!(
                    (&data, tag),
                    (&expected, expected_tag),
                    "in place, len {len}, ad {ad_len}"
                );
            }
        }
    }
}

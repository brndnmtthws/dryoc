//! # Extendable-output functions
//!
//! An extendable-output function (XOF) hashes input of any length into
//! output of any length. It can serve as a hash with a chosen output size, a
//! key-derivation step that turns one secret into several keys, or a
//! deterministic generator that expands a seed.
//!
//! [`Shake128`] and [`Shake256`] are the SHAKE functions from FIPS 202.
//! [`TurboShake128`] and [`TurboShake256`] (RFC 9861) run the same sponge
//! with 12 Keccak rounds instead of 24, so they are about twice as fast with
//! the same security claims. The 128 and 256 suffixes give the security
//! level in bits.
//!
//! Absorb input with `update`, then call `finalize` to get a reader. Each
//! `squeeze` call continues the same output stream, so squeezing 32 bytes
//! twice gives the same bytes as squeezing 64 once. `with_domain` selects a
//! custom domain byte in `0x01..=0x7f`; different domains give unrelated
//! outputs for the same input.
//!
//! An XOF is not a MAC. Output is only secret if the input is.
//!
//! ## Example
//!
//! ```
//! use dryoc::xof::TurboShake128;
//!
//! let mut xof = TurboShake128::new();
//! xof.update(b"input keying material");
//! let mut reader = xof.finalize();
//! let encryption_key = reader.squeeze_to_vec(32);
//! let mac_key = reader.squeeze_to_vec(32);
//! assert_ne!(encryption_key, mac_key);
//!
//! // One-shot output of any length.
//! let digest = dryoc::xof::Shake256::compute_to_vec(b"hello", 64);
//! assert_eq!(digest.len(), 64);
//! ```

use crate::error::{Error, ErrorContext};
use crate::keccak::{DOMAIN_SHAKE, RATE_128, RATE_256, ROUNDS_FULL, ROUNDS_TURBO, Sponge};
use crate::types::*;

/// Absorbing or squeezing sponge with its domain byte, shared by the
/// Rustaceous XOF types and the Classic `crypto_xof_*` states.
#[derive(Clone)]
pub(crate) struct XofCore<const RATE: usize, const ROUNDS: usize> {
    sponge: Sponge<RATE, ROUNDS>,
    domain: u8,
    squeezing: bool,
}

impl<const RATE: usize, const ROUNDS: usize> XofCore<RATE, ROUNDS> {
    pub(crate) fn new() -> Self {
        Self {
            sponge: Sponge::new(),
            domain: DOMAIN_SHAKE,
            squeezing: false,
        }
    }

    /// Returns a core with a custom `domain` byte.
    ///
    /// The byte carries the suffix bits and the first padding bit, so it
    /// must be nonzero and must leave the top bit clear for the final
    /// padding bit.
    pub(crate) fn with_domain(domain: u8) -> Result<Self, Error> {
        validate_value!(0x01u8, 0x7fu8, domain, ErrorContext::Domain);
        Ok(Self {
            domain,
            ..Self::new()
        })
    }

    /// Absorbs `input`; fails once squeezing has started.
    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.squeezing {
            return Err(Error::invalid_state(ErrorContext::Xof));
        }
        self.sponge.absorb(input);
        Ok(())
    }

    /// Pads on the first call, then continues the output stream.
    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        if !self.squeezing {
            self.sponge.pad(self.domain);
            self.squeezing = true;
        }
        self.sponge.squeeze(output);
    }
}

/// Defines an absorbing XOF type and its reader.
///
/// - `$name` / `$reader`: the absorbing and squeezing types; leading attributes
///   (docs) are applied to `$name`.
/// - `$algo`: the algorithm name for the generated docs.
/// - `$rate` / `$rounds`: the sponge rate in bytes and the Keccak rounds.
macro_rules! xof {
    (
        $(#[$meta:meta])*
        $name:ident, $reader:ident, $algo:literal, $rate:expr, $rounds:expr $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            core: XofCore<$rate, $rounds>,
        }

        impl $name {
            #[doc = concat!("Returns a new ", $algo, " instance with the standard domain.")]
            pub fn new() -> Self {
                Self {
                    core: XofCore::new(),
                }
            }

            #[doc = concat!("Returns a new ", $algo, " instance with a custom `domain` byte.")]
            ///
            /// # Errors
            ///
            /// Returns [`Error::InvalidValue`] unless `domain` is in
            /// `0x01..=0x7f`.
            pub fn with_domain(domain: u8) -> Result<Self, Error> {
                Ok(Self {
                    core: XofCore::with_domain(domain)?,
                })
            }

            /// Absorbs `input`.
            pub fn update<Input: Bytes + ?Sized>(&mut self, input: &Input) {
                // Only the reader squeezes, so this core is still absorbing.
                self.core.sponge.absorb(input.as_slice())
            }

            /// Finishes absorbing and returns a reader for the output stream.
            pub fn finalize(self) -> $reader {
                $reader { core: self.core }
            }

            #[doc = concat!(
                "Computes ", $algo, " of `input` with the standard domain, filling `output`."
            )]
            pub fn compute_into_bytes<Input: Bytes + ?Sized, Output: MutBytes + ?Sized>(
                output: &mut Output,
                input: &Input,
            ) {
                let mut xof = Self::new();
                xof.update(input);
                xof.finalize().squeeze(output);
            }

            #[doc = concat!(
                "Computes `len` bytes of ", $algo, " of `input` with the standard domain."
            )]
            pub fn compute_to_vec<Input: Bytes + ?Sized>(input: &Input, len: usize) -> Vec<u8> {
                let mut output = vec![0u8; len];
                Self::compute_into_bytes(&mut output, input);
                output
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        #[doc = concat!("Output stream of a finalized [`", stringify!($name), "`].")]
        #[derive(Clone)]
        pub struct $reader {
            core: XofCore<$rate, $rounds>,
        }

        impl $reader {
            /// Fills `output` with the next bytes of the output stream.
            pub fn squeeze<Output: MutBytes + ?Sized>(&mut self, output: &mut Output) {
                self.core.squeeze(output.as_mut_slice())
            }

            /// Returns the next `len` bytes of the output stream.
            pub fn squeeze_to_vec(&mut self, len: usize) -> Vec<u8> {
                let mut output = vec![0u8; len];
                self.squeeze(&mut output);
                output
            }
        }
    };
}

xof! {
    /// SHAKE128 extendable-output function (FIPS 202).
    Shake128, Shake128Reader, "SHAKE128", RATE_128, ROUNDS_FULL,
}

xof! {
    /// SHAKE256 extendable-output function (FIPS 202).
    Shake256, Shake256Reader, "SHAKE256", RATE_256, ROUNDS_FULL,
}

xof! {
    /// TurboSHAKE128 extendable-output function (RFC 9861).
    TurboShake128, TurboShake128Reader, "TurboSHAKE128", RATE_128, ROUNDS_TURBO,
}

xof! {
    /// TurboSHAKE256 extendable-output function (RFC 9861).
    TurboShake256, TurboShake256Reader, "TurboSHAKE256", RATE_256, ROUNDS_TURBO,
}

/// Known answers shared with the Classic `crypto_xof_*` tests.
///
/// SHAKE answers are the FIPS 202 empty-message outputs plus messages at the
/// rate boundaries (rate - 1, rate, rate + 1 and twice the rate) in the
/// `(i * 31 % 251)` pattern used by the SHA-2 and SHA-3 tests, all computed
/// with Python's `hashlib` (OpenSSL). TurboSHAKE answers are the RFC 9861
/// section 5 test vectors.
#[cfg(test)]
pub(crate) mod test_vectors {
    pub(crate) use crate::keccak::{RATE_128, RATE_256};

    /// One known answer: `output` is the first `output.len()` bytes, or,
    /// when `skip` is nonzero, the bytes after skipping `skip` bytes.
    pub(crate) struct Vector {
        pub(crate) message: Vec<u8>,
        pub(crate) domain: u8,
        pub(crate) skip: usize,
        pub(crate) output: Vec<u8>,
    }

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).expect("hex failed")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// RFC 9861 `ptn(n)`: `00 01 .. FA` repeated and truncated to `n` bytes.
    fn ptn(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn standard(message: Vec<u8>, output: &str) -> Vector {
        Vector {
            message,
            domain: 0x1f,
            skip: 0,
            output: hex(output),
        }
    }

    fn shake(rate: usize, answers: [&str; 6], empty_long: &str, million: &str) -> Vec<Vector> {
        let [empty, abc, below, at, above, twice] = answers;
        let mut vectors = vec![
            standard(vec![], empty),
            standard(b"abc".to_vec(), abc),
            standard(pattern(rate - 1), below),
            standard(pattern(rate), at),
            standard(pattern(rate + 1), above),
            standard(pattern(2 * rate), twice),
            // Squeezes across two permutations.
            standard(vec![], empty_long),
        ];
        // Rate boundaries above cover buffering under Miri; keep the
        // million-byte stress vector in the native suite.
        if !cfg!(miri) {
            vectors.push(standard(vec![b'a'; 1_000_000], million));
        }
        vectors
    }

    pub(crate) fn shake128() -> Vec<Vector> {
        shake(
            RATE_128,
            [
                "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
                "7e0e12d510e6c678e349578a047e64663fcdc6161f7da575e04e371efc327987",
                "443571f674f6eb618c233bec2531cc5d4c7b6b965d6082057a723f99435125a5",
                "696c3b1a8439985a424c6f13f61efbaaec6823bbb382b7125c925f288e9de43e",
                "f8d2cd2eb2f33dc5da2195f5f389889bae2c5cc75a98453688eca464c7f52cb6",
            ],
            concat!(
                "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
                "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
                "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
                "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
                "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef",
                "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
                "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
                "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619",
                "f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
                "1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f",
                "1368ec2967fc84ef2ae9aff268e0b1700a",
            ),
            "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58",
        )
    }

    pub(crate) fn shake256() -> Vec<Vector> {
        shake(
            RATE_256,
            [
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
                "1a7339556bb5aa2e7cba9470e03d5e6ee95bf2d6e4702e61d6a07a150c1ca5e1",
                "02e30a82e7d18bcd455f3379d1cf015b644314d23860bd26e230a32d933730fb",
                "6789fd741e422e3221d117b08930492886fce3d26d0e515b900bcb59191db23a",
                "51954833fffb74e3b3d7b59d453dc5016fb167056f5851eaebe55af357cc80aa",
            ],
            concat!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
                "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853",
                "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
                "f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6",
                "77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c",
                "aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2",
                "03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f",
                "5a1aaa96d313eacc890936c173cdcd0fab",
            ),
            "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a",
        )
    }

    /// Builds the RFC 9861 vectors shared by both TurboSHAKE variants:
    /// the empty message (short output and the last 32 of 10032 bytes),
    /// `ptn(17^i)` for `i` in `0..=6`, and the custom-domain cases.
    fn turboshake(
        empty: &str,
        empty_tail: &str,
        ptn_answers: [&str; 7],
        domains: [(&[u8], u8, &str); 6],
    ) -> Vec<Vector> {
        let mut vectors = vec![
            standard(vec![], empty),
            Vector {
                message: vec![],
                domain: 0x1f,
                skip: 10032 - 32,
                output: hex(empty_tail),
            },
        ];
        for (i, output) in ptn_answers.into_iter().enumerate() {
            // `ptn(17^6)` is 24 MB; keep it out of the Miri run.
            if cfg!(miri) && i > 3 {
                continue;
            }
            vectors.push(standard(ptn(17usize.pow(i as u32)), output));
        }
        for (message, domain, output) in domains {
            vectors.push(Vector {
                message: message.to_vec(),
                domain,
                skip: 0,
                output: hex(output),
            });
        }
        vectors
    }

    pub(crate) fn turboshake128() -> Vec<Vector> {
        turboshake(
            concat!(
                "1E 41 5F 1C 59 83 AF F2 16 92 17 27 7D 17 BB 53 8C D9 45 A3 97 DD EC 54 1F 1C E4 \
                 1A F2 C1 B7 4C",
                "3E 8C CA E2 A4 DA E5 6C 84 A0 4C 23 85 C0 3C 15 E8 19 3B DF 58 73 73 63 32 16 91 \
                 C0 54 62 C8 DF",
            ),
            "A3 B9 B0 38 59 00 CE 76 1F 22 AE D5 48 E7 54 DA 10 A5 24 2D 62 E8 C6 58 E3 F3 A9 23 \
             A7 55 56 07",
            [
                "55 CE DD 6F 60 AF 7B B2 9A 40 42 AE 83 2E F3 F5 8D B7 29 9F 89 3E BB 92 47 24 7D \
                 85 69 58 DA A9",
                "9C 97 D0 36 A3 BA C8 19 DB 70 ED E0 CA 55 4E C6 E4 C2 A1 A4 FF BF D9 EC 26 9C A6 \
                 A1 11 16 12 33",
                "96 C7 7C 27 9E 01 26 F7 FC 07 C9 B0 7F 5C DA E1 E0 BE 60 BD BE 10 62 00 40 E7 5D \
                 72 23 A6 24 D2",
                "D4 97 6E B5 6B CF 11 85 20 58 2B 70 9F 73 E1 D6 85 3E 00 1F DA F8 0E 1B 13 E0 D0 \
                 59 9D 5F B3 72",
                "DA 67 C7 03 9E 98 BF 53 0C F7 A3 78 30 C6 66 4E 14 CB AB 7F 54 0F 58 40 3B 1B 82 \
                 95 13 18 EE 5C",
                "B9 7A 90 6F BF 83 EF 7C 81 25 17 AB F3 B2 D0 AE A0 C4 F6 03 18 CE 11 CF 10 39 25 \
                 12 7F 59 EE CD",
                "35 CD 49 4A DE DE D2 F2 52 39 AF 09 A7 B8 EF 0C 4D 1C A4 FE 2D 1A C3 70 FA 63 21 \
                 6F E7 B4 C2 B1",
            ],
            [
                (
                    &[0xff; 3],
                    0x01,
                    "BF 32 3F 94 04 94 E8 8E E1 C5 40 FE 66 0B E8 A0 C9 3F 43 D1 5E C0 06 99 84 \
                     62 FA 99 4E ED 5D AB",
                ),
                (
                    &[0xff],
                    0x06,
                    "8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68 7A 25 CB 05 C7 4C CA 1E 42 \
                     50 1A BD 83 87 4A 67",
                ),
                (
                    &[0xff; 3],
                    0x07,
                    "B6 58 57 60 01 CA D9 B1 E5 F3 99 A9 F7 77 23 BB A0 54 58 04 2D 68 20 6F 72 \
                     52 68 2D BA 36 63 ED",
                ),
                (
                    &[0xff; 7],
                    0x0b,
                    "8D EE AA 1A EC 47 CC EE 56 9F 65 9C 21 DF A8 E1 12 DB 3C EE 37 B1 81 78 B2 \
                     AC D8 05 B7 99 CC 37",
                ),
                (
                    &[0xff],
                    0x30,
                    "55 31 22 E2 13 5E 36 3C 32 92 BE D2 C6 42 1F A2 32 BA B0 3D AA 07 C7 D6 63 \
                     66 03 28 65 06 32 5B",
                ),
                (
                    &[0xff; 3],
                    0x7f,
                    "16 27 4C C6 56 D4 4C EF D4 22 39 5D 0F 90 53 BD A6 D2 8E 12 2A BA 15 C7 65 \
                     E5 AD 0E 6E AF 26 F9",
                ),
            ],
        )
    }

    pub(crate) fn turboshake256() -> Vec<Vector> {
        turboshake(
            concat!(
                "36 7A 32 9D AF EA 87 1C 78 02 EC 67 F9 05 AE 13 C5 76 95 DC 2C 66 63 C6 10 35 F5 \
                 9A 18 F8 E7 DB",
                "11 ED C0 E1 2E 91 EA 60 EB 6B 32 DF 06 DD 7F 00 2F BA FA BB 6E 13 EC 1C C2 0D 99 \
                 55 47 60 0D B0",
            ),
            "AB EF A1 16 30 C6 61 26 92 49 74 26 85 EC 08 2F 20 72 65 DC CF 2F 43 53 4E 9C 61 BA \
             0C 9D 1D 75",
            [
                concat!(
                    "3E 17 12 F9 28 F8 EA F1 05 46 32 B2 AA 0A 24 6E D8 B0 C3 78 72 8F 60 BC 97 \
                     04 10 15 5C 28 82 0E",
                    "90 CC 90 D8 A3 00 6A A2 37 2C 5C 5E A1 76 B0 68 2B F2 2B AE 74 67 AC 94 F7 \
                     4D 43 D3 9B 04 82 E2",
                ),
                concat!(
                    "B3 BA B0 30 0E 6A 19 1F BE 61 37 93 98 35 92 35 78 79 4E A5 48 43 F5 01 10 \
                     90 FA 2F 37 80 A9 E5",
                    "CB 22 C5 9D 78 B4 0A 0F BF F9 E6 72 C0 FB E0 97 0B D2 C8 45 09 1C 60 44 D6 \
                     87 05 4D A5 D8 E9 C7",
                ),
                concat!(
                    "66 B8 10 DB 8E 90 78 04 24 C0 84 73 72 FD C9 57 10 88 2F DE 31 C6 DF 75 BE \
                     B9 D4 CD 93 05 CF CA",
                    "E3 5E 7B 83 E8 B7 E6 EB 4B 78 60 58 80 11 63 16 FE 2C 07 8A 09 B9 4A D7 B8 \
                     21 3C 0A 73 8B 65 C0",
                ),
                concat!(
                    "C7 4E BC 91 9A 5B 3B 0D D1 22 81 85 BA 02 D2 9E F4 42 D6 9D 3D 42 76 A9 3E \
                     FE 0B F9 A1 6A 7D C0",
                    "CD 4E AB AD AB 8C D7 A5 ED D9 66 95 F5 D3 60 AB E0 9E 2C 65 11 A3 EC 39 7D \
                     A3 B7 6B 9E 16 74 FB",
                ),
                concat!(
                    "02 CC 3A 88 97 E6 F4 F6 CC B6 FD 46 63 1B 1F 52 07 B6 6C 6D E9 C7 B5 5B 2D \
                     1A 23 13 4A 17 0A FD",
                    "AC 23 4E AB A9 A7 7C FF 88 C1 F0 20 B7 37 24 61 8C 56 87 B3 62 C4 30 B2 48 \
                     CD 38 64 7F 84 8A 1D",
                ),
                concat!(
                    "AD D5 3B 06 54 3E 58 4B 58 23 F6 26 99 6A EE 50 FE 45 ED 15 F2 02 43 A7 16 \
                     54 85 AC B4 AA 76 B4",
                    "FF DA 75 CE DF 6D 8C DC 95 C3 32 BD 56 F4 B9 86 B5 8B B1 7D 17 78 BF C1 B1 \
                     A9 75 45 CD F4 EC 9F",
                ),
                concat!(
                    "9E 11 BC 59 C2 4E 73 99 3C 14 84 EC 66 35 8E F7 1D B7 4A EF D8 4E 12 3F 78 \
                     00 BA 9C 48 53 E0 2C",
                    "FE 70 1D 9E 6B B7 65 A3 04 F0 DC 34 A4 EE 3B A8 2C 41 0F 0D A7 0E 86 BF BD \
                     90 EA 87 7C 2D 61 04",
                ),
            ],
            [
                (
                    &[0xff; 3],
                    0x01,
                    concat!(
                        "D2 1C 6F BB F5 87 FA 22 82 F2 9A EA 62 01 75 FB 02 57 41 3A F7 8A 0B 1B \
                         2A 87 41 9C E0 31 D9 33",
                        "AE 7A 4D 38 33 27 A8 A1 76 41 A3 4F 8A 1D 10 03 AD 7D A6 B7 2D BA 84 BB \
                         62 FE F2 8F 62 F1 24 24",
                    ),
                ),
                (
                    &[0xff],
                    0x06,
                    concat!(
                        "73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57 E3 DD 7D 07 05 6A 26 A3 03 \
                         C4 33 FA 35 33 45 52 80",
                        "F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0 7B E3 2A 0A 97 2E 22 E6 3A \
                         DC 1B 09 0D AE FE 00 4B",
                    ),
                ),
                (
                    &[0xff; 3],
                    0x07,
                    concat!(
                        "18 B3 B5 B7 06 1C 2E 67 C1 75 3A 00 E6 AD 7E D7 BA 1C 90 6C F9 3E FB 70 \
                         92 EA F2 7F BE EB B7 55",
                        "AE 6E 29 24 93 C1 10 E4 8D 26 00 28 49 2B 8E 09 B5 50 06 12 B8 F2 57 89 \
                         85 DE D5 35 7D 00 EC 67",
                    ),
                ),
                (
                    &[0xff; 7],
                    0x0b,
                    concat!(
                        "BB 36 76 49 51 EC 97 E9 D8 5F 7E E9 A6 7A 77 18 FC 00 5C F4 25 56 BE 79 \
                         CE 12 C0 BD E5 0E 57 36",
                        "D6 63 2B 0D 0D FB 20 2D 1B BB 8F FE 3D D7 4C B0 08 34 FA 75 6C B0 34 71 \
                         BA B1 3A 1E 2C 16 B3 C0",
                    ),
                ),
                (
                    &[0xff],
                    0x30,
                    concat!(
                        "F3 FE 12 87 3D 34 BC BB 2E 60 87 79 D6 B7 0E 7F 86 BE C7 E9 0B F1 13 CB \
                         D4 FD D0 C4 E2 F4 62 5E",
                        "14 8D D7 EE 1A 52 77 6C F7 7F 24 05 14 D9 CC FC 3B 5D DA B8 EE 25 5E 39 \
                         EE 38 90 72 96 2C 11 1A",
                    ),
                ),
                (
                    &[0xff; 3],
                    0x7f,
                    concat!(
                        "AB E5 69 C1 F7 7E C3 40 F0 27 05 E7 D3 7C 9A B7 E1 55 51 6E 4A 6A 15 00 \
                         21 D7 0B 6F AC 0B B4 0C",
                        "06 9F 9A 98 28 A0 D5 75 CD 99 F9 BA E4 35 AB 1A CF 7E D9 11 0B A9 7C E0 \
                         38 8D 07 4B AC 76 87 76",
                    ),
                ),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_vectors::*;
    use super::*;

    /// Checks one type against its vectors: absorbing in one call and in
    /// rate-sized pieces, and squeezing in one call and in pieces that cross
    /// the rate boundary.
    macro_rules! check_known_answers {
        ($xof:ty, $vectors:expr, $rate:expr) => {
            for Vector {
                message,
                domain,
                skip,
                output,
            } in $vectors
            {
                let len = message.len();
                let total = skip + output.len();
                let new = || <$xof>::with_domain(domain).expect("valid domain");

                let mut one = new();
                one.update(&message);
                let mut all = vec![0u8; total];
                one.finalize().squeeze(&mut all);
                assert_eq!(&all[skip..], output, "one-shot len {len}");

                if len > 2 * $rate {
                    continue;
                }
                let mut blocks = new();
                for chunk in message.chunks($rate) {
                    blocks.update(chunk);
                }
                let mut reader = blocks.finalize();
                let mut pieces = Vec::with_capacity(total);
                while pieces.len() < total {
                    let take = (total - pieces.len()).min($rate - 1);
                    pieces.extend(reader.squeeze_to_vec(take));
                }
                assert_eq!(&pieces[skip..], output, "chunked len {len}");

                if domain == 0x1f && skip == 0 {
                    assert_eq!(
                        <$xof>::compute_to_vec(&message, output.len()),
                        output,
                        "compute_to_vec len {len}"
                    );
                }
            }
        };
    }

    #[test]
    fn test_shake128_known_answers() {
        check_known_answers!(Shake128, shake128(), RATE_128);
    }

    #[test]
    fn test_shake256_known_answers() {
        check_known_answers!(Shake256, shake256(), RATE_256);
    }

    #[test]
    fn test_turboshake128_known_answers() {
        check_known_answers!(TurboShake128, turboshake128(), RATE_128);
    }

    #[test]
    fn test_turboshake256_known_answers() {
        check_known_answers!(TurboShake256, turboshake256(), RATE_256);
    }

    /// The domain byte must leave room for the final padding bit and must
    /// not be zero; both ends of the valid range are accepted.
    #[test]
    fn test_with_domain_rejects_out_of_range() {
        for domain in [0x00u8, 0x80, 0xff] {
            assert!(matches!(
                TurboShake128::with_domain(domain),
                Err(Error::InvalidValue {
                    context: ErrorContext::Domain,
                    ..
                })
            ));
        }
        for domain in [0x01u8, 0x7f] {
            assert!(Shake256::with_domain(domain).is_ok());
        }
    }
}

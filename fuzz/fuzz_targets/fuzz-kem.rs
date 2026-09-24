#![no_main]
//! ML-KEM-768 and X-Wing against independent implementations.
//!
//! ML-KEM-768 is checked against RustCrypto's `ml-kem` (FIPS 203): key
//! generation from `d || z` (the public key, and the expanded secret key's
//! `ek || H(ek) || z` tail; its leading `ŝ` has no non-deprecated oracle
//! accessor and is covered by decapsulation matching the oracle),
//! deterministic encapsulation from `m`, and decapsulation of the honest
//! ciphertext and of either a byte-flipped copy of it or an arbitrary
//! ciphertext, which unless it is the honest one must give FIPS 203's
//! implicit-rejection key `J(z || c)`, computed here with `sha3` 0.10. The
//! encapsulation key check is driven by forcing one fuzz-chosen coefficient of
//! `t̂` to `q - 1`, `q`, `4095` or an arbitrary 12-bit value (and flipping a
//! `rho` byte): dryoc must reject exactly the keys that both the oracle and a
//! direct `ByteDecode12` range check here reject, and encapsulate to the rest
//! exactly like the oracle.
//!
//! X-Wing is rebuilt below from draft-connolly-cfrg-xwing-kem-09 §5 on top of
//! the `ml-kem` oracle, `curve25519-dalek` X25519 and `sha3` 0.10
//! SHAKE256/SHA3-256, and compared byte for byte on key generation,
//! deterministic encapsulation (also to public keys with an out-of-range
//! ML-KEM coefficient or a low-order, noncanonical or arbitrary X25519 part)
//! and decapsulation of the honest and a mutated ciphertext (flipped bytes
//! anywhere, optionally a low-order or arbitrary X25519 part). dryoc, like
//! libsodium, refuses an all-zero X25519 shared secret, which the draft does
//! not check: an error must coincide with an all-zero reference X25519 output.
//!
//! The Rustaceous `dryoc::kem` and `dryoc::kem::mlkem768` key pairs'
//! `from_seed` and `decapsulate` are checked once per input, and
//! `mlkem768::encapsulate`'s random ciphertext against the oracle's
//! decapsulation.
//!
//! The post-quantum sealed box (`dryoc::dryocsealedbox`, HPKE base mode with
//! X-Wing, HKDF-SHA256 and ChaCha20-Poly1305) seals the input's trailing bytes
//! to the X-Wing key pair. The box must be `enc || ciphertext || tag`, and
//! RFC 9180's key schedule, written out below over the reference X-Wing
//! decapsulation of `enc` and an HMAC-SHA256 built on `sha2`, must give the
//! key and nonce that open it. The final ChaCha20-Poly1305 step is dryoc's,
//! which `fuzz-aead` checks against its own oracle. Flipping any byte of the
//! box, or truncating it, must make it fail to open.
//!
//! `ml-kem` hashes with `sha3` 0.11, whose Keccak-f permutation is the
//! `keccak` 0.2 crate dryoc also builds on; `fuzz-hashes` covers dryoc's
//! permutation against `sha3` 0.10's `keccak` 0.1, which the X-Wing reference
//! and `J` use here.
//!
//! The control bytes come first so that short inputs already reach every
//! mutation. Full-length seeds (one per selector mode) live in
//! `seeds/fuzz-kem`; pass that directory after the corpus, since libFuzzer
//! otherwise grows inputs towards the 1330 bytes the keys and ciphertexts
//! take only slowly: `cargo fuzz run fuzz-kem corpus/fuzz-kem seeds/fuzz-kem`.
use curve25519_dalek::montgomery::MontgomeryPoint;
use dryoc::Error;
use dryoc::classic::crypto_aead_chacha20poly1305_ietf::crypto_aead_chacha20poly1305_ietf_decrypt_detached;
use dryoc::classic::crypto_kem_mlkem768::{
    crypto_kem_mlkem768_dec, crypto_kem_mlkem768_enc_deterministic,
    crypto_kem_mlkem768_seed_keypair,
};
use dryoc::classic::crypto_kem_xwing::{
    crypto_kem_xwing_dec, crypto_kem_xwing_enc_deterministic, crypto_kem_xwing_seed_keypair,
};
use dryoc::constants::{
    CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES, CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES,
    CRYPTO_KEM_XWING_CIPHERTEXTBYTES, CRYPTO_KEM_XWING_PUBLICKEYBYTES,
};
use dryoc::dryocsealedbox::{SEALBYTES, VecBox};
use dryoc::kem::{self, mlkem768};
use dryoc::types::ByteArray;
use libfuzzer_sys::fuzz_target;
use ml_kem::array::Array;
use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Decapsulate, KeyExport, Seed};
use sha2::{Digest as _, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

#[path = "common.rs"]
mod common;
use common::fill;
#[path = "x25519.rs"]
mod x25519;
use x25519::low_order_points;

/// The ML-KEM modulus.
const Q: u16 = 3329;
/// Coefficients of `t̂` in an ML-KEM-768 encapsulation key (`k = 3`
/// polynomials of 256), packed two per three bytes ahead of `rho`.
const COEFFICIENTS: usize = 3 * 256;
const MLKEM_CT: usize = CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES;
const MLKEM_PK: usize = CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES;
/// X-Wing's combiner label, `\.//^\` (draft §5.3).
const XWING_LABEL: &[u8; 6] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
/// HPKE's `suite_id` for X-Wing (`0x647a`), HKDF-SHA256 (`0x0001`) and
/// ChaCha20-Poly1305 (`0x0003`), RFC 9180 §5.1.
const HPKE_SUITE_ID: &[u8; 10] = b"HPKE\x64\x7a\x00\x01\x00\x03";

fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn shake256<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; N];
    hasher.finalize_xof().read(&mut out);
    out
}

/// HMAC-SHA256 (RFC 2104) of the concatenated `parts` under a key of at most
/// one block.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new().chain_update(block.map(|b| b ^ 0x36));
    for part in parts {
        inner = inner.chain_update(part);
    }
    Sha256::new()
        .chain_update(block.map(|b| b ^ 0x5c))
        .chain_update(inner.finalize())
        .finalize()
        .into()
}

/// RFC 9180 §4 `LabeledExtract`: HKDF-Extract is `HMAC(salt, ikm)`.
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[b"HPKE-v1", HPKE_SUITE_ID, label, ikm])
}

/// RFC 9180 §4 `LabeledExpand` to `N <= 32` bytes: the first HKDF-Expand
/// block, `HMAC(prk, labeled_info || 0x01)`.
fn labeled_expand<const N: usize>(prk: &[u8; 32], label: &[u8], info: &[u8]) -> [u8; N] {
    let length = u16::try_from(N).expect("short output").to_be_bytes();
    let block = hmac_sha256(
        prk,
        &[&length, b"HPKE-v1", HPKE_SUITE_ID, label, info, &[1]],
    );
    block[..N].try_into().expect("N <= 32")
}

/// RFC 9180 §5.1 `KeySchedule` in base mode with an empty `info`: the AEAD
/// key and the base nonce (the nonce of the first and only message).
fn hpke_key_schedule(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", b"info_hash", b"");
    let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(shared_secret, b"secret", b"");
    (
        labeled_expand(&secret, b"key", &context),
        labeled_expand(&secret, b"base_nonce", &context),
    )
}

fn oracle_decapsulate(dk: &DecapsulationKey, ciphertext: &[u8]) -> [u8; 32] {
    let ciphertext = Array::try_from(ciphertext).expect("ML-KEM-768 ciphertext length");
    dk.decapsulate(&ciphertext).into()
}

/// The oracle's encapsulation key for `public_key`, `None` if it fails the
/// FIPS 203 §7.2 check.
fn oracle_encapsulation_key(public_key: &[u8]) -> Option<EncapsulationKey> {
    let public_key = Array::try_from(public_key).expect("ML-KEM-768 public key length");
    EncapsulationKey::new(&public_key).ok()
}

fn oracle_encapsulate(ek: &EncapsulationKey, m: &[u8; 32]) -> ([u8; MLKEM_CT], [u8; 32]) {
    let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&B32::from(*m));
    (ciphertext.into(), shared_secret.into())
}

/// FIPS 203 §7.2's modulus check written out: every 12-bit coefficient that
/// `ByteDecode12` reads from `t̂` is below `q`.
fn coefficients_reduced(public_key: &[u8]) -> bool {
    public_key[..COEFFICIENTS / 2 * 3].chunks_exact(3).all(|b| {
        let even = u16::from(b[0]) | u16::from(b[1] & 0x0f) << 8;
        let odd = u16::from(b[1] >> 4) | u16::from(b[2]) << 4;
        even < Q && odd < Q
    })
}

/// Overwrites 12-bit coefficient `index` of `t̂` in `public_key`.
fn set_coefficient(public_key: &mut [u8], index: usize, value: u16) {
    let b = &mut public_key[index / 2 * 3..][..3];
    if index % 2 == 0 {
        b[0] = value as u8;
        b[1] = (b[1] & 0xf0) | (value >> 8) as u8;
    } else {
        b[1] = (b[1] & 0x0f) | (value << 4) as u8;
        b[2] = (value >> 4) as u8;
    }
}

/// XORs each `(index, mask)` of `flips` into `ciphertext`.
fn flip(ciphertext: &mut [u8], flips: &[u8; 12]) {
    for flip in flips.chunks_exact(3) {
        let index = usize::from(u16::from_le_bytes([flip[0], flip[1]])) % ciphertext.len();
        ciphertext[index] ^= flip[2];
    }
}

/// The X25519 part to substitute for `mode`: none, a low-order or
/// noncanonical point picked by `arbitrary[0]`, or `arbitrary` itself.
fn x25519_override(mode: u8, arbitrary: &[u8; 32]) -> Option<[u8; 32]> {
    match mode & 3 {
        1 => {
            let points = low_order_points();
            Some(points[usize::from(arbitrary[0]) % points.len()])
        }
        2 => Some(*arbitrary),
        _ => None,
    }
}

fn x25519(scalar: &[u8], point: &[u8]) -> [u8; 32] {
    MontgomeryPoint(point.try_into().expect("32-byte point"))
        .mul_clamped(scalar.try_into().expect("32-byte scalar"))
        .to_bytes()
}

/// Draft §5.3 `Combiner`.
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    sha3_256(&[ss_m, ss_x, ct_x, pk_x, XWING_LABEL])
}

/// Reference X-Wing key: draft §5.2 `expandDecapsulationKey`.
struct XWing {
    dk: DecapsulationKey,
    sk_x: [u8; 32],
    pk_x: [u8; 32],
}

impl XWing {
    fn new(sk: &[u8; 32]) -> Self {
        let expanded = shake256::<96>(&[sk]);
        let dz: [u8; 64] = expanded[..64].try_into().expect("64 bytes");
        let sk_x: [u8; 32] = expanded[64..].try_into().expect("32 bytes");
        Self {
            dk: DecapsulationKey::from_seed(Seed::from(dz)),
            pk_x: MontgomeryPoint::mul_base_clamped(sk_x).to_bytes(),
            sk_x,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        [
            self.dk.encapsulation_key().to_bytes().as_slice(),
            &self.pk_x,
        ]
        .concat()
    }

    /// Draft §5.5 `Decapsulate`, and the X25519 shared secret.
    fn decapsulate(&self, ct: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (ct_m, ct_x) = ct.split_at(MLKEM_CT);
        let ss_m = oracle_decapsulate(&self.dk, ct_m);
        let ss_x = x25519(&self.sk_x, ct_x);
        (combiner(&ss_m, &ss_x, ct_x, &self.pk_x), ss_x)
    }
}

/// Draft §5.4.1 `EncapsulateDerand`: the ciphertext, the shared secret and
/// the X25519 shared secret, or `None` if the ML-KEM part of `pk` fails the
/// FIPS 203 §7.2 check.
fn xwing_encapsulate(pk: &[u8], eseed: &[u8; 64]) -> Option<(Vec<u8>, [u8; 32], [u8; 32])> {
    let (pk_m, pk_x) = pk.split_at(MLKEM_PK);
    let ek_x = &eseed[32..];
    let ct_x = MontgomeryPoint::mul_base_clamped(ek_x.try_into().expect("32 bytes")).to_bytes();
    let ss_x = x25519(ek_x, pk_x);
    let (ct_m, ss_m) = oracle_encapsulate(
        &oracle_encapsulation_key(pk_m)?,
        eseed[..32].try_into().expect("32"),
    );
    let ss = combiner(&ss_m, &ss_x, &ct_x, pk_x);
    Some(([ct_m.as_slice(), &ct_x].concat(), ss, ss_x))
}

/// dryoc must fail exactly when the reference X25519 shared secret is all
/// zero, and otherwise produce the reference output.
fn check_x25519<T: PartialEq + std::fmt::Debug>(
    what: &str,
    result: &Result<(), Error>,
    dryoc: T,
    reference: T,
    ss_x: &[u8; 32],
) {
    match (result, *ss_x == [0u8; 32]) {
        (Ok(()), false) => assert_eq!(dryoc, reference, "{what}"),
        (Err(_), true) => {}
        (result, zero) => {
            panic!("{what}: dryoc returned {result:?}, reference X25519 secret all-zero: {zero}")
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let [selector, choice, index_hi, index_lo, value_hi, value_lo] = fill::<6>(&mut data);
    let flips = fill::<12>(&mut data);
    let arbitrary_x25519 = fill::<32>(&mut data);
    let mlkem_seed = fill::<64>(&mut data);
    let m = fill::<32>(&mut data);
    let xwing_seed = fill::<32>(&mut data);
    let eseed = fill::<64>(&mut data);
    let arbitrary_ct = fill::<MLKEM_CT>(&mut data);

    let index = usize::from(u16::from_be_bytes([index_hi, index_lo])) % COEFFICIENTS;
    let value = match selector & 3 {
        0 => Q - 1,
        1 => Q,
        2 => 0x0fff,
        _ => u16::from_be_bytes([value_hi, value_lo]) & 0x0fff,
    };

    // ML-KEM-768 key generation, Classic and Rustaceous.
    let dk = DecapsulationKey::from_seed(Seed::from(mlkem_seed));
    let (pk, sk) = crypto_kem_mlkem768_seed_keypair(&mlkem_seed);
    assert_eq!(pk.as_slice(), dk.encapsulation_key().to_bytes().as_slice());
    // FIPS 203 Algorithm 16: dk = dk_pke || ek || H(ek) || z.
    let (sk_ek, sk_tail) = sk[COEFFICIENTS / 2 * 3..].split_at(MLKEM_PK);
    assert_eq!(sk_ek, pk.as_slice());
    assert_eq!(sk_tail[..32], sha3_256(&[&pk]));
    assert_eq!(sk_tail[32..], mlkem_seed[32..]);
    let keypair = mlkem768::StackKeyPair::from_seed(&mlkem_seed);
    assert_eq!(keypair.public_key.as_array(), &pk);
    assert_eq!(keypair.secret_key.as_array(), &sk);
    let rebuilt = mlkem768::StackKeyPair::from_secret_key(keypair.secret_key.clone());
    assert_eq!(rebuilt.public_key.as_array(), &pk);

    // Deterministic encapsulation and decapsulation of the honest ciphertext.
    let (oracle_ct, oracle_ss) = oracle_encapsulate(dk.encapsulation_key(), &m);
    let mut ct = [0u8; MLKEM_CT];
    let mut ss = [0u8; 32];
    crypto_kem_mlkem768_enc_deterministic(&mut ct, &mut ss, &pk, &m).expect("honest key");
    assert_eq!((ct, ss), (oracle_ct, oracle_ss));
    let mut decapsulated = [0u8; 32];
    crypto_kem_mlkem768_dec(&mut decapsulated, &ct, &sk);
    assert_eq!(decapsulated, ss);

    // Implicit rejection of a flipped ciphertext, and decapsulation of an
    // arbitrary one, through Classic and the Rustaceous key pair. A flipped
    // ciphertext cannot re-encrypt to itself, so it must give J(z || c); an
    // arbitrary one may be another valid encapsulation, so only the oracle
    // classifies it.
    let mut mutated = ct;
    flip(&mut mutated, &flips);
    let (mutated, expected) = if choice & 1 == 0 {
        let expected = if mutated == ct {
            ss
        } else {
            shake256::<32>(&[&mlkem_seed[32..], &mutated])
        };
        assert_eq!(oracle_decapsulate(&dk, &mutated), expected);
        (mutated, expected)
    } else {
        (arbitrary_ct, oracle_decapsulate(&dk, &arbitrary_ct))
    };
    crypto_kem_mlkem768_dec(&mut decapsulated, &mutated, &sk);
    assert_eq!(decapsulated, expected);
    let from_keypair: [u8; 32] = keypair.decapsulate(&mutated).expect("ML-KEM never fails");
    assert_eq!(from_keypair, expected);

    // The encapsulation key check, one coefficient at a time.
    let mut modified_pk = pk;
    set_coefficient(&mut modified_pk, index, value);
    if selector & 4 != 0 {
        modified_pk[MLKEM_PK - 1 - usize::from(value_lo % 32)] ^= value_hi | 1;
    }
    let oracle_ek = oracle_encapsulation_key(&modified_pk);
    assert_eq!(oracle_ek.is_some(), coefficients_reduced(&modified_pk));
    let result = crypto_kem_mlkem768_enc_deterministic(&mut ct, &mut ss, &modified_pk, &m);
    match (result, oracle_ek) {
        (Ok(()), Some(ek)) => assert_eq!((ct, ss), oracle_encapsulate(&ek, &m)),
        (Err(_), None) => {}
        (result, ek) => panic!("dryoc {result:?}, oracle accepts key: {}", ek.is_some()),
    }

    // Rustaceous randomized encapsulation, decapsulated by the oracle.
    let (random_ct, random_ss): ([u8; MLKEM_CT], [u8; 32]) =
        mlkem768::encapsulate(&pk).expect("honest key");
    assert_eq!(oracle_decapsulate(&dk, &random_ct), random_ss);

    // X-Wing key generation, Classic and Rustaceous.
    let reference = XWing::new(&xwing_seed);
    let (xwing_pk, xwing_sk) = crypto_kem_xwing_seed_keypair(&xwing_seed);
    assert_eq!(xwing_pk.as_slice(), reference.public_key().as_slice());
    assert_eq!(xwing_sk, xwing_seed);
    let keypair = kem::StackKeyPair::from_seed(&xwing_seed);
    assert_eq!(keypair.public_key.as_array(), &xwing_pk);
    assert_eq!(keypair.secret_key.as_array(), &xwing_sk);

    // Deterministic encapsulation to the honest key, decapsulated through the
    // Rustaceous key pair (a thin wrapper over `crypto_kem_xwing_dec`).
    let (reference_ct, reference_ss, ss_x) =
        xwing_encapsulate(&xwing_pk, &eseed).expect("honest key");
    let mut xwing_ct = [0u8; CRYPTO_KEM_XWING_CIPHERTEXTBYTES];
    let result = crypto_kem_xwing_enc_deterministic(&mut xwing_ct, &mut ss, &xwing_pk, &eseed);
    check_x25519(
        "X-Wing encapsulation",
        &result,
        (xwing_ct.as_slice(), ss),
        (reference_ct.as_slice(), reference_ss),
        &ss_x,
    );
    let from_keypair: [u8; 32] = keypair.decapsulate(&xwing_ct).expect("honest ciphertext");
    assert_eq!(from_keypair, ss);

    // Classic decapsulation of a mutated ciphertext.
    let mut mutated = xwing_ct;
    flip(&mut mutated, &flips);
    if let Some(ct_x) = x25519_override(selector >> 3, &arbitrary_x25519) {
        mutated[MLKEM_CT..].copy_from_slice(&ct_x);
    }
    let (reference_ss, ss_x) = reference.decapsulate(&mutated);
    let result = crypto_kem_xwing_dec(&mut decapsulated, &mutated, &xwing_sk);
    check_x25519(
        "mutated X-Wing decapsulation",
        &result,
        decapsulated,
        reference_ss,
        &ss_x,
    );

    // Encapsulation to a public key with an out-of-range ML-KEM coefficient
    // or a substituted X25519 part.
    let pk_x = x25519_override(selector >> 5, &arbitrary_x25519);
    if selector & 0x80 != 0 || pk_x.is_some() {
        let mut modified_pk: [u8; CRYPTO_KEM_XWING_PUBLICKEYBYTES] = xwing_pk;
        if selector & 0x80 != 0 {
            set_coefficient(&mut modified_pk, index, value);
        }
        if let Some(pk_x) = pk_x {
            modified_pk[MLKEM_PK..].copy_from_slice(&pk_x);
        }
        let result =
            crypto_kem_xwing_enc_deterministic(&mut xwing_ct, &mut ss, &modified_pk, &eseed);
        match xwing_encapsulate(&modified_pk, &eseed) {
            Some((reference_ct, reference_ss, ss_x)) => check_x25519(
                "X-Wing encapsulation to a modified key",
                &result,
                (xwing_ct.as_slice(), ss),
                (reference_ct.as_slice(), reference_ss),
                &ss_x,
            ),
            None => assert!(result.is_err(), "accepted an unreduced ML-KEM coefficient"),
        }
    }

    // Sealed box of the trailing input bytes to the X-Wing key pair, opened
    // through the reference decapsulation and key schedule and by `unseal`.
    let message = data;
    let sealed = VecBox::seal_to_vecbox(message, &keypair.public_key).expect("seal to honest key");
    let wire = sealed.to_vec();
    assert_eq!(wire.len(), message.len() + SEALBYTES);
    let (enc, rest) = wire.split_at(CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
    let (ciphertext, tag) = rest.split_at(message.len());
    let (shared_secret, ss_x) = reference.decapsulate(enc);
    assert_ne!(
        ss_x, [0u8; 32],
        "honest encapsulation gave a zero X25519 secret"
    );
    let (key, nonce) = hpke_key_schedule(&shared_secret);
    let mut opened = vec![0xa5u8; message.len()];
    crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        &mut opened,
        ciphertext,
        tag.try_into().expect("16-byte tag"),
        None,
        &nonce,
        &key,
    )
    .expect("the reference key schedule opens the box");
    assert_eq!(opened, message);
    let parsed = VecBox::from_bytes(&wire).expect("parse sealed box");
    assert_eq!(parsed.to_vec(), wire);
    assert_eq!(parsed.unseal_to_vec(&keypair).expect("unseal"), message);

    // One flipped byte anywhere (enc, ciphertext or tag) fails to open, and
    // so does every truncation: too short to parse, or a shifted tag.
    let mut tampered = wire.clone();
    let index = usize::from(u16::from_le_bytes([flips[0], flips[1]])) % wire.len();
    tampered[index] ^= flips[2] | 1;
    let tampered = VecBox::from_bytes(&tampered).expect("same length parses");
    assert!(
        tampered.unseal_to_vec(&keypair).is_err(),
        "opened a box with byte {index} flipped"
    );
    let removed = 1 + usize::from(u16::from_le_bytes([flips[3], flips[4]])) % wire.len();
    let truncated = &wire[..wire.len() - removed];
    match VecBox::from_bytes(truncated) {
        Ok(truncated_box) => {
            assert!(
                truncated.len() >= SEALBYTES,
                "parsed a {removed}-byte-short box"
            );
            assert!(
                truncated_box.unseal_to_vec(&keypair).is_err(),
                "opened a box {removed} bytes short"
            );
        }
        Err(_) => assert!(truncated.len() < SEALBYTES, "rejected a parseable length"),
    }
});

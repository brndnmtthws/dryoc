//! ML-KEM-768 known-answer and backend tests.
//!
//! Vectors in `test-vectors/` (provenance in each file's header): NIST ACVP
//! key generation, encapsulation, decapsulation (including implicit
//! rejection) and encapsulation-key checks; C2SP/CCTV's invalid-modulus
//! keys, `strcmp` ciphertext and unlucky rejection-sampling seed; and the
//! CCTV accumulated test. Every file was checked against libsodium 1.0.22.
//! Each KEM test runs on every backend the CPU supports.

use std::collections::BTreeMap;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use super::*;
use crate::keccak::Sponge;
use crate::test_prelude::*;

/// Parses a vector file: `#` comments, then blank-line-separated records of
/// `key = value` lines. Works line by line, so a CRLF checkout (Windows)
/// parses the same; a repeated key within a record is an error rather than
/// a silent merge of two records.
pub(crate) fn records(text: &str) -> Vec<BTreeMap<&str, &str>> {
    let mut records = vec![BTreeMap::new()];
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let record = records.last_mut().expect("at least one record");
        if line.is_empty() {
            if !record.is_empty() {
                records.push(BTreeMap::new());
            }
        } else {
            let (key, value) = line.split_once(" = ").expect("key = value");
            assert!(record.insert(key, value).is_none(), "repeated key {key}");
        }
    }
    records.retain(|record| !record.is_empty());
    records
}

/// Decodes the hex field `key` of `record` into a fixed-size array.
pub(crate) fn field<const LEN: usize>(record: &BTreeMap<&str, &str>, key: &str) -> [u8; LEN] {
    hex::decode(record[key])
        .expect("hex field")
        .try_into()
        .expect("field length")
}

fn keypair_vec(
    arith: Arith,
    seed: &[u8; SEEDBYTES],
) -> ([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]) {
    let mut pk = [0u8; PUBLICKEYBYTES];
    let mut sk = [0u8; SECRETKEYBYTES];
    keypair(arith, &mut pk, &mut sk, seed);
    (pk, sk)
}

fn encapsulate_vec(
    arith: Arith,
    pk: &[u8; PUBLICKEYBYTES],
    m: &[u8; 32],
) -> Result<([u8; CIPHERTEXTBYTES], [u8; 32]), Error> {
    let mut ct = [0u8; CIPHERTEXTBYTES];
    let mut ss = [0u8; 32];
    encapsulate(arith, &mut ct, &mut ss, pk, m)?;
    Ok((ct, ss))
}

fn decapsulate_vec(
    arith: Arith,
    ct: &[u8; CIPHERTEXTBYTES],
    sk: &[u8; SECRETKEYBYTES],
) -> [u8; 32] {
    let mut ss = [0u8; 32];
    decapsulate(arith, &mut ss, ct, sk);
    ss
}

/// LF and CRLF copies of a vector file parse to the same records, not one
/// merged record. The file itself is normalized first, since a Windows
/// checkout already has CRLF endings.
#[test]
fn test_records_ignore_line_endings() {
    let text = include_str!("test-vectors/mlkem768_acvp_keygen.txt");
    let lf_text = text.replace("\r\n", "\n");
    let crlf_text = lf_text.replace('\n', "\r\n");
    let lf = records(&lf_text);
    assert!(lf.len() > 1);
    assert_eq!(records(&crlf_text), lf);
    assert_eq!(records(text), lf);
}

#[test]
fn test_acvp_keygen() {
    for arith in Arith::all() {
        for record in records(include_str!("test-vectors/mlkem768_acvp_keygen.txt")) {
            let d: [u8; 32] = field(&record, "d");
            let z: [u8; 32] = field(&record, "z");
            let mut seed = [0u8; SEEDBYTES];
            seed[..32].copy_from_slice(&d);
            seed[32..].copy_from_slice(&z);
            let (pk, sk) = keypair_vec(arith, &seed);
            let tcid = record["tcid"];
            assert_eq!(pk, field(&record, "ek"), "{arith:?} tcid {tcid}");
            assert_eq!(sk, field(&record, "dk"), "{arith:?} tcid {tcid}");
        }
    }
}

#[test]
fn test_acvp_encapsulation() {
    for arith in Arith::all() {
        for record in records(include_str!("test-vectors/mlkem768_acvp_encap.txt")) {
            let (ct, ss) = encapsulate_vec(arith, &field(&record, "ek"), &field(&record, "m"))
                .expect("valid key");
            let tcid = record["tcid"];
            assert_eq!(ct, field(&record, "c"), "{arith:?} tcid {tcid}");
            assert_eq!(ss, field::<32>(&record, "k"), "{arith:?} tcid {tcid}");
        }
    }
}

/// Valid ciphertexts give the encapsulated key and modified ones the
/// implicit-rejection key; neither is an error.
#[test]
fn test_acvp_decapsulation() {
    for arith in Arith::all() {
        for record in records(include_str!("test-vectors/mlkem768_acvp_decap.txt")) {
            let ss = decapsulate_vec(arith, &field(&record, "c"), &field(&record, "dk"));
            let tcid = record["tcid"];
            assert_eq!(
                ss,
                field::<32>(&record, "k"),
                "{arith:?} tcid {tcid} {}",
                record["reason"]
            );
        }
    }
}

/// Decapsulation straight from a seed gives exactly what decapsulation
/// under the seed's key pair gives: the encapsulated key for valid
/// ciphertexts and the implicit-rejection key for modified ones.
#[test]
fn test_decapsulate_seed_matches_decapsulate() {
    let mut rng = crate::utils::test_util::XorShift64::new(0x6d6c_6b65_6d5f_7365);
    for arith in Arith::all() {
        for i in 0..6 {
            let mut seed = [0u8; SEEDBYTES];
            seed[..32].copy_from_slice(&rng.next_bytes32());
            seed[32..].copy_from_slice(&rng.next_bytes32());
            let (pk, sk) = keypair_vec(arith, &seed);
            let (mut ct, ss) = encapsulate_vec(arith, &pk, &rng.next_bytes32()).expect("valid key");
            for modified in [false, true] {
                if modified {
                    ct[(i * 331) % CIPHERTEXTBYTES] ^= 1 << (i % 8);
                }
                let mut from_seed = [0u8; 32];
                decapsulate_seed(arith, &mut from_seed, &ct, &seed);
                assert_eq!(from_seed, decapsulate_vec(arith, &ct, &sk), "{arith:?} {i}");
                assert_eq!(from_seed == ss, !modified, "{arith:?} {i}");
            }
        }
    }
}

#[test]
fn test_acvp_encapsulation_key_check() {
    for record in records(include_str!("test-vectors/mlkem768_acvp_ek_check.txt")) {
        let valid = record["valid"] == "true";
        let result = encapsulate_vec(Arith::detect(), &field(&record, "ek"), &[0x5a; 32]);
        assert_eq!(
            result.is_ok(),
            valid,
            "tcid {} {}",
            record["tcid"],
            record["reason"]
        );
        if !valid {
            assert!(matches!(
                result,
                Err(Error::InvalidKey {
                    context: ErrorContext::PublicKey
                })
            ));
        }
    }
}

/// Every key with exactly one coefficient in `q..4096`, at every position
/// CCTV chose, fails the modulus check; the unmodified key passes.
#[test]
fn test_cctv_modulus() {
    let records = records(include_str!("test-vectors/mlkem768_cctv_modulus.txt"));
    let base: [u8; PUBLICKEYBYTES] = field(&records[0], "base_ek");
    assert!(encapsulate_vec(Arith::detect(), &base, &[0; 32]).is_ok());
    assert_eq!(records.len(), 781);
    for record in &records[1..] {
        let coeff: usize = record["coeff"].parse().expect("coeff");
        let value: u16 = record["value"].parse().expect("value");
        let mut ek = base;
        let bytes = &mut ek[3 * (coeff / 2)..3 * (coeff / 2) + 3];
        if coeff.is_multiple_of(2) {
            bytes[0] = value as u8;
            bytes[1] = (bytes[1] & 0xf0) | (value >> 8) as u8;
        } else {
            bytes[1] = (bytes[1] & 0x0f) | ((value as u8) << 4);
            bytes[2] = (value >> 4) as u8;
        }
        assert!(
            encapsulate_vec(Arith::detect(), &ek, &[0; 32]).is_err(),
            "coeff {coeff} value {value}"
        );
    }
}

/// A ciphertext whose re-encryption first differs after a zero byte still
/// yields the rejection key.
#[test]
fn test_cctv_strcmp() {
    let record = &records(include_str!("test-vectors/mlkem768_cctv_strcmp.txt"))[0];
    for arith in Arith::all() {
        let ss = decapsulate_vec(arith, &field(record, "c"), &field(record, "dk"));
        assert_eq!(ss, field::<32>(record, "k"), "{arith:?}");
    }
}

/// A matrix seed whose first entry needs more than three SHAKE128 blocks of
/// rejection sampling.
#[test]
fn test_cctv_unlucky_sampling() {
    let record = &records(include_str!("test-vectors/mlkem768_cctv_unlucky.txt"))[0];
    for arith in Arith::all() {
        let (ct, ss) =
            encapsulate_vec(arith, &field(record, "ek"), &field(record, "m")).expect("valid");
        assert_eq!(ct, field(record, "c"), "{arith:?}");
        assert_eq!(ss, field::<32>(record, "k"), "{arith:?}");
        assert_eq!(
            decapsulate_vec(arith, &ct, &field(record, "dk")),
            ss,
            "{arith:?}"
        );
    }
}

/// CCTV's accumulated test with FIPS 203 final key generation: 1,000 key
/// pairs, encapsulations and decapsulations of valid and random ciphertexts
/// driven by one SHAKE128 stream, with every output absorbed into a second
/// SHAKE128. The expected hash is libsodium 1.0.22's for the same procedure
/// (at 10,000 iterations both give CCTV's procedure the FIPS 203 final
/// value `f959d18d...`).
#[cfg_attr(miri, ignore = "1,000 key generations")]
#[test]
fn test_cctv_accumulated() {
    for arith in Arith::all() {
        assert_eq!(
            accumulated(arith, 1000),
            "5706194c22e3e0977b570e636de7364abce0609b341433cc4eb48062080b7c76",
            "{arith:?}"
        );
    }
}

fn accumulated(arith: Arith, iterations: usize) -> String {
    let mut rng = Sponge::<RATE_128, ROUNDS_FULL>::new();
    rng.pad(DOMAIN_SHAKE);
    let mut acc = Sponge::<RATE_128, ROUNDS_FULL>::new();
    let mut seed = [0u8; SEEDBYTES];
    let mut m = [0u8; 32];
    let mut ct_rand = [0u8; CIPHERTEXTBYTES];
    for _ in 0..iterations {
        rng.squeeze(&mut seed);
        rng.squeeze(&mut m);
        rng.squeeze(&mut ct_rand);
        let (pk, sk) = keypair_vec(arith, &seed);
        let (ct, k) = encapsulate_vec(arith, &pk, &m).expect("valid key");
        assert_eq!(decapsulate_vec(arith, &ct, &sk), k);
        let k_rand = decapsulate_vec(arith, &ct_rand, &sk);
        for part in [&pk[..], &sk, &ct, &k, &k_rand] {
            acc.absorb(part);
        }
    }
    acc.pad(DOMAIN_SHAKE);
    let mut digest = [0u8; 32];
    acc.squeeze(&mut digest);
    hex::encode(digest)
}

/// Compression rounds exactly like `round(x * 2^d / q) mod 2^d` for every
/// canonical coefficient, and decompression inverts it to within rounding.
#[test]
fn test_compression_exhaustive() {
    let q = u32::from(Q as u16);
    let round = |x: u32, d: u32| ((x << (d + 1)) + q) / (2 * q) % (1 << d);
    for x in 0..Q {
        let mut p = [0i16; N];
        p[0] = x;
        let mut u = [[0i16; N]; K];
        u[0][0] = x;
        let mut bytes = [0u8; POLYVEC_COMPRESSEDBYTES];
        compress_u(&mut bytes, &u);
        let t10 = u32::from(bytes[0]) | ((u32::from(bytes[1]) & 3) << 8);
        assert_eq!(t10, round(x as u32, 10), "compress10 {x}");
        let mut v = [0u8; 128];
        compress_v(&mut v, &p);
        assert_eq!(u32::from(v[0] & 0x0f), round(x as u32, 4), "compress4 {x}");
        let mut m = [0u8; 32];
        poly_to_msg(&mut m, &p);
        let bit = m[0] & 1;
        assert_eq!(u32::from(bit), round(x as u32, 1), "compress1 {x}");
    }
    // Barrett-reduced inputs may be exactly q, which is 0.
    let mut p = [0i16; N];
    p[0] = Q;
    let mut v = [0u8; 128];
    compress_v(&mut v, &p);
    assert_eq!(v[0], 0);
}

/// Every non-portable backend computes exactly the portable values for
/// each kernel operation, including coefficients at the input bounds.
#[test]
fn test_backends_match_soft() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut random = |range: i16| -> Poly {
        std::array::from_fn(|_| (next() % (2 * range as u64 - 1)) as i16 - (range - 1))
    };
    for arith in Arith::all().into_iter().filter(|&a| a != Arith::Soft) {
        for round in 0..64 {
            // NTT inputs are in (-q, q); inverse NTT and multiply inputs are
            // decoded or reduced coefficients below 2^12.
            let (mut a, b, mut c): (PolyVec, PolyVec, Poly) = if round == 0 {
                ([[Q - 1; N]; K], [[-4095; N]; K], [4095; N])
            } else {
                (
                    std::array::from_fn(|_| random(Q)),
                    std::array::from_fn(|_| random(4096)),
                    random(4096),
                )
            };
            let mut expected = a[0];
            Arith::Soft.ntt(&mut expected);
            arith.ntt(&mut a[0]);
            assert_eq!(a[0], expected, "{arith:?} ntt round {round}");

            let mut expected = c;
            Arith::Soft.invntt_tomont(&mut expected);
            arith.invntt_tomont(&mut c);
            assert_eq!(c, expected, "{arith:?} invntt round {round}");

            let (mut r, mut expected) = ([0; N], [0; N]);
            Arith::Soft.basemul_acc(&mut expected, &a, &b);
            arith.basemul_acc(&mut r, &a, &b);
            assert_eq!(r, expected, "{arith:?} basemul round {round}");

            // Rows against one right-hand side: each row is its own
            // `basemul_acc`.
            let rows: [PolyVec; 3] = [a, b, core::array::from_fn(|i| a[(i + 1) % K])];
            let mut expected = [[0; N]; 3];
            for (e, row) in expected.iter_mut().zip(&rows) {
                Arith::Soft.basemul_acc(e, row, &b);
            }
            let mut r = [[0; N]; 3];
            let [r0, r1, r2] = &mut r;
            arith.basemul_rows([r0, r1, r2], [&rows[0], &rows[1], &rows[2]], &b);
            assert_eq!(r, expected, "{arith:?} basemul rows round {round}");

            // The fused tails, on multiply and transform outputs plus noise
            // (and the message).
            let (mut r, mut expected) = (c, c);
            poly_tomont(&mut expected);
            poly_add_assign(&mut expected, &a[1]);
            poly_reduce(&mut expected);
            arith.tomont_add_reduce(&mut r, &a[1]);
            assert_eq!(r, expected, "{arith:?} tomont_add_reduce round {round}");
            let (mut r, mut expected) = (c, c);
            poly_add_assign(&mut expected, &b[0]);
            poly_add_assign(&mut expected, &a[2]);
            poly_reduce(&mut expected);
            arith.add_reduce(&mut r, [&b[0], &a[2]]);
            assert_eq!(r, expected, "{arith:?} add_reduce round {round}");

            // Ciphertext bytes of every value (all ones in the first round).
            let mut x = 0x2545_f491_4f6c_dd1d ^ round as u64;
            let bytes: [u8; POLYVEC_COMPRESSEDBYTES] = std::array::from_fn(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if round == 0 { 0xff } else { x as u8 }
            });
            let (mut u, mut expected) = ([[0; N]; K], [[0; N]; K]);
            decompress_u(&mut expected, &bytes);
            arith.decompress_u(&mut u, &bytes);
            assert_eq!(u, expected, "{arith:?} decompress_u round {round}");
        }

        // `poly_to_msg` of every Barrett-reduced value `[0, q]`, each at
        // every lane position of its byte.
        for start in 0..8 {
            let mut values = (0..=Q).cycle().skip(start);
            for _ in 0..(Q as usize + 1).div_ceil(N) {
                let p: Poly = std::array::from_fn(|_| values.next().unwrap());
                let (mut m, mut expected) = ([0u8; 32], [0u8; 32]);
                poly_to_msg(&mut expected, &p);
                arith.poly_to_msg(&mut m, &p);
                assert_eq!(m, expected, "{arith:?} poly_to_msg from {start}");
            }
        }
    }
}

/// Every backend's rejection sampling accepts exactly the portable loop's
/// coefficients, from any fill level (including the last eight slots, where
/// the vector loop hands over), over byte runs of every length around its
/// sixteen-byte reads and with all, none or some candidates rejected.
#[test]
fn test_rej_uniform_backends_match_soft() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    };
    let fills = [0, 1, 7, 100, 247, 248, 249, 250, 255, 256];
    let lens = (0..64).chain([165, 168, 171, 504, 507]);
    for arith in Arith::all().into_iter().filter(|&a| a != Arith::Soft) {
        for len in lens.clone() {
            for kind in 0..4 {
                // Random, all accepted (zero), all rejected (0xff) and
                // candidates just either side of q.
                let bytes: Vec<u8> = (0..len)
                    .map(|i| match kind {
                        0 => next(),
                        1 => 0,
                        2 => 0xff,
                        _ => [0x00, 0x1d, 0xd0, 0x01, 0x0d, 0xd0][i % 6] ^ (next() & 1),
                    })
                    .collect();
                for &fill in &fills {
                    let start: Poly = std::array::from_fn(|i| i as i16);
                    let (mut expected, mut expected_filled) = (start, fill);
                    Arith::Soft.rej_uniform(&mut expected, &mut expected_filled, &bytes);
                    let (mut got, mut got_filled) = (start, fill);
                    arith.rej_uniform(&mut got, &mut got_filled, &bytes);
                    assert_eq!(got_filled, expected_filled, "{arith:?} {len} {kind} {fill}");
                    assert_eq!(
                        got[..got_filled],
                        expected[..expected_filled],
                        "{arith:?} {len} {kind} {fill}"
                    );
                }
            }
        }
    }
}

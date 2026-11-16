//! NIST ACVP known-answer tests for ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
//!
//! Vectors live in `tests/kat/vectors/` at the repository root (see its README for provenance).
//! Every test asserts that it actually executed a minimum number of cases, so an empty or
//! truncated vector file cannot make the suite pass vacuously.
// TM:T15-M2 KATs against official NIST ACVP vectors run on every build

use std::path::PathBuf;

use qshield_crypto::kat;
use qshield_crypto::kem::{self, KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey};
use qshield_crypto::sig::{self, SigAlgorithm, SigPublicKey, SigSecretKey, Signature};
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn load(name: &str) -> Vec<Value> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "tests",
        "kat",
        "vectors",
        &format!("{name}.json"),
    ]
    .iter()
    .collect();
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: Value = serde_json::from_slice(&raw).expect("valid JSON");
    let tests = doc["tests"].as_array().expect("tests array").clone();
    assert_eq!(
        tests.len() as u64,
        doc["count"].as_u64().unwrap(),
        "{name}: count mismatch"
    );
    tests
}

fn hx(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(
        t[k].as_str()
            .unwrap_or_else(|| panic!("missing {k} in tcId {}", t["tcId"])),
    )
    .expect("hex")
}

fn s<'a>(t: &'a Value, k: &str) -> &'a str {
    t[k].as_str().unwrap_or("")
}

fn kem_alg(ps: &str) -> KemAlgorithm {
    match ps {
        "ML-KEM-512" => KemAlgorithm::MlKem512,
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "ML-KEM-1024" => KemAlgorithm::MlKem1024,
        other => panic!("unexpected parameter set {other}"),
    }
}

fn dsa_alg(ps: &str) -> SigAlgorithm {
    match ps {
        "ML-DSA-44" => SigAlgorithm::MlDsa44,
        "ML-DSA-65" => SigAlgorithm::MlDsa65,
        "ML-DSA-87" => SigAlgorithm::MlDsa87,
        "SLH-DSA-SHA2-128s" => SigAlgorithm::SlhDsaSha2_128s,
        other => panic!("unexpected parameter set {other}"),
    }
}

fn ctx(t: &Value) -> Vec<u8> {
    t.get("context")
        .and_then(Value::as_str)
        .map(|c| hex::decode(c).expect("hex"))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// ML-KEM (FIPS 203)
// ---------------------------------------------------------------------------------------------

#[test]
fn ml_kem_keygen() {
    let mut n = 0;
    for t in load("ml-kem-keygen") {
        let alg = kem_alg(s(&t, "parameterSet"));
        let (ek, dk) = kat::mlkem_keypair_derand(alg, &hx(&t, "d"), &hx(&t, "z")).unwrap();
        assert_eq!(
            hex::encode(&ek),
            hex::encode(hx(&t, "ek")),
            "ek tcId {}",
            t["tcId"]
        );
        assert!(
            dk.expose_secret() == hx(&t, "dk").as_slice(),
            "dk tcId {}",
            t["tcId"]
        );
        // The generated keys also pass the FIPS 203 input checks of the public API.
        KemPublicKey::from_bytes(alg, &ek).unwrap();
        KemSecretKey::from_bytes(alg, dk.expose_secret()).unwrap();
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
fn ml_kem_encapsulation() {
    let mut n = 0;
    for t in load("ml-kem-encaps") {
        let alg = kem_alg(s(&t, "parameterSet"));
        let (c, k) = kat::mlkem_encaps_derand(alg, &hx(&t, "ek"), &hx(&t, "m")).unwrap();
        assert_eq!(
            hex::encode(&c),
            hex::encode(hx(&t, "c")),
            "c tcId {}",
            t["tcId"]
        );
        assert!(
            k.expose_secret() == hx(&t, "k").as_slice(),
            "k tcId {}",
            t["tcId"]
        );
        // Round trip through the public decapsulation API with NIST's dk.
        let sk = KemSecretKey::from_bytes(alg, &hx(&t, "dk")).unwrap();
        let ct = KemCiphertext::from_bytes(alg, &c).unwrap();
        let k2 = kem::decapsulate(&sk, &ct).unwrap();
        assert!(
            k2.expose_secret() == k.expose_secret(),
            "decaps tcId {}",
            t["tcId"]
        );
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
fn ml_kem_decapsulation_including_implicit_rejection() {
    let mut n = 0;
    for t in load("ml-kem-decaps") {
        let alg = kem_alg(s(&t, "parameterSet"));
        let sk = KemSecretKey::from_bytes(alg, &hx(&t, "dk")).unwrap();
        let ct = KemCiphertext::from_bytes(alg, &hx(&t, "c")).unwrap();
        let k = kem::decapsulate(&sk, &ct).unwrap();
        assert!(
            k.expose_secret() == hx(&t, "k").as_slice(),
            "tcId {} ({})",
            t["tcId"],
            s(&t, "reason")
        );
        n += 1;
    }
    assert_eq!(n, 30);
}

#[test]
fn ml_kem_key_checks() {
    let (mut n, mut failures_expected) = (0, 0);
    for t in load("ml-kem-keycheck") {
        let alg = kem_alg(s(&t, "parameterSet"));
        let expected = t["testPassed"].as_bool().unwrap();
        let got = match s(&t, "function") {
            "encapsulationKeyCheck" => KemPublicKey::from_bytes(alg, &hx(&t, "ek")).is_ok(),
            "decapsulationKeyCheck" => KemSecretKey::from_bytes(alg, &hx(&t, "dk")).is_ok(),
            other => panic!("unexpected function {other}"),
        };
        assert_eq!(
            got,
            expected,
            "tcId {} {} ({})",
            t["tcId"],
            s(&t, "function"),
            s(&t, "reason")
        );
        failures_expected += usize::from(!expected);
        n += 1;
    }
    assert_eq!(n, 24);
    assert!(failures_expected >= 6, "vectors must include rejected keys");
}

// ---------------------------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------------------------

/// PQClean exposes no seeded ML-DSA key generation, so the keyGen vectors are checked for
/// structural consistency with FIPS 204 (rho shared, tr = H(pk)) and for interoperability: a
/// signature made by PQClean with NIST's sk must verify under NIST's pk.
#[test]
fn ml_dsa_keygen_consistency() {
    let mut n = 0;
    for t in load("ml-dsa-keygen") {
        let alg = dsa_alg(s(&t, "parameterSet"));
        let pk = hx(&t, "pk");
        let sk = hx(&t, "sk");
        assert_eq!(pk.len(), alg.public_key_len());
        assert_eq!(sk.len(), alg.secret_key_len());
        assert_eq!(pk[..32], sk[..32], "rho tcId {}", t["tcId"]);
        let mut tr = [0u8; 64];
        let mut xof = sha3::Shake256::default();
        xof.update(&pk);
        xof.finalize_xof().read(&mut tr);
        assert_eq!(tr[..], sk[64..128], "tr tcId {}", t["tcId"]);
        let spk = SigPublicKey::from_bytes(alg, &pk).unwrap();
        let ssk = SigSecretKey::from_bytes(alg, &sk).unwrap();
        let sig = sig::sign_with_context(&ssk, b"kat interop", b"qshield").unwrap();
        sig::verify_with_context(&spk, b"kat interop", &sig, b"qshield").unwrap();
        n += 1;
    }
    assert_eq!(n, 9);
}

/// ML-DSA signing in PQClean is hedged (fresh randomness), so NIST's expected signatures are
/// checked by verification under the external pure interface. Internal-interface cases sign
/// M' directly, which PQClean does not expose; they are counted and reported as skipped.
#[test]
fn ml_dsa_siggen_signatures_verify() {
    let (mut verified, mut skipped) = (0, 0);
    for t in load("ml-dsa-siggen") {
        if s(&t, "signatureInterface") != "external" {
            skipped += 1;
            continue;
        }
        let alg = dsa_alg(s(&t, "parameterSet"));
        let pk = SigPublicKey::from_bytes(alg, &hx(&t, "pk")).unwrap();
        let signature = Signature::from_bytes(alg, &hx(&t, "signature")).unwrap();
        sig::verify_with_context(&pk, &hx(&t, "message"), &signature, &ctx(&t))
            .unwrap_or_else(|e| panic!("tcId {}: {e}", t["tcId"]));
        verified += 1;
    }
    assert_eq!(verified, 18);
    assert_eq!(skipped, 12);
}

#[test]
fn ml_dsa_sigver() {
    let (mut n, mut rejected, mut skipped) = (0, 0, 0);
    for t in load("ml-dsa-sigver") {
        if s(&t, "signatureInterface") != "external" {
            skipped += 1;
            continue;
        }
        let alg = dsa_alg(s(&t, "parameterSet"));
        let expected = t["testPassed"].as_bool().unwrap();
        let pk = SigPublicKey::from_bytes(alg, &hx(&t, "pk")).unwrap();
        let got = Signature::from_bytes(alg, &hx(&t, "signature"))
            .and_then(|sg| sig::verify_with_context(&pk, &hx(&t, "message"), &sg, &ctx(&t)))
            .is_ok();
        assert_eq!(got, expected, "tcId {} ({})", t["tcId"], s(&t, "reason"));
        rejected += usize::from(!expected);
        n += 1;
    }
    assert_eq!(n, 24);
    assert_eq!(skipped, 12);
    assert!(rejected >= 6, "vectors must include invalid signatures");
}

// ---------------------------------------------------------------------------------------------
// SLH-DSA (FIPS 205)
// ---------------------------------------------------------------------------------------------

#[test]
fn slh_dsa_keygen() {
    let mut n = 0;
    for t in load("slh-dsa-keygen") {
        let (pk, sk) =
            kat::slh_dsa_keypair_from_seeds(&hx(&t, "skSeed"), &hx(&t, "skPrf"), &hx(&t, "pkSeed"))
                .unwrap();
        assert_eq!(
            hex::encode(&pk),
            hex::encode(hx(&t, "pk")),
            "pk tcId {}",
            t["tcId"]
        );
        assert!(
            sk.expose_secret() == hx(&t, "sk").as_slice(),
            "sk tcId {}",
            t["tcId"]
        );
        n += 1;
    }
    assert_eq!(n, 10);
}

fn slh_verify(t: &Value) -> bool {
    let pk = hx(t, "pk");
    let sigb = hx(t, "signature");
    if s(t, "signatureInterface") == "internal" {
        return kat::slh_dsa_verify_internal(&pk, &hx(t, "message"), &sigb);
    }
    // External interface through the public API: a wrong-length signature is rejected at parse.
    let spk = SigPublicKey::from_bytes(SigAlgorithm::SlhDsaSha2_128s, &pk).unwrap();
    Signature::from_bytes(SigAlgorithm::SlhDsaSha2_128s, &sigb)
        .and_then(|sg| sig::verify_with_context(&spk, &hx(t, "message"), &sg, &ctx(t)))
        .is_ok()
}

/// Full KAT: deterministic (`opt_rand = PK.seed`) and randomized (`addrnd` from the vector)
/// signatures must equal NIST's expected bytes, for both the external and internal interfaces.
#[test]
fn slh_dsa_siggen() {
    let (mut deterministic, mut randomized) = (0, 0);
    for t in load("slh-dsa-siggen") {
        let sk = hx(&t, "sk");
        let msg = hx(&t, "message");
        let addrnd = t
            .get("additionalRandomness")
            .and_then(Value::as_str)
            .map(|h| hex::decode(h).unwrap());
        let got = if s(&t, "signatureInterface") == "internal" {
            kat::slh_dsa_sign_internal(&sk, &msg, addrnd.as_deref()).unwrap()
        } else {
            kat::slh_dsa_sign(&sk, &msg, &ctx(&t), addrnd.as_deref()).unwrap()
        };
        assert_eq!(
            hex::encode(&got),
            hex::encode(hx(&t, "signature")),
            "tcId {}",
            t["tcId"]
        );
        assert!(slh_verify(&t), "tcId {} verify", t["tcId"]);
        if addrnd.is_some() {
            randomized += 1;
        } else {
            deterministic += 1;
        }
    }
    assert_eq!(deterministic, 5);
    assert_eq!(randomized, 4);
}

#[test]
fn slh_dsa_sigver() {
    let (mut n, mut rejected) = (0, 0);
    for t in load("slh-dsa-sigver") {
        let expected = t["testPassed"].as_bool().unwrap();
        assert_eq!(
            slh_verify(&t),
            expected,
            "tcId {} ({})",
            t["tcId"],
            s(&t, "reason")
        );
        rejected += usize::from(!expected);
        n += 1;
    }
    assert_eq!(n, 12);
    assert!(rejected >= 4, "vectors must include invalid signatures");
}

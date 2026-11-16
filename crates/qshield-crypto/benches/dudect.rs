//! dudect-style constant-time tests (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant
//! time?", DATE 2017).
//!
//! Each bench splits inputs into two classes and measures the run time of the operation under
//! test for every input. A Welch t-test over cropped percentiles of the two timing
//! distributions reports `max t`. The usual interpretation is:
//!
//! * `|t| < 4.5`: no evidence of a timing difference between the classes;
//! * `|t| >= 4.5`: the classes are distinguishable and the code path should be investigated.
//!
//! Run with `cargo bench -p qshield-crypto --bench dudect`. Results and the machine they were
//! measured on are recorded in `docs/TIMING_RESULTS.md`.
// TM:T11-M3 dudect-style timing tests for decapsulation and signing

use dudect_bencher::rand::{Rng, RngExt};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use qshield_crypto::kem::{self, KemAlgorithm, KemCiphertext, KemSecretKey};
use qshield_crypto::secret::ct_eq;
use qshield_crypto::sig::{self, SigAlgorithm};

const KEM_SAMPLES: usize = 100_000;
const SIGN_SAMPLES: usize = 20_000;

fn random_bytes(rng: &mut BenchRng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

fn coin(rng: &mut BenchRng) -> Class {
    if rng.random::<bool>() {
        Class::Left
    } else {
        Class::Right
    }
}

/// Which pair of input distributions a KEM bench compares.
#[derive(Clone, Copy)]
enum Scenario {
    /// Left: honestly generated ciphertexts. Right: uniformly random ciphertexts.
    ValidVsRejected,
    /// Left: one fixed ciphertext. Right: fresh honestly generated ciphertexts.
    FixedVsRandom,
}

/// Builds inputs whose construction is identical for both classes: every sample runs one
/// encapsulation and one random draw, then copies the chosen bytes into a new ciphertext. Only
/// the content differs between classes, never the allocation pattern, so a measured difference
/// cannot come from memory layout or allocator state.
fn kem_inputs(
    rng: &mut BenchRng,
    alg: KemAlgorithm,
    scenario: Scenario,
) -> (KemSecretKey, Vec<(Class, KemCiphertext)>) {
    let (pk, sk) = kem::keypair(alg).expect("keypair");
    let fixed = kem::encapsulate(&pk)
        .expect("encapsulate")
        .0
        .as_bytes()
        .to_vec();
    let mut inputs = Vec::with_capacity(KEM_SAMPLES);
    for _ in 0..KEM_SAMPLES {
        let class = coin(rng);
        let fresh = kem::encapsulate(&pk).expect("encapsulate").0;
        let random = random_bytes(rng, alg.ciphertext_len());
        let chosen: &[u8] = match (scenario, class) {
            (Scenario::ValidVsRejected, Class::Left) | (Scenario::FixedVsRandom, Class::Right) => {
                fresh.as_bytes()
            }
            (Scenario::ValidVsRejected, Class::Right) => &random,
            (Scenario::FixedVsRandom, Class::Left) => &fixed,
        };
        let ct = KemCiphertext::from_bytes(alg, chosen).expect("length");
        inputs.push((class, ct));
    }
    (sk, inputs)
}

fn run_kem(runner: &mut CtRunner, sk: &KemSecretKey, inputs: Vec<(Class, KemCiphertext)>) {
    for (class, ct) in inputs {
        runner.run_one(class, || kem::decapsulate(sk, &ct));
    }
}

/// ML-KEM-768 decapsulation: honestly generated ciphertexts (Left) against uniformly random
/// ciphertexts that take the FIPS 203 implicit-rejection path (Right). A timing difference
/// here is the classic Fujisaki-Okamoto re-encryption side channel.
fn mlkem768_decaps_valid_vs_rejected(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk, inputs) = kem_inputs(rng, KemAlgorithm::MlKem768, Scenario::ValidVsRejected);
    run_kem(runner, &sk, inputs);
}

/// ML-KEM-1024 decapsulation: one fixed ciphertext (Left) against fresh valid ciphertexts
/// (Right), the standard "fix vs random" dudect configuration.
fn mlkem1024_decaps_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk, inputs) = kem_inputs(rng, KemAlgorithm::MlKem1024, Scenario::FixedVsRandom);
    run_kem(runner, &sk, inputs);
}

/// X25519 decapsulation (the classical half of the hybrid KEM): fixed peer key (Left) against
/// fresh peer keys (Right).
fn x25519_decaps_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk, inputs) = kem_inputs(rng, KemAlgorithm::X25519, Scenario::FixedVsRandom);
    run_kem(runner, &sk, inputs);
}

/// ML-DSA-65 signing: a fixed message (Left) against random messages (Right). Rejection
/// sampling makes the iteration count vary, but by design its distribution does not depend on
/// the secret key or on the message class, so both classes must look identical.
fn mldsa65_sign_fixed_vs_random_message(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (_, sk) = sig::keypair(SigAlgorithm::MlDsa65).expect("keypair");
    let fixed = vec![0x5Au8; 64];
    let mut inputs = Vec::with_capacity(SIGN_SAMPLES);
    for _ in 0..SIGN_SAMPLES {
        let class = coin(rng);
        // Both classes allocate and draw the same way; only the chosen content differs.
        let random = random_bytes(rng, 64);
        let msg = match class {
            Class::Left => fixed.as_slice(),
            Class::Right => random.as_slice(),
        }
        .to_vec();
        inputs.push((class, msg));
    }
    for (class, msg) in inputs {
        runner.run_one(class, || sig::sign(&sk, &msg));
    }
}

/// Keyed-hash comparison used for API key verification: equal hashes (Left) against hashes
/// that differ in the first byte (Right). A naive `==` would exit early on Right.
fn ct_eq_equal_vs_first_byte_differs(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::with_capacity(KEM_SAMPLES);
    for _ in 0..KEM_SAMPLES {
        let class = coin(rng);
        let a = random_bytes(rng, 32);
        let mut b = a.clone();
        if matches!(class, Class::Right) {
            b[0] ^= 0xFF;
        }
        inputs.push((class, a, b));
    }
    for (class, a, b) in inputs {
        runner.run_one(class, || ct_eq(&a, &b));
    }
}

/// Positive control: the same inputs compared with slice `==`, which exits at the first
/// differing byte. This bench must report a large `|t|`; if it does not, the harness or the
/// machine is too noisy for the other results to mean anything.
fn control_naive_eq_equal_vs_first_byte_differs(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::with_capacity(KEM_SAMPLES);
    for _ in 0..KEM_SAMPLES {
        let class = coin(rng);
        let a = random_bytes(rng, 4096);
        let mut b = a.clone();
        if matches!(class, Class::Right) {
            b[0] ^= 0xFF;
        }
        inputs.push((class, a, b));
    }
    for (class, a, b) in inputs {
        runner.run_one(class, || a == b);
    }
}

ctbench_main!(
    control_naive_eq_equal_vs_first_byte_differs,
    ct_eq_equal_vs_first_byte_differs,
    mldsa65_sign_fixed_vs_random_message,
    mlkem1024_decaps_fixed_vs_random,
    mlkem768_decaps_valid_vs_rejected,
    x25519_decaps_fixed_vs_random
);

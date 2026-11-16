# Known-Answer Test vectors

The files in `vectors/` are a deterministic subset of the official NIST ACVP vectors for FIPS 203
(ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA).

* Source: https://github.com/usnistgov/ACVP-Server, directory `gen-val/json-files/`, files
  `internalProjection.json` (the variant that includes the expected answers).
* Source commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12).
* Produced by `scripts/trim_acvp.py`, which only selects test cases and flattens the group
  attributes into each case. No value is altered. Re-run the script against a fresh checkout to
  refresh the vectors.

All three implementations (Rust/PQClean, Python/liboqs, TypeScript/noble) consume the same files.
CI fails if any implementation disagrees with NIST.

## What each file tests

| File | Cases | Contents |
|------|-------|----------|
| `ml-kem-keygen.json` | 15 | `d`, `z` seeds → expected `ek`, `dk` for ML-KEM-512/768/1024 |
| `ml-kem-encaps.json` | 15 | `ek`, randomness `m` → expected `c`, `k` (and `dk` for the round trip) |
| `ml-kem-decaps.json` | 30 | `dk`, `c` → expected `k`, including implicit-rejection cases (`reason`) |
| `ml-kem-keycheck.json` | 24 | Encapsulation-key modulus checks and decapsulation-key hash checks with expected pass/fail |
| `ml-dsa-keygen.json` | 9 | `seed` → expected `pk`, `sk` for ML-DSA-44/65/87 |
| `ml-dsa-siggen.json` | 30 | External interface (pure, with `context`) deterministic and hedged (`rnd`) signatures, plus internal-interface signatures |
| `ml-dsa-sigver.json` | 36 | Signature verification cases with expected `testPassed` and failure `reason` |
| `slh-dsa-keygen.json` | 10 | `skSeed`, `skPrf`, `pkSeed` → expected `sk`, `pk` for SLH-DSA-SHA2-128s |
| `slh-dsa-siggen.json` | 9 | Deterministic and randomized (`additionalRandomness`) external signatures plus internal-interface signatures |
| `slh-dsa-sigver.json` | 12 | Verification cases with expected `testPassed` |

## Coverage matrix per implementation

Not every implementation exposes a deterministic entry point for every operation. The matrix below
records which vectors are checked as **full KATs** (output must equal NIST's expected value) and
which as **verification KATs** (NIST's expected signature must verify, or NIST's key must be
structurally consistent and interoperate). Every test asserts how many cases it executed, so an
empty vector file cannot pass.

### Rust (`crates/qshield-crypto/tests/kat.rs`)

| Vectors | Implementation | Check | Cases |
|---------|----------------|-------|-------|
| ML-KEM keyGen | PQClean clean, `crypto_kem_keypair_derand` | full | 15 |
| ML-KEM encaps | PQClean clean, `crypto_kem_enc_derand` | full, plus decapsulation with NIST's `dk` | 15 |
| ML-KEM decaps | PQClean clean | full, including implicit-rejection cases | 30 |
| ML-KEM key checks | FIPS 203 §7.2/§7.3 checks in `kem.rs` | full (pass and fail cases) | 24 |
| ML-DSA keyGen | PQClean clean | consistency: `rho` shared, `tr = H(pk)`, PQClean signs with NIST's `sk` and verifies under NIST's `pk` | 9 |
| ML-DSA sigGen | PQClean clean | verification of NIST's signatures, external interface (signing is hedged, so no deterministic entry point exists). The 12 internal-interface cases are counted as skipped because PQClean does not expose `Sign_internal` | 18 |
| ML-DSA sigVer | PQClean clean | full, external interface; 12 internal-interface cases skipped as above | 24 |
| SLH-DSA keyGen | slhdsa-c, `slh_keygen_internal` | full | 10 |
| SLH-DSA sigGen | slhdsa-c, `slh_sign` / `slh_sign_internal` | full: deterministic and randomized (`addrnd`), external and internal | 9 |
| SLH-DSA sigVer | slhdsa-c | full, external and internal | 12 |

PQClean's SPHINCS+ (`pqcrypto-sphincsplus`) was tested against the same vectors and failed the
signature cases while passing key generation: it implements SPHINCS+ round 3.1, which differs from
FIPS 205 in how FORS indices are read from the digest. That result is why SLH-DSA comes from
slhdsa-c (see `crates/qshield-slhdsa-sys/README.md`).

### Python and TypeScript SDKs

Planned for phase 5 (SDKs): the same vector files will be consumed by the Python SDK test suite and
the TypeScript SDK test suite, and this section will list their matrix.

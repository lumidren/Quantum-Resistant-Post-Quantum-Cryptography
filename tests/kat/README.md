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
which as **verification KATs** (NIST's expected signature or key must verify / be consistent). CI
enforces every cell marked here.

| Vectors | Rust (PQClean via `pqcrypto-*`) | Python (liboqs via `oqs`) | TypeScript (`@noble/post-quantum`) |
|---------|----------------------------------|---------------------------|------------------------------------|
| ML-KEM keyGen | full (`crypto_kem_keypair_derand`) | full (`generate_keypair_derand`) | full (`keygen(seed)`) |
| ML-KEM encaps | full (`crypto_kem_enc_derand`) | round trip via `dk` (no derand encaps in bindings) | full (`encapsulate(ek, m)`) |
| ML-KEM decaps | full | full | full |
| ML-KEM key checks | full (checks implemented in wrapper) | full (checks implemented in wrapper) | full |
| ML-DSA keyGen | consistency (sign with `sk`, verify with `pk`) | consistency | full (`keygen(seed)`) |
| ML-DSA sigGen | verification of expected signature (hedged signing has no deterministic entry point) | verification | full for deterministic cases, verification for hedged |
| ML-DSA sigVer | full (external pure); internal interface not exposed | full (external pure) | full (external + internal) |
| SLH-DSA keyGen | full (`crypto_sign_seed_keypair`) | consistency | full |
| SLH-DSA sigGen | verification | verification | full for deterministic cases |
| SLH-DSA sigVer | full (external + internal) | full (external) | full |

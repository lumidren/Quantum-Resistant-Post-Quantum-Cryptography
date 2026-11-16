# qshield-slhdsa-sys

FFI bindings to a vendored copy of [slhdsa-c](https://github.com/pq-code-package/slhdsa-c), the
portable C implementation of FIPS 205 (SLH-DSA) maintained by the Post-Quantum Cryptography
Alliance (PQCA). liboqs generates its SLH-DSA support from this same code base
(`copy_from_slh_dsa_c.py`, upstream recorded in liboqs `docs/algorithms/sig/slh_dsa.yml`).

## Why this crate exists

QuantumShield first used `pqcrypto-sphincsplus`. That crate wraps PQClean's **SPHINCS+ round 3.1**,
which predates FIPS 205. The known-answer tests in `crates/qshield-crypto/tests/kat.rs` showed the
difference: key generation matched NIST's ACVP vectors, but signatures did not verify, because
FIPS 205 changed how FORS indices are read from the message digest. A FIPS 205 implementation was
therefore required.

liboqs (through the `oqs` crate) would provide one, but building liboqs needs CMake. slhdsa-c is
self-contained C90 with no build-system requirements, so it is compiled here with the `cc` crate.

## Vendored sources

* Upstream: https://github.com/pq-code-package/slhdsa-c
* Commit: `47451432bb04faf8217ffe8a961a75b542bf88e8` (2026-11-04, "Check RBG return value in slh_keygen")
* liboqs `main` pins the older commit `a0fc1ff253930060d0246aebca06c2538eb92b88`; the newer commit
  adds a return-value check in `slh_keygen` and does not change outputs.
* Files: the library sources and headers only (no tests, proofs or build files), copied without
  modification. Licence: Apache-2.0 OR ISC OR MIT (`vendor/slhdsa-c/LICENSE`).

SHA-256 of every vendored file:

```
70003c41da5c7f3f613127c8af84f56bd869837879c3e05aa359d1a8aebe0bc3  LICENSE
60ed46039954b9a9514f88af07a96e6b94cb8324869f43f851a413772f43f9c2  README.md
9424b1307d17a0c2abf518c4f36f603e9e2b078112bf265a56939e8d88bb43da  cbmc.h
affe337c8e750a208081ba14d518e63a4ba5c595b5c73d781c0a1261c0eefa8a  plat_local.h
803d2e0ca37a10286dc1f459fa0dcc7e0862d38606e98e2ddd266efa305652d0  sha2_256.c
430e4007d50556155227a3063c7dcd8b6dac26143f311e9958b9dbabbfbb2b75  sha2_512.c
693877c59204293e8401a4c59634003465184933542ba23910647e5c3452812f  sha2_api.h
de494c0007a35d02a029ee8aa62d2a4f2f9fbc73dd75f33cfc78e79c179815cb  sha3_api.c
f6ecf1d856caae46b9afc7d632a28d846c0eef0ed73c862935f612ae3017c812  sha3_api.h
d601196c32f2e84866a78da903d583ddc2efaa77323ad927fb25623808138d24  sha3_f1600.c
07a8ab476e6ae282d7ee680c2e0881ad89d090b340adaef45628bebcc2ae0de1  slh_adrs.h
ec47f2180f4b58d179befb938dcb649b3f41f5af62c19002e73a56d1ba947bea  slh_dsa.c
4559cda7320c3a0c8ed5cc38b69083a01c3425126975cab2d01c97fe2105631b  slh_dsa.h
bdf877749c858e887bd4f4e41e2dde4f3b0a69f0881d51c8362af7ea10216d5b  slh_param.h
e5ad11c2e4b583cfcccf491f583344f8cc31c22856c72d8b66c7342df789d340  slh_prehash.c
8415e1911ba6a9029be79fe76d330087b97d00ac0cecc68bdaa1284ad3b11113  slh_prehash.h
ba406c1f3479922d4b70a281dbe5a77d158d60d3caa6843fb32c982b3afb5b19  slh_sha2.c
f58bdd0f989a6d8cd35b6c4ed53ad2ae1cb9ed10da4eb81e53225ccf6386ed32  slh_shake.c
a78deb49ad0dfa329ad5509c201c36de0a83e6e21c8f27602413a1213a8ef951  slh_sys.h
9ae8c5f4a8646bae74d9ebb6abd7c67627bde8aa78ddc97c3e523154460592b9  slh_var.h
```

`scripts/vendor_slhdsa.sh <commit>` re-vendors from upstream and prints the new hashes; CI runs
`scripts/vendor_slhdsa.sh --check` to fail if a vendored file was edited.

## Symbol prefixing

`build.rs` renames every external symbol (`sha3`, `shake`, `sha2_256`, `slh_sign`, the parameter
set constants, ...) to `qshield_slhdsa_*` with preprocessor definitions, so the library cannot collide
with other C code in the same binary. The sources are compiled unmodified.

## Status and caveats

* The upstream README states that slhdsa-c is work in progress and not yet recommended for
  production. liboqs, which the project brief lists as an acceptable source, carries the same
  code and the same caveat. QuantumShield uses SLH-DSA only for low-volume, long-horizon signing
  in the KMS; the messaging protocol uses ML-DSA-65. This residual risk is recorded in
  `THREAT_MODEL.md`.
* Every NIST ACVP SLH-DSA-SHA2-128s vector in `tests/kat/vectors` (key generation, deterministic
  and randomized signing, internal and external interfaces, verification) passes byte for byte.
* Secret-dependent intermediate values may remain on the C stack after a call returns; the Rust
  wrappers zeroize every buffer they own.

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

SHA-256 of every vendored file (the upstream blobs, LF line endings):

```
f5f353e7c2308465c5e82021a06acfba74d3d5e70d13e4af8226e9051a25ce2c  LICENSE
cc7f4aec314addc80f9c270c42a7eb8d849ad8e6ec26027e02953bb883707a2d  README.md
4f90b426dc23e18b36ac8f4b9ef43cecb66c82d70ece15b43f16577b2fde536d  cbmc.h
bf40bd38691272a7751639a65b1bf1dd086e710f8d74db725035590ed1243111  plat_local.h
5549450700247929989511f388b7e494f27fd091c5c6d7d06e8b872f7865cc9f  sha2_256.c
32ea1034e09e4879ad3326ff7ac810feb17756867e380508e8fc499984098e96  sha2_512.c
4315f4891acfdcadfdc220770fd3a8a080aec94f6346eec9d8badbea1bb3a6ba  sha2_api.h
27c366ba3fe34c48f415071a2af68bc91b18384c35b8bd4efdc87428c91ae519  sha3_api.c
fe8a8749e8aababb121cb317f6fb3643bde1c4b69b62d35d07e3443f3d957ae8  sha3_api.h
119ece300472413bc0efd120b1fde181113dd44b3ebdd6073959ec6626c714cc  sha3_f1600.c
75a5ed6b5636e013471190efa88ccdd3d39fb2e12fe51e8ba22a4d158980a98c  slh_adrs.h
306430bf2475600c5b82dcf663f9df0bef612bdf444cd70517aabac7cf32d7d4  slh_dsa.c
cce0d50708185920271faa88309c1cb9480a71096cf6f5169298d6e493d8f421  slh_dsa.h
d848f41c5f5ac2b911d077209da0f9fb313ffcc8865c55b43dd09cdfce009ac7  slh_param.h
0fb74cb91e91db7b4fe58c05b9cf6036af6c54fa731273e44663873eccdb9576  slh_prehash.c
c5b4eb9686d35cb9b3def746340bd1e44da452cfd0340fdaec9259ddc14630dd  slh_prehash.h
1c541614e6eb3ce2699c5f8f6a1d32cc798561fcf5c0492b39ec9373c7f13041  slh_sha2.c
a212b05e9c01dc4404c5af170b19c8b19d1bbcf3f77e661fb43dd816ad351339  slh_shake.c
7cf5a5dd7ebc76dd3f576606c6936486945feb59750483fc3b2aacd2b901d210  slh_sys.h
0c87ae009a76c07f3c0c066b2d255e5f6cb18e6f38f7df3d805e395d37ef96b0  slh_var.h
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

# Constant-time test results (dudect)

QuantumShield runs dudect-style timing tests (Reparaz, Balasch and Verbauwhede, *Dude, is my code
constant time?*, DATE 2017) on the secret-dependent paths of its cryptographic core. Each bench
splits inputs into two classes, times the operation for every input, and runs Welch's t-test on
cropped percentiles of the two timing distributions. A bench reports the largest absolute
t-statistic found (`max t`).

* `|t| < 4.5`: no evidence that the two classes can be told apart by timing.
* `|t| >= 4.5`: the classes are distinguishable; the code path must be investigated.

These tests give statistical evidence, not proof. They complement the design-level guarantees:
PQClean's portable implementations and slhdsa-c are written to be constant time, and
`qshield-crypto` adds no secret-dependent branches (see `THREAT_MODEL.md`, T11).

## How to reproduce

```bash
scripts/run_dudect.sh
```

The script builds `crates/qshield-crypto/benches/dudect.rs` in release mode and runs the binary
directly, because `cargo bench` passes a `--bench` flag that dudect-bencher's argument parser
rejects. On Linux it pins the process to one CPU with `taskset`. The Windows runs below were pinned
to one performance core through the process affinity mask and ran at high priority.

## Machine

| Item | Value |
|------|-------|
| CPU | 12th Gen Intel Core i7-12700H (hybrid P-core and E-core design) |
| Pinning | logical CPU 2 (a performance core), high process priority |
| OS | Windows 11 Home 10.0.26200 |
| Rust | rustc 1.99.1, release profile (`opt-level = 3`, thin LTO) |
| C compiler | MSVC 14.38 (`cl`), PQClean and slhdsa-c compiled with `/O2` or higher |
| Date | 2026-11-16 |

## Benches

| Bench | Left class | Right class | Inputs per run | What a leak would mean |
|-------|------------|-------------|----------------|------------------------|
| `mlkem768_decaps_valid_vs_rejected` | honestly generated ciphertexts | uniformly random ciphertexts (implicit rejection) | 100,000 | Fujisaki-Okamoto re-encryption leaks whether a ciphertext was valid |
| `mlkem1024_decaps_fixed_vs_random` | one fixed valid ciphertext | fresh valid ciphertexts | 100,000 | decapsulation time depends on ciphertext content |
| `x25519_decaps_fixed_vs_random` | one fixed peer key | fresh peer keys | 100,000 | scalar multiplication time depends on the point |
| `mldsa65_sign_fixed_vs_random_message` | fixed 64-byte message | random 64-byte messages | 20,000 | signing time depends on the message beyond the designed rejection sampling |
| `ct_eq_equal_vs_first_byte_differs` | equal 32-byte values | values differing in byte 0 | 100,000 | the API-key hash comparison exits early |
| `control_naive_eq_equal_vs_first_byte_differs` | equal 4,096-byte values | values differing in byte 0 | 100,000 | positive control: slice `==` exits early, so this **must** leak |

## Results

Five consecutive runs of every bench. `n` is the number of samples in the cropped percentile that
produced `max t`.

| Bench | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 | Largest \|t\| | Verdict |
|-------|-------|-------|-------|-------|-------|---------------|---------|
| `mlkem768_decaps_valid_vs_rejected` | +1.78 | +1.96 | -2.53 | +1.27 | -1.90 | 2.53 | no evidence of leakage |
| `mlkem1024_decaps_fixed_vs_random` | -1.63 | -2.15 | +1.36 | -1.90 | -2.43 | 2.43 | no evidence of leakage |
| `x25519_decaps_fixed_vs_random` | +3.09 | -1.51 | +2.64 | +1.66 | +2.12 | 3.09 | no evidence of leakage |
| `mldsa65_sign_fixed_vs_random_message` | +2.09 | -1.51 | +3.54 | +3.19 | +1.09 | 3.54 | no evidence of leakage |
| `ct_eq_equal_vs_first_byte_differs` | +1.54 | -1.93 | +1.44 | -0.76 | +1.67 | 1.93 | no evidence of leakage |

Positive control (two runs): `max t = +399.56` and `+379.78`. The harness detects a real
early-exit leak by two orders of magnitude, so the small values above are meaningful.

## Investigation: a false positive caused by the bench itself

The first version of the ML-KEM benches built the two classes differently: valid ciphertexts came
straight out of `encapsulate()`, while random ciphertexts were copied from a separately allocated
buffer. Three repeated runs of `mlkem768_decaps_valid_vs_rejected` gave `max t` of -2.94, -5.68
and -5.12, twice above the threshold.

Before changing the bench, the C code was checked for a genuine leak:

* `poly_tomsg` and the compression routines use the KyberSlash fix (multiply and shift by
  precomputed constants, no division by `q`).
* `verify` compares ciphertexts with an OR-accumulator and returns `(-(uint64_t)r) >> 63`; `cmov`
  selects the shared secret with a mask. Both are constant time.
* On MSVC, `PQCLEAN_PREVENT_BRANCH_HACK` expands to nothing, but `cmov` (in `verify.c`) and
  decapsulation (in `kem.c`) are separate translation units built without cross-unit
  optimisation, so the compiler cannot infer that the condition is 0 or 1 and branch on it.

The benches were then changed so that every sample performs the same allocations and random draws
for both classes, and only the chosen content differs (`kem_inputs` in the bench file). With that
change, five runs of every bench stayed below 4.5, as the table shows. The original difference was
a memory-layout artefact of the bench, not a property of the decapsulation code.

## Limits

* SLH-DSA signing is not benchmarked: one SLH-DSA-SHA2-128s signature takes tens of milliseconds,
  so the hundreds of thousands of samples dudect needs are impractical. SLH-DSA has no
  secret-dependent branching by construction, and slhdsa-c ships hooks for valgrind-based
  constant-time testing (`SLH_CT_TESTING_*`), which upstream runs.
* Results are for this machine and compiler. CI repeats the run on a Linux runner with GCC as a
  smoke test; shared CI runners are noisier, so CI flags `|t| >= 10` as a failure and treats
  values between 4.5 and 10 as a warning that needs a local rerun.

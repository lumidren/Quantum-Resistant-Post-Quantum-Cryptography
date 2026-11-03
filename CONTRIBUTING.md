# Contributing to QuantumShield

Thank you for helping make real services quantum-safe.

## Ground rules

1. **No hand-rolled cryptography.** Lattice, hash-based and curve arithmetic come only from the
   vetted implementations listed in `ARCHITECTURE.md` §2. Pull requests that implement a primitive
   are closed.
2. **Hybrid or nothing.** Any new key exchange or signature path must combine a classical and a
   PQ algorithm.
3. **Registry first.** Adding an algorithm starts with an entry in `registry/algorithms.toml`,
   a KAT file under `crates/qshield-crypto/testdata/kat/`, and a migration if the KMS schema is
   affected.
4. **Every mitigation has a test.** Changes that touch `THREAT_MODEL.md` must include or update
   the test referenced there, and anchor comments (`// TM:<id>`) must be kept so
   `scripts/threat_refs.py --check` passes.
5. **Coverage gates.** Overall ≥ 90 %; `qshield-crypto`, `qshield/pqxdh.py`, `qshield/ratchet.py`,
   `src/pqxdh.ts` and `src/ratchet.ts` must stay at 100 % line coverage.

## Development setup

### Prerequisites

* Rust 1.85+ (stable) with a C toolchain (MSVC Build Tools on Windows, gcc/clang elsewhere)
* Python 3.12+ (64-bit) and `uv`
* Node 24+
* Docker and docker compose (for the quickstart and integration tests)
* OpenSSL 3.5+ CLI (for the TLS benchmarks and scanner TLS probes)

### Build and test

```bash
# Rust workspace
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Python SDK and scanner
uv venv .venv && uv pip install -e sdk/python[dev] -e scanner[dev]
pytest sdk/python scanner --cov

# TypeScript SDK and web app
cd sdk/typescript && npm ci && npm test && npm run build
cd ../../web && npm ci && npm run lint && npm run typecheck && npm run build

# Cross-SDK interop
python tests/interop/run.py
```

### liboqs for the Python SDK

`oqs` needs the liboqs shared library. On Debian/Ubuntu: `apt install liboqs-dev` (or build from
source as `deploy/docker/python-base.Dockerfile` does). On Windows, build liboqs with CMake and set
`OQS_INSTALL_PATH`. `scripts/build_liboqs.sh` and `scripts/build_liboqs.ps1` automate this.

## Commit style

* Small, focused commits with Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, `test:`,
  `chore:`, `ci:`, `perf:`, `refactor:`.
* Reference the threat id when a commit changes a mitigation, e.g. `fix(kms): T08-M1 enforce scope on rotate`.
* Sign commits if you can (`git commit -S`).

## Pull request checklist

- [ ] Tests added or updated; `cargo test`, `pytest`, `npm test` pass locally
- [ ] Coverage gates still met
- [ ] `THREAT_MODEL.md` anchors updated if a mitigation changed
- [ ] `CHANGELOG.md` entry under *Unreleased*
- [ ] No secrets, private keys or `.env` files in the diff
- [ ] Documentation updated (`ARCHITECTURE.md`, API reference, runbook) if behaviour changed

## Code of conduct

Be kind, be precise, assume good faith. Harassment of any kind is not tolerated.

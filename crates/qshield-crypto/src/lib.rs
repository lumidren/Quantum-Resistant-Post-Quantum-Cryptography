//! # qshield-crypto
//!
//! The cryptographic core of QuantumShield.
//!
//! * [`kem`]: ML-KEM-512/768/1024 (FIPS 203) and X25519 under one interface.
//! * [`sig`]: ML-DSA-44/65/87 (FIPS 204), SLH-DSA-SHA2-128s (FIPS 205) and Ed25519.
//! * [`hybrid`]: the mandatory hybrid combiners (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65).
//! * [`envelope`]: AES-256-GCM envelope sealing of private keys under per-key DEKs.
//! * [`registry`]: the versioned algorithm registry that drives crypto-agility.
//! * [`secret`]: zeroizing, redacted containers for secret material.
//!
//! No lattice, hash-based or curve arithmetic is implemented here. Post-quantum primitives come
//! from PQClean through the `pqcrypto-*` crates; classical primitives from the dalek and
//! RustCrypto projects. This crate adds type safety, input validation required by the FIPS
//! documents (encapsulation and decapsulation key checks), domain separation, zeroization and
//! the registry.
//!
//! The `kat` feature exposes deterministic entry points used exclusively by the NIST
//! known-answer tests and must never be enabled in a production build.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::doc_markdown
)]

pub mod envelope;
pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod kem;
mod pqc;
pub mod random;
pub mod registry;
pub mod secret;
pub mod sig;

#[cfg(feature = "kat")]
pub mod kat;

pub use error::CryptoError;
pub use secret::SecretBytes;

/// Crate version, embedded in CBOM output and `/healthz` responses.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

//! Error type. Errors never carry secret material: variants hold algorithm identifiers, lengths
//! and static descriptions only.

use crate::registry::Status;

/// Errors produced by the cryptographic core.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The algorithm identifier is not present in the registry.
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    /// The algorithm exists but its registry status forbids the requested operation.
    #[error("algorithm {id} is {status} and may not be used for {operation}")]
    AlgorithmNotAllowed {
        /// Registry identifier.
        id: String,
        /// Current registry status.
        status: Status,
        /// Operation that was refused (`generate`, `sign`, `use`).
        operation: &'static str,
    },

    /// A key, ciphertext or signature had an unexpected length.
    #[error("invalid {what} length for {algorithm}: expected {expected}, got {actual}")]
    InvalidLength {
        /// What was being parsed.
        what: &'static str,
        /// Algorithm identifier.
        algorithm: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// An encapsulation key failed the FIPS 203 modulus check or a decapsulation key failed the
    /// hash check.
    #[error("{0} failed FIPS 203 key check")]
    InvalidKey(&'static str),

    /// Two objects of different algorithms were combined.
    #[error("algorithm mismatch: {0} vs {1}")]
    AlgorithmMismatch(&'static str, &'static str),

    /// Decapsulation produced a non-contributory (all-zero) shared secret.
    #[error("decapsulation failed")]
    Decapsulation,

    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Authenticated decryption failed (wrong key, wrong AAD or modified ciphertext).
    #[error("authenticated decryption failed")]
    Aead,

    /// Malformed input that is not a length problem.
    #[error("malformed input: {0}")]
    Malformed(&'static str),

    /// The operation is not supported for this algorithm.
    #[error("unsupported operation for {algorithm}: {operation}")]
    Unsupported {
        /// Algorithm identifier.
        algorithm: &'static str,
        /// Operation name.
        operation: &'static str,
    },

    /// The registry file is invalid.
    #[error("registry error: {0}")]
    Registry(String),

    /// Key derivation failed (invalid output length).
    #[error("key derivation failed")]
    Kdf,
}

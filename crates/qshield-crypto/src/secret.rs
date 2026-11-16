//! Zeroizing, redacted containers for secret material.
//!
//! `SecretBytes` is the only type in this crate that holds secret key bytes. It wipes its memory
//! on drop, prints `[REDACTED]` for `Debug`, has no `Display` and no `Serialize`, and compares in
//! constant time. The KMS leak-scan test relies on these properties.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret bytes that are zeroized on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps an owned buffer. The buffer is consumed so that no unzeroized copy remains.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Copies a slice into a new secret buffer.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// A zero-filled buffer of `len` bytes, to be filled in place (FFI outputs).
    #[must_use]
    pub(crate) fn zeroed(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    /// Mutable access for in-place filling. The buffer never reallocates, so no copy escapes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the secret bytes. Call sites should be few and obvious.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    // TM:T03-M1 secret containers never print their contents
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        // `subtle` returns 0 immediately for differing lengths; lengths are public here (they are
        // fixed per algorithm), so this does not leak secret information.
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBytes {}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

/// Constant-time equality of two byte strings whose lengths are public (MAC tags, keyed
/// hashes of API keys). Returns `false` immediately only when the lengths differ.
// TM:T11-M2 secret comparisons are constant-time
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::from_slice(&[0xAB; 16]);
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretBytes([REDACTED])");
        assert!(!dbg.contains("AB"));
        assert!(!dbg.contains("171"));
    }

    #[test]
    fn equality_is_by_content() {
        let a = SecretBytes::from_slice(&[1, 2, 3]);
        let b = SecretBytes::from_slice(&[1, 2, 3]);
        let c = SecretBytes::from_slice(&[1, 2, 4]);
        let d = SecretBytes::from_slice(&[1, 2]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 3);
        assert!(!a.is_empty());
        assert!(SecretBytes::new(Vec::new()).is_empty());
    }

    #[test]
    fn ct_eq_compares_content_and_length() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn from_vec_and_expose() {
        let s: SecretBytes = vec![9u8, 8, 7].into();
        assert_eq!(s.expose_secret(), &[9, 8, 7]);
        let t = s.clone();
        assert_eq!(t.expose_secret(), &[9, 8, 7]);
    }
}

//! Operating-system randomness. All randomness in the crate flows through this module so that the
//! source is auditable in one place.

use rand_core::{OsRng, RngCore};

/// Fills `buf` with cryptographically secure random bytes from the operating system.
pub fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Returns `n` cryptographically secure random bytes.
#[must_use]
pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(&mut v);
    v
}

/// Returns a random 32-byte array (nonce seeds, key ids, challenges).
#[must_use]
pub fn array32() -> [u8; 32] {
    let mut a = [0u8; 32];
    fill(&mut a);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_differ() {
        let a = bytes(32);
        let b = bytes(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_ne!(array32(), array32());
        let mut buf = [0u8; 8];
        fill(&mut buf);
        assert_ne!(buf, [0u8; 8]);
    }
}

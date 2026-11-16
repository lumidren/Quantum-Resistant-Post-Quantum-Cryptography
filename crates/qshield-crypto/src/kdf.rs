//! Key derivation helpers: HKDF-SHA256 and HMAC-SHA256 with explicit domain separation.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CryptoError;
use crate::secret::SecretBytes;

/// HKDF-SHA256 extract-and-expand.
///
/// `salt` of `None` uses the RFC 5869 default (a block of zeros). `info` must be a fixed,
/// context-specific label; see `ARCHITECTURE.md` §5.5 for the registry of labels.
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<SecretBytes, CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Kdf)?;
    Ok(SecretBytes::new(okm))
}

/// HMAC-SHA256.
///
/// # Panics
///
/// Never: HMAC accepts keys of any length.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        // RFC 5869 Appendix A.1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(Some(&salt), &ikm, &info, 42).unwrap();
        assert_eq!(
            hex::encode(okm.expose_secret()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_rfc5869_test_case_3_no_salt() {
        // RFC 5869 Appendix A.3: zero-length salt and info.
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let okm = hkdf_sha256(None, &ikm, b"", 42).unwrap();
        assert_eq!(
            hex::encode(okm.expose_secret()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_rejects_oversized_output() {
        assert_eq!(
            hkdf_sha256(None, b"k", b"i", 255 * 32 + 1),
            Err(CryptoError::Kdf)
        );
    }

    #[test]
    fn hmac_rfc4231_test_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}

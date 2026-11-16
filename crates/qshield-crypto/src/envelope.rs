//! Envelope encryption of private keys.
//!
//! Every private key is sealed with AES-256-GCM under its own random data-encryption key (DEK).
//! The DEK is in turn wrapped by a key-encryption key (KEK) that lives in Vault Transit, AWS KMS
//! or the Shamir-sealed local provider (see `qshield-kms::kek`). The associated data binds the
//! key id, algorithm id and key version so that a sealed blob can never be transplanted onto a
//! different record.

use core::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::random;
use crate::secret::SecretBytes;

/// DEK length in bytes (AES-256).
pub const DEK_LEN: usize = 32;
/// GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// GCM tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;
/// Domain-separation label for key envelopes.
pub const ENVELOPE_LABEL: &[u8] = b"qshield-envelope-v1";
/// Domain-separation label for DEK wrapping by the local KEK provider.
pub const DEK_WRAP_LABEL: &[u8] = b"qshield-dek-wrap-v1";

/// A data-encryption key. Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Dek(SecretBytes);

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek([REDACTED])")
    }
}

impl Dek {
    /// Generates a random DEK.
    #[must_use]
    pub fn generate() -> Self {
        Self(SecretBytes::new(random::bytes(DEK_LEN)))
    }

    /// Wraps existing key bytes (must be exactly 32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DEK_LEN {
            return Err(CryptoError::InvalidLength {
                what: "DEK",
                algorithm: "aes-256-gcm",
                expected: DEK_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(SecretBytes::from_slice(bytes)))
    }

    /// Key bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

/// A sealed blob: version, nonce and AES-256-GCM ciphertext (tag appended).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    /// Envelope format version.
    pub version: u8,
    /// 96-bit GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte tag.
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    /// Encodes as `version || nonce || ciphertext`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + NONCE_LEN + self.ciphertext.len());
        v.push(self.version);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ciphertext);
        v
    }

    /// Parses `version || nonce || ciphertext`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Malformed("sealed blob too short"));
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(CryptoError::Malformed("unsupported envelope version"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1..=NONCE_LEN]);
        Ok(Self {
            version: bytes[0],
            nonce,
            ciphertext: bytes[1 + NONCE_LEN..].to_vec(),
        })
    }
}

/// The record attributes bound into the envelope AAD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeContext<'a> {
    /// Key record identifier.
    pub key_id: &'a str,
    /// Registry algorithm identifier.
    pub algorithm: &'a str,
    /// Key version (rotations increment this).
    pub key_version: u32,
}

impl EnvelopeContext<'_> {
    /// `label || 0 || key_id || 0 || algorithm || 0 || version(BE u32)`.
    // TM:T02-M3 AAD binds key id, algorithm and version into the envelope
    // TM:T09-M1 a sealed blob moved to another record fails to open
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(ENVELOPE_LABEL.len() + self.key_id.len() + self.algorithm.len() + 7);
        v.extend_from_slice(ENVELOPE_LABEL);
        v.push(0);
        v.extend_from_slice(self.key_id.as_bytes());
        v.push(0);
        v.extend_from_slice(self.algorithm.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.key_version.to_be_bytes());
        v
    }
}

/// Seals `plaintext` under `dek` with a fresh random nonce and the context's AAD.
// TM:T02-M1 private keys are sealed with AES-256-GCM under a per-key DEK
pub fn seal(
    dek: &Dek,
    ctx: &EnvelopeContext<'_>,
    plaintext: &[u8],
) -> Result<SealedBlob, CryptoError> {
    seal_with_aad(dek, &ctx.aad(), plaintext)
}

/// Opens a sealed blob. Fails if the DEK, nonce, AAD or ciphertext differ from sealing.
pub fn open(
    dek: &Dek,
    ctx: &EnvelopeContext<'_>,
    blob: &SealedBlob,
) -> Result<SecretBytes, CryptoError> {
    open_with_aad(dek, &ctx.aad(), blob)
}

/// Seals with caller-provided AAD (used for DEK wrapping).
pub fn seal_with_aad(dek: &Dek, aad: &[u8], plaintext: &[u8]) -> Result<SealedBlob, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(dek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    let mut nonce = [0u8; NONCE_LEN];
    random::fill(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(SealedBlob {
        version: ENVELOPE_VERSION,
        nonce,
        ciphertext,
    })
}

/// Opens with caller-provided AAD.
pub fn open_with_aad(dek: &Dek, aad: &[u8], blob: &SealedBlob) -> Result<SecretBytes, CryptoError> {
    if blob.version != ENVELOPE_VERSION {
        return Err(CryptoError::Malformed("unsupported envelope version"));
    }
    let cipher = Aes256Gcm::new_from_slice(dek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&blob.nonce),
                Payload {
                    msg: &blob.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Aead)?,
    );
    Ok(SecretBytes::from_slice(&plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EnvelopeContext<'static> {
        EnvelopeContext {
            key_id: "key-123",
            algorithm: "ml-kem-768",
            key_version: 1,
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let dek = Dek::generate();
        let blob = seal(&dek, &ctx(), b"private key bytes").unwrap();
        assert_eq!(blob.version, ENVELOPE_VERSION);
        assert_eq!(blob.ciphertext.len(), 17 + TAG_LEN);
        let pt = open(&dek, &ctx(), &blob).unwrap();
        assert_eq!(pt.expose_secret(), b"private key bytes");
        let parsed = SealedBlob::from_bytes(&blob.to_bytes()).unwrap();
        assert_eq!(parsed, blob);
        assert_eq!(format!("{dek:?}"), "Dek([REDACTED])");
        let dek2 = Dek::from_bytes(dek.expose_secret()).unwrap();
        assert_eq!(
            open(&dek2, &ctx(), &blob).unwrap().expose_secret(),
            b"private key bytes"
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let dek = Dek::generate();
        let a = seal(&dek, &ctx(), b"x").unwrap();
        let b = seal(&dek, &ctx(), b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn envelope_rejects_swapped_aad() {
        let dek = Dek::generate();
        let blob = seal(&dek, &ctx(), b"secret").unwrap();
        let other_key = EnvelopeContext {
            key_id: "key-456",
            ..ctx()
        };
        assert_eq!(open(&dek, &other_key, &blob), Err(CryptoError::Aead));
        let other_alg = EnvelopeContext {
            algorithm: "ml-kem-1024",
            ..ctx()
        };
        assert_eq!(open(&dek, &other_alg, &blob), Err(CryptoError::Aead));
        let other_version = EnvelopeContext {
            key_version: 2,
            ..ctx()
        };
        assert_eq!(open(&dek, &other_version, &blob), Err(CryptoError::Aead));
    }

    #[test]
    fn envelope_rejects_tampering_and_wrong_key() {
        let dek = Dek::generate();
        let blob = seal(&dek, &ctx(), b"secret").unwrap();
        let mut t = blob.clone();
        t.ciphertext[0] ^= 1;
        assert_eq!(open(&dek, &ctx(), &t), Err(CryptoError::Aead));
        let mut t = blob.clone();
        t.nonce[0] ^= 1;
        assert_eq!(open(&dek, &ctx(), &t), Err(CryptoError::Aead));
        let mut t = blob.clone();
        let last = t.ciphertext.len() - 1;
        t.ciphertext[last] ^= 1;
        assert_eq!(open(&dek, &ctx(), &t), Err(CryptoError::Aead));
        assert_eq!(
            open(&Dek::generate(), &ctx(), &blob),
            Err(CryptoError::Aead)
        );
        let mut t = blob.clone();
        t.version = 2;
        assert!(matches!(
            open(&dek, &ctx(), &t),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn parsing_errors() {
        assert!(SealedBlob::from_bytes(&[1u8; 5]).is_err());
        let mut b = vec![2u8];
        b.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        assert!(SealedBlob::from_bytes(&b).is_err());
        assert!(Dek::from_bytes(&[0u8; 16]).is_err());
    }

    #[test]
    fn aad_layout() {
        let aad = ctx().aad();
        let mut expected = ENVELOPE_LABEL.to_vec();
        expected.push(0);
        expected.extend_from_slice(b"key-123");
        expected.push(0);
        expected.extend_from_slice(b"ml-kem-768");
        expected.push(0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(aad, expected);
    }
}

//! Mandatory hybrid constructions.
//!
//! * Hybrid KEM `hybrid-x25519-ml-kem-768`: both shared secrets and both ciphertexts (plus both
//!   public keys) are bound through HKDF-SHA256, so the result is secure if **either** component
//!   is secure and mix-and-match attacks across sessions are impossible.
//! * Hybrid signature `hybrid-ed25519-ml-dsa-65`: both signatures over the same
//!   domain-separated message; verification requires both and evaluates both before deciding.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};

use crate::error::CryptoError;
use crate::kdf::hkdf_sha256;
use crate::kem::{self, KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey, SharedSecret};
use crate::secret::SecretBytes;
use crate::sig::{self, SigAlgorithm, SigPublicKey, SigSecretKey, Signature};

/// Registry id of the hybrid KEM.
pub const HYBRID_KEM_ID: &str = "hybrid-x25519-ml-kem-768";
/// Registry id of the hybrid signature.
pub const HYBRID_SIG_ID: &str = "hybrid-ed25519-ml-dsa-65";

/// Domain-separation label of the KEM combiner.
pub const HYBRID_KEM_LABEL: &[u8] = b"QuantumShield-Hybrid-KEM-v1";
/// Domain-separation prefix of the hybrid signature message.
pub const HYBRID_SIG_LABEL: &[u8] = b"QuantumShield-Hybrid-SIG-v1";

const X_PK: usize = 32;
const PQ_PK: usize = 1184;
const X_SK: usize = 32;
const PQ_SK: usize = 2400;
const X_CT: usize = 32;
const PQ_CT: usize = 1088;
const ED_PK: usize = 32;
const MLDSA_PK: usize = 1952;
const ED_SK: usize = 32;
const MLDSA_SK: usize = 4032;
const ED_SIG: usize = 64;
const MLDSA_SIG: usize = 3309;

/// Encoded hybrid KEM public key length (X25519 || ML-KEM-768).
pub const HYBRID_KEM_PUBLIC_KEY_LEN: usize = X_PK + PQ_PK;
/// Encoded hybrid KEM secret key length.
pub const HYBRID_KEM_SECRET_KEY_LEN: usize = X_SK + PQ_SK;
/// Encoded hybrid KEM ciphertext length.
pub const HYBRID_KEM_CIPHERTEXT_LEN: usize = X_CT + PQ_CT;
/// Encoded hybrid signature public key length (Ed25519 || ML-DSA-65).
pub const HYBRID_SIG_PUBLIC_KEY_LEN: usize = ED_PK + MLDSA_PK;
/// Encoded hybrid signature secret key length.
pub const HYBRID_SIG_SECRET_KEY_LEN: usize = ED_SK + MLDSA_SK;
/// Encoded hybrid signature length.
pub const HYBRID_SIGNATURE_LEN: usize = ED_SIG + MLDSA_SIG;

// ---------------------------------------------------------------------------------------------
// Hybrid KEM
// ---------------------------------------------------------------------------------------------

/// Hybrid KEM public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridKemPublicKey {
    /// X25519 component.
    pub x25519: KemPublicKey,
    /// ML-KEM-768 component.
    pub mlkem: KemPublicKey,
}

impl HybridKemPublicKey {
    /// Encodes as `x25519 || ml-kem-768`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HYBRID_KEM_PUBLIC_KEY_LEN);
        v.extend_from_slice(self.x25519.as_bytes());
        v.extend_from_slice(self.mlkem.as_bytes());
        v
    }

    /// Parses `x25519 || ml-kem-768`, applying the FIPS 203 encapsulation key check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                what: "public key",
                algorithm: HYBRID_KEM_ID,
                expected: HYBRID_KEM_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            x25519: KemPublicKey::from_bytes(KemAlgorithm::X25519, &bytes[..X_PK])?,
            mlkem: KemPublicKey::from_bytes(KemAlgorithm::MlKem768, &bytes[X_PK..])?,
        })
    }
}

/// Hybrid KEM secret key.
pub struct HybridKemSecretKey {
    /// X25519 component.
    pub x25519: KemSecretKey,
    /// ML-KEM-768 component.
    pub mlkem: KemSecretKey,
}

impl fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridKemSecretKey([REDACTED])")
    }
}

impl HybridKemSecretKey {
    /// Encodes as `x25519 || ml-kem-768` into a zeroizing buffer.
    #[must_use]
    pub fn to_bytes(&self) -> SecretBytes {
        let mut v = Vec::with_capacity(HYBRID_KEM_SECRET_KEY_LEN);
        v.extend_from_slice(self.x25519.expose_secret());
        v.extend_from_slice(self.mlkem.expose_secret());
        SecretBytes::new(v)
    }

    /// Parses `x25519 || ml-kem-768`, applying the FIPS 203 decapsulation key check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                what: "secret key",
                algorithm: HYBRID_KEM_ID,
                expected: HYBRID_KEM_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            x25519: KemSecretKey::from_bytes(KemAlgorithm::X25519, &bytes[..X_SK])?,
            mlkem: KemSecretKey::from_bytes(KemAlgorithm::MlKem768, &bytes[X_SK..])?,
        })
    }

    /// Derives the public key.
    #[must_use]
    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            x25519: self.x25519.public_key(),
            mlkem: self.mlkem.public_key(),
        }
    }
}

/// Hybrid KEM ciphertext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridKemCiphertext {
    /// X25519 ephemeral public key.
    pub x25519: KemCiphertext,
    /// ML-KEM-768 ciphertext.
    pub mlkem: KemCiphertext,
}

impl HybridKemCiphertext {
    /// Encodes as `x25519_eph || ml-kem-768_ct`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HYBRID_KEM_CIPHERTEXT_LEN);
        v.extend_from_slice(self.x25519.as_bytes());
        v.extend_from_slice(self.mlkem.as_bytes());
        v
    }

    /// Parses `x25519_eph || ml-kem-768_ct`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidLength {
                what: "ciphertext",
                algorithm: HYBRID_KEM_ID,
                expected: HYBRID_KEM_CIPHERTEXT_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            x25519: KemCiphertext::from_bytes(KemAlgorithm::X25519, &bytes[..X_CT])?,
            mlkem: KemCiphertext::from_bytes(KemAlgorithm::MlKem768, &bytes[X_CT..])?,
        })
    }
}

/// Generates a hybrid KEM key pair.
pub fn hybrid_kem_keypair() -> Result<(HybridKemPublicKey, HybridKemSecretKey), CryptoError> {
    let (xpk, xsk) = kem::keypair(KemAlgorithm::X25519)?;
    let (ppk, psk) = kem::keypair(KemAlgorithm::MlKem768)?;
    Ok((
        HybridKemPublicKey {
            x25519: xpk,
            mlkem: ppk,
        },
        HybridKemSecretKey {
            x25519: xsk,
            mlkem: psk,
        },
    ))
}

/// Encapsulates to a hybrid public key.
// TM:T01-M4 hybrid combiner binds both shared secrets and both ciphertexts
pub fn hybrid_encapsulate(
    pk: &HybridKemPublicKey,
) -> Result<(HybridKemCiphertext, SharedSecret), CryptoError> {
    let (xct, xss) = kem::encapsulate(&pk.x25519)?;
    let (pct, pss) = kem::encapsulate(&pk.mlkem)?;
    let ss = combine(
        &xss,
        &pss,
        xct.as_bytes(),
        pct.as_bytes(),
        pk.x25519.as_bytes(),
        pk.mlkem.as_bytes(),
    );
    Ok((
        HybridKemCiphertext {
            x25519: xct,
            mlkem: pct,
        },
        ss,
    ))
}

/// Decapsulates a hybrid ciphertext.
pub fn hybrid_decapsulate(
    sk: &HybridKemSecretKey,
    ct: &HybridKemCiphertext,
) -> Result<SharedSecret, CryptoError> {
    let xss = kem::decapsulate(&sk.x25519, &ct.x25519)?;
    let pss = kem::decapsulate(&sk.mlkem, &ct.mlkem)?;
    let pk = sk.public_key();
    Ok(combine(
        &xss,
        &pss,
        ct.x25519.as_bytes(),
        ct.mlkem.as_bytes(),
        pk.x25519.as_bytes(),
        pk.mlkem.as_bytes(),
    ))
}

/// `HKDF-SHA256(salt = 0^32, ikm = ss_x || ss_pq, info = label || ct_x || ct_pq || pk_x || pk_pq)`.
fn combine(
    xss: &SharedSecret,
    pss: &SharedSecret,
    xct: &[u8],
    pct: &[u8],
    xpk: &[u8],
    ppk: &[u8],
) -> SharedSecret {
    let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(xss.expose_secret());
    ikm.extend_from_slice(pss.expose_secret());
    let mut info =
        Vec::with_capacity(HYBRID_KEM_LABEL.len() + xct.len() + pct.len() + xpk.len() + ppk.len());
    info.extend_from_slice(HYBRID_KEM_LABEL);
    info.extend_from_slice(xct);
    info.extend_from_slice(pct);
    info.extend_from_slice(xpk);
    info.extend_from_slice(ppk);
    let okm = hkdf_sha256(Some(&[0u8; 32]), &ikm, &info, 32)
        .expect("HKDF-SHA256 can always produce 32 bytes");
    SharedSecret::from_secret(okm)
}

// ---------------------------------------------------------------------------------------------
// Hybrid signature
// ---------------------------------------------------------------------------------------------

/// Hybrid signature public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridSigPublicKey {
    /// Ed25519 component.
    pub ed25519: SigPublicKey,
    /// ML-DSA-65 component.
    pub mldsa: SigPublicKey,
}

impl HybridSigPublicKey {
    /// Encodes as `ed25519 || ml-dsa-65`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HYBRID_SIG_PUBLIC_KEY_LEN);
        v.extend_from_slice(self.ed25519.as_bytes());
        v.extend_from_slice(self.mldsa.as_bytes());
        v
    }

    /// Parses `ed25519 || ml-dsa-65`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_SIG_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                what: "public key",
                algorithm: HYBRID_SIG_ID,
                expected: HYBRID_SIG_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            ed25519: SigPublicKey::from_bytes(SigAlgorithm::Ed25519, &bytes[..ED_PK])?,
            mldsa: SigPublicKey::from_bytes(SigAlgorithm::MlDsa65, &bytes[ED_PK..])?,
        })
    }
}

/// Hybrid signature secret key.
pub struct HybridSigSecretKey {
    /// Ed25519 component.
    pub ed25519: SigSecretKey,
    /// ML-DSA-65 component.
    pub mldsa: SigSecretKey,
}

impl fmt::Debug for HybridSigSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSigSecretKey([REDACTED])")
    }
}

impl HybridSigSecretKey {
    /// Encodes as `ed25519 || ml-dsa-65` into a zeroizing buffer.
    #[must_use]
    pub fn to_bytes(&self) -> SecretBytes {
        let mut v = Vec::with_capacity(HYBRID_SIG_SECRET_KEY_LEN);
        v.extend_from_slice(self.ed25519.expose_secret());
        v.extend_from_slice(self.mldsa.expose_secret());
        SecretBytes::new(v)
    }

    /// Parses `ed25519 || ml-dsa-65`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_SIG_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                what: "secret key",
                algorithm: HYBRID_SIG_ID,
                expected: HYBRID_SIG_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            ed25519: SigSecretKey::from_bytes(SigAlgorithm::Ed25519, &bytes[..ED_SK])?,
            mldsa: SigSecretKey::from_bytes(SigAlgorithm::MlDsa65, &bytes[ED_SK..])?,
        })
    }
}

/// Hybrid signature `ed25519_sig (64) || ml-dsa-65_sig (3309)`.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature(Vec<u8>);

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSignature({} bytes)", self.0.len())
    }
}

impl HybridSignature {
    /// Encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses an encoded hybrid signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                what: "signature",
                algorithm: HYBRID_SIG_ID,
                expected: HYBRID_SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    fn ed25519(&self) -> Result<Signature, CryptoError> {
        Signature::from_bytes(SigAlgorithm::Ed25519, &self.0[..ED_SIG])
    }

    fn mldsa(&self) -> Result<Signature, CryptoError> {
        Signature::from_bytes(SigAlgorithm::MlDsa65, &self.0[ED_SIG..])
    }
}

/// Generates a hybrid signing key pair.
pub fn hybrid_sig_keypair() -> Result<(HybridSigPublicKey, HybridSigSecretKey), CryptoError> {
    let (epk, esk) = sig::keypair(SigAlgorithm::Ed25519)?;
    let (mpk, msk) = sig::keypair(SigAlgorithm::MlDsa65)?;
    Ok((
        HybridSigPublicKey {
            ed25519: epk,
            mldsa: mpk,
        },
        HybridSigSecretKey {
            ed25519: esk,
            mldsa: msk,
        },
    ))
}

/// The message both components sign: `label || message`.
#[must_use]
pub fn hybrid_sig_message(message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HYBRID_SIG_LABEL.len() + message.len());
    m.extend_from_slice(HYBRID_SIG_LABEL);
    m.extend_from_slice(message);
    m
}

/// Signs with both components.
pub fn hybrid_sign(
    sk: &HybridSigSecretKey,
    message: &[u8],
) -> Result<HybridSignature, CryptoError> {
    let m = hybrid_sig_message(message);
    let e = sig::sign(&sk.ed25519, &m)?;
    let p = sig::sign(&sk.mldsa, &m)?;
    let mut v = Vec::with_capacity(HYBRID_SIGNATURE_LEN);
    v.extend_from_slice(e.as_bytes());
    v.extend_from_slice(p.as_bytes());
    Ok(HybridSignature(v))
}

/// Verifies both components. Both verifications always run; the result is combined with a
/// constant-time AND so that the classical outcome cannot be inferred from timing.
// TM:T11-M4 both component signatures are verified before deciding (no early exit)
pub fn hybrid_verify(
    pk: &HybridSigPublicKey,
    message: &[u8],
    signature: &HybridSignature,
) -> Result<(), CryptoError> {
    let m = hybrid_sig_message(message);
    let e_ok: Choice = Choice::from(u8::from(
        sig::verify(&pk.ed25519, &m, &signature.ed25519()?).is_ok(),
    ));
    let p_ok: Choice = Choice::from(u8::from(
        sig::verify(&pk.mldsa, &m, &signature.mldsa()?).is_ok(),
    ));
    if bool::from(e_ok & p_ok) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Constant-time equality of two hybrid signatures.
#[must_use]
pub fn hybrid_signatures_equal(a: &HybridSignature, b: &HybridSignature) -> bool {
    a.0.ct_eq(&b.0).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::shared_secrets_equal;

    #[test]
    fn kem_round_trip_and_encoding() {
        let (pk, sk) = hybrid_kem_keypair().unwrap();
        let (ct, ss1) = hybrid_encapsulate(&pk).unwrap();
        let ss2 = hybrid_decapsulate(&sk, &ct).unwrap();
        assert!(shared_secrets_equal(&ss1, &ss2));
        assert_eq!(pk.to_bytes().len(), HYBRID_KEM_PUBLIC_KEY_LEN);
        assert_eq!(sk.to_bytes().len(), HYBRID_KEM_SECRET_KEY_LEN);
        assert_eq!(ct.to_bytes().len(), HYBRID_KEM_CIPHERTEXT_LEN);
        assert_eq!(HybridKemPublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
        assert_eq!(HybridKemCiphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        let sk2 = HybridKemSecretKey::from_bytes(sk.to_bytes().expose_secret()).unwrap();
        assert!(shared_secrets_equal(
            &hybrid_decapsulate(&sk2, &ct).unwrap(),
            &ss1
        ));
        assert_eq!(sk.public_key(), pk);
        assert_eq!(format!("{sk:?}"), "HybridKemSecretKey([REDACTED])");
    }

    #[test]
    fn kem_tampering_changes_secret() {
        let (pk, sk) = hybrid_kem_keypair().unwrap();
        let (ct, ss) = hybrid_encapsulate(&pk).unwrap();
        // Tamper with the ML-KEM half: implicit rejection yields a different secret.
        let mut b = ct.to_bytes();
        b[X_CT + 5] ^= 0x01;
        let ct2 = HybridKemCiphertext::from_bytes(&b).unwrap();
        assert!(!shared_secrets_equal(
            &hybrid_decapsulate(&sk, &ct2).unwrap(),
            &ss
        ));
        // Tamper with the X25519 half.
        let mut b = ct.to_bytes();
        b[1] ^= 0x01;
        let ct3 = HybridKemCiphertext::from_bytes(&b).unwrap();
        let r = hybrid_decapsulate(&sk, &ct3);
        assert!(r.is_err() || !shared_secrets_equal(&r.unwrap(), &ss));
        // Wrong key.
        let (_, sk2) = hybrid_kem_keypair().unwrap();
        assert!(!shared_secrets_equal(
            &hybrid_decapsulate(&sk2, &ct).unwrap(),
            &ss
        ));
        // Bad lengths.
        assert!(HybridKemPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridKemSecretKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridKemCiphertext::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn sig_round_trip_and_encoding() {
        let (pk, sk) = hybrid_sig_keypair().unwrap();
        let s = hybrid_sign(&sk, b"prekey bundle").unwrap();
        assert_eq!(s.as_bytes().len(), HYBRID_SIGNATURE_LEN);
        hybrid_verify(&pk, b"prekey bundle", &s).unwrap();
        assert_eq!(
            hybrid_verify(&pk, b"other", &s),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(HybridSigPublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
        assert_eq!(HybridSignature::from_bytes(s.as_bytes()).unwrap(), s);
        let sk2 = HybridSigSecretKey::from_bytes(sk.to_bytes().expose_secret()).unwrap();
        let s2 = hybrid_sign(&sk2, b"prekey bundle").unwrap();
        hybrid_verify(&pk, b"prekey bundle", &s2).unwrap();
        assert!(hybrid_signatures_equal(&s, &s));
        assert_eq!(format!("{sk:?}"), "HybridSigSecretKey([REDACTED])");
        assert_eq!(
            format!("{s:?}"),
            format!("HybridSignature({HYBRID_SIGNATURE_LEN} bytes)")
        );
        assert_eq!(pk.to_bytes().len(), HYBRID_SIG_PUBLIC_KEY_LEN);
        assert_eq!(sk.to_bytes().len(), HYBRID_SIG_SECRET_KEY_LEN);
        assert_eq!(
            hybrid_sig_message(b"m")[..HYBRID_SIG_LABEL.len()],
            *HYBRID_SIG_LABEL
        );
    }

    #[test]
    fn sig_requires_both_components() {
        let (pk, sk) = hybrid_sig_keypair().unwrap();
        let s = hybrid_sign(&sk, b"m").unwrap();
        // Break only the Ed25519 half.
        let mut b = s.as_bytes().to_vec();
        b[0] ^= 0x01;
        assert_eq!(
            hybrid_verify(&pk, b"m", &HybridSignature::from_bytes(&b).unwrap()),
            Err(CryptoError::InvalidSignature)
        );
        // Break only the ML-DSA half.
        let mut b = s.as_bytes().to_vec();
        b[ED_SIG + 10] ^= 0x01;
        assert_eq!(
            hybrid_verify(&pk, b"m", &HybridSignature::from_bytes(&b).unwrap()),
            Err(CryptoError::InvalidSignature)
        );
        // Wrong key.
        let (pk2, _) = hybrid_sig_keypair().unwrap();
        assert_eq!(
            hybrid_verify(&pk2, b"m", &s),
            Err(CryptoError::InvalidSignature)
        );
        assert!(HybridSignature::from_bytes(&[0u8; 5]).is_err());
        assert!(HybridSigPublicKey::from_bytes(&[0u8; 5]).is_err());
        assert!(HybridSigSecretKey::from_bytes(&[0u8; 5]).is_err());
    }
}

//! Key encapsulation: ML-KEM-512/768/1024 (FIPS 203) via PQClean and X25519 (RFC 7748) via
//! `x25519-dalek`, behind one algorithm-tagged interface.
//!
//! Input validation required by FIPS 203 §7.2 and §7.3 is implemented here because the
//! underlying implementations assume well-formed keys:
//!
//! * encapsulation key check: every 12-bit coefficient of `t̂` must be < q = 3329 (modulus check);
//! * decapsulation key check: `H(ek)` stored inside `dk` must equal SHA3-256 of the embedded `ek`.
//!
//! Typed keys and ciphertexts can only be built through `from_bytes` (which validates) or by
//! this module's generators, so every value that reaches PQClean has the correct length.

use core::fmt;

use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::pqc::{self, MlKem};
use crate::secret::SecretBytes;

/// ML-KEM modulus.
const Q: u16 = 3329;

/// Supported KEM algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    /// ML-KEM-512 (FIPS 203, level 1). Deprecated in the registry.
    MlKem512,
    /// ML-KEM-768 (FIPS 203, level 3). Platform default.
    MlKem768,
    /// ML-KEM-1024 (FIPS 203, level 5).
    MlKem1024,
    /// X25519 (RFC 7748). Classical component of the hybrid KEM.
    X25519,
}

impl KemAlgorithm {
    /// Every supported algorithm.
    pub const ALL: [KemAlgorithm; 4] = [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
        KemAlgorithm::X25519,
    ];

    /// Registry identifier.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            KemAlgorithm::MlKem512 => "ml-kem-512",
            KemAlgorithm::MlKem768 => "ml-kem-768",
            KemAlgorithm::MlKem1024 => "ml-kem-1024",
            KemAlgorithm::X25519 => "x25519",
        }
    }

    /// Parses a registry identifier.
    pub fn from_id(id: &str) -> Result<Self, CryptoError> {
        KemAlgorithm::ALL
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or_else(|| CryptoError::UnknownAlgorithm(id.to_string()))
    }

    /// The ML-KEM parameter set, or `None` for X25519.
    fn ml(self) -> Option<MlKem> {
        match self {
            KemAlgorithm::MlKem512 => Some(MlKem::K512),
            KemAlgorithm::MlKem768 => Some(MlKem::K768),
            KemAlgorithm::MlKem1024 => Some(MlKem::K1024),
            KemAlgorithm::X25519 => None,
        }
    }

    /// ML-KEM rank `k` (0 for X25519).
    fn k(self) -> usize {
        match self {
            KemAlgorithm::MlKem512 => 2,
            KemAlgorithm::MlKem768 => 3,
            KemAlgorithm::MlKem1024 => 4,
            KemAlgorithm::X25519 => 0,
        }
    }

    /// Public (encapsulation) key length.
    #[must_use]
    pub fn public_key_len(self) -> usize {
        match self {
            KemAlgorithm::X25519 => 32,
            a => 384 * a.k() + 32,
        }
    }

    /// Secret (decapsulation) key length.
    #[must_use]
    pub fn secret_key_len(self) -> usize {
        match self {
            KemAlgorithm::X25519 => 32,
            a => 768 * a.k() + 96,
        }
    }

    /// Ciphertext length (for X25519 the ephemeral public key).
    #[must_use]
    pub fn ciphertext_len(self) -> usize {
        match self {
            KemAlgorithm::MlKem512 => 768,
            KemAlgorithm::MlKem768 => 1088,
            KemAlgorithm::MlKem1024 => 1568,
            KemAlgorithm::X25519 => 32,
        }
    }

    /// Shared secret length.
    #[must_use]
    pub fn shared_secret_len(self) -> usize {
        32
    }

    /// Whether the algorithm resists a quantum adversary.
    #[must_use]
    pub fn is_quantum_safe(self) -> bool {
        !matches!(self, KemAlgorithm::X25519)
    }
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A KEM public key with its algorithm tag.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicKey({}, {} bytes)", self.alg, self.bytes.len())
    }
}

impl KemPublicKey {
    /// Parses and validates an encoded public key.
    ///
    /// For ML-KEM this performs the FIPS 203 encapsulation key check (length and modulus).
    // TM:T14-M1 every key is length-checked and FIPS 203 key-checked on parse
    pub fn from_bytes(alg: KemAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("public key", alg.id(), alg.public_key_len(), bytes.len())?;
        if alg.ml().is_some() && !mlkem_ek_modulus_check(alg, bytes) {
            return Err(CryptoError::InvalidKey("encapsulation key"));
        }
        Ok(Self {
            alg,
            bytes: bytes.to_vec(),
        })
    }

    /// Encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
    }
}

/// A KEM secret key. Zeroized on drop, redacted in `Debug`.
pub struct KemSecretKey {
    alg: KemAlgorithm,
    bytes: SecretBytes,
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey({}, [REDACTED])", self.alg)
    }
}

impl KemSecretKey {
    /// Parses and validates an encoded secret key.
    ///
    /// For ML-KEM this performs the FIPS 203 decapsulation key check (length and hash of the
    /// embedded encapsulation key).
    pub fn from_bytes(alg: KemAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("secret key", alg.id(), alg.secret_key_len(), bytes.len())?;
        if alg.ml().is_some() && !mlkem_dk_hash_check(alg, bytes) {
            return Err(CryptoError::InvalidKey("decapsulation key"));
        }
        Ok(Self {
            alg,
            bytes: SecretBytes::from_slice(bytes),
        })
    }

    /// Secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// Algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
    }

    /// Derives the matching public key (ML-KEM embeds it; X25519 computes it).
    #[must_use]
    pub fn public_key(&self) -> KemPublicKey {
        let bytes = match self.alg.ml() {
            Some(_) => {
                let k = self.alg.k();
                self.bytes.expose_secret()[384 * k..768 * k + 32].to_vec()
            }
            None => x25519_dalek::PublicKey::from(&*x25519_secret(self.bytes.expose_secret()))
                .as_bytes()
                .to_vec(),
        };
        KemPublicKey {
            alg: self.alg,
            bytes,
        }
    }
}

/// A KEM ciphertext with its algorithm tag.
#[derive(Clone, PartialEq, Eq)]
pub struct KemCiphertext {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

impl fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemCiphertext({}, {} bytes)", self.alg, self.bytes.len())
    }
}

impl KemCiphertext {
    /// Parses an encoded ciphertext (length check only; ML-KEM rejects implicitly).
    pub fn from_bytes(alg: KemAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("ciphertext", alg.id(), alg.ciphertext_len(), bytes.len())?;
        Ok(Self {
            alg,
            bytes: bytes.to_vec(),
        })
    }

    /// Encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
    }
}

/// A 32-byte shared secret. Zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret(SecretBytes);

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl SharedSecret {
    /// Secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn from_secret(s: SecretBytes) -> Self {
        Self(s)
    }
}

/// Generates a fresh key pair.
pub fn keypair(alg: KemAlgorithm) -> Result<(KemPublicKey, KemSecretKey), CryptoError> {
    let (pk, sk) = if let Some(p) = alg.ml() {
        pqc::mlkem_keypair(p)
    } else {
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        (
            pk.as_bytes().to_vec(),
            SecretBytes::from_slice(sk.as_bytes()),
        )
    };
    Ok((
        KemPublicKey { alg, bytes: pk },
        KemSecretKey { alg, bytes: sk },
    ))
}

/// Encapsulates to `pk`, returning the ciphertext and the shared secret.
pub fn encapsulate(pk: &KemPublicKey) -> Result<(KemCiphertext, SharedSecret), CryptoError> {
    let (ct, ss) = if let Some(p) = pk.alg.ml() {
        pqc::mlkem_encaps(p, &pk.bytes)
    } else {
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
        let eph_pk = x25519_dalek::PublicKey::from(&eph);
        let ss = eph.diffie_hellman(&x25519_public(&pk.bytes));
        if !ss.was_contributory() {
            return Err(CryptoError::Decapsulation);
        }
        (
            eph_pk.as_bytes().to_vec(),
            SecretBytes::from_slice(ss.as_bytes()),
        )
    };
    Ok((
        KemCiphertext {
            alg: pk.alg,
            bytes: ct,
        },
        SharedSecret::from_secret(ss),
    ))
}

/// Decapsulates `ct` with `sk`.
///
/// ML-KEM never fails on a malformed ciphertext of the right length: it returns an implicit
/// rejection value derived from the secret, exactly as FIPS 203 requires. X25519 fails on a
/// non-contributory (low-order) result.
pub fn decapsulate(sk: &KemSecretKey, ct: &KemCiphertext) -> Result<SharedSecret, CryptoError> {
    if sk.alg != ct.alg {
        return Err(CryptoError::AlgorithmMismatch(sk.alg.id(), ct.alg.id()));
    }
    let ss = if let Some(p) = sk.alg.ml() {
        pqc::mlkem_decaps(p, &ct.bytes, sk.bytes.expose_secret())
    } else {
        let secret = x25519_secret(sk.bytes.expose_secret());
        let ss = secret.diffie_hellman(&x25519_public(&ct.bytes));
        if !ss.was_contributory() {
            return Err(CryptoError::Decapsulation);
        }
        SecretBytes::from_slice(ss.as_bytes())
    };
    Ok(SharedSecret::from_secret(ss))
}

/// Constant-time comparison of two shared secrets.
#[must_use]
pub fn shared_secrets_equal(a: &SharedSecret, b: &SharedSecret) -> bool {
    a.0.ct_eq(&b.0).into()
}

fn check_len(
    what: &'static str,
    algorithm: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidLength {
            what,
            algorithm,
            expected,
            actual,
        })
    }
}

/// Builds an X25519 secret from a 32-byte buffer. Callers pass buffers whose length was
/// validated when the typed key was constructed.
fn x25519_secret(bytes: &[u8]) -> Zeroizing<x25519_dalek::StaticSecret> {
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(bytes);
    Zeroizing::new(x25519_dalek::StaticSecret::from(*arr))
}

/// Builds an X25519 public key from a 32-byte buffer validated at construction.
fn x25519_public(bytes: &[u8]) -> x25519_dalek::PublicKey {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    x25519_dalek::PublicKey::from(arr)
}

/// FIPS 203 §7.2 encapsulation key check: `ByteEncode12(ByteDecode12(ek[0..384k])) == ek[0..384k]`,
/// i.e. every 12-bit coefficient is < q.
#[must_use]
pub fn mlkem_ek_modulus_check(alg: KemAlgorithm, ek: &[u8]) -> bool {
    let k = alg.k();
    if k == 0 || ek.len() != 384 * k + 32 {
        return false;
    }
    ek[..384 * k].chunks_exact(3).all(|c| {
        let a = u16::from(c[0]) | (u16::from(c[1] & 0x0F) << 8);
        let b = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        a < Q && b < Q
    })
}

/// FIPS 203 §7.3 decapsulation key check: `SHA3-256(ek) == dk[768k+32 .. 768k+64]`, where `ek`
/// is the encapsulation key embedded at `dk[384k .. 768k+32]`.
#[must_use]
pub fn mlkem_dk_hash_check(alg: KemAlgorithm, dk: &[u8]) -> bool {
    let k = alg.k();
    if k == 0 || dk.len() != 768 * k + 96 {
        return false;
    }
    let ek = &dk[384 * k..768 * k + 32];
    let stored = &dk[768 * k + 32..768 * k + 64];
    let computed = Sha3_256::digest(ek);
    bool::from(computed.as_slice().ct_eq(stored)) && mlkem_ek_modulus_check(alg, ek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for a in KemAlgorithm::ALL {
            assert_eq!(KemAlgorithm::from_id(a.id()).unwrap(), a);
            assert_eq!(a.to_string(), a.id());
            assert_eq!(a.shared_secret_len(), 32);
        }
        assert!(KemAlgorithm::from_id("rsa").is_err());
        assert!(KemAlgorithm::MlKem768.is_quantum_safe());
        assert!(!KemAlgorithm::X25519.is_quantum_safe());
    }

    #[test]
    fn lengths_match_fips_203() {
        assert_eq!(KemAlgorithm::MlKem512.public_key_len(), 800);
        assert_eq!(KemAlgorithm::MlKem512.secret_key_len(), 1632);
        assert_eq!(KemAlgorithm::MlKem768.public_key_len(), 1184);
        assert_eq!(KemAlgorithm::MlKem768.secret_key_len(), 2400);
        assert_eq!(KemAlgorithm::MlKem768.ciphertext_len(), 1088);
        assert_eq!(KemAlgorithm::MlKem1024.public_key_len(), 1568);
        assert_eq!(KemAlgorithm::MlKem1024.secret_key_len(), 3168);
        assert_eq!(KemAlgorithm::MlKem1024.ciphertext_len(), 1568);
        assert_eq!(KemAlgorithm::X25519.ciphertext_len(), 32);
    }

    #[test]
    fn round_trip_all_algorithms() {
        for a in KemAlgorithm::ALL {
            let (pk, sk) = keypair(a).unwrap();
            assert_eq!(pk.as_bytes().len(), a.public_key_len());
            assert_eq!(sk.expose_secret().len(), a.secret_key_len());
            assert_eq!(sk.algorithm(), a);
            assert_eq!(pk.algorithm(), a);
            let (ct, ss1) = encapsulate(&pk).unwrap();
            assert_eq!(ct.as_bytes().len(), a.ciphertext_len());
            assert_eq!(ct.algorithm(), a);
            let ss2 = decapsulate(&sk, &ct).unwrap();
            assert!(shared_secrets_equal(&ss1, &ss2));
            assert_eq!(ss1, ss2);
            assert_eq!(sk.public_key(), pk);
            let pk2 = KemPublicKey::from_bytes(a, pk.as_bytes()).unwrap();
            assert_eq!(pk2, pk);
            let sk2 = KemSecretKey::from_bytes(a, sk.expose_secret()).unwrap();
            assert_eq!(sk2.expose_secret(), sk.expose_secret());
            let ct2 = KemCiphertext::from_bytes(a, ct.as_bytes()).unwrap();
            assert_eq!(ct2, ct);
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let (pk, sk) = keypair(KemAlgorithm::MlKem768).unwrap();
        let (ct, ss) = encapsulate(&pk).unwrap();
        assert_eq!(format!("{sk:?}"), "KemSecretKey(ml-kem-768, [REDACTED])");
        assert_eq!(format!("{ss:?}"), "SharedSecret([REDACTED])");
        assert_eq!(format!("{pk:?}"), "KemPublicKey(ml-kem-768, 1184 bytes)");
        assert_eq!(format!("{ct:?}"), "KemCiphertext(ml-kem-768, 1088 bytes)");
    }

    #[test]
    fn wrong_lengths_rejected() {
        let e = KemPublicKey::from_bytes(KemAlgorithm::MlKem768, &[0u8; 10]).unwrap_err();
        assert_eq!(
            e,
            CryptoError::InvalidLength {
                what: "public key",
                algorithm: "ml-kem-768",
                expected: 1184,
                actual: 10
            }
        );
        assert!(KemSecretKey::from_bytes(KemAlgorithm::X25519, &[0u8; 31]).is_err());
        assert!(KemCiphertext::from_bytes(KemAlgorithm::MlKem1024, &[0u8; 1567]).is_err());
    }

    #[test]
    fn mlkem_key_checks_reject_corruption() {
        let (pk, sk) = keypair(KemAlgorithm::MlKem768).unwrap();
        // Set a coefficient to 0xFFF (>= q).
        let mut corrupt_encaps_key = pk.as_bytes().to_vec();
        corrupt_encaps_key[0] = 0xFF;
        corrupt_encaps_key[1] |= 0x0F;
        assert_eq!(
            KemPublicKey::from_bytes(KemAlgorithm::MlKem768, &corrupt_encaps_key),
            Err(CryptoError::InvalidKey("encapsulation key"))
        );
        // Corrupt the stored hash in dk.
        let mut bad_dk = sk.expose_secret().to_vec();
        bad_dk[768 * 3 + 40] ^= 0x01;
        assert_eq!(
            KemSecretKey::from_bytes(KemAlgorithm::MlKem768, &bad_dk).map(|_| ()),
            Err(CryptoError::InvalidKey("decapsulation key"))
        );
        assert!(!mlkem_ek_modulus_check(KemAlgorithm::X25519, &[0u8; 32]));
        assert!(!mlkem_dk_hash_check(KemAlgorithm::X25519, &[0u8; 32]));
        assert!(!mlkem_ek_modulus_check(KemAlgorithm::MlKem768, &[0u8; 5]));
        assert!(!mlkem_dk_hash_check(KemAlgorithm::MlKem768, &[0u8; 5]));
    }

    #[test]
    fn mismatched_algorithms_rejected() {
        let (_, sk) = keypair(KemAlgorithm::MlKem768).unwrap();
        let (pk2, _) = keypair(KemAlgorithm::MlKem1024).unwrap();
        let (ct2, _) = encapsulate(&pk2).unwrap();
        assert_eq!(
            decapsulate(&sk, &ct2),
            Err(CryptoError::AlgorithmMismatch("ml-kem-768", "ml-kem-1024"))
        );
    }

    #[test]
    fn x25519_rejects_low_order_points() {
        let (_, sk) = keypair(KemAlgorithm::X25519).unwrap();
        let zero = KemCiphertext::from_bytes(KemAlgorithm::X25519, &[0u8; 32]).unwrap();
        assert_eq!(decapsulate(&sk, &zero), Err(CryptoError::Decapsulation));
        let zero_pk = KemPublicKey::from_bytes(KemAlgorithm::X25519, &[0u8; 32]).unwrap();
        assert_eq!(
            encapsulate(&zero_pk).map(|_| ()),
            Err(CryptoError::Decapsulation)
        );
    }

    #[test]
    fn mlkem_implicit_rejection_differs_from_real_secret() {
        let (pk, sk) = keypair(KemAlgorithm::MlKem768).unwrap();
        let (ct, ss) = encapsulate(&pk).unwrap();
        let mut tampered = ct.as_bytes().to_vec();
        tampered[7] ^= 0x80;
        let ct2 = KemCiphertext::from_bytes(KemAlgorithm::MlKem768, &tampered).unwrap();
        let ss2 = decapsulate(&sk, &ct2).unwrap();
        assert!(!shared_secrets_equal(&ss, &ss2));
    }
}

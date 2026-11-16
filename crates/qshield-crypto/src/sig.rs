//! Digital signatures behind one algorithm-tagged interface:
//!
//! * ML-DSA-44/65/87 (FIPS 204) via PQClean's clean implementation (see [`crate::pqc`]);
//! * SLH-DSA-SHA2-128s (FIPS 205) via the vendored slhdsa-c library (`qshield-slhdsa-sys`);
//! * Ed25519 (RFC 8032) via `ed25519-dalek`, verified strictly.
//!
//! Context strings follow FIPS 204/205: the "pure" external interface signs
//! `0x00 || len(ctx) || ctx || M`; both PQ libraries implement that encoding natively.
//! ML-DSA and SLH-DSA signing are hedged (fresh randomness per signature), as both standards
//! recommend.

use core::fmt;

use ed25519_dalek::Signer;
use qshield_slhdsa_sys::{self as slh, ParamSet};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::pqc::{self, MlDsa};
use crate::random;
use crate::secret::SecretBytes;

const SLH: ParamSet = ParamSet::Sha2_128s;

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlgorithm {
    /// ML-DSA-44 (FIPS 204, level 2). Deprecated in the registry.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, level 3). Platform default.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, level 5).
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205).
    SlhDsaSha2_128s,
    /// Ed25519 (RFC 8032). Classical component of the hybrid signature.
    Ed25519,
}

impl SigAlgorithm {
    /// Every supported algorithm.
    pub const ALL: [SigAlgorithm; 5] = [
        SigAlgorithm::MlDsa44,
        SigAlgorithm::MlDsa65,
        SigAlgorithm::MlDsa87,
        SigAlgorithm::SlhDsaSha2_128s,
        SigAlgorithm::Ed25519,
    ];

    /// Registry identifier.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            SigAlgorithm::MlDsa44 => "ml-dsa-44",
            SigAlgorithm::MlDsa65 => "ml-dsa-65",
            SigAlgorithm::MlDsa87 => "ml-dsa-87",
            SigAlgorithm::SlhDsaSha2_128s => "slh-dsa-sha2-128s",
            SigAlgorithm::Ed25519 => "ed25519",
        }
    }

    /// Parses a registry identifier.
    pub fn from_id(id: &str) -> Result<Self, CryptoError> {
        SigAlgorithm::ALL
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or_else(|| CryptoError::UnknownAlgorithm(id.to_string()))
    }

    /// Public key length.
    #[must_use]
    pub fn public_key_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 1312,
            SigAlgorithm::MlDsa65 => 1952,
            SigAlgorithm::MlDsa87 => 2592,
            SigAlgorithm::SlhDsaSha2_128s | SigAlgorithm::Ed25519 => 32,
        }
    }

    /// Secret key length.
    #[must_use]
    pub fn secret_key_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 2560,
            SigAlgorithm::MlDsa65 => 4032,
            SigAlgorithm::MlDsa87 => 4896,
            SigAlgorithm::SlhDsaSha2_128s => 64,
            SigAlgorithm::Ed25519 => 32,
        }
    }

    /// Signature length.
    #[must_use]
    pub fn signature_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 2420,
            SigAlgorithm::MlDsa65 => 3309,
            SigAlgorithm::MlDsa87 => 4627,
            SigAlgorithm::SlhDsaSha2_128s => 7856,
            SigAlgorithm::Ed25519 => 64,
        }
    }

    /// Whether the algorithm resists a quantum adversary.
    #[must_use]
    pub fn is_quantum_safe(self) -> bool {
        !matches!(self, SigAlgorithm::Ed25519)
    }

    /// Whether the algorithm supports a FIPS 204/205 context string.
    #[must_use]
    pub fn supports_context(self) -> bool {
        !matches!(self, SigAlgorithm::Ed25519)
    }

    fn ml(self) -> Option<MlDsa> {
        match self {
            SigAlgorithm::MlDsa44 => Some(MlDsa::D44),
            SigAlgorithm::MlDsa65 => Some(MlDsa::D65),
            SigAlgorithm::MlDsa87 => Some(MlDsa::D87),
            SigAlgorithm::SlhDsaSha2_128s | SigAlgorithm::Ed25519 => None,
        }
    }
}

impl fmt::Display for SigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A signature public key with its algorithm tag.
#[derive(Clone, PartialEq, Eq)]
pub struct SigPublicKey {
    alg: SigAlgorithm,
    bytes: Vec<u8>,
}

impl fmt::Debug for SigPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigPublicKey({}, {} bytes)", self.alg, self.bytes.len())
    }
}

impl SigPublicKey {
    /// Parses an encoded public key. Ed25519 keys must decode to a curve point.
    pub fn from_bytes(alg: SigAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("public key", alg.id(), alg.public_key_len(), bytes.len())?;
        if alg == SigAlgorithm::Ed25519 && ed25519_verifying_key(bytes).is_none() {
            return Err(CryptoError::InvalidKey("ed25519 public key"));
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
    pub fn algorithm(&self) -> SigAlgorithm {
        self.alg
    }
}

/// A signature secret key. Zeroized on drop, redacted in `Debug`.
pub struct SigSecretKey {
    alg: SigAlgorithm,
    bytes: SecretBytes,
}

impl fmt::Debug for SigSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigSecretKey({}, [REDACTED])", self.alg)
    }
}

impl SigSecretKey {
    /// Parses an encoded secret key.
    pub fn from_bytes(alg: SigAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("secret key", alg.id(), alg.secret_key_len(), bytes.len())?;
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
    pub fn algorithm(&self) -> SigAlgorithm {
        self.alg
    }

    /// Derives the matching public key where the key encoding allows it. SLH-DSA secret keys
    /// embed the public key and Ed25519 public keys are computed from the seed. ML-DSA secret
    /// keys do not contain `t1`, so the KMS stores ML-DSA public keys explicitly.
    pub fn public_key(&self) -> Result<SigPublicKey, CryptoError> {
        match self.alg {
            SigAlgorithm::Ed25519 => Ok(SigPublicKey {
                alg: self.alg,
                bytes: ed25519_signing_key(self.bytes.expose_secret())
                    .verifying_key()
                    .as_bytes()
                    .to_vec(),
            }),
            // sk = SK.seed || SK.prf || PK.seed || PK.root ; pk = PK.seed || PK.root
            SigAlgorithm::SlhDsaSha2_128s => Ok(SigPublicKey {
                alg: self.alg,
                bytes: self.bytes.expose_secret()[32..64].to_vec(),
            }),
            a => Err(CryptoError::Unsupported {
                algorithm: a.id(),
                operation: "derive public key",
            }),
        }
    }
}

/// A detached signature with its algorithm tag.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    alg: SigAlgorithm,
    bytes: Vec<u8>,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}, {} bytes)", self.alg, self.bytes.len())
    }
}

impl Signature {
    /// Parses an encoded signature.
    pub fn from_bytes(alg: SigAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        check_len("signature", alg.id(), alg.signature_len(), bytes.len())?;
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
    pub fn algorithm(&self) -> SigAlgorithm {
        self.alg
    }
}

/// Generates a fresh key pair.
///
/// # Panics
///
/// Never: buffer sizes are fixed by the parameter set.
pub fn keypair(alg: SigAlgorithm) -> Result<(SigPublicKey, SigSecretKey), CryptoError> {
    let (pk, sk) = match (alg.ml(), alg) {
        (Some(p), _) => pqc::mldsa_keypair(p),
        (None, SigAlgorithm::SlhDsaSha2_128s) => {
            let mut seeds = Zeroizing::new([0u8; 48]);
            random::fill(&mut seeds[..]);
            let mut pk = vec![0u8; SLH.public_key_len()];
            let mut sk = SecretBytes::zeroed(SLH.secret_key_len());
            slh::keygen_internal(
                SLH,
                &seeds[..16],
                &seeds[16..32],
                &seeds[32..],
                &mut pk,
                sk.as_mut_slice(),
            )
            .expect("buffer sizes match the parameter set");
            (pk, sk)
        }
        (None, _) => {
            let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            (
                sk.verifying_key().as_bytes().to_vec(),
                SecretBytes::from_slice(sk.as_bytes()),
            )
        }
    };
    Ok((
        SigPublicKey { alg, bytes: pk },
        SigSecretKey { alg, bytes: sk },
    ))
}

/// Signs `message` with an empty context.
pub fn sign(sk: &SigSecretKey, message: &[u8]) -> Result<Signature, CryptoError> {
    sign_with_context(sk, message, &[])
}

/// Verifies `signature` over `message` with an empty context.
pub fn verify(pk: &SigPublicKey, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    verify_with_context(pk, message, signature, &[])
}

/// Signs `message` under a FIPS 204/205 context string (at most 255 bytes).
///
/// Ed25519 has no context parameter; a non-empty context is an error.
///
/// # Panics
///
/// Never: key sizes are validated when the typed key is built and the context length is
/// checked before the call.
pub fn sign_with_context(
    sk: &SigSecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<Signature, CryptoError> {
    check_context(sk.alg, context)?;
    let secret = sk.bytes.expose_secret();
    let bytes = match (sk.alg.ml(), sk.alg) {
        (Some(p), _) => pqc::mldsa_sign(p, secret, message, context),
        (None, SigAlgorithm::SlhDsaSha2_128s) => {
            // Hedged variant (FIPS 205 §9.2): fresh opt_rand for every signature.
            let addrnd = random::bytes(SLH.n());
            slh::sign(SLH, secret, message, context, Some(&addrnd))
                .expect("key size and context validated")
        }
        (None, _) => ed25519_signing_key(secret)
            .sign(message)
            .to_bytes()
            .to_vec(),
    };
    Ok(Signature { alg: sk.alg, bytes })
}

/// Verifies `signature` over `message` under a FIPS 204/205 context string.
///
/// # Panics
///
/// Never: Ed25519 public keys are validated as curve points when the typed key is built.
pub fn verify_with_context(
    pk: &SigPublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<(), CryptoError> {
    if pk.alg != signature.alg {
        return Err(CryptoError::AlgorithmMismatch(
            pk.alg.id(),
            signature.alg.id(),
        ));
    }
    check_context(pk.alg, context)?;
    let ok = match (pk.alg.ml(), pk.alg) {
        (Some(p), _) => pqc::mldsa_verify(p, &pk.bytes, message, &signature.bytes, context),
        (None, SigAlgorithm::SlhDsaSha2_128s) => {
            slh::verify(SLH, &pk.bytes, message, &signature.bytes, context)
        }
        (None, _) => {
            let vk = ed25519_verifying_key(&pk.bytes).expect("validated at construction");
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&signature.bytes);
            // Strict verification rejects small-order keys and non-canonical encodings, which
            // closes signature malleability. Honest signers always pass it.
            vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&arr))
                .is_ok()
        }
    };
    if ok {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

fn check_context(alg: SigAlgorithm, context: &[u8]) -> Result<(), CryptoError> {
    if context.len() > 255 {
        return Err(CryptoError::Malformed("context longer than 255 bytes"));
    }
    if !context.is_empty() && !alg.supports_context() {
        return Err(CryptoError::Unsupported {
            algorithm: alg.id(),
            operation: "context string",
        });
    }
    Ok(())
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

/// Builds a signing key from a 32-byte seed validated at construction.
fn ed25519_signing_key(bytes: &[u8]) -> ed25519_dalek::SigningKey {
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(bytes);
    ed25519_dalek::SigningKey::from_bytes(&arr)
}

/// Decodes a 32-byte verifying key; `None` if it is not a valid point.
fn ed25519_verifying_key(bytes: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_lengths() {
        for a in SigAlgorithm::ALL {
            assert_eq!(SigAlgorithm::from_id(a.id()).unwrap(), a);
            assert_eq!(a.to_string(), a.id());
        }
        assert!(SigAlgorithm::from_id("ecdsa").is_err());
        assert_eq!(SigAlgorithm::MlDsa65.public_key_len(), 1952);
        assert_eq!(SigAlgorithm::MlDsa65.secret_key_len(), 4032);
        assert_eq!(SigAlgorithm::MlDsa65.signature_len(), 3309);
        assert_eq!(SigAlgorithm::MlDsa87.signature_len(), 4627);
        assert_eq!(SigAlgorithm::MlDsa44.signature_len(), 2420);
        assert_eq!(SigAlgorithm::SlhDsaSha2_128s.signature_len(), 7856);
        assert_eq!(SigAlgorithm::Ed25519.signature_len(), 64);
        assert!(SigAlgorithm::MlDsa65.is_quantum_safe());
        assert!(!SigAlgorithm::Ed25519.is_quantum_safe());
        assert!(!SigAlgorithm::Ed25519.supports_context());
        assert!(SigAlgorithm::SlhDsaSha2_128s.supports_context());
        // The registry constants agree with the slhdsa-c library.
        assert_eq!(SLH.library_sizes(), (32, 64, 7856));
    }

    #[test]
    fn round_trip_all_algorithms() {
        for a in SigAlgorithm::ALL {
            let (pk, sk) = keypair(a).unwrap();
            assert_eq!(pk.as_bytes().len(), a.public_key_len());
            assert_eq!(sk.expose_secret().len(), a.secret_key_len());
            assert_eq!(pk.algorithm(), a);
            assert_eq!(sk.algorithm(), a);
            let msg = b"QuantumShield signature round trip";
            let sig = sign(&sk, msg).unwrap();
            assert_eq!(sig.as_bytes().len(), a.signature_len());
            assert_eq!(sig.algorithm(), a);
            verify(&pk, msg, &sig).unwrap();
            assert_eq!(
                verify(&pk, b"other", &sig),
                Err(CryptoError::InvalidSignature)
            );
            let mut bad = sig.as_bytes().to_vec();
            bad[3] ^= 0x01;
            let bad_sig = Signature::from_bytes(a, &bad).unwrap();
            assert_eq!(
                verify(&pk, msg, &bad_sig),
                Err(CryptoError::InvalidSignature)
            );
            let (pk2, _) = keypair(a).unwrap();
            assert_eq!(verify(&pk2, msg, &sig), Err(CryptoError::InvalidSignature));
            assert_eq!(SigPublicKey::from_bytes(a, pk.as_bytes()).unwrap(), pk);
            assert_eq!(Signature::from_bytes(a, sig.as_bytes()).unwrap(), sig);
            assert_eq!(
                SigSecretKey::from_bytes(a, sk.expose_secret())
                    .unwrap()
                    .expose_secret(),
                sk.expose_secret()
            );
        }
    }

    #[test]
    fn pq_signing_is_hedged() {
        for a in [SigAlgorithm::MlDsa65, SigAlgorithm::SlhDsaSha2_128s] {
            let (_, sk) = keypair(a).unwrap();
            assert_ne!(
                sign(&sk, b"same").unwrap(),
                sign(&sk, b"same").unwrap(),
                "{a}"
            );
        }
    }

    #[test]
    fn context_strings() {
        for a in [SigAlgorithm::MlDsa65, SigAlgorithm::SlhDsaSha2_128s] {
            let (pk, sk) = keypair(a).unwrap();
            let sig = sign_with_context(&sk, b"m", b"ctx").unwrap();
            verify_with_context(&pk, b"m", &sig, b"ctx").unwrap();
            assert_eq!(
                verify_with_context(&pk, b"m", &sig, b"ctx2"),
                Err(CryptoError::InvalidSignature)
            );
            assert_eq!(verify(&pk, b"m", &sig), Err(CryptoError::InvalidSignature));
            assert_eq!(
                sign_with_context(&sk, b"m", &[0u8; 256]),
                Err(CryptoError::Malformed("context longer than 255 bytes"))
            );
        }
        let (pk, sk) = keypair(SigAlgorithm::Ed25519).unwrap();
        assert!(matches!(
            sign_with_context(&sk, b"m", b"ctx"),
            Err(CryptoError::Unsupported { .. })
        ));
        let sig = sign(&sk, b"m").unwrap();
        assert!(matches!(
            verify_with_context(&pk, b"m", &sig, b"ctx"),
            Err(CryptoError::Unsupported { .. })
        ));
    }

    #[test]
    fn public_key_derivation() {
        let (pk, sk) = keypair(SigAlgorithm::Ed25519).unwrap();
        assert_eq!(sk.public_key().unwrap(), pk);
        let (pk, sk) = keypair(SigAlgorithm::SlhDsaSha2_128s).unwrap();
        assert_eq!(sk.public_key().unwrap(), pk);
        let (_, sk) = keypair(SigAlgorithm::MlDsa65).unwrap();
        assert!(matches!(
            sk.public_key(),
            Err(CryptoError::Unsupported { .. })
        ));
    }

    #[test]
    fn debug_and_errors() {
        let (pk, sk) = keypair(SigAlgorithm::MlDsa65).unwrap();
        let sig = sign(&sk, b"x").unwrap();
        assert_eq!(format!("{sk:?}"), "SigSecretKey(ml-dsa-65, [REDACTED])");
        assert_eq!(format!("{pk:?}"), "SigPublicKey(ml-dsa-65, 1952 bytes)");
        assert_eq!(format!("{sig:?}"), "Signature(ml-dsa-65, 3309 bytes)");
        assert!(SigPublicKey::from_bytes(SigAlgorithm::MlDsa65, &[0u8; 3]).is_err());
        assert!(SigSecretKey::from_bytes(SigAlgorithm::MlDsa65, &[0u8; 3]).is_err());
        assert!(Signature::from_bytes(SigAlgorithm::MlDsa65, &[0u8; 3]).is_err());
        let (pk2, _) = keypair(SigAlgorithm::MlDsa87).unwrap();
        assert_eq!(
            verify(&pk2, b"x", &sig),
            Err(CryptoError::AlgorithmMismatch("ml-dsa-87", "ml-dsa-65"))
        );
        // Roughly half of all y-coordinates have no matching x on the curve; take the first.
        let not_a_point = (2u8..=255)
            .map(|y| {
                let mut a = [0u8; 32];
                a[0] = y;
                a
            })
            .find(|a| ed25519_dalek::VerifyingKey::from_bytes(a).is_err())
            .expect("some small y is not on the curve");
        assert_eq!(
            SigPublicKey::from_bytes(SigAlgorithm::Ed25519, &not_a_point),
            Err(CryptoError::InvalidKey("ed25519 public key"))
        );
    }
}

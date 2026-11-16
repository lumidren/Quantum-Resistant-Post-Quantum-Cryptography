//! Deterministic entry points used only by the NIST known-answer tests.
//!
//! Compiled only with the `kat` feature, which production builds never enable. These functions
//! take the randomness that FIPS 203/205 key generation, encapsulation and signing would
//! otherwise draw from the operating system, so outputs can be compared with NIST's expected
//! values byte for byte.

use qshield_slhdsa_sys::{self as slh, ParamSet};

use crate::error::CryptoError;
use crate::kem::KemAlgorithm;
use crate::pqc::{self, MlKem};
use crate::secret::SecretBytes;

const SLH: ParamSet = ParamSet::Sha2_128s;

fn ml(alg: KemAlgorithm) -> Result<MlKem, CryptoError> {
    match alg {
        KemAlgorithm::MlKem512 => Ok(MlKem::K512),
        KemAlgorithm::MlKem768 => Ok(MlKem::K768),
        KemAlgorithm::MlKem1024 => Ok(MlKem::K1024),
        KemAlgorithm::X25519 => Err(CryptoError::Unsupported {
            algorithm: "x25519",
            operation: "derandomized key generation",
        }),
    }
}

fn exact<const N: usize>(what: &'static str, b: &[u8]) -> Result<[u8; N], CryptoError> {
    b.try_into().map_err(|_| CryptoError::InvalidLength {
        what,
        algorithm: "kat",
        expected: N,
        actual: b.len(),
    })
}

fn slh_err(e: slh::Error) -> CryptoError {
    match e {
        slh::Error::InvalidLength {
            what,
            expected,
            actual,
        } => CryptoError::InvalidLength {
            what,
            algorithm: "slh-dsa-sha2-128s",
            expected,
            actual,
        },
        slh::Error::ContextTooLong => CryptoError::Malformed("context longer than 255 bytes"),
        slh::Error::LibraryFailure => CryptoError::Malformed("slhdsa-c failure"),
    }
}

/// FIPS 203 `ML-KEM.KeyGen_internal(d, z)`: returns `(ek, dk)`.
pub fn mlkem_keypair_derand(
    alg: KemAlgorithm,
    d: &[u8],
    z: &[u8],
) -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    let p = ml(alg)?;
    let d: [u8; 32] = exact("d", d)?;
    let z: [u8; 32] = exact("z", z)?;
    let mut coins = [0u8; 64];
    coins[..32].copy_from_slice(&d);
    coins[32..].copy_from_slice(&z);
    Ok(pqc::mlkem_keypair_derand(p, &coins))
}

/// FIPS 203 `ML-KEM.Encaps_internal(ek, m)`: returns `(c, K)`.
pub fn mlkem_encaps_derand(
    alg: KemAlgorithm,
    ek: &[u8],
    m: &[u8],
) -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    let p = ml(alg)?;
    if ek.len() != alg.public_key_len() {
        return Err(CryptoError::InvalidLength {
            what: "ek",
            algorithm: alg.id(),
            expected: alg.public_key_len(),
            actual: ek.len(),
        });
    }
    let m: [u8; 32] = exact("m", m)?;
    Ok(pqc::mlkem_encaps_derand(p, ek, &m))
}

/// FIPS 205 `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` for SLH-DSA-SHA2-128s:
/// returns `(pk, sk)`.
pub fn slh_dsa_keypair_from_seeds(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    let mut pk = vec![0u8; SLH.public_key_len()];
    let mut sk = SecretBytes::zeroed(SLH.secret_key_len());
    slh::keygen_internal(SLH, sk_seed, sk_prf, pk_seed, &mut pk, sk.as_mut_slice())
        .map_err(slh_err)?;
    Ok((pk, sk))
}

/// FIPS 205 `slh_sign(M, ctx, SK)` with explicit `addrnd` (`None` = deterministic variant).
pub fn slh_dsa_sign(
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    slh::sign(SLH, sk, message, context, addrnd).map_err(slh_err)
}

/// FIPS 205 `slh_sign_internal(M, SK, addrnd)`.
pub fn slh_dsa_sign_internal(
    sk: &[u8],
    message: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    slh::sign_internal(SLH, sk, message, addrnd).map_err(slh_err)
}

/// FIPS 205 `slh_verify_internal(M, SIG, PK)`.
#[must_use]
pub fn slh_dsa_verify_internal(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    slh::verify_internal(SLH, pk, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_errors() {
        assert!(matches!(
            mlkem_keypair_derand(KemAlgorithm::X25519, &[0; 32], &[0; 32]),
            Err(CryptoError::Unsupported { .. })
        ));
        assert!(mlkem_keypair_derand(KemAlgorithm::MlKem768, &[0; 31], &[0; 32]).is_err());
        assert!(mlkem_keypair_derand(KemAlgorithm::MlKem768, &[0; 32], &[0; 33]).is_err());
        assert!(mlkem_encaps_derand(KemAlgorithm::MlKem768, &[0; 5], &[0; 32]).is_err());
        assert!(mlkem_encaps_derand(KemAlgorithm::MlKem768, &[0; 1184], &[0; 2]).is_err());
        assert!(mlkem_encaps_derand(KemAlgorithm::X25519, &[0; 32], &[0; 32]).is_err());
        assert!(slh_dsa_keypair_from_seeds(&[0; 15], &[0; 16], &[0; 16]).is_err());
        assert_eq!(
            slh_dsa_sign(&[0; 64], b"m", &[0; 256], None),
            Err(CryptoError::Malformed("context longer than 255 bytes"))
        );
        assert!(slh_dsa_sign_internal(&[0; 63], b"m", None).is_err());
        assert_eq!(
            slh_err(slh::Error::LibraryFailure),
            CryptoError::Malformed("slhdsa-c failure")
        );
    }
}

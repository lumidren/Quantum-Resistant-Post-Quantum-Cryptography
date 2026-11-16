//! Property-based tests across every parameter set:
//!
//! * encapsulation/decapsulation and sign/verify round trips over arbitrary messages and contexts;
//! * rejection of tampered ciphertexts, signatures and messages at arbitrary positions;
//! * rejection under the wrong key;
//! * parsers never panic on arbitrary input and enforce exact lengths.
//!
//! Key pairs are generated once per algorithm (key generation draws its own randomness); the
//! properties quantify over the inputs an attacker controls.
// TM:T14-M2 wrong-key and tampered-input rejection across all parameter sets

use std::sync::OnceLock;

use proptest::prelude::*;
use qshield_crypto::envelope::{self, Dek, EnvelopeContext, SealedBlob};
use qshield_crypto::hybrid::{self, HybridKemCiphertext, HybridKemPublicKey, HybridSignature};
use qshield_crypto::kem::{self, KemAlgorithm, KemCiphertext, KemPublicKey, KemSecretKey};
use qshield_crypto::sig::{self, SigAlgorithm, SigPublicKey, SigSecretKey, Signature};
use qshield_crypto::CryptoError;

struct KemKeys {
    pk: KemPublicKey,
    sk: KemSecretKey,
    other_sk: KemSecretKey,
}

fn kem_keys(alg: KemAlgorithm) -> &'static KemKeys {
    static CELLS: [OnceLock<KemKeys>; 4] = [const { OnceLock::new() }; 4];
    let i = KemAlgorithm::ALL.iter().position(|a| *a == alg).unwrap();
    CELLS[i].get_or_init(|| {
        let (pk, sk) = kem::keypair(alg).unwrap();
        let (_, other_sk) = kem::keypair(alg).unwrap();
        KemKeys { pk, sk, other_sk }
    })
}

struct SigKeys {
    pk: SigPublicKey,
    sk: SigSecretKey,
    other_pk: SigPublicKey,
}

fn sig_keys(alg: SigAlgorithm) -> &'static SigKeys {
    static CELLS: [OnceLock<SigKeys>; 5] = [const { OnceLock::new() }; 5];
    let i = SigAlgorithm::ALL.iter().position(|a| *a == alg).unwrap();
    CELLS[i].get_or_init(|| {
        let (pk, sk) = sig::keypair(alg).unwrap();
        let (other_pk, _) = sig::keypair(alg).unwrap();
        SigKeys { pk, sk, other_pk }
    })
}

fn kem_alg() -> impl Strategy<Value = KemAlgorithm> {
    prop::sample::select(KemAlgorithm::ALL.to_vec())
}

fn fast_sig_alg() -> impl Strategy<Value = SigAlgorithm> {
    prop::sample::select(vec![
        SigAlgorithm::MlDsa44,
        SigAlgorithm::MlDsa65,
        SigAlgorithm::MlDsa87,
        SigAlgorithm::Ed25519,
    ])
}

fn context_for(alg: SigAlgorithm, ctx: Vec<u8>) -> Vec<u8> {
    if alg.supports_context() {
        ctx
    } else {
        Vec::new()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn kem_round_trip(alg in kem_alg()) {
        let k = kem_keys(alg);
        let (ct, ss) = kem::encapsulate(&k.pk).unwrap();
        let ss2 = kem::decapsulate(&k.sk, &ct).unwrap();
        prop_assert!(kem::shared_secrets_equal(&ss, &ss2));
    }

    #[test]
    fn kem_tampered_ciphertext_yields_different_secret(alg in kem_alg(), pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = kem_keys(alg);
        let (ct, ss) = kem::encapsulate(&k.pk).unwrap();
        let mut bytes = ct.as_bytes().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let tampered = KemCiphertext::from_bytes(alg, &bytes).unwrap();
        // ML-KEM: implicit rejection returns a pseudorandom secret. X25519: a different point
        // gives a different secret, or a low-order point is refused.
        match kem::decapsulate(&k.sk, &tampered) {
            Ok(ss2) => prop_assert!(!kem::shared_secrets_equal(&ss, &ss2)),
            Err(e) => prop_assert_eq!(e, CryptoError::Decapsulation),
        }
    }

    #[test]
    fn kem_wrong_key_yields_different_secret(alg in kem_alg()) {
        let k = kem_keys(alg);
        let (ct, ss) = kem::encapsulate(&k.pk).unwrap();
        let ss2 = kem::decapsulate(&k.other_sk, &ct).unwrap();
        prop_assert!(!kem::shared_secrets_equal(&ss, &ss2));
    }

    #[test]
    fn kem_parsers_enforce_lengths(alg in kem_alg(), bytes in prop::collection::vec(any::<u8>(), 0..3300)) {
        let pk = KemPublicKey::from_bytes(alg, &bytes);
        let sk = KemSecretKey::from_bytes(alg, &bytes);
        let ct = KemCiphertext::from_bytes(alg, &bytes);
        if bytes.len() != alg.public_key_len() { prop_assert!(pk.is_err()); }
        if bytes.len() != alg.secret_key_len() { prop_assert!(sk.is_err()); }
        prop_assert_eq!(ct.is_ok(), bytes.len() == alg.ciphertext_len());
    }

    #[test]
    fn sig_round_trip(alg in fast_sig_alg(), msg in prop::collection::vec(any::<u8>(), 0..2048), ctx in prop::collection::vec(any::<u8>(), 0..=255)) {
        let k = sig_keys(alg);
        let ctx = context_for(alg, ctx);
        let s = sig::sign_with_context(&k.sk, &msg, &ctx).unwrap();
        prop_assert!(sig::verify_with_context(&k.pk, &msg, &s, &ctx).is_ok());
    }

    #[test]
    fn sig_rejects_tampered_signature(alg in fast_sig_alg(), msg in prop::collection::vec(any::<u8>(), 0..512), pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = sig_keys(alg);
        let s = sig::sign(&k.sk, &msg).unwrap();
        let mut bytes = s.as_bytes().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let bad = Signature::from_bytes(alg, &bytes).unwrap();
        prop_assert_eq!(sig::verify(&k.pk, &msg, &bad), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn sig_rejects_tampered_message(alg in fast_sig_alg(), msg in prop::collection::vec(any::<u8>(), 1..512), pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = sig_keys(alg);
        let s = sig::sign(&k.sk, &msg).unwrap();
        let mut other = msg.clone();
        let i = pos.index(other.len());
        other[i] ^= mask;
        prop_assert_eq!(sig::verify(&k.pk, &other, &s), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn sig_rejects_wrong_key(alg in fast_sig_alg(), msg in prop::collection::vec(any::<u8>(), 0..512)) {
        let k = sig_keys(alg);
        let s = sig::sign(&k.sk, &msg).unwrap();
        prop_assert_eq!(sig::verify(&k.other_pk, &msg, &s), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn sig_rejects_wrong_context(msg in prop::collection::vec(any::<u8>(), 0..256), a in prop::collection::vec(any::<u8>(), 0..64), b in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assume!(a != b);
        let k = sig_keys(SigAlgorithm::MlDsa65);
        let s = sig::sign_with_context(&k.sk, &msg, &a).unwrap();
        prop_assert_eq!(sig::verify_with_context(&k.pk, &msg, &s, &b), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn sig_parsers_enforce_lengths(alg in prop::sample::select(SigAlgorithm::ALL.to_vec()), bytes in prop::collection::vec(any::<u8>(), 0..5000)) {
        if bytes.len() != alg.public_key_len() { prop_assert!(SigPublicKey::from_bytes(alg, &bytes).is_err()); }
        prop_assert_eq!(SigSecretKey::from_bytes(alg, &bytes).is_ok(), bytes.len() == alg.secret_key_len());
        prop_assert_eq!(Signature::from_bytes(alg, &bytes).is_ok(), bytes.len() == alg.signature_len());
    }

    #[test]
    fn envelope_round_trip_and_tamper(pt in prop::collection::vec(any::<u8>(), 0..5000), key_id in "[a-z0-9-]{1,40}", version in 1u32..1000, pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let dek = Dek::generate();
        let ctx = EnvelopeContext { key_id: &key_id, algorithm: "ml-kem-768", key_version: version };
        let blob = envelope::seal(&dek, &ctx, &pt).unwrap();
        let opened = envelope::open(&dek, &ctx, &blob).unwrap();
        prop_assert_eq!(opened.expose_secret(), pt.as_slice());
        let parsed = SealedBlob::from_bytes(&blob.to_bytes()).unwrap();
        prop_assert_eq!(&parsed, &blob);
        let mut bytes = blob.to_bytes();
        // Skip the version byte: changing it is a parse error rather than an AEAD failure.
        let i = 1 + pos.index(bytes.len() - 1);
        bytes[i] ^= mask;
        let tampered = SealedBlob::from_bytes(&bytes).unwrap();
        prop_assert_eq!(envelope::open(&dek, &ctx, &tampered).map(|_| ()), Err(CryptoError::Aead));
        let other = EnvelopeContext { key_version: version + 1, ..ctx.clone() };
        prop_assert_eq!(envelope::open(&dek, &other, &blob).map(|_| ()), Err(CryptoError::Aead));
    }

    #[test]
    fn hybrid_encodings_round_trip(_x in 0u8..4) {
        let (pk, sk) = hybrid::hybrid_kem_keypair().unwrap();
        let (ct, ss) = hybrid::hybrid_encapsulate(&HybridKemPublicKey::from_bytes(&pk.to_bytes()).unwrap()).unwrap();
        let ct2 = HybridKemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        prop_assert!(kem::shared_secrets_equal(&hybrid::hybrid_decapsulate(&sk, &ct2).unwrap(), &ss));
    }
}

proptest! {
    // The hybrid signature includes ML-DSA-65; keep the case count moderate.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn hybrid_signature_requires_both_halves(msg in prop::collection::vec(any::<u8>(), 0..512), pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        static KEYS: OnceLock<(hybrid::HybridSigPublicKey, hybrid::HybridSigSecretKey)> = OnceLock::new();
        let (pk, sk) = KEYS.get_or_init(|| hybrid::hybrid_sig_keypair().unwrap());
        let s = hybrid::hybrid_sign(sk, &msg).unwrap();
        prop_assert!(hybrid::hybrid_verify(pk, &msg, &s).is_ok());
        let mut bytes = s.as_bytes().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let bad = HybridSignature::from_bytes(&bytes).unwrap();
        prop_assert_eq!(hybrid::hybrid_verify(pk, &msg, &bad), Err(CryptoError::InvalidSignature));
    }
}

proptest! {
    // SLH-DSA-SHA2-128s signing takes tens of milliseconds; fewer cases, same properties.
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn slh_dsa_round_trip_tamper_and_wrong_key(msg in prop::collection::vec(any::<u8>(), 0..1024), ctx in prop::collection::vec(any::<u8>(), 0..=255), pos in any::<prop::sample::Index>(), mask in 1u8..=255) {
        let k = sig_keys(SigAlgorithm::SlhDsaSha2_128s);
        let s = sig::sign_with_context(&k.sk, &msg, &ctx).unwrap();
        prop_assert!(sig::verify_with_context(&k.pk, &msg, &s, &ctx).is_ok());
        prop_assert_eq!(sig::verify_with_context(&k.other_pk, &msg, &s, &ctx), Err(CryptoError::InvalidSignature));
        let mut bytes = s.as_bytes().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let bad = Signature::from_bytes(SigAlgorithm::SlhDsaSha2_128s, &bytes).unwrap();
        prop_assert_eq!(sig::verify_with_context(&k.pk, &msg, &bad, &ctx), Err(CryptoError::InvalidSignature));
    }
}

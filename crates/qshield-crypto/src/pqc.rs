//! Direct bindings to PQClean's portable ("clean") ML-KEM and ML-DSA implementations, which the
//! `pqcrypto-mlkem` and `pqcrypto-mldsa` crates compile and link.
//!
//! **Why not the pqcrypto Rust API.** Its `SecretKey` and `SharedSecret` types are `Copy` byte
//! arrays without zeroization, so every call would leave copies of secrets in memory that are
//! never wiped. Calling the C entry points directly lets each secret land in a zeroizing
//! [`SecretBytes`] buffer owned by this crate.
//!
//! **Why the clean implementation everywhere.** pqcrypto compiles the AVX2 variants only on
//! x86-64 Linux, while the clean code is compiled on every target. Using it everywhere means that
//! development (Windows), CI and production run exactly the code the KATs and the dudect timing
//! tests measured. PQClean's clean implementations are written to be constant time.
//!
//! Every function asserts buffer lengths before passing pointers to C, so a caller bug panics
//! instead of causing undefined behaviour.
// TM:T11-M1 PQ operations are delegated to PQClean; no secret-dependent branch is added here

#![allow(unsafe_code)]

// The Rust APIs of these crates are not used; linking them pulls in the compiled PQClean objects.
extern crate pqcrypto_mldsa;
extern crate pqcrypto_mlkem;

use libc::c_int;

use crate::secret::SecretBytes;

type KemKeypair = unsafe extern "C" fn(*mut u8, *mut u8) -> c_int;
type KemEnc = unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int;
type KemDec = unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int;
type SigKeypair = unsafe extern "C" fn(*mut u8, *mut u8) -> c_int;
type SigSign = unsafe extern "C" fn(
    *mut u8,
    *mut usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
) -> c_int;
type SigVerify =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> c_int;

extern "C" {
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> c_int;
}

#[cfg(feature = "kat")]
extern "C" {
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
    ) -> c_int;
    fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> c_int;
}

/// ML-KEM parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MlKem {
    K512,
    K768,
    K1024,
}

struct KemImpl {
    pk: usize,
    sk: usize,
    ct: usize,
    keypair: KemKeypair,
    enc: KemEnc,
    dec: KemDec,
}

impl MlKem {
    fn imp(self) -> KemImpl {
        match self {
            MlKem::K512 => KemImpl {
                pk: 800,
                sk: 1632,
                ct: 768,
                keypair: PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
                enc: PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
                dec: PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec,
            },
            MlKem::K768 => KemImpl {
                pk: 1184,
                sk: 2400,
                ct: 1088,
                keypair: PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
                enc: PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
                dec: PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec,
            },
            MlKem::K1024 => KemImpl {
                pk: 1568,
                sk: 3168,
                ct: 1568,
                keypair: PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
                enc: PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
                dec: PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec,
            },
        }
    }
}

/// `ML-KEM.KeyGen()`: returns `(ek, dk)`.
pub(crate) fn mlkem_keypair(p: MlKem) -> (Vec<u8>, SecretBytes) {
    let i = p.imp();
    let mut pk = vec![0u8; i.pk];
    let mut sk = SecretBytes::zeroed(i.sk);
    // SAFETY: `pk` and `sk` have exactly the FIPS 203 sizes this routine writes.
    let rc = unsafe { (i.keypair)(pk.as_mut_ptr(), sk.as_mut_slice().as_mut_ptr()) };
    assert_eq!(rc, 0, "ML-KEM key generation cannot fail");
    (pk, sk)
}

/// `ML-KEM.Encaps(ek)`: returns `(c, K)`.
pub(crate) fn mlkem_encaps(p: MlKem, pk: &[u8]) -> (Vec<u8>, SecretBytes) {
    let i = p.imp();
    assert_eq!(pk.len(), i.pk, "encapsulation key length");
    let mut ct = vec![0u8; i.ct];
    let mut ss = SecretBytes::zeroed(32);
    // SAFETY: `ct` (ciphertext size) and `ss` (32 bytes) are written; `pk` is read with its
    // asserted size.
    let rc = unsafe { (i.enc)(ct.as_mut_ptr(), ss.as_mut_slice().as_mut_ptr(), pk.as_ptr()) };
    assert_eq!(rc, 0, "ML-KEM encapsulation cannot fail");
    (ct, ss)
}

/// `ML-KEM.Decaps(dk, c)`: returns `K`, or the implicit-rejection value for invalid `c`.
pub(crate) fn mlkem_decaps(p: MlKem, ct: &[u8], sk: &[u8]) -> SecretBytes {
    let i = p.imp();
    assert_eq!(ct.len(), i.ct, "ciphertext length");
    assert_eq!(sk.len(), i.sk, "decapsulation key length");
    let mut ss = SecretBytes::zeroed(32);
    // SAFETY: `ss` (32 bytes) is written; `ct` and `sk` are read with their asserted sizes.
    let rc = unsafe { (i.dec)(ss.as_mut_slice().as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    assert_eq!(rc, 0, "ML-KEM decapsulation cannot fail");
    ss
}

/// FIPS 203 `ML-KEM.KeyGen_internal(d, z)` with `coins = d || z`.
#[cfg(feature = "kat")]
pub(crate) fn mlkem_keypair_derand(p: MlKem, coins: &[u8; 64]) -> (Vec<u8>, SecretBytes) {
    let f = match p {
        MlKem::K512 => PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand,
        MlKem::K768 => PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand,
        MlKem::K1024 => PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand,
    };
    let i = p.imp();
    let mut pk = vec![0u8; i.pk];
    let mut sk = SecretBytes::zeroed(i.sk);
    // SAFETY: output buffers have the FIPS 203 sizes; `coins` is 64 bytes as required.
    let rc = unsafe {
        f(
            pk.as_mut_ptr(),
            sk.as_mut_slice().as_mut_ptr(),
            coins.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    (pk, sk)
}

/// FIPS 203 `ML-KEM.Encaps_internal(ek, m)`.
#[cfg(feature = "kat")]
pub(crate) fn mlkem_encaps_derand(p: MlKem, pk: &[u8], m: &[u8; 32]) -> (Vec<u8>, SecretBytes) {
    let f = match p {
        MlKem::K512 => PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand,
        MlKem::K768 => PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand,
        MlKem::K1024 => PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand,
    };
    let i = p.imp();
    assert_eq!(pk.len(), i.pk, "encapsulation key length");
    let mut ct = vec![0u8; i.ct];
    let mut ss = SecretBytes::zeroed(32);
    // SAFETY: as in `mlkem_encaps`; `m` is 32 bytes as required.
    let rc = unsafe {
        f(
            ct.as_mut_ptr(),
            ss.as_mut_slice().as_mut_ptr(),
            pk.as_ptr(),
            m.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    (ct, ss)
}

/// ML-DSA parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MlDsa {
    D44,
    D65,
    D87,
}

struct DsaImpl {
    pk: usize,
    sk: usize,
    sig: usize,
    keypair: SigKeypair,
    sign: SigSign,
    verify: SigVerify,
}

impl MlDsa {
    fn imp(self) -> DsaImpl {
        match self {
            MlDsa::D44 => DsaImpl {
                pk: 1312,
                sk: 2560,
                sig: 2420,
                keypair: PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                sign: PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx,
                verify: PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx,
            },
            MlDsa::D65 => DsaImpl {
                pk: 1952,
                sk: 4032,
                sig: 3309,
                keypair: PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                sign: PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
                verify: PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
            },
            MlDsa::D87 => DsaImpl {
                pk: 2592,
                sk: 4896,
                sig: 4627,
                keypair: PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                sign: PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx,
                verify: PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx,
            },
        }
    }
}

/// `ML-DSA.KeyGen()`: returns `(pk, sk)`.
pub(crate) fn mldsa_keypair(p: MlDsa) -> (Vec<u8>, SecretBytes) {
    let i = p.imp();
    let mut pk = vec![0u8; i.pk];
    let mut sk = SecretBytes::zeroed(i.sk);
    // SAFETY: `pk` and `sk` have exactly the FIPS 204 sizes this routine writes.
    let rc = unsafe { (i.keypair)(pk.as_mut_ptr(), sk.as_mut_slice().as_mut_ptr()) };
    assert_eq!(rc, 0, "ML-DSA key generation cannot fail");
    (pk, sk)
}

/// `ML-DSA.Sign(sk, M, ctx)` (hedged; PQClean draws `rnd` from the OS).
pub(crate) fn mldsa_sign(p: MlDsa, sk: &[u8], message: &[u8], context: &[u8]) -> Vec<u8> {
    let i = p.imp();
    assert_eq!(sk.len(), i.sk, "signing key length");
    assert!(context.len() <= 255, "context length");
    let mut sig = vec![0u8; i.sig];
    let mut siglen = 0usize;
    // SAFETY: `sig` has the maximum signature size; message, context and key are read within
    // their lengths; `siglen` receives the written length.
    let rc = unsafe {
        (i.sign)(
            sig.as_mut_ptr(),
            &raw mut siglen,
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            sk.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "ML-DSA signing cannot fail for a valid context");
    assert_eq!(siglen, i.sig, "ML-DSA signatures have a fixed length");
    sig
}

/// `ML-DSA.Verify(pk, M, σ, ctx)`.
pub(crate) fn mldsa_verify(
    p: MlDsa,
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> bool {
    let i = p.imp();
    assert_eq!(pk.len(), i.pk, "verification key length");
    assert!(context.len() <= 255, "context length");
    // SAFETY: all inputs are read within their lengths; the routine checks `siglen` itself.
    let rc = unsafe {
        (i.verify)(
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            pk.as_ptr(),
        )
    };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_round_trip_every_parameter_set() {
        for p in [MlKem::K512, MlKem::K768, MlKem::K1024] {
            let (pk, sk) = mlkem_keypair(p);
            let (ct, ss) = mlkem_encaps(p, &pk);
            assert_eq!(mlkem_decaps(p, &ct, sk.expose_secret()), ss);
        }
    }

    #[test]
    fn dsa_round_trip_every_parameter_set() {
        for p in [MlDsa::D44, MlDsa::D65, MlDsa::D87] {
            let (pk, sk) = mldsa_keypair(p);
            let sig = mldsa_sign(p, sk.expose_secret(), b"m", b"c");
            assert!(mldsa_verify(p, &pk, b"m", &sig, b"c"));
            assert!(!mldsa_verify(p, &pk, b"m", &sig, b"d"));
            assert!(!mldsa_verify(p, &pk, b"m", &sig[..sig.len() - 1], b"c"));
        }
    }

    #[test]
    #[should_panic(expected = "ciphertext length")]
    fn kem_rejects_wrong_ciphertext_length_before_calling_c() {
        let (_, sk) = mlkem_keypair(MlKem::K768);
        let _ = mlkem_decaps(MlKem::K768, &[0u8; 10], sk.expose_secret());
    }
}

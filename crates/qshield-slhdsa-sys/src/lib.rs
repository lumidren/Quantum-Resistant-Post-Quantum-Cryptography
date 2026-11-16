//! FFI bindings to the vendored [slhdsa-c](https://github.com/pq-code-package/slhdsa-c)
//! implementation of FIPS 205 (SLH-DSA), the code base liboqs copies for its SLH-DSA support.
//!
//! Only the parameter sets listed in [`ParamSet`] are exposed. Secret outputs are written into
//! caller-provided buffers so that the caller controls zeroization.

#![allow(unsafe_code)]
#![deny(missing_docs)]

use core::ffi::{c_char, c_int};

/// Opaque `slh_param_t`.
#[repr(C)]
pub struct SlhParam {
    _opaque: [u8; 0],
}

extern "C" {
    static qshield_slhdsa_slh_dsa_sha2_128s: SlhParam;

    fn qshield_slhdsa_slh_alg_id(prm: *const SlhParam) -> *const c_char;
    fn qshield_slhdsa_slh_pk_sz(prm: *const SlhParam) -> usize;
    fn qshield_slhdsa_slh_sk_sz(prm: *const SlhParam) -> usize;
    fn qshield_slhdsa_slh_sig_sz(prm: *const SlhParam) -> usize;
    fn qshield_slhdsa_slh_keygen_internal(
        sk: *mut u8,
        pk: *mut u8,
        sk_seed: *const u8,
        sk_prf: *const u8,
        pk_seed: *const u8,
        prm: *const SlhParam,
    ) -> c_int;
    fn qshield_slhdsa_slh_sign_internal(
        sig: *mut u8,
        m: *const u8,
        m_sz: usize,
        sk: *const u8,
        addrnd: *const u8,
        prm: *const SlhParam,
    ) -> usize;
    fn qshield_slhdsa_slh_sign(
        sig: *mut u8,
        m: *const u8,
        m_sz: usize,
        ctx: *const u8,
        ctx_sz: usize,
        sk: *const u8,
        addrnd: *const u8,
        prm: *const SlhParam,
    ) -> usize;
    fn qshield_slhdsa_slh_verify_internal(
        m: *const u8,
        m_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        pk: *const u8,
        prm: *const SlhParam,
    ) -> c_int;
    fn qshield_slhdsa_slh_verify(
        m: *const u8,
        m_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        ctx: *const u8,
        ctx_sz: usize,
        pk: *const u8,
        prm: *const SlhParam,
    ) -> c_int;
}

/// FIPS 205 parameter sets available through this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamSet {
    /// SLH-DSA-SHA2-128s (security category 1, small signatures).
    Sha2_128s,
}

impl ParamSet {
    /// Security parameter `n` in bytes.
    #[must_use]
    pub const fn n(self) -> usize {
        match self {
            ParamSet::Sha2_128s => 16,
        }
    }

    /// Public key length (`2n`).
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        2 * self.n()
    }

    /// Secret key length (`4n`).
    #[must_use]
    pub const fn secret_key_len(self) -> usize {
        4 * self.n()
    }

    /// Signature length.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            ParamSet::Sha2_128s => 7856,
        }
    }

    /// FIPS 205 name, e.g. `SLH-DSA-SHA2-128s`, as reported by the C library.
    #[must_use]
    pub fn name(self) -> &'static str {
        // SAFETY: `raw()` points at a static parameter set; the returned pointer is a static,
        // NUL-terminated ASCII string owned by the library.
        let p = unsafe { qshield_slhdsa_slh_alg_id(self.raw()) };
        assert!(!p.is_null(), "parameter set has an identifier");
        // SAFETY: see above.
        unsafe { core::ffi::CStr::from_ptr(p) }
            .to_str()
            .expect("ASCII identifier")
    }

    fn raw(self) -> *const SlhParam {
        match self {
            ParamSet::Sha2_128s => core::ptr::addr_of!(qshield_slhdsa_slh_dsa_sha2_128s),
        }
    }

    /// Sizes as reported by the C library: `(pk, sk, sig)`.
    #[must_use]
    pub fn library_sizes(self) -> (usize, usize, usize) {
        let p = self.raw();
        // SAFETY: pure functions over a static parameter set.
        unsafe {
            (
                qshield_slhdsa_slh_pk_sz(p),
                qshield_slhdsa_slh_sk_sz(p),
                qshield_slhdsa_slh_sig_sz(p),
            )
        }
    }
}

/// Errors returned by the safe wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A buffer had the wrong length.
    InvalidLength {
        /// Which argument.
        what: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// The library reported a failure.
    LibraryFailure,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidLength {
                what,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid {what} length: expected {expected}, got {actual}"
                )
            }
            Error::ContextTooLong => f.write_str("context longer than 255 bytes"),
            Error::LibraryFailure => f.write_str("slhdsa-c reported a failure"),
        }
    }
}

impl std::error::Error for Error {}

fn check(what: &'static str, expected: usize, actual: usize) -> Result<(), Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what,
            expected,
            actual,
        })
    }
}

/// FIPS 205 Algorithm 18, `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`.
///
/// Writes `pk = PK.seed || PK.root` and `sk = SK.seed || SK.prf || PK.seed || PK.root`.
pub fn keygen_internal(
    ps: ParamSet,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) -> Result<(), Error> {
    let n = ps.n();
    check("SK.seed", n, sk_seed.len())?;
    check("SK.prf", n, sk_prf.len())?;
    check("PK.seed", n, pk_seed.len())?;
    check("pk buffer", ps.public_key_len(), pk_out.len())?;
    check("sk buffer", ps.secret_key_len(), sk_out.len())?;
    // SAFETY: all buffers have exactly the lengths FIPS 205 specifies for this parameter set,
    // which are the lengths the C routine reads and writes.
    let rc = unsafe {
        qshield_slhdsa_slh_keygen_internal(
            sk_out.as_mut_ptr(),
            pk_out.as_mut_ptr(),
            sk_seed.as_ptr(),
            sk_prf.as_ptr(),
            pk_seed.as_ptr(),
            ps.raw(),
        )
    };
    rc_ok(rc)
}

/// Maps a C status code (0 = success) to a result.
fn rc_ok(rc: c_int) -> Result<(), Error> {
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::LibraryFailure)
    }
}

/// The signing routines return the number of bytes written, or 0 on failure.
fn signature_written(ps: ParamSet, written: usize, sig: Vec<u8>) -> Result<Vec<u8>, Error> {
    if written == ps.signature_len() {
        Ok(sig)
    } else {
        Err(Error::LibraryFailure)
    }
}

fn addrnd_ptr(ps: ParamSet, addrnd: Option<&[u8]>) -> Result<*const u8, Error> {
    match addrnd {
        Some(r) => {
            check("addrnd", ps.n(), r.len())?;
            Ok(r.as_ptr())
        }
        None => Ok(core::ptr::null()),
    }
}

/// FIPS 205 Algorithm 22, `slh_sign(M, ctx, SK)` (pure external interface).
///
/// `addrnd = None` selects the deterministic variant (`opt_rand = PK.seed`); `Some(r)` with
/// `n` fresh random bytes selects the hedged variant, which FIPS 205 recommends.
pub fn sign(
    ps: ParamSet,
    sk: &[u8],
    message: &[u8],
    context: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    check("sk", ps.secret_key_len(), sk.len())?;
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    let rnd = addrnd_ptr(ps, addrnd)?;
    let mut sig = vec![0u8; ps.signature_len()];
    // SAFETY: `sig` has the full signature length; `sk` has the secret key length; `rnd` is
    // null or points at `n` bytes; message and context are valid for their lengths.
    let written = unsafe {
        qshield_slhdsa_slh_sign(
            sig.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            sk.as_ptr(),
            rnd,
            ps.raw(),
        )
    };
    signature_written(ps, written, sig)
}

/// FIPS 205 Algorithm 19, `slh_sign_internal(M, SK, addrnd)`.
pub fn sign_internal(
    ps: ParamSet,
    sk: &[u8],
    message: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    check("sk", ps.secret_key_len(), sk.len())?;
    let rnd = addrnd_ptr(ps, addrnd)?;
    let mut sig = vec![0u8; ps.signature_len()];
    // SAFETY: as in `sign`.
    let written = unsafe {
        qshield_slhdsa_slh_sign_internal(
            sig.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            sk.as_ptr(),
            rnd,
            ps.raw(),
        )
    };
    signature_written(ps, written, sig)
}

/// FIPS 205 Algorithm 24, `slh_verify(M, SIG, ctx, PK)`.
#[must_use]
pub fn verify(ps: ParamSet, pk: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> bool {
    if pk.len() != ps.public_key_len() || context.len() > 255 {
        return false;
    }
    // SAFETY: `pk` has the public key length; the library checks `sig_sz` itself and reads
    // the message and context only within their lengths.
    let rc = unsafe {
        qshield_slhdsa_slh_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            context.as_ptr(),
            context.len(),
            pk.as_ptr(),
            ps.raw(),
        )
    };
    rc == 1
}

/// FIPS 205 Algorithm 20, `slh_verify_internal(M, SIG, PK)`.
#[must_use]
pub fn verify_internal(ps: ParamSet, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pk.len() != ps.public_key_len() {
        return false;
    }
    // SAFETY: as in `verify`.
    let rc = unsafe {
        qshield_slhdsa_slh_verify_internal(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            pk.as_ptr(),
            ps.raw(),
        )
    };
    rc == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: ParamSet = ParamSet::Sha2_128s;

    fn keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; PS.public_key_len()];
        let mut sk = vec![0u8; PS.secret_key_len()];
        keygen_internal(
            PS,
            &[seed; 16],
            &[seed ^ 1; 16],
            &[seed ^ 2; 16],
            &mut pk,
            &mut sk,
        )
        .unwrap();
        (pk, sk)
    }

    #[test]
    fn library_agrees_on_sizes_and_name() {
        assert_eq!(PS.library_sizes(), (32, 64, 7856));
        assert_eq!(PS.name(), "SLH-DSA-SHA2-128s");
        assert_eq!(PS.n(), 16);
    }

    #[test]
    fn keygen_layout() {
        let (pk, sk) = keypair(7);
        assert_eq!(&sk[..16], &[7u8; 16]);
        assert_eq!(&sk[16..32], &[6u8; 16]);
        assert_eq!(&sk[32..48], &[5u8; 16]);
        assert_eq!(&sk[32..], &pk[..]);
    }

    #[test]
    fn sign_verify_round_trips() {
        let (pk, sk) = keypair(1);
        let det1 = sign(PS, &sk, b"msg", b"ctx", None).unwrap();
        let det2 = sign(PS, &sk, b"msg", b"ctx", None).unwrap();
        assert_eq!(det1, det2, "deterministic variant is reproducible");
        let hedged = sign(PS, &sk, b"msg", b"ctx", Some(&[9u8; 16])).unwrap();
        assert_ne!(det1, hedged);
        assert!(verify(PS, &pk, b"msg", &det1, b"ctx"));
        assert!(verify(PS, &pk, b"msg", &hedged, b"ctx"));
        assert!(!verify(PS, &pk, b"msg", &det1, b"other"));
        assert!(!verify(PS, &pk, b"other", &det1, b"ctx"));
        let mut bad = det1.clone();
        bad[100] ^= 1;
        assert!(!verify(PS, &pk, b"msg", &bad, b"ctx"));
        assert!(!verify(PS, &pk, b"msg", &det1[..7855], b"ctx"));
        assert!(!verify(PS, &pk[..31], b"msg", &det1, b"ctx"));
        assert!(!verify(PS, &pk, b"msg", &det1, &[0u8; 256]));
        let (pk2, _) = keypair(2);
        assert!(!verify(PS, &pk2, b"msg", &det1, b"ctx"));

        let internal = sign_internal(PS, &sk, b"raw", None).unwrap();
        assert!(verify_internal(PS, &pk, b"raw", &internal));
        assert!(!verify_internal(PS, &pk, b"raw2", &internal));
        assert!(!verify_internal(PS, &pk[..1], b"raw", &internal));
        // The pure interface prefixes 0x00 || len(ctx) || ctx, so an internal signature over
        // that encoding verifies as a pure signature with an empty context.
        let prefixed = sign_internal(PS, &sk, &[0u8, 0u8, b'm'], Some(&[3u8; 16])).unwrap();
        assert!(verify(PS, &pk, b"m", &prefixed, b""));
    }

    #[test]
    fn status_mapping() {
        assert_eq!(rc_ok(0), Ok(()));
        assert_eq!(rc_ok(-1), Err(Error::LibraryFailure));
        assert_eq!(signature_written(PS, 7856, vec![1]), Ok(vec![1]));
        assert_eq!(
            signature_written(PS, 0, vec![1]),
            Err(Error::LibraryFailure)
        );
    }

    #[test]
    fn argument_validation() {
        let (_, sk) = keypair(3);
        let mut pk = [0u8; 32];
        let mut skb = [0u8; 64];
        assert_eq!(
            keygen_internal(PS, &[0; 15], &[0; 16], &[0; 16], &mut pk, &mut skb),
            Err(Error::InvalidLength {
                what: "SK.seed",
                expected: 16,
                actual: 15
            })
        );
        assert!(
            keygen_internal(PS, &[0; 16], &[0; 16], &[0; 16], &mut pk[..31], &mut skb).is_err()
        );
        assert_eq!(
            sign(PS, &sk, b"m", &[0u8; 256], None),
            Err(Error::ContextTooLong)
        );
        assert!(sign(PS, &sk[..63], b"m", b"", None).is_err());
        assert!(sign(PS, &sk, b"m", b"", Some(&[0u8; 15])).is_err());
        assert!(sign_internal(PS, &sk[..1], b"m", None).is_err());
        assert!(sign_internal(PS, &sk, b"m", Some(&[0u8; 3])).is_err());
        assert_eq!(
            Error::ContextTooLong.to_string(),
            "context longer than 255 bytes"
        );
        assert_eq!(
            Error::LibraryFailure.to_string(),
            "slhdsa-c reported a failure"
        );
        assert_eq!(
            Error::InvalidLength {
                what: "sk",
                expected: 64,
                actual: 1
            }
            .to_string(),
            "invalid sk length: expected 64, got 1"
        );
    }
}

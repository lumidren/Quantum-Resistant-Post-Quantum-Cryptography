//! Compiles the vendored slhdsa-c (FIPS 205) library sources.
//!
//! Every external symbol of slhdsa-c is renamed with a `qshield_slhdsa_` prefix through
//! preprocessor definitions. Short names such as `sha3`, `shake` and `sha2_256` would otherwise
//! risk colliding with other C code linked into the same binary (PQClean via the `pqcrypto-*`
//! crates, OpenSSL, liboqs). The sources themselves are compiled unmodified.

use std::path::Path;

const VENDOR: &str = "vendor/slhdsa-c";

const SOURCES: &[&str] = &[
    "sha2_256.c",
    "sha2_512.c",
    "sha3_api.c",
    "sha3_f1600.c",
    "slh_dsa.c",
    "slh_prehash.c",
    "slh_sha2.c",
    "slh_shake.c",
];

const HEADERS: &[&str] = &[
    "cbmc.h",
    "plat_local.h",
    "sha2_api.h",
    "sha3_api.h",
    "slh_adrs.h",
    "slh_dsa.h",
    "slh_param.h",
    "slh_prehash.h",
    "slh_sys.h",
    "slh_var.h",
];

/// Every symbol with external linkage defined by the library sources.
const EXPORTED: &[&str] = &[
    // sha2_256.c
    "sha2_256_compress",
    "sha2_256_init",
    "sha2_224_init",
    "sha2_256_copy",
    "sha2_256_update",
    "sha2_256_final_pad",
    "sha2_256_final_len",
    "sha2_256",
    "sha2_224",
    // sha2_512.c
    "sha2_512_compress",
    "sha2_512_init",
    "sha2_384_init",
    "sha2_512_224_init",
    "sha2_512_256_init",
    "sha2_512_copy",
    "sha2_512_update",
    "sha2_512_final_pad",
    "sha2_512_final_len",
    "sha2_512",
    "sha2_384",
    "sha2_512_224",
    "sha2_512_256",
    // sha3_api.c, sha3_f1600.c
    "sha3_init",
    "sha3_update",
    "sha3_final",
    "sha3",
    "shake_out",
    "shake",
    "keccak_f1600_xor_bytes",
    "keccak_f1600_extract_bytes",
    "keccak_f1600",
    // slh_dsa.c, slh_prehash.c
    "slh_alg_id",
    "slh_pk_sz",
    "slh_sk_sz",
    "slh_sig_sz",
    "slh_keygen",
    "slh_keygen_internal",
    "slh_sign_internal",
    "slh_sign",
    "slh_verify_internal",
    "slh_verify",
    "hash_slh_sign",
    "hash_slh_verify",
    // parameter sets (slh_sha2.c, slh_shake.c)
    "slh_dsa_sha2_128s",
    "slh_dsa_sha2_128f",
    "slh_dsa_sha2_192s",
    "slh_dsa_sha2_192f",
    "slh_dsa_sha2_256s",
    "slh_dsa_sha2_256f",
    "slh_dsa_shake_128s",
    "slh_dsa_shake_128f",
    "slh_dsa_shake_192s",
    "slh_dsa_shake_192f",
    "slh_dsa_shake_256s",
    "slh_dsa_shake_256f",
];

fn main() {
    let dir = Path::new(VENDOR);
    let mut build = cc::Build::new();
    build
        .include(dir)
        // SLH-DSA signing is hash-heavy; compile optimized even in debug builds so that tests
        // run in reasonable time. Optimization does not change the outputs (KATs enforce it).
        .opt_level(3)
        .warnings(false)
        .define("_CRT_SECURE_NO_WARNINGS", None);
    for sym in EXPORTED {
        build.define(sym, Some(format!("qshield_slhdsa_{sym}").as_str()));
    }
    for src in SOURCES {
        let p = dir.join(src);
        println!("cargo:rerun-if-changed={}", p.display());
        build.file(p);
    }
    for h in HEADERS {
        println!("cargo:rerun-if-changed={}", dir.join(h).display());
    }
    println!("cargo:rerun-if-changed=build.rs");
    build.compile("qshield_slhdsa");
}

//! The versioned algorithm registry.
//!
//! `registry/algorithms.toml` is embedded at compile time ([`Registry::builtin`]) and can also be
//! loaded from a file at runtime so that operators can deprecate an algorithm with a configuration
//! change. Loading validates every entry and [`Registry::validate_transition`] guarantees that a
//! newer registry only moves statuses forward and never alters an entry's immutable fields.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;

/// Lifecycle status of an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// May generate new keys, use existing keys and be rotated into.
    Active,
    /// Existing keys may decapsulate and verify; no generation, no signing.
    Deprecated,
    /// Refused everywhere.
    Disabled,
}

impl Status {
    fn rank(self) -> u8 {
        match self {
            Status::Active => 0,
            Status::Deprecated => 1,
            Status::Disabled => 2,
        }
    }

    /// Statuses move forward only: active → deprecated → disabled.
    #[must_use]
    pub fn may_transition_to(self, next: Status) -> bool {
        next.rank() >= self.rank()
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Active => f.write_str("active"),
            Status::Deprecated => f.write_str("deprecated"),
            Status::Disabled => f.write_str("disabled"),
        }
    }
}

/// Algorithm family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Family {
    /// Key encapsulation mechanism.
    Kem,
    /// Digital signature.
    Signature,
    /// Classical + PQ KEM combiner.
    HybridKem,
    /// Classical + PQ signature combiner.
    HybridSignature,
    /// Authenticated encryption.
    Aead,
    /// Key derivation function.
    Kdf,
    /// Hash function.
    Hash,
}

/// One registry entry. The identity fields (everything that defines *what* the algorithm is:
/// family, standard, OID, level, sizes, components) are immutable once published. `status`,
/// `deprecated`, `implementation` and `notes` may change: swapping the library that implements
/// an algorithm (as happened for SLH-DSA, see `qshield-slhdsa-sys`) does not change the
/// algorithm, and KATs guard the outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmEntry {
    /// Stable identifier, e.g. `ml-kem-768`.
    pub id: String,
    /// Entry version (a parameter change is a new id, so this is normally 1).
    pub version: u32,
    /// Family.
    pub family: Family,
    /// Standard document.
    pub standard: String,
    /// Object identifier, when one is assigned.
    #[serde(default)]
    pub oid: Option<String>,
    /// NIST security category (0 for classical-only algorithms).
    pub nist_level: u8,
    /// Lifecycle status.
    pub status: Status,
    /// Whether the algorithm resists a cryptographically relevant quantum computer.
    pub quantum_safe: bool,
    /// Component algorithm ids for hybrids.
    #[serde(default)]
    pub components: Vec<String>,
    /// Public key length in bytes (KEM, signature, hybrids).
    #[serde(default)]
    pub public_key_len: Option<usize>,
    /// Secret key length in bytes.
    #[serde(default)]
    pub secret_key_len: Option<usize>,
    /// Ciphertext length in bytes (KEMs).
    #[serde(default)]
    pub ciphertext_len: Option<usize>,
    /// Signature length in bytes (signatures).
    #[serde(default)]
    pub signature_len: Option<usize>,
    /// Shared secret length in bytes (KEMs).
    #[serde(default)]
    pub shared_secret_len: Option<usize>,
    /// Key length in bytes (symmetric).
    #[serde(default)]
    pub key_len: Option<usize>,
    /// Implementation recorded in the CBOM.
    pub implementation: String,
    /// ISO date the entry was introduced.
    pub introduced: String,
    /// ISO date the entry was deprecated (required when status is not active).
    #[serde(default)]
    pub deprecated: Option<String>,
    /// Free-form notes.
    #[serde(default)]
    pub notes: Option<String>,
}

impl AlgorithmEntry {
    fn immutable_fields_equal(&self, other: &AlgorithmEntry) -> bool {
        self.id == other.id
            && self.version == other.version
            && self.family == other.family
            && self.standard == other.standard
            && self.oid == other.oid
            && self.nist_level == other.nist_level
            && self.quantum_safe == other.quantum_safe
            && self.components == other.components
            && self.public_key_len == other.public_key_len
            && self.secret_key_len == other.secret_key_len
            && self.ciphertext_len == other.ciphertext_len
            && self.signature_len == other.signature_len
            && self.shared_secret_len == other.shared_secret_len
            && self.key_len == other.key_len
            && self.introduced == other.introduced
    }
}

#[derive(Deserialize)]
struct RegistryFile {
    #[serde(default = "default_registry_version")]
    registry_version: u32,
    #[serde(default)]
    algorithm: Vec<AlgorithmEntry>,
}

fn default_registry_version() -> u32 {
    1
}

/// A validated set of algorithm entries.
#[derive(Debug, Clone)]
pub struct Registry {
    version: u32,
    entries: BTreeMap<String, AlgorithmEntry>,
}

const BUILTIN_TOML: &str = include_str!("../../../registry/algorithms.toml");

static BUILTIN: OnceLock<Registry> = OnceLock::new();

impl Registry {
    /// The registry compiled into the binary from `registry/algorithms.toml`.
    ///
    /// # Panics
    ///
    /// If the embedded registry is invalid. Unit tests load it, so such a build never ships.
    #[must_use]
    pub fn builtin() -> &'static Registry {
        BUILTIN.get_or_init(|| {
            Registry::from_toml(BUILTIN_TOML).expect("embedded registry must be valid")
        })
    }

    /// Parses and validates a registry document.
    pub fn from_toml(text: &str) -> Result<Self, CryptoError> {
        let file: RegistryFile =
            toml::from_str(text).map_err(|e| CryptoError::Registry(e.to_string()))?;
        let mut entries = BTreeMap::new();
        for entry in file.algorithm {
            validate_entry(&entry)?;
            if entries.insert(entry.id.clone(), entry.clone()).is_some() {
                return Err(CryptoError::Registry(format!("duplicate id {}", entry.id)));
            }
        }
        let registry = Registry {
            version: file.registry_version,
            entries,
        };
        registry.validate_components()?;
        Ok(registry)
    }

    /// Registry document version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Looks up an entry.
    pub fn get(&self, id: &str) -> Result<&AlgorithmEntry, CryptoError> {
        self.entries
            .get(id)
            .ok_or_else(|| CryptoError::UnknownAlgorithm(id.to_string()))
    }

    /// Whether the id is known.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// All entries in id order.
    pub fn entries(&self) -> impl Iterator<Item = &AlgorithmEntry> {
        self.entries.values()
    }

    /// Entries of one family.
    pub fn by_family(&self, family: Family) -> impl Iterator<Item = &AlgorithmEntry> {
        self.entries.values().filter(move |e| e.family == family)
    }

    /// Checks that new keys may be generated for `id` (status must be `active`).
    // TM:T09-M2 registry status gates every key generation
    pub fn check_generate(&self, id: &str) -> Result<&AlgorithmEntry, CryptoError> {
        let e = self.get(id)?;
        match e.status {
            Status::Active => Ok(e),
            status @ (Status::Deprecated | Status::Disabled) => {
                Err(CryptoError::AlgorithmNotAllowed {
                    id: id.to_string(),
                    status,
                    operation: "generate",
                })
            }
        }
    }

    /// Checks that existing keys of `id` may still be used for decapsulation or verification
    /// (status `active` or `deprecated`).
    pub fn check_use(&self, id: &str) -> Result<&AlgorithmEntry, CryptoError> {
        let e = self.get(id)?;
        match e.status {
            Status::Active | Status::Deprecated => Ok(e),
            status @ Status::Disabled => Err(CryptoError::AlgorithmNotAllowed {
                id: id.to_string(),
                status,
                operation: "use",
            }),
        }
    }

    /// Checks that `id` may produce new signatures or encapsulations (status `active`).
    pub fn check_produce(&self, id: &str) -> Result<&AlgorithmEntry, CryptoError> {
        let e = self.get(id)?;
        match e.status {
            Status::Active => Ok(e),
            status @ (Status::Deprecated | Status::Disabled) => {
                Err(CryptoError::AlgorithmNotAllowed {
                    id: id.to_string(),
                    status,
                    operation: "sign/encapsulate",
                })
            }
        }
    }

    /// Validates that `next` is a legal successor of `self`: every entry still exists with
    /// identical immutable fields, statuses only move forward, and the document version does not
    /// go backwards.
    // TM:T09-M2 status transitions are forward-only; immutable fields cannot change
    pub fn validate_transition(&self, next: &Registry) -> Result<(), CryptoError> {
        if next.version < self.version {
            return Err(CryptoError::Registry(format!(
                "registry_version {} is older than current {}",
                next.version, self.version
            )));
        }
        for (id, old) in &self.entries {
            let new = next.entries.get(id).ok_or_else(|| {
                CryptoError::Registry(format!("entry {id} removed; set status = disabled instead"))
            })?;
            if !old.immutable_fields_equal(new) {
                return Err(CryptoError::Registry(format!(
                    "entry {id} changed an immutable field; publish a new id instead"
                )));
            }
            if !old.status.may_transition_to(new.status) {
                return Err(CryptoError::Registry(format!(
                    "entry {id} may not move from {} back to {}",
                    old.status, new.status
                )));
            }
        }
        Ok(())
    }

    fn validate_components(&self) -> Result<(), CryptoError> {
        for e in self.entries.values() {
            let is_hybrid = matches!(e.family, Family::HybridKem | Family::HybridSignature);
            if is_hybrid {
                if e.components.len() < 2 {
                    return Err(CryptoError::Registry(format!(
                        "hybrid {} needs at least two components",
                        e.id
                    )));
                }
                let mut has_pq = false;
                let mut has_classical = false;
                for c in &e.components {
                    let comp = self.entries.get(c).ok_or_else(|| {
                        CryptoError::Registry(format!("hybrid {} references unknown {c}", e.id))
                    })?;
                    let expected = match e.family {
                        Family::HybridKem => Family::Kem,
                        _ => Family::Signature,
                    };
                    if comp.family != expected {
                        return Err(CryptoError::Registry(format!(
                            "hybrid {} component {c} has family {:?}, expected {expected:?}",
                            e.id, comp.family
                        )));
                    }
                    has_pq |= comp.quantum_safe;
                    has_classical |= !comp.quantum_safe;
                }
                if !(has_pq && has_classical) {
                    return Err(CryptoError::Registry(format!(
                        "hybrid {} must combine one classical and one quantum-safe component",
                        e.id
                    )));
                }
            } else if !e.components.is_empty() {
                return Err(CryptoError::Registry(format!(
                    "non-hybrid {} must not list components",
                    e.id
                )));
            }
        }
        Ok(())
    }
}

fn validate_entry(e: &AlgorithmEntry) -> Result<(), CryptoError> {
    let err = |m: String| Err(CryptoError::Registry(format!("{}: {m}", e.id)));
    if e.id.is_empty()
        || !e
            .id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return err("id must be non-empty lowercase [a-z0-9-]".into());
    }
    if e.version == 0 {
        return err("version must be >= 1".into());
    }
    if e.nist_level > 5 {
        return err("nist_level must be 0..=5".into());
    }
    if e.quantum_safe && e.nist_level == 0 {
        return err("quantum-safe algorithms must declare a NIST level".into());
    }
    if e.status != Status::Active && e.deprecated.is_none() {
        return err("deprecated/disabled entries need a `deprecated` date".into());
    }
    if e.status == Status::Active && e.deprecated.is_some() {
        return err("active entries must not carry a `deprecated` date".into());
    }
    if !is_iso_date(&e.introduced) {
        return err("introduced must be YYYY-MM-DD".into());
    }
    if let Some(d) = &e.deprecated {
        if !is_iso_date(d) {
            return err("deprecated must be YYYY-MM-DD".into());
        }
    }
    let need = |v: Option<usize>, name: &str| -> Result<(), CryptoError> {
        match v {
            Some(n) if n > 0 => Ok(()),
            _ => Err(CryptoError::Registry(format!("{}: {name} required", e.id))),
        }
    };
    match e.family {
        Family::Kem | Family::HybridKem => {
            need(e.public_key_len, "public_key_len")?;
            need(e.secret_key_len, "secret_key_len")?;
            need(e.ciphertext_len, "ciphertext_len")?;
            need(e.shared_secret_len, "shared_secret_len")?;
        }
        Family::Signature | Family::HybridSignature => {
            need(e.public_key_len, "public_key_len")?;
            need(e.secret_key_len, "secret_key_len")?;
            need(e.signature_len, "signature_len")?;
        }
        Family::Aead | Family::Kdf => need(e.key_len, "key_len")?,
        Family::Hash => {}
    }
    Ok(())
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                true
            } else {
                c.is_ascii_digit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_loads_and_has_required_algorithms() {
        let r = Registry::builtin();
        for id in [
            "ml-kem-768",
            "ml-kem-1024",
            "ml-dsa-65",
            "ml-dsa-87",
            "slh-dsa-sha2-128s",
            "hybrid-x25519-ml-kem-768",
            "hybrid-ed25519-ml-dsa-65",
            "aes-256-gcm",
            "hkdf-sha256",
        ] {
            let e = r.get(id).unwrap();
            assert_eq!(e.status, Status::Active, "{id} should be active");
        }
        assert_eq!(r.get("ml-kem-512").unwrap().status, Status::Deprecated);
        assert!(r.contains("ed25519"));
        assert!(!r.contains("rsa-2048"));
        assert!(r.version() >= 1);
        assert_eq!(r.by_family(Family::HybridKem).count(), 1);
        assert!(r.entries().count() >= 13);
    }

    #[test]
    fn status_gates() {
        let r = Registry::builtin();
        assert!(r.check_generate("ml-kem-768").is_ok());
        assert!(r.check_produce("ml-dsa-65").is_ok());
        assert!(r.check_use("ml-kem-512").is_ok());
        assert_eq!(
            r.check_generate("ml-kem-512"),
            Err(CryptoError::AlgorithmNotAllowed {
                id: "ml-kem-512".into(),
                status: Status::Deprecated,
                operation: "generate",
            })
        );
        assert!(matches!(
            r.check_produce("ml-dsa-44"),
            Err(CryptoError::AlgorithmNotAllowed { .. })
        ));
        assert_eq!(
            r.get("nope"),
            Err(CryptoError::UnknownAlgorithm("nope".into()))
        );
    }

    fn minimal(status: &str, deprecated: &str) -> String {
        format!(
            r#"
registry_version = 1
[[algorithm]]
id = "ml-kem-768"
version = 1
family = "kem"
standard = "FIPS 203"
nist_level = 3
status = "{status}"
{deprecated}
quantum_safe = true
public_key_len = 1184
secret_key_len = 2400
ciphertext_len = 1088
shared_secret_len = 32
implementation = "pqclean"
introduced = "2026-11-03"
"#
        )
    }

    #[test]
    fn transitions_are_forward_only() {
        let active = Registry::from_toml(&minimal("active", "")).unwrap();
        let deprecated =
            Registry::from_toml(&minimal("deprecated", "deprecated = \"2026-12-01\"")).unwrap();
        let disabled =
            Registry::from_toml(&minimal("disabled", "deprecated = \"2026-12-01\"")).unwrap();
        assert!(active.validate_transition(&deprecated).is_ok());
        assert!(deprecated.validate_transition(&disabled).is_ok());
        assert!(active.validate_transition(&active).is_ok());
        // registry_rejects_reactivation
        assert!(deprecated.validate_transition(&active).is_err());
        assert!(disabled.validate_transition(&deprecated).is_err());
        assert!(Status::Active.may_transition_to(Status::Disabled));
        assert!(!Status::Disabled.may_transition_to(Status::Active));
        assert_eq!(Status::Deprecated.to_string(), "deprecated");
        assert_eq!(Status::Active.to_string(), "active");
        assert_eq!(Status::Disabled.to_string(), "disabled");
    }

    #[test]
    fn transition_rejects_removed_or_mutated_entries() {
        let a = Registry::from_toml(&minimal("active", "")).unwrap();
        let empty = Registry::from_toml("registry_version = 1\n").unwrap();
        assert!(a.validate_transition(&empty).is_err());
        let mutated = Registry::from_toml(&minimal("active", "").replace("1184", "1185")).unwrap();
        assert!(a.validate_transition(&mutated).is_err());
        let older = Registry::from_toml(
            &minimal("active", "").replace("registry_version = 1", "registry_version = 0"),
        )
        .unwrap();
        assert!(a.validate_transition(&older).is_err());
        // Changing the implementing library is allowed.
        let reimplemented = Registry::from_toml(&minimal("active", "").replace(
            "implementation = \"pqclean\"",
            "implementation = \"liboqs\"",
        ))
        .unwrap();
        assert!(a.validate_transition(&reimplemented).is_ok());
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let bad_id = minimal("active", "").replace("\"ml-kem-768\"", "\"ML_KEM\"");
        assert!(Registry::from_toml(&bad_id).is_err());
        let no_date = minimal("deprecated", "");
        assert!(Registry::from_toml(&no_date).is_err());
        let active_with_date = minimal("active", "deprecated = \"2026-12-01\"");
        assert!(Registry::from_toml(&active_with_date).is_err());
        let bad_level = minimal("active", "").replace("nist_level = 3", "nist_level = 9");
        assert!(Registry::from_toml(&bad_level).is_err());
        let pq_no_level = minimal("active", "").replace("nist_level = 3", "nist_level = 0");
        assert!(Registry::from_toml(&pq_no_level).is_err());
        let zero_version = minimal("active", "").replace("version = 1\n", "version = 0\n");
        assert!(Registry::from_toml(&zero_version).is_err());
        let bad_intro = minimal("active", "").replace("2026-11-03", "yesterday");
        assert!(Registry::from_toml(&bad_intro).is_err());
        let bad_dep = minimal("deprecated", "deprecated = \"soon\"");
        assert!(Registry::from_toml(&bad_dep).is_err());
        let missing_len = minimal("active", "").replace("ciphertext_len = 1088\n", "");
        assert!(Registry::from_toml(&missing_len).is_err());
        let dup = format!(
            "{}{}",
            minimal("active", ""),
            minimal("active", "").replace("registry_version = 1", "")
        );
        assert!(Registry::from_toml(&dup).is_err());
        assert!(Registry::from_toml("this is not toml = = =").is_err());
    }

    #[test]
    fn defaults_disabled_status_and_hash_family() {
        // registry_version defaults to 1 when omitted.
        let no_version = minimal("active", "").replace(
            "registry_version = 1
",
            "",
        );
        assert_eq!(Registry::from_toml(&no_version).unwrap().version(), 1);
        // Disabled algorithms are refused for every operation.
        let disabled =
            Registry::from_toml(&minimal("disabled", "deprecated = \"2026-12-01\"")).unwrap();
        for result in [
            disabled.check_use("ml-kem-768"),
            disabled.check_generate("ml-kem-768"),
            disabled.check_produce("ml-kem-768"),
        ] {
            assert!(matches!(
                result,
                Err(CryptoError::AlgorithmNotAllowed {
                    status: Status::Disabled,
                    ..
                })
            ));
        }
        // Hash entries need no size fields.
        let hash = r#"
[[algorithm]]
id = "sha3-256"
version = 1
family = "hash"
standard = "FIPS 202"
nist_level = 2
status = "active"
quantum_safe = true
implementation = "sha3 (RustCrypto)"
introduced = "2026-11-03"
"#;
        let r = Registry::from_toml(hash).unwrap();
        assert_eq!(r.get("sha3-256").unwrap().family, Family::Hash);
        assert_eq!(r.by_family(Family::Hash).count(), 1);
    }

    #[test]
    fn hybrid_validation() {
        let base = minimal("active", "");
        let hybrid_missing_component = format!(
            r#"{base}
[[algorithm]]
id = "hybrid-x"
version = 1
family = "hybrid-kem"
standard = "x"
nist_level = 3
status = "active"
quantum_safe = true
components = ["x25519", "ml-kem-768"]
public_key_len = 1
secret_key_len = 1
ciphertext_len = 1
shared_secret_len = 32
implementation = "x"
introduced = "2026-11-03"
"#
        );
        assert!(Registry::from_toml(&hybrid_missing_component).is_err());
        let one_component =
            hybrid_missing_component.replace("[\"x25519\", \"ml-kem-768\"]", "[\"ml-kem-768\"]");
        assert!(Registry::from_toml(&one_component).is_err());
        let two_pq = hybrid_missing_component.replace(
            "[\"x25519\", \"ml-kem-768\"]",
            "[\"ml-kem-768\", \"ml-kem-768\"]",
        );
        assert!(Registry::from_toml(&two_pq).is_err());
        let non_hybrid_with_components = base.replace(
            "quantum_safe = true",
            "quantum_safe = true\ncomponents = [\"x25519\"]",
        );
        assert!(Registry::from_toml(&non_hybrid_with_components).is_err());
        let wrong_family = format!(
            r#"{base}
[[algorithm]]
id = "ed25519"
version = 1
family = "signature"
standard = "RFC 8032"
nist_level = 0
status = "active"
quantum_safe = false
public_key_len = 32
secret_key_len = 32
signature_len = 64
implementation = "dalek"
introduced = "2026-11-03"
[[algorithm]]
id = "hybrid-x"
version = 1
family = "hybrid-kem"
standard = "x"
nist_level = 3
status = "active"
quantum_safe = true
components = ["ed25519", "ml-kem-768"]
public_key_len = 1
secret_key_len = 1
ciphertext_len = 1
shared_secret_len = 32
implementation = "x"
introduced = "2026-11-03"
"#
        );
        assert!(Registry::from_toml(&wrong_family).is_err());
    }
}

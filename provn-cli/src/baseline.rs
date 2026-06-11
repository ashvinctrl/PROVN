//! Findings baseline — lets a repo adopt Provn without drowning in pre-existing
//! findings. A baseline records the *fingerprints* of accepted findings; later
//! scans suppress anything whose fingerprint is already in the baseline.
//!
//! ## Security properties (these are load-bearing — do not weaken)
//!
//! 1. **A baseline can only suppress the exact finding it recorded.** The
//!    fingerprint is `SHA-256(file \0 rule \0 secret)`. Because the secret
//!    value is part of the hash, a *different* secret — even in the same file
//!    under the same rule — produces a different fingerprint and is still
//!    reported. Rotating or changing a secret therefore re-triggers detection.
//! 2. **The baseline never stores a plaintext secret.** Only the one-way hash
//!    is written, so committing `.provn/baseline.json` does not leak secrets.
//! 3. The line number is deliberately **excluded** from the fingerprint so
//!    unrelated edits that shift line numbers don't resurrect accepted findings.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;

use crate::scanner::ScanResult;

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    /// Format version for forward compatibility.
    pub version: u32,
    pub generated_at: String,
    /// Sorted set of accepted finding fingerprints (hex SHA-256).
    pub fingerprints: BTreeSet<String>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: 1,
            generated_at: String::new(),
            fingerprints: BTreeSet::new(),
        }
    }
}

/// Stable fingerprint of a finding: `SHA-256(file \0 rule \0 secret)`.
///
/// `secret` is the captured secret when available, else the snippet — so even
/// findings the layers can't pinpoint still get a deterministic fingerprint.
/// The raw inputs are never persisted; only this digest is.
pub fn fingerprint(result: &ScanResult) -> String {
    let file = result.file.as_deref().unwrap_or("");
    let rule = result.match_type.as_deref().unwrap_or("");
    let secret = result
        .secret
        .as_deref()
        .or(result.snippet.as_deref())
        .unwrap_or("");

    let mut hasher = Sha256::new();
    hasher.update(file.as_bytes());
    hasher.update([0u8]);
    hasher.update(rule.as_bytes());
    hasher.update([0u8]);
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

impl Baseline {
    /// Load a baseline from disk. A missing file yields an empty baseline
    /// (so `--no-baseline`-free scans simply behave as before on fresh repos).
    pub fn load(path: &str) -> Result<Baseline, BaselineError> {
        if !Path::new(path).exists() {
            return Ok(Baseline::default());
        }
        let content = std::fs::read_to_string(path)?;
        let baseline: Baseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    /// Build a baseline accepting every supplied finding.
    pub fn from_findings(findings: &[ScanResult]) -> Baseline {
        Baseline {
            version: 1,
            generated_at: chrono::Utc::now().to_rfc3339(),
            fingerprints: findings.iter().map(fingerprint).collect(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), BaselineError> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn contains(&self, result: &ScanResult) -> bool {
        self.fingerprints.contains(&fingerprint(result))
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(file: &str, rule: &str, secret: &str) -> ScanResult {
        ScanResult {
            file: Some(file.to_string()),
            match_type: Some(rule.to_string()),
            secret: Some(secret.to_string()),
            tier: Some("T0".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn fingerprint_is_stable_across_line_moves() {
        let mut a = result("a.py", "aws_access_key", "AKIAEXAMPLE"); // provn:allow
        let mut b = a.clone();
        a.line = Some(10);
        b.line = Some(999);
        assert_eq!(
            fingerprint(&a),
            fingerprint(&b),
            "line must not affect fingerprint"
        );
    }

    #[test]
    fn baseline_suppresses_recorded_finding() {
        let f = result("a.py", "aws_access_key", "AKIAEXAMPLE"); // provn:allow
        let baseline = Baseline::from_findings(std::slice::from_ref(&f));
        assert!(baseline.contains(&f));
    }

    #[test]
    fn changed_secret_is_not_suppressed() {
        // SECURITY: rotating/altering the secret must re-trigger detection.
        let original = result("a.py", "aws_access_key", "AKIAOLDKEY00000000000"); // provn:allow
        let baseline = Baseline::from_findings(std::slice::from_ref(&original));
        let rotated = result("a.py", "aws_access_key", "AKIANEWKEY99999999999"); // provn:allow
        assert!(
            !baseline.contains(&rotated),
            "a different secret must NOT be suppressed by an old baseline entry"
        );
    }

    #[test]
    fn same_secret_different_file_not_suppressed() {
        // File is part of the fingerprint, so accepting a test fixture's secret
        // does not silently allow the same value elsewhere.
        let fixture = result("tests/fixture.py", "aws_access_key", "AKIAEXAMPLE"); // provn:allow
        let baseline = Baseline::from_findings(std::slice::from_ref(&fixture));
        let prod = result("src/app.py", "aws_access_key", "AKIAEXAMPLE"); // provn:allow
        assert!(!baseline.contains(&prod));
    }

    #[test]
    fn baseline_file_contains_no_plaintext_secret() {
        // SECURITY: only the hash may be persisted.
        let secret = "AKIAVERYSECRETKEY123"; // provn:allow
        let f = result("a.py", "aws_access_key", secret);
        let baseline = Baseline::from_findings(std::slice::from_ref(&f));
        let json = serde_json::to_string(&baseline).unwrap();
        assert!(
            !json.contains(secret),
            "serialized baseline must not contain the secret"
        );
    }

    #[test]
    fn roundtrip_load_save() {
        let dir = std::env::temp_dir().join(format!("provn-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        let f = result("a.py", "aws_access_key", "AKIAEXAMPLE"); // provn:allow
        Baseline::from_findings(std::slice::from_ref(&f))
            .save(path.to_str().unwrap())
            .unwrap();
        let loaded = Baseline::load(path.to_str().unwrap()).unwrap();
        assert!(loaded.contains(&f));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_baseline_is_empty() {
        let bl = Baseline::load("/nonexistent/path/baseline.json").unwrap();
        assert!(bl.is_empty());
    }
}

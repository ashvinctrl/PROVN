use crate::config::Config;
use crate::policy::Verdict;
use crate::scanner::ScanResult;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Chain invalid: {0}")]
    Chain(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: String,
    pub event: String,
    pub file: Option<String>,
    pub tier: Option<String>,
    pub layer: Option<String>,
    pub verdict: String,
    // Structured context fields — optional so chains written by older
    // versions still verify (absent fields are excluded from the HMAC
    // payload on both the write and verify paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provn_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_layer: Option<String>,
    pub prev_hash: String,
    pub hmac: String,
}

/// Canonical JSON payload used for HMAC signing. serde_json maps serialize
/// with sorted keys, so this is deterministic; optional fields are included
/// only when present, keeping old log entries verifiable.
#[allow(clippy::too_many_arguments)]
fn signing_payload(
    seq: u64,
    timestamp: &str,
    event: &str,
    file: &Option<String>,
    tier: &Option<String>,
    layer: &Option<String>,
    verdict: &str,
    prev_hash: &str,
    provn_version: &Option<String>,
    scan_duration_ms: &Option<u64>,
    ai_layer: &Option<String>,
) -> String {
    let mut payload = serde_json::json!({
        "seq": seq,
        "timestamp": timestamp,
        "event": event,
        "file": file,
        "tier": tier,
        "layer": layer,
        "verdict": verdict,
        "prev_hash": prev_hash,
    });
    let obj = payload.as_object_mut().expect("payload is an object");
    if let Some(v) = provn_version {
        obj.insert("provn_version".into(), serde_json::json!(v));
    }
    if let Some(v) = scan_duration_ms {
        obj.insert("scan_duration_ms".into(), serde_json::json!(v));
    }
    if let Some(v) = ai_layer {
        obj.insert("ai_layer".into(), serde_json::json!(v));
    }
    payload.to_string()
}

fn get_or_create_hmac_key(key_path: &str) -> Vec<u8> {
    if let Ok(key) = fs::read(key_path) {
        return key;
    }
    // Generate a random 32-byte key
    let key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    if let Some(parent) = Path::new(key_path).parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(key_path, &key).ok();
    key
}

fn read_hmac_key(key_path: &str) -> Result<Vec<u8>, AuditError> {
    fs::read(key_path).map_err(AuditError::Io)
}

fn hmac_sign(key: &[u8], data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn read_last_entry(audit_path: &str) -> Option<AuditEntry> {
    let file = fs::File::open(audit_path).ok()?;
    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            last = Some(entry);
        }
    }
    last
}

fn hash_entry(entry: &AuditEntry) -> String {
    use sha2::{Digest, Sha256};
    let data = serde_json::to_string(entry).unwrap_or_default();
    let digest = Sha256::digest(data.as_bytes());
    hex::encode(digest)
}

pub fn append(verdict: &Verdict, result: &ScanResult, cfg: &Config) -> Result<(), AuditError> {
    if !cfg.audit.enabled {
        return Ok(());
    }

    let audit_path = &cfg.audit.path;
    if let Some(parent) = Path::new(audit_path.as_str()).parent() {
        fs::create_dir_all(parent)?;
    }

    let key = get_or_create_hmac_key(&cfg.audit.hmac_key_path);

    let last = read_last_entry(audit_path);
    let seq = last.as_ref().map(|e| e.seq + 1).unwrap_or(0);
    let prev_hash = last
        .as_ref()
        .map(hash_entry)
        .unwrap_or_else(|| "genesis".to_string());
    let timestamp = Utc::now().to_rfc3339();

    let verdict_str = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Warn(t) | Verdict::Block(t) => t.as_str(),
    };

    let event = format!("{:?}", verdict)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_uppercase();

    let provn_version = Some(env!("CARGO_PKG_VERSION").to_string());
    let scan_duration_ms = Some(result.latency_ms);
    let ai_layer = if result.ai_skipped {
        Some("skipped".to_string())
    } else if result.layer.as_deref() == Some("semantic") {
        Some("used".to_string())
    } else {
        None
    };

    let payload = signing_payload(
        seq,
        &timestamp,
        &event,
        &result.file,
        &result.tier,
        &result.layer,
        verdict_str,
        &prev_hash,
        &provn_version,
        &scan_duration_ms,
        &ai_layer,
    );
    let hmac = hmac_sign(&key, &payload);

    let entry = AuditEntry {
        seq,
        timestamp,
        event,
        file: result.file.clone(),
        tier: result.tier.clone(),
        layer: result.layer.clone(),
        verdict: verdict_str.to_string(),
        provn_version,
        scan_duration_ms,
        ai_layer,
        prev_hash,
        hmac,
    };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;
    writeln!(file, "{}", serde_json::to_string(&entry)?)?;

    Ok(())
}

pub fn verify_chain(audit_path: &str, hmac_key_path: &str) -> Result<usize, AuditError> {
    if !Path::new(audit_path).exists() {
        return Ok(0);
    }

    let key = read_hmac_key(hmac_key_path)?;

    let file = fs::File::open(audit_path)?;
    let reader = BufReader::new(file);
    let mut count = 0;
    let mut prev_hash = "genesis".to_string();

    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;

        if entry.prev_hash != prev_hash {
            return Err(AuditError::Chain(format!(
                "Hash chain broken at seq {} — expected prev_hash {}",
                entry.seq, prev_hash
            )));
        }

        // Verify HMAC
        let payload = signing_payload(
            entry.seq,
            &entry.timestamp,
            &entry.event,
            &entry.file,
            &entry.tier,
            &entry.layer,
            &entry.verdict,
            &entry.prev_hash,
            &entry.provn_version,
            &entry.scan_duration_ms,
            &entry.ai_layer,
        );
        let expected_hmac = hmac_sign(&key, &payload);
        if entry.hmac != expected_hmac {
            return Err(AuditError::Chain(format!(
                "HMAC invalid at seq {}",
                entry.seq
            )));
        }

        prev_hash = hash_entry(&entry);
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{append, verify_chain};
    use crate::config::Config;
    use crate::policy::Verdict;
    use crate::scanner::ScanResult;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn appended_entries_verify_successfully() {
        let temp_dir = std::env::temp_dir().join(format!("provn-audit-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut cfg = Config::default();
        cfg.audit.path = temp_dir.join("audit.jsonl").display().to_string();
        cfg.audit.hmac_key_path = temp_dir.join("hmac.key").display().to_string();

        let t1_result = ScanResult {
            file: Some("bot.py".to_string()),
            line: Some(1),
            match_type: Some("ast_taint".to_string()),
            description: Some(
                "Sensitive variable 'system_prompt' assigned string literal".to_string(),
            ),
            snippet: Some(
                "system_prompt = \"Use our proprietary ranking rubric and do not disclose it.\""
                    .to_string(),
            ),
            redacted: Some("PROVN_REDACTED_SYSTEM_PROMPT".to_string()),
            confidence: 0.70,
            layer: Some("ast".to_string()),
            tier: Some("T1".to_string()),
            ..Default::default()
        };

        let t2_result = ScanResult {
            file: Some("config.py".to_string()),
            line: Some(1),
            match_type: Some("high_entropy".to_string()),
            description: Some("High entropy token (H=5.00)".to_string()),
            snippet: Some("secret_token = \"x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXnPqRsT\"".to_string()), // provn:allow
            redacted: Some("PROVN_REDACTED_HIGH_ENTROPY".to_string()),
            confidence: 0.66,
            layer: Some("entropy".to_string()),
            tier: Some("T2".to_string()),
            ..Default::default()
        };

        append(&Verdict::Block("T1".to_string()), &t1_result, &cfg).unwrap();
        append(&Verdict::Warn("T2".to_string()), &t2_result, &cfg).unwrap();

        let count = verify_chain(&cfg.audit.path, &cfg.audit.hmac_key_path).unwrap();
        assert_eq!(count, 2);

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn new_entries_carry_structured_fields() {
        let temp_dir = std::env::temp_dir().join(format!("provn-audit-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut cfg = Config::default();
        cfg.audit.path = temp_dir.join("audit.jsonl").display().to_string();
        cfg.audit.hmac_key_path = temp_dir.join("hmac.key").display().to_string();

        let result = ScanResult {
            file: Some("a.py".to_string()),
            tier: Some("T1".to_string()),
            latency_ms: 42,
            ai_skipped: true,
            ..Default::default()
        };
        append(&Verdict::Block("T1".to_string()), &result, &cfg).unwrap();

        let raw = fs::read_to_string(&cfg.audit.path).unwrap();
        assert!(raw.contains("\"provn_version\""));
        assert!(raw.contains("\"scan_duration_ms\":42"));
        assert!(raw.contains("\"ai_layer\":\"skipped\""));
        // Chain must still verify with the new fields in the payload.
        assert_eq!(
            verify_chain(&cfg.audit.path, &cfg.audit.hmac_key_path).unwrap(),
            1
        );

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let temp_dir = std::env::temp_dir().join(format!("provn-audit-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut cfg = Config::default();
        cfg.audit.path = temp_dir.join("audit.jsonl").display().to_string();
        cfg.audit.hmac_key_path = temp_dir.join("hmac.key").display().to_string();

        let result = ScanResult {
            file: Some("a.py".to_string()),
            tier: Some("T0".to_string()),
            ..Default::default()
        };
        append(&Verdict::Block("T0".to_string()), &result, &cfg).unwrap();

        // Flip the verdict in the stored entry — verification must fail.
        let raw = fs::read_to_string(&cfg.audit.path).unwrap();
        let tampered = raw.replace("\"verdict\":\"T0\"", "\"verdict\":\"ALLOW\"");
        assert_ne!(raw, tampered, "test setup: replacement must change content");
        fs::write(&cfg.audit.path, tampered).unwrap();

        assert!(verify_chain(&cfg.audit.path, &cfg.audit.hmac_key_path).is_err());

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}

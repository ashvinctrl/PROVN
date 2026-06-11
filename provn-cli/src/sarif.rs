//! SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.
//!
//! ## Security
//!
//! SARIF is frequently uploaded to GitHub Code Scanning, stored as a CI
//! artifact, and rendered in PR UIs. It therefore MUST NOT contain the raw
//! secret. This module emits only the rule id, severity, a redacted message,
//! and the location (file + line). The `secret` / `snippet` fields of a
//! finding are never serialized here — `no_secret_in_sarif` enforces it.

use crate::baseline;
use crate::scanner::ScanResult;

/// Map a Provn risk tier to a SARIF result level.
fn tier_to_level(tier: Option<&str>) -> &'static str {
    match tier {
        Some("T0") => "error",
        Some("T1") => "warning",
        Some("T2") => "note",
        _ => "none", // T3 and unknown
    }
}

/// Render findings as a SARIF 2.1.0 document (pretty-printed JSON).
pub fn render(findings: &[ScanResult]) -> String {
    // Build the rule catalog (unique by ruleId) for tool.driver.rules.
    let mut rule_ids: Vec<String> = Vec::new();
    for f in findings {
        if let Some(id) = f.match_type.as_deref() {
            if !rule_ids.iter().any(|r| r == id) {
                rule_ids.push(id.to_string());
            }
        }
    }

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            // Use the first finding with this rule for a description — never
            // its secret/snippet, only the human description text.
            let desc = findings
                .iter()
                .find(|f| f.match_type.as_deref() == Some(id))
                .and_then(|f| f.description.clone())
                .unwrap_or_else(|| id.clone());
            serde_json::json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": desc },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule_id = f
                .match_type
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let level = tier_to_level(f.tier.as_deref());
            // Message describes the rule and tier — never the secret value.
            let message = format!(
                "[{}] {}",
                f.tier.as_deref().unwrap_or("?"),
                f.description
                    .as_deref()
                    .unwrap_or("Potential secret or IP leak")
            );
            let file = f.file.clone().unwrap_or_default();
            let line = f.line.unwrap_or(1).max(1);

            serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": normalize_uri(&file) },
                        "region": { "startLine": line }
                    }
                }],
                // Stable dedup key — the same one-way fingerprint the baseline
                // uses. Safe to publish: it is a SHA-256 hash, not the secret.
                "partialFingerprints": {
                    "provnFingerprint/v1": baseline::fingerprint(f)
                }
            })
        })
        .collect();

    let doc = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Provn",
                    "informationUri": "https://github.com/ashvinctrl/Provn",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// SARIF URIs use forward slashes and no leading "./".
fn normalize_uri(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(tier: &str, rule: &str, secret: &str) -> ScanResult {
        ScanResult {
            file: Some("src/app.py".to_string()),
            line: Some(42),
            match_type: Some(rule.to_string()),
            description: Some(format!("{rule} matched")),
            snippet: Some(format!("api_key = \"{secret}\"")),
            secret: Some(secret.to_string()),
            tier: Some(tier.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn produces_valid_sarif_structure() {
        let out = render(&[finding("T0", "aws_access_key", "AKIAEXAMPLE")]); // provn:allow
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Provn");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "aws_access_key");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            42
        );
        assert!(
            v["runs"][0]["results"][0]["partialFingerprints"]["provnFingerprint/v1"].is_string()
        );
    }

    #[test]
    fn tier_levels_map_correctly() {
        for (tier, level) in [
            ("T0", "error"),
            ("T1", "warning"),
            ("T2", "note"),
            ("T3", "none"),
        ] {
            let out = render(&[finding(tier, "r", "s")]);
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["runs"][0]["results"][0]["level"], level, "tier {tier}");
        }
    }

    #[test]
    fn no_secret_in_sarif() {
        // SECURITY: the raw secret must never appear in SARIF output.
        let secret = "AKIAVERYSECRETVALUE9"; // provn:allow
        let out = render(&[finding("T0", "aws_access_key", secret)]);
        assert!(
            !out.contains(secret),
            "SARIF output leaked the secret value"
        );
    }

    #[test]
    fn empty_findings_still_valid() {
        let out = render(&[]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn windows_paths_normalized() {
        let mut f = finding("T0", "r", "s");
        f.file = Some("src\\sub\\app.py".to_string());
        let out = render(&[f]);
        assert!(out.contains("src/sub/app.py"));
        assert!(!out.contains("src\\\\sub"));
    }
}

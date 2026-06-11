use crate::scanner::ScanResult;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RedactError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No file to redact")]
    NoFile,
    #[error("No snippet to redact")]
    NoSnippet,
}

/// Apply redaction to the file on disk and re-stage it with `git add`.
///
/// When the finding carries the exact secret text, only that span is replaced
/// — the rest of the line (variable name, assignment, quotes) survives. The
/// whole-snippet replacement remains as a fallback for findings where the
/// layer could not pinpoint the secret.
pub fn apply_redaction(result: &ScanResult) -> Result<(), RedactError> {
    let file_path = result.file.as_deref().ok_or(RedactError::NoFile)?;
    let replacement = result.redacted.as_deref().unwrap_or("PROVN_REDACTED");

    let content = fs::read_to_string(file_path)?;

    let new_content = if let Some(secret) = result.secret.as_deref() {
        content.replacen(secret, replacement, 1)
    } else {
        let snippet = result.snippet.as_deref().ok_or(RedactError::NoSnippet)?;
        let trimmed_snippet = snippet.trim_start_matches(['+', '-', ' ']);
        content.replacen(trimmed_snippet, replacement, 1)
    };

    if new_content == content {
        // Couldn't find exact match — skip
        return Ok(());
    }

    fs::write(file_path, &new_content)?;

    // Re-stage the file
    std::process::Command::new("git")
        .args(["add", file_path])
        .output()
        .ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn result_for(file: &str, secret: Option<&str>, snippet: &str) -> ScanResult {
        ScanResult {
            file: Some(file.to_string()),
            snippet: Some(snippet.to_string()),
            secret: secret.map(|s| s.to_string()),
            redacted: Some("PROVN_REDACTED_TEST".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn span_precise_redaction_preserves_line_structure() {
        let dir = std::env::temp_dir().join(format!("provn-redact-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.py");
        let secret = concat!("sk-proj-abcdefghijklm", "nopqrstuvwxyz123456"); // provn:allow
        let line = format!("api_key = \"{secret}\"");
        fs::write(&path, &line).unwrap();

        let r = result_for(path.to_str().unwrap(), Some(secret), &line);
        apply_redaction(&r).unwrap();

        let redacted = fs::read_to_string(&path).unwrap();
        assert_eq!(redacted, "api_key = \"PROVN_REDACTED_TEST\"");
        assert!(!redacted.contains("sk-proj"), "secret must be gone");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn redacted_output_never_contains_secret() {
        let dir = std::env::temp_dir().join(format!("provn-redact2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.env");
        let secret = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn"; // provn:allow
        fs::write(&path, format!("TOKEN={secret}\nOTHER=ok\n")).unwrap();

        let r = result_for(path.to_str().unwrap(), Some(secret), "");
        apply_redaction(&r).unwrap();

        let out = fs::read_to_string(&path).unwrap();
        assert!(!out.contains(secret));
        assert!(out.contains("OTHER=ok"), "unrelated lines must survive");

        fs::remove_dir_all(&dir).ok();
    }
}

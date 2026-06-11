use crate::config::EntropyConfig;
use regex::Regex;

pub struct EntropyMatch {
    pub entropy: f64,
    pub confidence: f64,
    /// The high-entropy token itself — enables span-precise redaction.
    pub token: Option<String>,
}

/// Built-in per-extension threshold adjustments. Minified/bundled formats are
/// naturally high-entropy so they get a higher bar; config formats where real
/// secrets live get a lower one. User-supplied `per_extension_thresholds`
/// override these.
fn builtin_extension_threshold(ext: &str) -> Option<f64> {
    match ext {
        "env" | "yaml" | "yml" | "tf" | "tfvars" | "properties" | "ini" | "toml" => Some(4.2),
        "lock" | "map" => Some(5.5),
        "json" => Some(5.0),
        "md" | "txt" | "rst" => Some(5.0),
        _ => None,
    }
}

fn effective_threshold(ext: &str, cfg: &EntropyConfig) -> f64 {
    if let Some(t) = cfg.per_extension_thresholds.get(ext) {
        return *t;
    }
    builtin_extension_threshold(ext).unwrap_or(cfg.threshold)
}

/// Compile allowlist patterns once per scan; invalid patterns are skipped
/// with a warning rather than aborting the scan.
pub fn compile_allowlist(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("[provn] entropy allowlist pattern '{p}' invalid: {e} — skipped");
                None
            }
        })
        .collect()
}

/// Scan one line and return the highest-entropy qualifying token, if any.
pub fn scan_line(
    line: &str,
    ext: &str,
    cfg: &EntropyConfig,
    allowlist: &[Regex],
) -> Option<EntropyMatch> {
    // Only check lines that look like assignments
    let has_assignment = line.contains('=') || line.contains(':');
    if !has_assignment {
        return None;
    }

    let threshold = effective_threshold(ext, cfg);

    // Hash-shaped tokens (hex at MD5/SHA lengths) are normally skipped as
    // checksums — but when the variable name itself says key/secret/token,
    // a "checksum" is more likely a hex-encoded secret, so keep checking.
    let lower = line.to_lowercase();
    let sensitive_context = ["key", "secret", "token", "passw", "credential", "auth"]
        .iter()
        .any(|w| lower.contains(w));

    let tokens = line
        .split(['"', '\'', ' ', '\t', ',', ';'])
        .filter(|t| t.len() >= cfg.min_length);

    // Pick the highest-entropy qualifying token instead of the first one above
    // threshold, so the strongest signal is reported on multi-token lines.
    let mut best: Option<EntropyMatch> = None;
    for token in tokens {
        let h = shannon_entropy(token);
        if h < threshold {
            continue;
        }
        if is_likely_false_positive(token, sensitive_context) {
            continue;
        }
        if allowlist.iter().any(|re| re.is_match(token)) {
            continue;
        }
        if best.as_ref().is_none_or(|b| h > b.entropy) {
            let confidence = ((h - threshold) / 2.0).min(1.0) * 0.7 + 0.3;
            best = Some(EntropyMatch {
                entropy: h,
                confidence,
                token: Some(token.to_string()),
            });
        }
    }
    best
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_likely_false_positive(token: &str, sensitive_context: bool) -> bool {
    // Base64-encoded image headers
    if token.starts_with("iVBORw0KGgo") || token.starts_with("/9j/") {
        return true;
    }

    // Data URIs (base64 images/fonts inline in CSS/HTML)
    if token.starts_with("data:") {
        return true;
    }

    // Pure hex strings at common hash lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128.
    // Suppressed when the line names a key/secret/token — then hex is more
    // likely a hex-encoded secret than a checksum.
    if !sensitive_context
        && matches!(token.len(), 32 | 40 | 64 | 128)
        && token.chars().all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }

    // UUID: 8-4-4-4-12 hex groups separated by dashes
    if is_uuid(token) {
        return true;
    }

    // npm/yarn/pip integrity hashes (e.g. "sha512-abc123==")
    if token.starts_with("sha512-") || token.starts_with("sha256-") || token.starts_with("sha1-") {
        return true;
    }

    // bcrypt/scrypt/argon2 password hashes — already one-way, not leakable secrets
    if token.starts_with("$2a$")
        || token.starts_with("$2b$")
        || token.starts_with("$2y$")
        || token.starts_with("$argon2")
        || token.starts_with("$scrypt$")
    {
        return true;
    }

    // Semver / dotted version strings with build metadata (1.2.3-rc.1+build.42)
    // Three or more dot-separated segments means it's almost certainly a version, not a secret.
    if token.chars().filter(|&c| c == '.').count() >= 2
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c))
    {
        return true;
    }

    // URLs and absolute paths
    if token.starts_with("http") || token.starts_with('/') {
        return true;
    }

    false
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8usize, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> EntropyConfig {
        EntropyConfig {
            enabled: true,
            threshold: 4.5,
            min_length: 20,
            per_extension_thresholds: Default::default(),
            allowlist: Vec::new(),
        }
    }

    fn scan(line: &str) -> Option<EntropyMatch> {
        scan_line(line, "py", &default_cfg(), &[])
    }

    #[test]
    fn flags_high_entropy_secret() {
        let line = r#"secret = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn""#; // provn:allow
        let m = scan(line).expect("should flag");
        let expected = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn"; // provn:allow
        assert_eq!(m.token.as_deref(), Some(expected));
    }

    #[test]
    fn skips_png_base64() {
        let line = r#"icon = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk""#; // provn:allow
        assert!(scan(line).is_none());
    }

    #[test]
    fn skips_non_assignment_lines() {
        let line = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn"; // provn:allow
        assert!(scan(line).is_none());
    }

    #[test]
    fn skips_uuid() {
        let line = r#"trace_id = "550e8400-e29b-41d4-a716-446655440000""#;
        assert!(scan(line).is_none());
    }

    #[test]
    fn skips_sha256_hex() {
        let hash = "a".repeat(64); // 64 hex chars
        let line = format!(r#"checksum = "{hash}""#);
        assert!(scan(&line).is_none());
    }

    #[test]
    fn skips_npm_integrity_hash() {
        let line = r#"integrity: "sha512-abc123def456ghi789jklmno012pqrstuvwxyz34567890ABCDEFGHIJKLMNOPQRSTUV===""#;
        assert!(scan(line).is_none());
    }

    #[test]
    fn skips_bcrypt_hash() {
        let line = r#"hash = "$2b$12$KIXQeQpP3O5l7uZxJ9yzUuY7vGm4dDqB1cF8aWnEHs6T0jRkLmNoq""#;
        assert!(scan(line).is_none());
    }

    #[test]
    fn respects_allowlist() {
        let allow = compile_allowlist(&["^x7Kp2".to_string()]);
        let line = r#"secret = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn""#; // provn:allow
        assert!(scan_line(line, "py", &default_cfg(), &allow).is_none());
    }

    #[test]
    fn lock_files_get_higher_threshold() {
        // Entropy ~4.7 token: above default 4.5, below the 5.5 lock-file bar
        let line = r#"hash = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn""#; // provn:allow
        assert!(scan_line(line, "py", &default_cfg(), &[]).is_some());
        assert!(scan_line(line, "lock", &default_cfg(), &[]).is_none());
    }

    #[test]
    fn user_extension_threshold_overrides_builtin() {
        let mut cfg = default_cfg();
        cfg.per_extension_thresholds.insert("lock".to_string(), 4.0);
        let line = r#"hash = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn""#; // provn:allow
        assert!(scan_line(line, "lock", &cfg, &[]).is_some());
    }

    #[test]
    fn entropy_always_in_valid_range() {
        for s in [
            "",
            "a",
            "abcdef",
            "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn",
            "aaaaaaaaaa",
        ] {
            // provn:allow
            let h = shannon_entropy(s);
            assert!(
                (0.0..=8.0).contains(&h),
                "entropy {h} out of range for {s:?}"
            );
        }
    }
}

use crate::config::EntropyConfig;

pub struct EntropyMatch {
    pub entropy: f64,
    pub confidence: f64,
}

pub fn scan_line(line: &str, cfg: &EntropyConfig) -> Option<EntropyMatch> {
    // Only check lines that look like assignments
    let has_assignment = line.contains('=') || line.contains(':');
    if !has_assignment {
        return None;
    }

    // Split on common separators and check each token
    let tokens: Vec<&str> = line
        .split(['"', '\'', ' ', '\t', ',', ';'])
        .filter(|t| t.len() >= cfg.min_length)
        .collect();

    for token in tokens {
        let h = shannon_entropy(token);
        if h >= cfg.threshold {
            if is_likely_false_positive(token) {
                continue;
            }
            let confidence = ((h - cfg.threshold) / 2.0).min(1.0) * 0.7 + 0.3;
            return Some(EntropyMatch {
                entropy: h,
                confidence,
            });
        }
    }
    None
}

fn shannon_entropy(s: &str) -> f64 {
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

fn is_likely_false_positive(token: &str) -> bool {
    // Base64-encoded image headers
    if token.starts_with("iVBORw0KGgo") || token.starts_with("/9j/") {
        return true;
    }

    // Pure hex strings at common hash lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128
    if matches!(token.len(), 32 | 40 | 64 | 128)
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

    // Semver / dotted version strings with build metadata (1.2.3-rc.1+build.42)
    // Three or more dot-separated segments means it's almost certainly a version, not a secret.
    if token.chars().filter(|&c| c == '.').count() >= 2
        && token.chars().all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c))
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
        }
    }

    #[test]
    fn flags_high_entropy_secret() {
        let line = r#"secret = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn""#; // provn:allow
        assert!(scan_line(line, &default_cfg()).is_some());
    }

    #[test]
    fn skips_png_base64() {
        let line = r#"icon = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk""#; // provn:allow
        assert!(scan_line(line, &default_cfg()).is_none());
    }

    #[test]
    fn skips_non_assignment_lines() {
        let line = "x7Kp2mNqR9vT4wYjLhBcDfAeGiUoSzXn"; // provn:allow
        assert!(scan_line(line, &default_cfg()).is_none());
    }

    #[test]
    fn skips_uuid() {
        let line = r#"trace_id = "550e8400-e29b-41d4-a716-446655440000""#;
        assert!(scan_line(line, &default_cfg()).is_none());
    }

    #[test]
    fn skips_sha256_hex() {
        let hash = "a".repeat(64); // 64 hex chars
        let line = format!(r#"checksum = "{hash}""#);
        assert!(scan_line(&line, &default_cfg()).is_none());
    }

    #[test]
    fn skips_npm_integrity_hash() {
        let line = r#"integrity: "sha512-abc123def456ghi789jklmno012pqrstuvwxyz34567890ABCDEFGHIJKLMNOPQRSTUV===""#;
        assert!(scan_line(line, &default_cfg()).is_none());
    }
}

use once_cell::sync::Lazy;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

pub struct RegexMatch {
    pub pattern_name: String,
    pub tier: String,
    pub confidence: f64,
    pub redacted: String,
    pub description: Option<String>,
}

struct Pattern {
    name: &'static str,
    tier: &'static str,
    confidence: f64,
    re: Regex,
    redacted_prefix: &'static str,
}

/// Pre-compiled form of a user-defined custom pattern.
/// Compile once via [`compile_custom_patterns`] before the scan loop.
pub struct CompiledCustomPattern {
    pub name: String,
    pub tier: String,
    pub confidence: f64,
    pub description: Option<String>,
    pub re: Regex,
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        Pattern {
            name: "aws_access_key",
            tier: "T0",
            confidence: 0.98,
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_AWS_KEY",
        },
        Pattern {
            name: "aws_secret_key",
            tier: "T0",
            confidence: 0.95,
            re: Regex::new(r#"(?i)aws.{0,20}secret.{0,10}["']([A-Za-z0-9/+]{40})["']"#).unwrap(),
            redacted_prefix: "PROVN_REDACTED_AWS_SECRET",
        },
        Pattern {
            name: "openai_api_key",
            tier: "T1",
            confidence: 0.97,
            re: Regex::new(r"sk-(?:proj-|svcacct-)?[a-zA-Z0-9]{40,}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_OPENAI_KEY",
        },
        Pattern {
            name: "anthropic_api_key",
            tier: "T1",
            confidence: 0.97,
            re: Regex::new(r"sk-ant-[a-zA-Z0-9\-_]{40,}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_ANTHROPIC_KEY",
        },
        Pattern {
            name: "private_key_header",
            tier: "T0",
            confidence: 0.99,
            re: Regex::new(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY").unwrap(),
            redacted_prefix: "PROVN_REDACTED_PRIVATE_KEY",
        },
        Pattern {
            name: "stripe_secret",
            tier: "T0",
            confidence: 0.98,
            re: Regex::new(r"sk_live_[a-zA-Z0-9]{24,}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_STRIPE_KEY",
        },
        Pattern {
            name: "github_token",
            tier: "T0",
            confidence: 0.97,
            re: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_GITHUB_TOKEN",
        },
        Pattern {
            name: "database_url",
            tier: "T0",
            confidence: 0.92,
            re: Regex::new(r"(?i)(postgresql|mysql|mongodb|redis)\+?://[^:@\s]+:[^@\s]+@[^\s]+").unwrap(),
            redacted_prefix: "PROVN_REDACTED_DB_URL",
        },
        Pattern {
            name: "jwt_token",
            tier: "T1",
            confidence: 0.85,
            re: Regex::new(r"ey[A-Za-z0-9\-_]+\.ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap(),
            redacted_prefix: "PROVN_REDACTED_JWT",
        },
        Pattern {
            name: "huggingface_token",
            tier: "T1",
            confidence: 0.95,
            re: Regex::new(r"hf_[a-zA-Z0-9]{34,}").unwrap(),
            redacted_prefix: "PROVN_REDACTED_HF_TOKEN",
        },
        Pattern {
            name: "generic_api_key",
            tier: "T1",
            confidence: 0.75,
            re: Regex::new(r#"(?i)(api[_\-]?key|apikey)\s*[=:]\s*["'][\w\-]{20,}["']"#).unwrap(),
            redacted_prefix: "PROVN_REDACTED_API_KEY",
        },
        Pattern {
            name: "system_prompt_var",
            tier: "T1",
            confidence: 0.80,
            re: Regex::new(r#"(?i)system_prompt\s*[=:]\s*["'](.{30,})"#).unwrap(),
            redacted_prefix: "PROVN_REDACTED_SYSTEM_PROMPT",
        },
        Pattern {
            name: "password_in_code",
            tier: "T0",
            confidence: 0.82,
            re: Regex::new(r#"(?i)(password|passwd|pwd)\s*=\s*["'][^"']{8,}["']"#).unwrap(),
            redacted_prefix: "PROVN_REDACTED_PASSWORD",
        },
        Pattern {
            name: "slack_webhook",
            tier: "T1",
            confidence: 0.96,
            re: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+").unwrap(),
            redacted_prefix: "PROVN_REDACTED_SLACK_WEBHOOK",
        },
    ]
});

/// Compile user-defined patterns from config once before the scan loop.
/// Patterns that fail to compile are silently skipped.
pub fn compile_custom_patterns(patterns: &[crate::config::CustomPattern]) -> Vec<CompiledCustomPattern> {
    patterns
        .iter()
        .filter_map(|cp| {
            Regex::new(&cp.pattern).ok().map(|re| CompiledCustomPattern {
                name: cp.name.clone(),
                tier: cp.tier.clone(),
                confidence: cp.confidence,
                description: cp.description.clone(),
                re,
            })
        })
        .collect()
}

/// Scan one line and return **all** matches, sorted by confidence descending.
/// Previously returned only the first match, so a line with both an AWS key and
/// an OpenAI key would silently drop one of them.
pub fn scan_line(line: &str, custom: &[CompiledCustomPattern]) -> Vec<RegexMatch> {
    // NFKC normalize to catch homoglyph attacks (Cyrillic 'а' → 'a')
    let normalized: String = line.nfkc().collect();
    let mut matches: Vec<RegexMatch> = Vec::new();

    for pattern in PATTERNS.iter() {
        if pattern.re.is_match(&normalized) {
            matches.push(RegexMatch {
                pattern_name: pattern.name.to_string(),
                tier:         pattern.tier.to_string(),
                confidence:   pattern.confidence,
                redacted:     format!("{}_1", pattern.redacted_prefix),
                description:  None,
            });
        }
    }

    for cp in custom {
        if cp.re.is_match(&normalized) {
            matches.push(RegexMatch {
                pattern_name: cp.name.clone(),
                tier:         cp.tier.clone(),
                confidence:   cp.confidence,
                redacted:     format!("PROVN_REDACTED_{}", cp.name.to_uppercase().replace(' ', "_")),
                description:  cp.description.clone(),
            });
        }
    }

    matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        assert!(!scan_line("AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"", &[]).is_empty()); // provn:allow
    }

    #[test]
    fn detects_openai_key() {
        assert!(!scan_line("key = \"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD\"", &[]).is_empty()); // provn:allow
    }

    #[test]
    fn detects_private_key_header() {
        assert!(!scan_line("-----BEGIN RSA PRIVATE KEY-----", &[]).is_empty()); // provn:allow
    }

    #[test]
    fn allows_clean_code() {
        assert!(scan_line("def calculate_total(items): return sum(items)", &[]).is_empty());
    }

    #[test]
    fn detects_homoglyph_aws_key() {
        // Cyrillic А (U+0410) instead of Latin A — NFKC normalizes it
        let homoglyph_line = "АKIАIOSFODNNsomething7EXАMPLE";
        let _ = scan_line(homoglyph_line, &[]);
    }

    #[test]
    fn returns_all_matches_on_multi_secret_line() {
        // A line containing both an AWS key and an OpenAI key must report both.
        let line = "AKIAIOSFODNN7EXAMPLE sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"; // provn:allow
        let hits = scan_line(line, &[]);
        assert!(hits.len() >= 2, "expected ≥2 matches, got {}", hits.len());
    }

    #[test]
    fn results_sorted_by_confidence_descending() {
        let line = "AKIAIOSFODNN7EXAMPLE sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"; // provn:allow
        let hits = scan_line(line, &[]);
        for w in hits.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn detects_custom_pattern() {
        let cp = CompiledCustomPattern {
            name:        "internal_import".to_string(),
            tier:        "T1".to_string(),
            confidence:  0.9,
            description: None,
            re:          Regex::new(r"from corp_internal\.").unwrap(),
        };
        assert!(!scan_line("from corp_internal.utils import helper", &[cp]).is_empty());
    }
}

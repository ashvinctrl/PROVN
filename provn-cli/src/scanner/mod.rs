use crate::config::Config;
use crate::diff::DiffChunk;
use std::time::Instant;

pub mod ast;
pub mod entropy;
pub mod regex_scan;
pub mod semantic;

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub file: Option<String>,
    pub line: Option<usize>,
    pub match_type: Option<String>,
    pub description: Option<String>,
    pub snippet: Option<String>,
    /// Exact secret text when the layer can pinpoint it. Kept in memory for
    /// span-precise redaction only — never written to JSON output or the
    /// audit log.
    pub secret: Option<String>,
    pub redacted: Option<String>,
    pub confidence: f64,
    pub layer: Option<String>,
    pub tier: Option<String>,
    pub latency_ms: u64,
    /// True when Layer 3 was wanted for this finding but the semantic server
    /// was unavailable — recorded in the audit log as `ai_layer: skipped`.
    pub ai_skipped: bool,
}

/// Maximum number of ambiguous candidates forwarded to Layer 3.
/// Capping at 3 bounds worst-case pre-commit latency while still catching
/// multi-secret diffs that the old single-candidate approach would miss.
const MAX_AMBIGUOUS: usize = 3;

/// True when an assigned/captured string is an obvious placeholder rather than a
/// real secret. Shared by the regex and AST layers so documentation and template
/// forms — `api_key = "your-api-key-here"`, `password = "<YOUR_PASSWORD>"`,
/// `token = "${GITHUB_TOKEN}"` — don't get reported as leaks.
pub(crate) fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.starts_with("test_")
        || value.starts_with("fake_")
        || lower.starts_with("placeholder")
        || value.starts_with("${") // ${VAR} shell/template interpolation
        || value.starts_with("{{") // {{ jinja/handlebars }}
        || (value.starts_with('<') && value.ends_with('>')) // <YOUR_PASSWORD>
        || (lower.starts_with("your") && lower.ends_with("here")) // your-api-key-here / your_api_key_here
        || lower == "changeme"
        || lower == "xxx"
}

/// Scan a single in-memory code snippet as if it were an added file of the
/// given extension. Lets callers that hold raw source (the benchmark, tests)
/// reuse the exact pipeline `scan`/`check` run instead of reimplementing it.
/// Layer 3 honours `cfg` like any other scan, so pass a config with semantic
/// disabled for a deterministic, offline run.
pub fn scan_snippet(code: &str, extension: &str, cfg: &Config) -> Vec<ScanResult> {
    let added_lines: Vec<(usize, String)> = code
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.to_string()))
        .collect();
    let chunk = DiffChunk {
        file: std::path::PathBuf::from(format!("snippet.{extension}")),
        extension: extension.to_string(),
        added_lines,
    };
    scan_chunks(&[chunk], cfg)
}

/// Scan all chunks and return every finding, sorted by confidence descending.
pub fn scan_chunks(chunks: &[DiffChunk], cfg: &Config) -> Vec<ScanResult> {
    let start = Instant::now();

    // Build the full pattern set (built-in or runtime override + custom)
    // once before the scan loop to avoid recompiling per line.
    let pattern_set = regex_scan::build_pattern_set(&cfg.layers.regex);
    let entropy_allowlist = entropy::compile_allowlist(&cfg.layers.entropy.allowlist);

    let mut confirmed: Vec<ScanResult> = Vec::new();
    let mut ambiguous: Vec<ScanResult> = Vec::new(); // top-N by confidence

    for chunk in chunks {
        for (line_num, line_content) in &chunk.added_lines {
            // ── Layer 1a: regex — all matches on this line ───────────────────
            if cfg.layers.regex.enabled {
                for m in regex_scan::scan_line(line_content, &pattern_set) {
                    let conf = m.confidence;
                    let r = ScanResult {
                        file: Some(chunk.file.to_string_lossy().into_owned()),
                        line: Some(*line_num),
                        match_type: Some(m.pattern_name.clone()),
                        description: Some(
                            m.description
                                .unwrap_or_else(|| format!("Matched pattern: {}", m.pattern_name)),
                        ),
                        snippet: Some(line_content.chars().take(120).collect()),
                        secret: m.secret,
                        redacted: Some(m.redacted),
                        confidence: conf,
                        layer: Some("regex".to_string()),
                        tier: Some(m.tier),
                        latency_ms: 0,
                        ai_skipped: false,
                    };
                    if conf >= cfg.layers.semantic.ambiguous_high {
                        confirmed.push(r);
                    } else {
                        add_ambiguous(&mut ambiguous, r);
                    }
                }
            }

            // ── Layer 1b: entropy ────────────────────────────────────────────
            if cfg.layers.entropy.enabled {
                if let Some(m) = entropy::scan_line(
                    line_content,
                    &chunk.extension,
                    &cfg.layers.entropy,
                    &entropy_allowlist,
                ) {
                    let conf = m.confidence;
                    let r = ScanResult {
                        file: Some(chunk.file.to_string_lossy().into_owned()),
                        line: Some(*line_num),
                        match_type: Some("high_entropy".to_string()),
                        description: Some(format!("High entropy token (H={:.2})", m.entropy)),
                        snippet: Some(line_content.chars().take(120).collect()),
                        secret: m.token.clone(),
                        redacted: Some("PROVN_REDACTED_HIGH_ENTROPY".to_string()),
                        confidence: conf,
                        layer: Some("entropy".to_string()),
                        tier: Some("T2".to_string()),
                        latency_ms: 0,
                        ai_skipped: false,
                    };
                    if conf >= cfg.layers.semantic.ambiguous_high {
                        confirmed.push(r);
                    } else {
                        add_ambiguous(&mut ambiguous, r);
                    }
                }
            }
        }

        // ── Layer 2: AST — all sensitive assignments in this file ────────────
        if cfg.layers.ast.enabled {
            let src: String = chunk
                .added_lines
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");

            let lang = match chunk.extension.as_str() {
                "py" => Some("python"),
                "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
                "ts" | "mts" | "cts" => Some("typescript"),
                "tsx" => Some("tsx"),
                _ => None,
            };

            if let Some(lang) = lang {
                for m in ast::scan_source(&src, lang, &cfg.layers.ast) {
                    let conf = m.confidence;
                    // m.line is the row in the joined added-lines source —
                    // map it back to the real file line number.
                    let real_line = chunk
                        .added_lines
                        .get(m.line.saturating_sub(1))
                        .map(|(n, _)| *n)
                        .unwrap_or(m.line);
                    let r = ScanResult {
                        file: Some(chunk.file.to_string_lossy().into_owned()),
                        line: Some(real_line),
                        match_type: Some("ast_taint".to_string()),
                        description: Some(format!(
                            "Sensitive variable '{}' assigned string literal",
                            m.var_name
                        )),
                        snippet: Some(m.snippet.chars().take(120).collect()),
                        secret: m.value.clone(),
                        redacted: Some(format!("PROVN_REDACTED_{}", m.var_name.to_uppercase())),
                        confidence: conf,
                        layer: Some("ast".to_string()),
                        tier: Some("T1".to_string()),
                        latency_ms: 0,
                        ai_skipped: false,
                    };
                    if conf >= cfg.layers.semantic.ambiguous_high {
                        confirmed.push(r);
                    } else {
                        add_ambiguous(&mut ambiguous, r);
                    }
                }
            }
        }
    }

    // ── Layer 3: semantic — fan out to all ambiguous candidates ──────────────
    if !ambiguous.is_empty() {
        let sem_cfg = &cfg.layers.semantic;
        let ready = sem_cfg.enabled && !sem_cfg.model.trim().is_empty();

        if ready {
            let endpoint = sem_cfg.endpoint.clone();
            let timeout_ms = sem_cfg.timeout_ms;
            let lo = sem_cfg.ambiguous_low;
            let hi = sem_cfg.ambiguous_high;
            let fallback = sem_cfg.fallback.clone();

            let handles: Vec<_> = ambiguous
                .into_iter()
                .map(|cand| {
                    let ep = endpoint.clone();
                    let fb = fallback.clone();
                    std::thread::spawn(move || -> Option<ScanResult> {
                        let conf = cand.confidence;
                        if conf >= lo && conf < hi {
                            let code = cand.snippet.as_deref().unwrap_or("").to_string();
                            let sem = semantic::classify(&code, &ep, timeout_ms);
                            if sem.skipped {
                                if fb != "clean" {
                                    let mut c = cand;
                                    c.ai_skipped = true;
                                    Some(c)
                                } else {
                                    None
                                }
                            } else if sem.label == "leak" {
                                let mut c = cand;
                                c.confidence = 0.85;
                                c.layer = Some("semantic".to_string());
                                Some(c)
                            } else {
                                None // L3 cleared it
                            }
                        } else if conf >= lo {
                            Some(cand) // above band — include as-is
                        } else {
                            None
                        }
                    })
                })
                .collect();

            for handle in handles {
                if let Ok(Some(r)) = handle.join() {
                    confirmed.push(r);
                }
            }
        } else {
            // L3 not configured — include any candidate above the low threshold
            for cand in ambiguous {
                if cand.confidence >= sem_cfg.ambiguous_low {
                    confirmed.push(cand);
                }
            }
        }
    }

    confirmed.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let elapsed = start.elapsed().as_millis() as u64;
    for r in &mut confirmed {
        r.latency_ms = elapsed;
    }
    confirmed
}

/// Keep the top [`MAX_AMBIGUOUS`] candidates by confidence.
fn add_ambiguous(pool: &mut Vec<ScanResult>, new: ScanResult) {
    if pool.len() < MAX_AMBIGUOUS {
        pool.push(new);
        pool.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    } else if pool.last().is_some_and(|w| new.confidence > w.confidence) {
        *pool.last_mut().unwrap() = new;
        pool.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::is_placeholder_value;

    #[test]
    fn flags_placeholders() {
        for v in [
            "your-api-key-here",
            "your_api_key_here",
            "<YOUR_PASSWORD>",
            "${GITHUB_TOKEN}",
            "{{ secret }}",
            "test_key_placeholder",
            "fake_secret_value",
            "placeholder_value",
            "changeme",
            "xxx",
        ] {
            assert!(is_placeholder_value(v), "should be a placeholder: {v}");
        }
    }

    #[test]
    fn keeps_real_secrets() {
        for v in [
            "AKIAIOSFODNN7EXAMPLE",
            "sk_live_EXAMPLE0123456789abcdef",
            "Pr0dDbP@ssw0rd2025",
            "ghp_FAKE0123456789abcdefABCDEFghijklMN",
        ] {
            assert!(!is_placeholder_value(v), "should not be a placeholder: {v}");
        }
    }
}

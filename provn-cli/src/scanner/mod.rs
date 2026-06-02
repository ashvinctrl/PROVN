use std::time::Instant;
use crate::config::Config;
use crate::diff::DiffChunk;

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
    pub redacted: Option<String>,
    pub confidence: f64,
    pub layer: Option<String>,
    pub tier: Option<String>,
    pub latency_ms: u64,
}

/// Maximum number of ambiguous candidates forwarded to Layer 3.
/// Capping at 3 bounds worst-case pre-commit latency while still catching
/// multi-secret diffs that the old single-candidate approach would miss.
const MAX_AMBIGUOUS: usize = 3;

/// Scan all chunks and return every finding, sorted by confidence descending.
pub fn scan_chunks(chunks: &[DiffChunk], cfg: &Config) -> Vec<ScanResult> {
    let start = Instant::now();

    // Compile user-defined patterns once before the scan loop to avoid
    // recompiling the same regex on every line of the diff.
    let compiled_custom = regex_scan::compile_custom_patterns(&cfg.layers.regex.custom_patterns);

    let mut confirmed: Vec<ScanResult> = Vec::new();
    let mut ambiguous: Vec<ScanResult> = Vec::new(); // top-N by confidence

    for chunk in chunks {
        for (line_num, line_content) in &chunk.added_lines {
            // ── Layer 1a: regex — all matches on this line ───────────────────
            if cfg.layers.regex.enabled {
                for m in regex_scan::scan_line(line_content, &compiled_custom) {
                    let conf = m.confidence;
                    let r = ScanResult {
                        file:        Some(chunk.file.to_string_lossy().into_owned()),
                        line:        Some(*line_num),
                        match_type:  Some(m.pattern_name.clone()),
                        description: Some(
                            m.description.unwrap_or_else(|| {
                                format!("Matched pattern: {}", m.pattern_name)
                            }),
                        ),
                        snippet:     Some(line_content.chars().take(120).collect()),
                        redacted:    Some(m.redacted),
                        confidence:  conf,
                        layer:       Some("regex".to_string()),
                        tier:        Some(m.tier),
                        latency_ms:  0,
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
                if let Some(m) = entropy::scan_line(line_content, &cfg.layers.entropy) {
                    let conf = m.confidence;
                    let r = ScanResult {
                        file:        Some(chunk.file.to_string_lossy().into_owned()),
                        line:        Some(*line_num),
                        match_type:  Some("high_entropy".to_string()),
                        description: Some(format!("High entropy token (H={:.2})", m.entropy)),
                        snippet:     Some(line_content.chars().take(120).collect()),
                        redacted:    Some("PROVN_REDACTED_HIGH_ENTROPY".to_string()),
                        confidence:  conf,
                        layer:       Some("entropy".to_string()),
                        tier:        Some("T2".to_string()),
                        latency_ms:  0,
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
                "py"                                  => Some("python"),
                "ts" | "tsx" | "js" | "jsx" | "mjs" => Some("javascript"),
                _                                     => None,
            };

            if let Some(lang) = lang {
                for m in ast::scan_source(&src, lang, &cfg.layers.ast) {
                    let conf = m.confidence;
                    let r = ScanResult {
                        file:        Some(chunk.file.to_string_lossy().into_owned()),
                        line:        Some(m.line),
                        match_type:  Some("ast_taint".to_string()),
                        description: Some(format!(
                            "Sensitive variable '{}' assigned string literal",
                            m.var_name
                        )),
                        snippet:     Some(m.snippet.chars().take(120).collect()),
                        redacted:    Some(format!("PROVN_REDACTED_{}", m.var_name.to_uppercase())),
                        confidence:  conf,
                        layer:       Some("ast".to_string()),
                        tier:        Some("T1".to_string()),
                        latency_ms:  0,
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
            let endpoint    = sem_cfg.endpoint.clone();
            let timeout_ms  = sem_cfg.timeout_ms;
            let lo          = sem_cfg.ambiguous_low;
            let hi          = sem_cfg.ambiguous_high;
            let fallback    = sem_cfg.fallback.clone();

            let handles: Vec<_> = ambiguous
                .into_iter()
                .map(|cand| {
                    let ep  = endpoint.clone();
                    let fb  = fallback.clone();
                    std::thread::spawn(move || -> Option<ScanResult> {
                        let conf = cand.confidence;
                        if conf >= lo && conf < hi {
                            let code = cand.snippet.as_deref().unwrap_or("").to_string();
                            let sem  = semantic::classify(&code, &ep, timeout_ms);
                            if sem.skipped {
                                if fb != "clean" { Some(cand) } else { None }
                            } else if sem.label == "leak" {
                                let mut c    = cand;
                                c.confidence = 0.85;
                                c.layer      = Some("semantic".to_string());
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
    } else if pool.last().map_or(false, |w| new.confidence > w.confidence) {
        *pool.last_mut().unwrap() = new;
        pool.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}

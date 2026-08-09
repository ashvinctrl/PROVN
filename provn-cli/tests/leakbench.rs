//! LeakBench regression gate.
//!
//! Runs the shipped `provn bench` command over the committed corpus and asserts
//! the deterministic (Layer 1+2, offline) detection metrics stay within bounds.
//! The thresholds carry margin below/above the values measured when the corpus
//! was last refreshed, so the gate catches a real regression (recall drop, false
//! positive spike) without breaking when the detector legitimately improves.
//!
//! Update the comment with new measured values — never the assertions to chase a
//! regression — if a change moves the numbers.

use std::process::Command;

const ADVERSARIAL: &str = "tests/corpus/leakbench.jsonl";
const REALISTIC: &str = "tests/corpus/realistic.jsonl";

fn run_bench(corpus: &str) -> serde_json::Value {
    // Cargo points this at the freshly built binary for this package.
    let bin = env!("CARGO_BIN_EXE_provn");
    let output = Command::new(bin)
        .args(["bench", corpus, "--json"])
        .output()
        .expect("failed to run `provn bench`");
    assert!(
        output.status.success(),
        "bench exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "bench did not emit valid JSON: {e}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn f(v: &serde_json::Value, key: &str) -> f64 {
    v[key]
        .as_f64()
        .unwrap_or_else(|| panic!("missing numeric field `{key}` in bench output"))
}

fn u(v: &serde_json::Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing integer field `{key}` in bench output"))
}

#[test]
fn corpora_load_cleanly() {
    // Every line must parse and carry a valid label — a malformed corpus would
    // silently shrink the denominator and inflate the rates.
    for (corpus, min_samples) in [(ADVERSARIAL, 220), (REALISTIC, 90)] {
        let r = run_bench(corpus);
        assert_eq!(u(&r, "skipped"), 0, "{corpus}: unparseable/unlabeled lines");
        assert!(
            u(&r, "samples") >= min_samples,
            "{corpus}: unexpectedly small ({})",
            u(&r, "samples")
        );
        assert_eq!(
            u(&r, "leaks") + u(&r, "clean"),
            u(&r, "samples"),
            "{corpus}: leak + clean must equal total samples"
        );
    }
}

#[test]
fn adversarial_corpus_metrics_hold() {
    // The adversarial LeakBench (also the Layer 3 training set). Measured
    // 2026-08-09 after adding the proprietary-IP content detectors
    // (confidentiality notices/keywords, prompt-secrecy instructions, private
    // data paths, safety-control overrides, internal identifiers, training
    // config): precision 98.8%, FPR 0.96% (1/104), secret recall 67.3% (33/49),
    // IP recall 68.4% (52/76, up from 30.3% — the previous set only found
    // *locations*, via object-storage URIs and internal hostnames; these find
    // marked-confidential content and prompt/model material too). The remaining
    // IP misses are unmarked proprietary algorithms, which stay a Layer 3 job.
    // FPR and precision are the load-bearing gates.
    let r = run_bench(ADVERSARIAL);
    assert!(
        f(&r, "fpr") <= 0.02,
        "adversarial FPR regressed to {:.1}% (gate: <=2%)",
        f(&r, "fpr") * 100.0
    );
    assert!(
        f(&r, "precision") >= 0.95,
        "adversarial precision regressed to {:.1}% (gate: >=95%)",
        f(&r, "precision") * 100.0
    );
    assert!(
        f(&r, "secret_recall") >= 0.60,
        "adversarial secret recall regressed to {:.1}% (gate: >=60%)",
        f(&r, "secret_recall") * 100.0
    );
    // Lock in the IP-detector gain (measured 68.4%) with margin, so dropping or
    // over-narrowing any of the IP rules is caught rather than quietly halving
    // the number the product is actually sold on.
    assert!(
        f(&r, "ip_recall") >= 0.60,
        "adversarial IP recall regressed to {:.1}% (gate: >=60%)",
        f(&r, "ip_recall") * 100.0
    );
}

/// Latency gate.
///
/// PROJECT.md targets p50 < 120 ms / p95 < 200 ms for a scan, and the README
/// quotes single-digit milliseconds — but until now nothing failed when that
/// stopped being true. `provn bench` already reports per-snippet percentiles,
/// so this asserts on them directly.
///
/// The bounds are deliberately far above the measured values (p50 ~0.6-0.8 ms,
/// p95 ~1.0 ms on a 2026 laptop) because CI runners are shared and noisy: the
/// gate exists to catch an order-of-magnitude regression — a catastrophically
/// backtracking regex, or per-line pattern recompilation — not to police jitter.
#[test]
fn scan_latency_stays_within_budget() {
    for corpus in [ADVERSARIAL, REALISTIC] {
        let r = run_bench(corpus);
        let p50 = f(&r, "p50_ms");
        let p95 = f(&r, "p95_ms");
        assert!(
            p50 <= 20.0,
            "{corpus}: p50 regressed to {p50:.2}ms (gate: <=20ms, measured ~0.7ms)"
        );
        assert!(
            p95 <= 50.0,
            "{corpus}: p95 regressed to {p95:.2}ms (gate: <=50ms, measured ~1.0ms)"
        );
    }
}

#[test]
fn realistic_corpus_metrics_hold() {
    // Real-format secrets + secret-adjacent clean code — the representative
    // real-world signal. Measured 2026-06-28 after adding the 18 new-provider
    // fixtures (Terraform/Databricks/Doppler/Grafana/DockerHub/RubyGems/Stripe
    // webhook/Slack app/Postman/Linear/Notion/Atlassian/New Relic/Datadog/
    // PlanetScale/Supabase/Google OAuth/age): secret recall 100% (48/48),
    // precision 100%, FPR 0% (0/46).
    let r = run_bench(REALISTIC);
    assert!(
        u(&r, "secret_total") >= 46,
        "realistic secret subset shrank to {}",
        u(&r, "secret_total")
    );
    assert!(
        f(&r, "secret_recall") >= 0.97,
        "realistic secret recall regressed to {:.1}% (gate: >=97%)",
        f(&r, "secret_recall") * 100.0
    );
    assert!(
        f(&r, "precision") >= 0.97,
        "realistic precision regressed to {:.1}% (gate: >=97%)",
        f(&r, "precision") * 100.0
    );
    assert!(
        f(&r, "fpr") <= 0.02,
        "realistic FPR regressed to {:.1}% (gate: <=2%)",
        f(&r, "fpr") * 100.0
    );
}

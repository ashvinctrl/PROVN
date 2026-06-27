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
    for (corpus, min_samples) in [(ADVERSARIAL, 220), (REALISTIC, 65)] {
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
    // 2026-06-27: precision 97.9%, FPR 0.96% (1/104), secret recall 65.3%
    // (32/49). Low overall recall is expected — most leaks are semantic IP that
    // needs Layer 3. FPR and precision are the load-bearing gates here.
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
}

#[test]
fn realistic_corpus_metrics_hold() {
    // Real-format secrets + secret-adjacent clean code — the representative
    // real-world signal. Measured 2026-06-27 after the placeholder, connection
    // string, and credential-key-name fixes: secret recall 100% (30/30),
    // precision 100%, FPR 0% (0/40).
    let r = run_bench(REALISTIC);
    assert!(
        u(&r, "secret_total") >= 28,
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

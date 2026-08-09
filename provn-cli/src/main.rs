use clap::{Parser, Subcommand};
use std::process;

mod audit;
mod baseline;
mod config;
mod diff;
mod model;
mod policy;
mod redact;
mod sarif;
mod scanner;

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const RESET: &str = "\x1b[0m";

#[allow(dead_code)]
const _BOLD_CHECK: &str = BOLD; // ensure constants are reachable

macro_rules! dim {
    ($s:expr) => {
        format!("{DIM}{}{RESET}", $s)
    };
}

// ── CLI definition ─────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(
    name = "provn",
    version,
    about = "AI-powered secret & IP leak detection",
    // Suppress default help so bare `provn` shows our dashboard instead
    disable_help_subcommand = true,
    disable_help_flag = true,
)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan staged git changes (pre-commit hook mode)
    Scan {
        /// Exit non-zero on findings at these tiers, never prompt (e.g. --fail-on T0,T1)
        #[arg(long, value_delimiter = ',', value_name = "TIERS")]
        fail_on: Vec<String>,
        /// Redact all blocked findings automatically without prompting
        #[arg(long)]
        auto_redact: bool,
        /// Output findings as JSON lines (one finding per line)
        #[arg(long, short = 'j')]
        json: bool,
        /// Ignore the accepted-findings baseline (report everything)
        #[arg(long)]
        no_baseline: bool,
    },
    /// Scan a file or directory tree for secrets and IP leaks
    Check {
        #[arg(value_name = "PATH")]
        file: String,
        /// Output format: text | json | sarif
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        format: String,
        /// Output results as JSON (shorthand for --format json)
        #[arg(long, short = 'j')]
        json: bool,
        /// Fail only on findings at these tiers (default: fail on any finding)
        #[arg(long, value_delimiter = ',', value_name = "TIERS")]
        fail_on: Vec<String>,
        /// Ignore the accepted-findings baseline (report everything)
        #[arg(long)]
        no_baseline: bool,
    },
    /// Scan the diff between two commits (pre-push hook mode)
    CheckRange {
        /// Old commit SHA (all zeros = new branch, diffs against empty tree)
        old: String,
        /// New commit SHA being pushed
        new: String,
        /// Output format: text | json | sarif
        #[arg(long, value_name = "FORMAT", default_value = "text")]
        format: String,
        /// Output findings as JSON lines
        #[arg(long, short = 'j')]
        json: bool,
        /// Fail only on findings at these tiers (default: fail on any finding)
        #[arg(long, value_delimiter = ',', value_name = "TIERS")]
        fail_on: Vec<String>,
        /// Ignore the accepted-findings baseline (report everything)
        #[arg(long)]
        no_baseline: bool,
    },
    /// Scan git history for secrets introduced in past commits
    ScanHistory {
        /// Limit to the most recent N commits (0 = all reachable from HEAD)
        #[arg(long, default_value_t = 1000)]
        max_commits: usize,
        /// Output findings as JSON lines
        #[arg(long, short = 'j')]
        json: bool,
    },
    /// Accept all current findings into the baseline (.provn/baseline.json)
    Baseline {
        /// Path to scan when building the baseline (default: current directory)
        #[arg(value_name = "PATH", default_value = ".")]
        path: String,
    },
    /// Verify the integrity of the audit log HMAC chain
    VerifyAudit,
    /// Install Provn git hooks in the current repo (pre-commit; --pre-push adds push gate)
    Install {
        /// Also install a pre-push hook that scans every outgoing commit
        #[arg(long)]
        pre_push: bool,
    },
    /// Manage the local Layer 3 semantic inference server
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Download and manage Layer 3 models
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },
    /// Measure detection accuracy against a labeled LeakBench corpus (JSONL)
    Bench {
        /// Path to the corpus JSONL (default: bundled tests/corpus/leakbench.jsonl)
        #[arg(value_name = "CORPUS", default_value = "tests/corpus/leakbench.jsonl")]
        corpus: String,
        /// Output the report as JSON instead of text
        #[arg(long, short = 'j')]
        json: bool,
        /// Extension each snippet is scanned as (sets entropy thresholds + AST language)
        #[arg(long, default_value = "py")]
        ext: String,
    },
}

#[derive(Subcommand)]
enum ModelAction {
    /// Show available Layer 3 models and which are already installed
    List,
    /// Download a Layer 3 model into ~/.provn/models
    Install {
        /// Model id from `provn model list` (default: the open-weights model)
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Re-download even if the file is already present
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the semantic server (auto-starts at login via launchd)
    Start,
    /// Stop the semantic server
    Stop,
    /// Show whether the semantic server is online
    Status,
}

// ── Entry point ────────────────────────────────────────────────────────────────
fn main() {
    let result = std::panic::catch_unwind(run);
    match result {
        Ok(code) => process::exit(code),
        Err(_) => {
            eprintln!("[provn] Unexpected panic — allowing commit");
            process::exit(0);
        }
    }
}

fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        None => cmd_dashboard(),
        Some(Command::Scan {
            fail_on,
            auto_redact,
            json,
            no_baseline,
        }) => cmd_scan(&ScanOpts {
            fail_on,
            auto_redact,
            json,
            no_baseline,
        }),
        Some(Command::Check {
            file,
            format,
            json,
            fail_on,
            no_baseline,
        }) => {
            let fmt = if json { "json" } else { format.as_str() };
            cmd_check(&file, fmt, &fail_on, no_baseline)
        }
        Some(Command::CheckRange {
            old,
            new,
            format,
            json,
            fail_on,
            no_baseline,
        }) => {
            let fmt = if json { "json" } else { format.as_str() };
            cmd_check_range(&old, &new, fmt, &fail_on, no_baseline)
        }
        Some(Command::ScanHistory { max_commits, json }) => cmd_scan_history(max_commits, json),
        Some(Command::Baseline { path }) => cmd_baseline(&path),
        Some(Command::VerifyAudit) => cmd_verify_audit(),
        Some(Command::Install { pre_push }) => cmd_install(pre_push),
        Some(Command::Server { action }) => cmd_server(action),
        Some(Command::Model { action }) => cmd_model(action),
        Some(Command::Bench { corpus, json, ext }) => cmd_bench(&corpus, json, &ext),
    }
}

struct ScanOpts {
    fail_on: Vec<String>,
    auto_redact: bool,
    json: bool,
    no_baseline: bool,
}

/// Exit-code policy for the report-only commands (`check`, `check-range`).
///
/// With no `--fail-on`, any surviving finding fails — the default a pre-push
/// gate wants. With `--fail-on T0,T1`, only findings at those tiers fail, so a
/// pipeline can surface T2 entropy noise without going red on it. This is a
/// filter, unlike `scan --fail-on`, which additionally suppresses prompting and
/// leaves policy blocks failing regardless.
fn fails_build(findings: &[scanner::ScanResult], fail_on: &[String]) -> bool {
    if findings.is_empty() {
        return false;
    }
    if fail_on.is_empty() {
        return true;
    }
    findings.iter().any(|f| {
        f.tier
            .as_deref()
            .is_some_and(|t| fail_on.iter().any(|w| w.eq_ignore_ascii_case(t)))
    })
}

/// Load the baseline unless suppression is disabled. A missing/invalid baseline
/// yields an empty one (fail-open for *suppression* only — never hides findings
/// silently on error; an unreadable baseline simply suppresses nothing).
fn load_baseline(cfg: &config::Config, disabled: bool) -> baseline::Baseline {
    if disabled {
        return baseline::Baseline::default();
    }
    match baseline::Baseline::load(&cfg.baseline_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "{}[provn] could not read baseline ({e}) — reporting all findings{}",
                DIM, RESET
            );
            baseline::Baseline::default()
        }
    }
}

// ── Dashboard (bare `provn`) ───────────────────────────────────────────────────
fn cmd_dashboard() -> i32 {
    let healthy = server_healthy();
    let cfg = config::load().unwrap_or_default();

    let l3_link = hyperlink(
        "https://github.com/ashvinctrl/Provn#layer-3-semantic-ai",
        "docs ↗",
    );
    let (l3_dot, l3_label) = if !cfg.layers.semantic.enabled {
        (
            format!("{}○{}", DIM, RESET),
            format!("{}Semantic AI  disabled{}", DIM, RESET),
        )
    } else if healthy {
        (
            format!("{}●{}", GREEN, RESET),
            format!("Semantic AI (Gemma 4 E2B)  {}online{}", GREEN, RESET),
        )
    } else {
        (
            format!("{}○{}", RED, RESET),
            format!(
                "Semantic AI (Gemma 4 E2B)  {}offline{}  ·  provn server start  {}{}{}",
                RED, RESET, DIM, l3_link, RESET,
            ),
        )
    };

    let hook_ok = std::path::Path::new(".git/hooks/pre-commit").exists();
    let hook_status = if hook_ok {
        format!("{}installed{}", GREEN, RESET)
    } else {
        format!("{}not installed{}  →  provn install", YELLOW, RESET)
    };

    eprintln!(
        "\n  {}Provn{}  ·  {}AI-powered secret & IP leak detection{}  ·  {}\n",
        BOLD,
        RESET,
        DIM,
        RESET,
        dim!(env!("CARGO_PKG_VERSION")),
    );
    eprintln!("  {}Layers{}", BOLD, RESET);
    eprintln!(
        "    Layer 1  {}●{}  Regex patterns          always active",
        GREEN, RESET
    );
    eprintln!(
        "    Layer 2  {}●{}  Entropy + AST analysis  always active",
        GREEN, RESET
    );
    eprintln!("    Layer 3  {}  {}", l3_dot, l3_label);
    eprintln!();
    eprintln!("  {}Pre-commit hook{}  {}", BOLD, RESET, hook_status);
    eprintln!();
    eprintln!("  {}Commands{}", BOLD, RESET);
    eprintln!(
        "    {}provn check <path>{}     scan a file for secrets or IP leaks",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn scan{}             scan staged git changes",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn server start{}     enable Layer 3 semantic AI",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn server stop{}      stop Layer 3 semantic AI",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn server status{}    check if Layer 3 is online",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn install{}          install git pre-commit hook",
        CYAN, RESET
    );
    eprintln!(
        "    {}provn verify-audit{}     verify audit log integrity",
        CYAN, RESET
    );
    eprintln!();
    eprintln!("  {}https://github.com/ashvinctrl/Provn{}", DIM, RESET);
    eprintln!();

    0
}

// ── Remote allowlist ───────────────────────────────────────────────────────────
/// Returns true if the commit is allowed to proceed (remote is in the allowlist,
/// or the allowlist is empty, or no remote is configured).
fn check_remote_allowed(cfg: &config::Config) -> bool {
    if cfg.allowed_remotes.is_empty() {
        return true;
    }
    let remote = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    if remote.is_empty() {
        return true; // local-only repo, no remote to check
    }
    cfg.allowed_remotes
        .iter()
        .any(|pattern| wildcard_match(pattern, &remote))
}

/// Minimal wildcard match: `*` matches any sequence of characters.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else {
            match text[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

// ── Scan (pre-commit) ──────────────────────────────────────────────────────────
fn cmd_scan(opts: &ScanOpts) -> i32 {
    let cfg = config::load().unwrap_or_default();

    // Remote allowlist: block pushes to unapproved remotes
    if !check_remote_allowed(&cfg) {
        let remote = std::process::Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
            .trim()
            .to_string();
        eprintln!();
        eprintln!("  {}✗  blocked  [remote not in allowlist]{}", RED, RESET);
        eprintln!("  {}Remote: {}{}", DIM, remote, RESET);
        eprintln!(
            "  {}Add to allowed_remotes in provn.yml to permit commits to this remote.{}",
            DIM, RESET
        );
        eprintln!();
        return 1;
    }

    let chunks = match diff::parse_staged_diff(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}provn  could not read diff: {e} — allowing commit{}",
                DIM, RESET
            );
            return 0;
        }
    };

    scan_and_report(&chunks, &cfg, opts, /* allow_prompt */ true)
}

// ── Check range (pre-push) ─────────────────────────────────────────────────────
fn cmd_check_range(old: &str, new: &str, fmt: &str, fail_on: &[String], no_baseline: bool) -> i32 {
    let cfg = config::load().unwrap_or_default();
    let sarif = fmt.eq_ignore_ascii_case("sarif");
    let chunks = match diff::parse_range_diff(old, new, &cfg) {
        Ok(c) => c,
        Err(e) => {
            if sarif {
                // A SARIF consumer expects a valid report on stdout no matter
                // what; an empty run is the honest representation of "nothing
                // could be scanned".
                println!("{}", sarif::render(&[]));
                return 0;
            }
            eprintln!(
                "{}provn  could not read range diff: {e} — allowing push{}",
                DIM, RESET
            );
            return 0;
        }
    };

    // SARIF is a report format, not an interactive gate — render and exit
    // rather than going through the prompt/redact path.
    if sarif {
        let mut findings = scanner::scan_chunks(&chunks, &cfg);
        let baseline = load_baseline(&cfg, no_baseline);
        if !baseline.is_empty() {
            findings.retain(|f| !baseline.contains(f));
        }
        println!("{}", sarif::render(&findings));
        return if fails_build(&findings, fail_on) {
            1
        } else {
            0
        };
    }

    let opts = ScanOpts {
        fail_on: fail_on.to_vec(),
        auto_redact: false,
        json: fmt.eq_ignore_ascii_case("json"),
        no_baseline,
    };
    // Pushed commits are immutable — redaction prompts make no sense here.
    scan_and_report(&chunks, &cfg, &opts, /* allow_prompt */ false)
}

/// Shared scan engine for `scan` (pre-commit) and `check-range` (pre-push).
///
/// Non-interactive behavior: when stdin or stderr is not a terminal (CI,
/// Docker, git hooks invoked without a TTY) Provn never prompts, and findings
/// are emitted as JSON lines on stdout when stdout is redirected or --json is
/// given. Exit code is the contract: 0 clean, 1 findings blocked.
fn scan_and_report(
    chunks: &[diff::DiffChunk],
    cfg: &config::Config,
    opts: &ScanOpts,
    allow_prompt: bool,
) -> i32 {
    use std::io::IsTerminal;

    if cfg.mode == "shadow" {
        eprintln!(
            "{}  shadow mode — logging only, commits always pass{}",
            DIM, RESET
        );
    }

    if chunks.is_empty() {
        return 0;
    }

    let mut findings = scanner::scan_chunks(chunks, cfg);
    let latency = findings.first().map(|r| r.latency_ms).unwrap_or(0);

    // Suppress findings already accepted into the baseline.
    let baseline = load_baseline(cfg, opts.no_baseline);
    if !baseline.is_empty() {
        let before = findings.len();
        findings.retain(|f| !baseline.contains(f));
        let suppressed = before - findings.len();
        if suppressed > 0 && !opts.json {
            eprintln!(
                "  {}{} finding(s) suppressed by baseline{}",
                DIM, suppressed, RESET
            );
        }
    }

    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    // JSON lines only when explicitly requested — hooks keep human output on
    // stderr; CI pipelines pass --json (or --fail-on for exit-code-only use).
    let json_mode = opts.json;

    if findings.is_empty() {
        if !json_mode {
            eprintln!(
                "  {}✓  clean{}  {}",
                GREEN,
                RESET,
                dim!(format!("{latency}ms"))
            );
        }
        return 0;
    }

    let mut exit_code = 0i32;
    let mut blocked: Vec<&scanner::ScanResult> = Vec::new();
    let mut tier_counts: std::collections::BTreeMap<String, usize> = Default::default();

    for result in &findings {
        let verdict = policy::determine_verdict(result, cfg);
        audit::append(&verdict, result, cfg).ok();

        if let Some(t) = result.tier.as_deref() {
            *tier_counts.entry(t.to_string()).or_default() += 1;
            // --fail-on overrides verdict policy: any finding at a listed tier
            // fails the scan even if policy would only warn.
            if opts.fail_on.iter().any(|f| f.eq_ignore_ascii_case(t)) {
                exit_code = 1;
            }
        }

        if json_mode {
            let verdict_str = match &verdict {
                policy::Verdict::Allow => "allow",
                policy::Verdict::Warn(_) => "warn",
                policy::Verdict::Block(_) => "block",
            };
            println!(
                "{}",
                serde_json::json!({
                    "file":        result.file,
                    "line":        result.line,
                    "match_type":  result.match_type,
                    "tier":        result.tier,
                    "layer":       result.layer,
                    "confidence":  result.confidence,
                    "description": result.description,
                    "verdict":     verdict_str,
                })
            );
        }

        match &verdict {
            policy::Verdict::Allow => {}
            policy::Verdict::Warn(tier) => {
                if !json_mode {
                    eprintln!(
                        "  {}⚠  [{}]{}  {}  {}",
                        YELLOW,
                        tier,
                        RESET,
                        result.file.as_deref().unwrap_or("?"),
                        dim!(result.description.as_deref().unwrap_or("")),
                    );
                }
            }
            policy::Verdict::Block(tier) => {
                if cfg.mode == "shadow" {
                    eprintln!(
                        "  {}[shadow]{}  would block [{}] — allowing",
                        DIM, RESET, tier
                    );
                    continue;
                }
                if !json_mode {
                    print_block(result, tier);
                }
                blocked.push(result);
                exit_code = 1;
            }
        }
    }

    // ── Redaction ────────────────────────────────────────────────────────────
    if !blocked.is_empty() {
        if opts.auto_redact {
            let mut applied = 0usize;
            for r in &blocked {
                if r.secret.is_some() && redact::apply_redaction(r).is_ok() {
                    applied += 1;
                }
            }
            eprintln!(
                "  {}{} redaction(s) applied — re-stage and commit again{}",
                YELLOW, applied, RESET
            );
        } else if allow_prompt
            && interactive
            && opts.fail_on.is_empty()
            && blocked.len() == 1
            && blocked[0].tier.as_deref() == Some("T1")
        {
            // Offer interactive redaction only for a single T1 block on a real TTY
            eprint!("\n  Accept redaction? [y/N]  ");
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok()
                && input.trim().eq_ignore_ascii_case("y")
                && redact::apply_redaction(blocked[0]).is_ok()
            {
                eprintln!("  redaction applied — re-stage and commit again");
                return 1;
            }
        }
    }

    // Summary line: PROVN: 3 findings (1 T0, 2 T1) in 12ms — exit 1
    if !json_mode {
        let breakdown: Vec<String> = tier_counts
            .iter()
            .map(|(t, n)| format!("{n} {t}"))
            .collect();
        eprintln!(
            "  {}PROVN: {} finding(s) ({}) in {}ms — exit {}{}",
            DIM,
            findings.len(),
            breakdown.join(", "),
            latency,
            exit_code,
            RESET
        );
    }

    exit_code
}

fn print_block(result: &scanner::ScanResult, tier: &str) {
    eprintln!();
    eprintln!("  {}✗  blocked  [{}]{}", RED, tier, RESET);
    if let Some(d) = &result.description {
        eprintln!("  {}", dim!(d));
    }
    if let Some(f) = &result.file {
        eprintln!(
            "  {}:{}{}",
            f,
            result.line.unwrap_or(0),
            if let Some(l) = &result.layer {
                format!("  {}", dim!(format!("via {l}")))
            } else {
                String::new()
            }
        );
    }
    if let Some(s) = &result.snippet {
        let short: String = s.chars().take(80).collect();
        let token = result.redacted.as_deref().unwrap_or("PROVN_REDACTED");
        // Preview the actual post-redaction line: replace only the secret span
        // when we know it, so users see their code survives redaction intact.
        let preview = match result.secret.as_deref() {
            Some(secret) if short.contains(secret) => short.replacen(secret, token, 1),
            _ => token.to_string(),
        };
        eprintln!("\n  {}- {}{}", RED, short, RESET);
        eprintln!("  {}+ {}{}", GREEN, preview, RESET);
    }
}

// ── Check ──────────────────────────────────────────────────────────────────────
#[derive(serde::Deserialize)]
struct BenchSample {
    code: String,
    label: String,
    /// "secret" (credential — Layer 1+2's job) or "ip" (proprietary logic /
    /// prompt — only the optional Layer 3 model catches these). Absent on clean
    /// samples. Lets the report separate what the offline layers are responsible
    /// for from what needs the model.
    #[serde(default)]
    category: Option<String>,
}

/// First non-empty line of a snippet, truncated — used to name misses/false alarms.
fn snippet_label(code: &str) -> String {
    code.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(80)
        .collect()
}

fn cmd_bench(corpus: &str, json: bool, ext: &str) -> i32 {
    let content = match std::fs::read_to_string(corpus) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  {RED}error{RESET}  cannot read corpus {corpus}: {e}");
            return 2;
        }
    };

    // Deterministic, offline benchmark: Layer 1+2 only. Disabling the semantic
    // layer keeps the result reproducible on any machine with no model server,
    // and the regex/AST layers are rule-based so the full corpus is a valid
    // evaluation set for them (nothing is trained on it).
    let mut cfg = config::load().unwrap_or_default();
    cfg.layers.semantic.enabled = false;

    let (mut tp, mut misses, mut fp, mut tn) = (0u32, 0u32, 0u32, 0u32);
    // Recall split by category: secrets are the offline layers' responsibility,
    // IP/prompt leaks need the optional Layer 3 model.
    let (mut secret_tp, mut secret_total) = (0u32, 0u32);
    let (mut ip_tp, mut ip_total) = (0u32, 0u32);
    let mut latencies_us: Vec<u128> = Vec::new();
    let mut skipped = 0u32;
    let mut missed_leaks: Vec<String> = Vec::new();
    let mut false_alarms: Vec<String> = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let sample: BenchSample = match serde_json::from_str(line) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  {YELLOW}warn{RESET}  corpus line {} skipped: {e}", i + 1);
                skipped += 1;
                continue;
            }
        };
        let is_leak = sample.label.eq_ignore_ascii_case("leak");
        let is_clean = sample.label.eq_ignore_ascii_case("clean");
        if !is_leak && !is_clean {
            eprintln!(
                "  {YELLOW}warn{RESET}  corpus line {} has unknown label '{}', skipped",
                i + 1,
                sample.label
            );
            skipped += 1;
            continue;
        }

        let start = std::time::Instant::now();
        let findings = scanner::scan_snippet(&sample.code, ext, &cfg);
        latencies_us.push(start.elapsed().as_micros());
        let flagged = !findings.is_empty();

        if is_leak {
            let is_secret = sample.category.as_deref() == Some("secret");
            if is_secret {
                secret_total += 1;
            } else {
                ip_total += 1;
            }
            if flagged {
                tp += 1;
                if is_secret {
                    secret_tp += 1;
                } else {
                    ip_tp += 1;
                }
            } else {
                misses += 1;
                missed_leaks.push(snippet_label(&sample.code));
            }
        } else if flagged {
            fp += 1;
            false_alarms.push(snippet_label(&sample.code));
        } else {
            tn += 1;
        }
    }

    let leaks = tp + misses;
    let cleans = fp + tn;
    let total = leaks + cleans;
    if total == 0 {
        eprintln!("  {RED}error{RESET}  corpus {corpus} has no usable samples");
        return 2;
    }

    let rate = |num: u32, den: u32| -> f64 {
        if den > 0 {
            num as f64 / den as f64
        } else {
            0.0
        }
    };
    let recall = rate(tp, leaks);
    let secret_recall = rate(secret_tp, secret_total);
    let ip_recall = rate(ip_tp, ip_total);
    let fpr = rate(fp, cleans);
    let precision = rate(tp, tp + fp);

    latencies_us.sort_unstable();
    let pct = |q: f64| -> f64 {
        if latencies_us.is_empty() {
            return 0.0;
        }
        let idx = (((latencies_us.len() - 1) as f64) * q).round() as usize;
        latencies_us[idx] as f64 / 1000.0 // microseconds → milliseconds
    };
    let p50 = pct(0.50);
    let p95 = pct(0.95);

    if json {
        let round3 = |x: f64| (x * 1000.0).round() / 1000.0;
        let round2 = |x: f64| (x * 100.0).round() / 100.0;
        println!(
            "{}",
            serde_json::json!({
                "corpus": corpus,
                "samples": total,
                "leaks": leaks,
                "clean": cleans,
                "tp": tp, "fn": misses, "fp": fp, "tn": tn,
                "recall": round3(recall),
                "secret_recall": round3(secret_recall),
                "secret_total": secret_total,
                "ip_recall": round3(ip_recall),
                "ip_total": ip_total,
                "fpr": round3(fpr),
                "precision": round3(precision),
                "p50_ms": round2(p50),
                "p95_ms": round2(p95),
                "skipped": skipped,
            })
        );
        return 0;
    }

    println!();
    println!("  {BOLD}LeakBench — Layer 1+2 (offline){RESET}");
    println!("  {}", dim!(corpus));
    println!();
    println!("  samples       {total}  ({leaks} leak, {cleans} clean)");
    println!(
        "  secret recall {GREEN}{:.1}%{RESET}  ({secret_tp}/{secret_total} credential leaks — offline layers' job)",
        secret_recall * 100.0
    );
    println!(
        "  ip recall     {:.1}%  ({ip_tp}/{ip_total} proprietary/prompt leaks — needs Layer 3)",
        ip_recall * 100.0
    );
    println!(
        "  overall       {:.1}%  ({tp}/{leaks} leaks, Layer 3 off)",
        recall * 100.0
    );
    println!(
        "  FPR           {}{:.1}%{RESET}  ({fp}/{cleans} clean flagged)",
        if fp == 0 { GREEN } else { YELLOW },
        fpr * 100.0
    );
    println!("  precision     {:.1}%", precision * 100.0);
    println!(
        "  latency       p50 {p50:.2}ms · p95 {p95:.2}ms  {}",
        dim!("per snippet, incl. pattern compile")
    );
    if skipped > 0 {
        println!("  {YELLOW}{skipped} line(s) skipped (parse/label errors){RESET}");
    }
    print_bench_list("missed leaks", &missed_leaks);
    print_bench_list("false alarms", &false_alarms);
    println!();
    0
}

fn print_bench_list(title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    println!();
    println!("  {YELLOW}{title} ({}):{RESET}", items.len());
    for item in items.iter().take(10) {
        println!("    {}", dim!(item));
    }
    if items.len() > 10 {
        println!("    {}", dim!(format!("... and {} more", items.len() - 10)));
    }
}

fn cmd_check(file: &str, fmt: &str, fail_on: &[String], no_baseline: bool) -> i32 {
    let cfg = config::load().unwrap_or_default();
    let json = fmt.eq_ignore_ascii_case("json");
    let sarif = fmt.eq_ignore_ascii_case("sarif");

    // Directory → recursive scan of every non-excluded file under it.
    let path = std::path::Path::new(file);
    let chunks = if path.is_dir() {
        let mut files = Vec::new();
        diff::walk_dir(path, &cfg, &mut files);
        let mut all = Vec::new();
        for f in &files {
            // Binary / unreadable files are skipped silently — same contract
            // as diff mode, which never sees them either.
            if let Ok(mut c) = diff::parse_file(&f.display().to_string(), &cfg) {
                all.append(&mut c);
            }
        }
        all
    } else {
        match diff::parse_file(file, &cfg) {
            Ok(c) => c,
            Err(e) => {
                if json {
                    println!("{}", serde_json::json!({ "error": e.to_string() }));
                } else if sarif {
                    println!("{}", sarif::render(&[]));
                } else {
                    eprintln!("  {}error{}  {}: {e}", RED, RESET, file);
                }
                return 2;
            }
        }
    };

    let mut findings = scanner::scan_chunks(&chunks, &cfg);
    let latency = findings.first().map(|r| r.latency_ms).unwrap_or(0);

    // Baseline suppression (applies to every output format).
    let baseline = load_baseline(&cfg, no_baseline);
    if !baseline.is_empty() {
        findings.retain(|f| !baseline.contains(f));
    }
    let clean = findings.is_empty();
    let failed = fails_build(&findings, fail_on);

    if sarif {
        println!("{}", sarif::render(&findings));
        return if failed { 1 } else { 0 };
    }

    if json {
        let items: Vec<_> = findings
            .iter()
            .map(|r| {
                serde_json::json!({
                    "file":        r.file,
                    "line":        r.line,
                    "match_type":  r.match_type,
                    "tier":        r.tier,
                    "layer":       r.layer,
                    "confidence":  r.confidence,
                    "description": r.description,
                    "snippet":     r.snippet,
                    "redacted":    r.redacted,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "file":       file,
                "clean":      clean,
                "findings":   items,
                "latency_ms": latency,
            })
        );
        return if failed { 1 } else { 0 };
    }

    if clean {
        println!(
            "  {}✓  clean{}  {}",
            GREEN,
            RESET,
            dim!(format!("{latency}ms"))
        );
        return 0;
    }

    for result in &findings {
        let verdict = policy::determine_verdict(result, &cfg);
        let tier = match &verdict {
            policy::Verdict::Allow => continue,
            policy::Verdict::Warn(t) | policy::Verdict::Block(t) => t.clone(),
        };
        let desc = result.description.as_deref().unwrap_or("unknown");
        let layer = result
            .layer
            .as_deref()
            .map(|l| format!("  {}", dim!(format!("via {l}"))))
            .unwrap_or_default();
        let loc = match (result.file.as_deref(), result.line) {
            (Some(f), Some(l)) => format!("  {}", dim!(format!("{f}:{l}"))),
            (Some(f), None) => format!("  {}", dim!(f)),
            _ => String::new(),
        };
        println!("  {}✗  [{}]{}  {}{}{}", RED, tier, RESET, desc, layer, loc);
    }

    if failed {
        1
    } else {
        0
    }
}

// ── Layer 3 models ───────────────────────────────────────────────────────────
fn cmd_model(action: ModelAction) -> i32 {
    match action {
        ModelAction::List => cmd_model_list(),
        ModelAction::Install { id, force } => cmd_model_install(id.as_deref(), force),
    }
}

fn cmd_model_list() -> i32 {
    let dir = model::models_dir();
    eprintln!();
    eprintln!("  {}Layer 3 models{}  {}", BOLD, RESET, dim!(dir.display()));
    eprintln!();
    for m in model::REGISTRY {
        let installed = dir.join(m.file).exists();
        let mark = if installed {
            format!("{GREEN}●{RESET}")
        } else {
            format!("{DIM}○{RESET}")
        };
        eprintln!("  {mark}  {}{}{}", BOLD, m.id, RESET);
        eprintln!("     {}", dim!(m.name));
        eprintln!(
            "     {}",
            dim!(format!(
                "{}  ·  {}{}",
                m.size_label(),
                m.notes,
                if installed { "  ·  installed" } else { "" }
            ))
        );
        eprintln!();
    }
    eprintln!("  {}provn model install <id>{}", DIM, RESET);
    eprintln!();
    0
}

fn cmd_model_install(id: Option<&str>, force: bool) -> i32 {
    // No id given → the first registry entry, which is deliberately the one
    // that needs no account.
    let spec = match id {
        Some(want) => match model::find(want) {
            Some(s) => s,
            None => {
                eprintln!("  {}✗  unknown model{}  {want}", RED, RESET);
                eprintln!("  {}provn model list{}", DIM, RESET);
                return 1;
            }
        },
        None => &model::REGISTRY[0],
    };

    let dest = model::models_dir().join(spec.file);

    if dest.exists() && !force {
        eprintln!();
        eprintln!(
            "  {}●  already installed{}  {}",
            GREEN,
            RESET,
            dim!(dest.display())
        );
        eprintln!("  {}re-download with --force{}", DIM, RESET);
        eprintln!();
        print_enable_instructions(spec);
        return 0;
    }

    eprintln!();
    eprintln!("  {}Installing {}{}", BOLD, spec.name, RESET);
    eprintln!("  {}", dim!(spec.url()));
    eprintln!("  {}", dim!(format!("→ {}", dest.display())));
    if spec.needs_auth {
        eprintln!();
        eprintln!(
            "  {}note{}  {}",
            YELLOW,
            RESET,
            dim!("this repo needs Hugging Face credentials; the download will fail without them")
        );
    }
    eprintln!();

    let mut last_pct = u64::MAX;
    let result = model::download(spec, &dest, |written, total| {
        // Only repaint on a whole-percent change — a 2.8 GB file is ~2700
        // callbacks per percent otherwise.
        match total {
            Some(t) if t > 0 => {
                let pct = written * 100 / t;
                if pct != last_pct {
                    last_pct = pct;
                    eprint!(
                        "\r  downloading  {pct:>3}%  {} / {}",
                        model::human_bytes(written),
                        model::human_bytes(t)
                    );
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
            }
            _ => {
                let mb = written / (1 << 20);
                if mb != last_pct {
                    last_pct = mb;
                    eprint!("\r  downloading  {}", model::human_bytes(written));
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
            }
        }
    });
    eprintln!();

    match result {
        Ok(()) => {
            eprintln!();
            eprintln!("  {}✓  installed{}  {}", GREEN, RESET, dim!(dest.display()));
            eprintln!();
            print_enable_instructions(spec);
            0
        }
        Err(e) => {
            eprintln!();
            eprintln!("  {}✗  download failed{}  {e}", RED, RESET);
            eprintln!();
            1
        }
    }
}

/// Print what still has to happen for Layer 3 to actually run. Provn does not
/// edit the user's provn.yml for them — a scanner that silently rewrites config
/// is a scanner people stop trusting.
fn print_enable_instructions(spec: &model::ModelSpec) {
    eprintln!("  {}Enable Layer 3{}", BOLD, RESET);
    eprintln!("  {}1. add to provn.yml:{}", DIM, RESET);
    eprintln!("       layers:");
    eprintln!("         semantic:");
    eprintln!("           enabled: true");
    eprintln!("           model: {}", spec.file);
    eprintln!("  {}2. start the server:{}  provn server start", DIM, RESET);
    eprintln!("  {}3. confirm:{}          provn server status", DIM, RESET);
    eprintln!();
    eprintln!(
        "  {}",
        dim!("requires llama-server (llama.cpp) on PATH — brew install llama.cpp")
    );
    eprintln!();
}

// ── Scan history ─────────────────────────────────────────────────────────────
fn cmd_scan_history(max_commits: usize, json: bool) -> i32 {
    let cfg = config::load().unwrap_or_default();

    let commits = match diff::parse_history(max_commits, &cfg) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "error": e.to_string() }));
            } else {
                eprintln!("  {}error{}  could not read git history: {e}", RED, RESET);
            }
            return 2;
        }
    };

    let mut total = 0usize;
    let mut tier_counts: std::collections::BTreeMap<String, usize> = Default::default();

    if !json {
        eprintln!(
            "  {}scanning {} commit(s) of history…{}",
            DIM,
            commits.len(),
            RESET
        );
    }

    for commit in &commits {
        let findings = scanner::scan_chunks(&commit.chunks, &cfg);
        for f in &findings {
            total += 1;
            if let Some(t) = f.tier.as_deref() {
                *tier_counts.entry(t.to_string()).or_default() += 1;
            }
            let short_sha: String = commit.sha.chars().take(8).collect();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "commit":      commit.sha,
                        "subject":     commit.subject,
                        "file":        f.file,
                        "line":        f.line,
                        "match_type":  f.match_type,
                        "tier":        f.tier,
                        "layer":       f.layer,
                        "confidence":  f.confidence,
                        "description": f.description,
                    })
                );
            } else {
                eprintln!(
                    "  {}✗  [{}]{}  {}  {}  {}",
                    RED,
                    f.tier.as_deref().unwrap_or("?"),
                    RESET,
                    f.description.as_deref().unwrap_or("finding"),
                    dim!(format!(
                        "{}:{}",
                        f.file.as_deref().unwrap_or("?"),
                        f.line.unwrap_or(0)
                    )),
                    dim!(format!("{short_sha} {}", commit.subject)),
                );
            }
        }
    }

    if !json {
        if total == 0 {
            eprintln!("  {}✓  no secrets found in history{}", GREEN, RESET);
        } else {
            let breakdown: Vec<String> = tier_counts
                .iter()
                .map(|(t, n)| format!("{n} {t}"))
                .collect();
            eprintln!(
                "  {}PROVN: {} finding(s) in history ({}){}",
                DIM,
                total,
                breakdown.join(", "),
                RESET
            );
            eprintln!(
                "  {}secrets already in history stay in git objects — rotate them and consider history rewriting{}",
                DIM, RESET
            );
        }
    }

    if total == 0 {
        0
    } else {
        1
    }
}

// ── Baseline ───────────────────────────────────────────────────────────────────
fn cmd_baseline(path: &str) -> i32 {
    let cfg = config::load().unwrap_or_default();

    let p = std::path::Path::new(path);
    let chunks = if p.is_dir() {
        let mut files = Vec::new();
        diff::walk_dir(p, &cfg, &mut files);
        let mut all = Vec::new();
        for f in &files {
            if let Ok(mut c) = diff::parse_file(&f.display().to_string(), &cfg) {
                all.append(&mut c);
            }
        }
        all
    } else {
        match diff::parse_file(path, &cfg) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  {}error{}  {}: {e}", RED, RESET, path);
                return 2;
            }
        }
    };

    let findings = scanner::scan_chunks(&chunks, &cfg);
    let baseline = baseline::Baseline::from_findings(&findings);
    match baseline.save(&cfg.baseline_path) {
        Ok(_) => {
            println!(
                "  {}✓  baseline written{}  {} finding(s) accepted → {}",
                GREEN,
                RESET,
                baseline.len(),
                dim!(&cfg.baseline_path)
            );
            println!(
                "  {}commit {} so the team shares the same accepted set{}",
                DIM, cfg.baseline_path, RESET
            );
            0
        }
        Err(e) => {
            eprintln!("  {}✗  could not write baseline{}  {e}", RED, RESET);
            1
        }
    }
}

// ── Verify audit ───────────────────────────────────────────────────────────────
fn cmd_verify_audit() -> i32 {
    let cfg = config::load().unwrap_or_default();
    match audit::verify_chain(&cfg.audit.path, &cfg.audit.hmac_key_path) {
        Ok(count) => {
            if count == 0 {
                println!(
                    "  {}✓  no audit entries yet{}  {}",
                    GREEN,
                    RESET,
                    dim!("fresh repo or no findings logged")
                );
            } else {
                println!(
                    "  {}✓  audit chain intact{}  {} entries",
                    GREEN, RESET, count
                );
            }
            0
        }
        Err(e) => {
            eprintln!("  {}✗  audit chain invalid{}  {e}", RED, RESET);
            1
        }
    }
}

// ── Install ────────────────────────────────────────────────────────────────────
fn write_hook(hook_path: &str, content: &str) -> std::io::Result<()> {
    std::fs::write(hook_path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(hook_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(hook_path, perms).ok();
        }
    }
    Ok(())
}

fn cmd_install(pre_push: bool) -> i32 {
    let provn_bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "provn".to_string());

    let pre_commit = format!("#!/bin/sh\n\"{provn_bin}\" scan\n");
    if let Err(e) = write_hook(".git/hooks/pre-commit", &pre_commit) {
        eprintln!("  {}✗  failed to install hook{}  {e}", RED, RESET);
        eprintln!("  {}make sure you are inside a git repo{}", DIM, RESET);
        return 1;
    }
    println!("  {}✓  pre-commit hook installed{}", GREEN, RESET);
    println!("  {}provn scan will run on every git commit{}", DIM, RESET);

    if pre_push {
        // Pre-push receives "local_ref local_sha remote_ref remote_sha" lines
        // on stdin — scan every outgoing commit range and block on findings.
        let hook = format!(
            "#!/bin/sh\n\
             # Provn pre-push gate — scans all outgoing commits\n\
             status=0\n\
             while read local_ref local_sha remote_ref remote_sha; do\n\
             \t\"{provn_bin}\" check-range \"$remote_sha\" \"$local_sha\" || status=1\n\
             done\n\
             exit $status\n"
        );
        if let Err(e) = write_hook(".git/hooks/pre-push", &hook) {
            eprintln!("  {}✗  failed to install pre-push hook{}  {e}", RED, RESET);
            return 1;
        }
        println!("  {}✓  pre-push hook installed{}", GREEN, RESET);
        println!(
            "  {}every outgoing commit range is scanned before it leaves your machine{}",
            DIM, RESET
        );
    }

    0
}

// ── Server ─────────────────────────────────────────────────────────────────────
#[cfg(target_os = "macos")]
const PLIST_LABEL: &str = "com.provn.semantic-server";

/// Port from a configured endpoint URL ("http://localhost:8080" → 8080),
/// falling back to llama-server's default.
fn endpoint_port(endpoint: &str) -> u16 {
    endpoint
        .rsplit(':')
        .next()
        .and_then(|s| s.trim_matches('/').parse().ok())
        .unwrap_or(8080)
}

/// Write the launchd user agent that runs llama-server for Layer 3.
#[cfg(target_os = "macos")]
fn write_launch_agent(plist_path: &str, model_path: &str, port: u16) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(plist_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let llama_bin = which_bin("llama-server");
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{llama_bin}</string>
    <string>-m</string><string>{model_path}</string>
    <string>--host</string><string>127.0.0.1</string>
    <string>--port</string><string>{port}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>StandardOutPath</key><string>/tmp/provn-semantic-server.log</string>
  <key>StandardErrorPath</key><string>/tmp/provn-semantic-server.log</string>
</dict>
</plist>
"#
    );
    std::fs::write(plist_path, content)
}

/// Absolute path to a binary on PATH, or the bare name so the OS reports a
/// clear "not found" itself.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn which_bin(name: &str) -> String {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| name.to_string())
}

#[cfg(target_os = "linux")]
const SERVICE_UNIT: &str = "provn-semantic";

fn print_server_status() -> i32 {
    if server_healthy() {
        eprintln!("  {}●  Layer 3 online{}  ·  127.0.0.1:8080", GREEN, RESET);
        eprintln!(
            "  {}Gemma 4 E2B · Q4_K_M · ambiguous-case classifier{}",
            DIM, RESET
        );
        0
    } else {
        eprintln!("  {}○  Layer 3 offline{}", RED, RESET);
        eprintln!(
            "  {}provn server start{}  to enable semantic AI  {}{}{}",
            CYAN,
            RESET,
            DIM,
            hyperlink(
                "https://github.com/ashvinctrl/Provn#layer-3-semantic-ai",
                "docs ↗"
            ),
            RESET,
        );
        1
    }
}

#[cfg(target_os = "macos")]
fn cmd_server(action: ServerAction) -> i32 {
    let plist = format!(
        "{}/Library/LaunchAgents/{PLIST_LABEL}.plist",
        std::env::var("HOME").unwrap_or_default()
    );
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");

    match action {
        ServerAction::Start => {
            let cfg = config::load().unwrap_or_default();
            let model_path = model::resolve_path(&cfg.layers.semantic.model);
            let port = endpoint_port(&cfg.layers.semantic.endpoint);

            eprintln!();
            eprintln!("  {}Layer 3  ·  Semantic AI{}", BOLD, RESET);
            eprintln!(
                "  {}model   {}{}{}",
                DIM,
                RESET,
                cfg.layers.semantic.model.trim(),
                DIM
            );
            eprintln!(
                "  {}scope   {}ambiguous detections only  (confidence 40 – 80 %){}",
                DIM, RESET, DIM
            );
            eprintln!(
                "  {}logs    {}/tmp/provn-semantic-server.log{}",
                DIM, RESET, DIM
            );
            eprintln!();

            if server_healthy() {
                eprintln!("  {}●  already online{}  ·  127.0.0.1:{port}", GREEN, RESET);
                eprintln!();
                return 0;
            }

            if !model_path.exists() {
                eprintln!(
                    "  {}✗  model not found{}  {}",
                    RED,
                    RESET,
                    dim!(model_path.display())
                );
                eprintln!("  {}Download it first:{}  provn model install", DIM, RESET);
                eprintln!();
                return 1;
            }

            // Write the launch agent rather than requiring the user to have
            // hand-authored one: previously this path only ever *looked* for a
            // plist that nothing in Provn created, so `server start` could not
            // succeed on a clean install.
            if let Err(e) = write_launch_agent(&plist, &model_path.to_string_lossy(), port) {
                eprintln!("  {}✗  cannot write launch agent{}  {e}", RED, RESET);
                eprintln!("  {}", dim!(&plist));
                eprintln!();
                return 1;
            }

            // Re-bootstrapping an already-loaded label fails; drop it first so
            // a config change (new model or port) actually takes effect.
            let _ = std::process::Command::new("launchctl")
                .args(["bootout", &domain, &plist])
                .output();

            eprint!("  starting");
            let out = std::process::Command::new("launchctl")
                .args(["bootstrap", &domain, &plist])
                .output();

            match out {
                Ok(o) if o.status.success() => {
                    eprintln!("  {}●  online{}  ·  127.0.0.1:{port}", GREEN, RESET);
                    eprintln!(
                        "  {}model loads in ~25 s  ·  provn server status to confirm{}",
                        DIM, RESET
                    );
                }
                Ok(o) => {
                    eprintln!();
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    eprintln!("  {}✗  failed to start{}  {}", RED, RESET, stderr.trim());
                    eprintln!("  {}tail -f /tmp/provn-semantic-server.log{}", DIM, RESET);
                    eprintln!();
                    return 1;
                }
                Err(e) => {
                    eprintln!();
                    eprintln!("  {}✗  launchctl error{}  {e}", RED, RESET);
                    eprintln!();
                    return 1;
                }
            }
            eprintln!();
            0
        }

        ServerAction::Stop => {
            let out = std::process::Command::new("launchctl")
                .args(["bootout", &domain, &plist])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    eprintln!("  {}○  semantic server stopped{}", DIM, RESET);
                    eprintln!(
                        "  {}Layer 3 will fall back to Layer 1 / 2 result{}",
                        DIM, RESET
                    );
                    0
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    eprintln!(
                        "  {}✗  {}{}  (may already be stopped)",
                        RED,
                        RESET,
                        stderr.trim()
                    );
                    1
                }
                Err(e) => {
                    eprintln!("  {}✗  launchctl error{}  {e}", RED, RESET);
                    1
                }
            }
        }

        ServerAction::Status => print_server_status(),
    }
}

#[cfg(target_os = "linux")]
fn cmd_server(action: ServerAction) -> i32 {
    match action {
        ServerAction::Status => print_server_status(),
        ServerAction::Start => linux_server_start(),
        ServerAction::Stop => linux_server_stop(),
    }
}

#[cfg(target_os = "linux")]
fn linux_server_start() -> i32 {
    let cfg = config::load().unwrap_or_default();

    eprintln!();
    eprintln!("  {}Layer 3  ·  Semantic AI{}", BOLD, RESET);
    eprintln!(
        "  {}model   {}Gemma 4 E2B · fine-tuned on LeakBench · Q4_K_M{}",
        DIM, RESET, DIM
    );
    eprintln!(
        "  {}scope   {}ambiguous detections only  (confidence 40 – 80 %%){}",
        DIM, RESET, DIM
    );
    eprintln!(
        "  {}logs    {}journalctl --user -u {SERVICE_UNIT} -f{}",
        DIM, RESET, DIM
    );
    eprintln!();

    if server_healthy() {
        eprintln!("  {}●  already online{}  ·  127.0.0.1:8080", GREEN, RESET);
        eprintln!();
        return 0;
    }

    let model_path = model::resolve_path(&cfg.layers.semantic.model)
        .to_string_lossy()
        .into_owned();

    if !std::path::Path::new(&model_path).exists() {
        eprintln!(
            "  {}✗  model not found{}  {}",
            RED,
            RESET,
            dim!(&model_path)
        );
        eprintln!("  {}Download it first:{}  provn model install", DIM, RESET);
        eprintln!();
        return 1;
    }

    let llama_bin = which_bin("llama-server");
    let port = endpoint_port(&cfg.layers.semantic.endpoint);

    // Write a systemd user service unit — no root required.
    let home = std::env::var("HOME").unwrap_or_default();
    let unit_dir = format!("{home}/.config/systemd/user");
    let unit_path = format!("{unit_dir}/{SERVICE_UNIT}.service");

    if let Err(e) = std::fs::create_dir_all(&unit_dir) {
        eprintln!("  {}✗  cannot create unit dir{}  {e}", RED, RESET);
        return 1;
    }

    let unit_content = format!(
        "[Unit]\n\
         Description=Provn Layer 3 semantic inference server\n\
         After=network.target\n\n\
         [Service]\n\
         ExecStart={llama_bin} -m {model_path} --host 127.0.0.1 --port {port}\n\
         Restart=on-failure\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    );

    if let Err(e) = std::fs::write(&unit_path, unit_content) {
        eprintln!("  {}✗  cannot write unit file{}  {e}", RED, RESET);
        return 1;
    }

    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    if reload.map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("  {}✗  systemctl daemon-reload failed{}", RED, RESET);
        eprintln!(
            "  {}Is systemd --user running?  Try: systemctl --user status{}",
            DIM, RESET
        );
        return 1;
    }

    match std::process::Command::new("systemctl")
        .args(["--user", "start", SERVICE_UNIT])
        .output()
    {
        Ok(o) if o.status.success() => {
            eprintln!("  {}●  online{}  ·  127.0.0.1:{port}", GREEN, RESET);
            eprintln!(
                "  {}model loads in ~25 s  ·  provn server status to confirm{}",
                DIM, RESET
            );
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("  {}✗  failed to start{}  {}", RED, RESET, stderr.trim());
            eprintln!("  {}journalctl --user -u {SERVICE_UNIT} -f{}", DIM, RESET);
            eprintln!();
            return 1;
        }
        Err(e) => {
            eprintln!("  {}✗  systemctl error{}  {e}", RED, RESET);
            eprintln!();
            return 1;
        }
    }
    eprintln!();
    0
}

#[cfg(target_os = "linux")]
fn linux_server_stop() -> i32 {
    match std::process::Command::new("systemctl")
        .args(["--user", "stop", SERVICE_UNIT])
        .output()
    {
        Ok(o) if o.status.success() => {
            eprintln!("  {}○  semantic server stopped{}", DIM, RESET);
            eprintln!(
                "  {}Layer 3 will fall back to Layer 1 / 2 result{}",
                DIM, RESET
            );
            0
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!(
                "  {}✗  {}{}  (may already be stopped)",
                RED,
                RESET,
                stderr.trim()
            );
            1
        }
        Err(e) => {
            eprintln!("  {}✗  systemctl error{}  {e}", RED, RESET);
            1
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cmd_server(action: ServerAction) -> i32 {
    match action {
        ServerAction::Status => print_server_status(),
        ServerAction::Start => {
            let cfg = config::load().unwrap_or_default();
            let port = endpoint_port(&cfg.layers.semantic.endpoint);

            eprintln!();
            if server_healthy() {
                eprintln!("  {}●  already online{}  ·  127.0.0.1:{port}", GREEN, RESET);
                eprintln!();
                return 0;
            }
            eprintln!("  {}Layer 3  ·  Semantic AI{}", BOLD, RESET);
            eprintln!(
                "  {}there is no supervised service to attach to on this platform{}",
                YELLOW, RESET
            );
            eprintln!();

            // Even without a service manager, the command can be exact rather
            // than leaving the user to reconstruct it from the docs.
            let model_path = model::resolve_path(&cfg.layers.semantic.model);
            if !model_path.exists() {
                eprintln!(
                    "  {}✗  model not found{}  {}",
                    RED,
                    RESET,
                    dim!(model_path.display())
                );
                eprintln!("  {}Download it first:{}  provn model install", DIM, RESET);
                eprintln!();
                return 1;
            }

            eprintln!(
                "  {}Run this, then {}provn server status{}",
                DIM, CYAN, RESET
            );
            eprintln!(
                "    llama-server -m \"{}\" --host 127.0.0.1 --port {port}",
                model_path.display()
            );
            eprintln!();
            1
        }
        ServerAction::Stop => {
            if server_healthy() {
                eprintln!(
                    "  {}✗  auto-stop is not yet supported on this platform{}",
                    YELLOW, RESET
                );
                eprintln!("  {}Stop llama-server manually.{}", DIM, RESET);
                1
            } else {
                eprintln!("  {}○  Layer 3 offline{}", DIM, RESET);
                0
            }
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────
/// OSC 8 terminal hyperlink — renders as clickable text in iTerm2, Warp, kitty, etc.
fn hyperlink(url: &str, label: &str) -> String {
    format!("\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\")
}

fn server_healthy() -> bool {
    let cfg = config::load().unwrap_or_default();
    let base = cfg
        .layers
        .semantic
        .endpoint
        .trim_end_matches('/')
        .trim_end_matches("/completion")
        .to_string();
    let url = format!("{base}/health");

    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()
        .and_then(|c| c.get(&url).send().ok())
        .and_then(|r| r.text().ok())
        .map(|t| t.contains("\"ok\""))
        .unwrap_or(false)
}

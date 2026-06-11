use clap::{Parser, Subcommand};
use std::process;

mod audit;
mod baseline;
mod config;
mod diff;
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
        /// Output findings as JSON lines
        #[arg(long, short = 'j')]
        json: bool,
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
            no_baseline,
        }) => {
            let fmt = if json { "json" } else { format.as_str() };
            cmd_check(&file, fmt, no_baseline)
        }
        Some(Command::CheckRange {
            old,
            new,
            json,
            no_baseline,
        }) => cmd_check_range(&old, &new, json, no_baseline),
        Some(Command::ScanHistory { max_commits, json }) => cmd_scan_history(max_commits, json),
        Some(Command::Baseline { path }) => cmd_baseline(&path),
        Some(Command::VerifyAudit) => cmd_verify_audit(),
        Some(Command::Install { pre_push }) => cmd_install(pre_push),
        Some(Command::Server { action }) => cmd_server(action),
    }
}

struct ScanOpts {
    fail_on: Vec<String>,
    auto_redact: bool,
    json: bool,
    no_baseline: bool,
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
fn cmd_check_range(old: &str, new: &str, json: bool, no_baseline: bool) -> i32 {
    let cfg = config::load().unwrap_or_default();
    let chunks = match diff::parse_range_diff(old, new, &cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}provn  could not read range diff: {e} — allowing push{}",
                DIM, RESET
            );
            return 0;
        }
    };
    let opts = ScanOpts {
        fail_on: Vec::new(),
        auto_redact: false,
        json,
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
fn cmd_check(file: &str, fmt: &str, no_baseline: bool) -> i32 {
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

    if sarif {
        println!("{}", sarif::render(&findings));
        return if clean { 0 } else { 1 };
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
        return if clean { 0 } else { 1 };
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

    1
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
                "  {}logs    {}/tmp/provn-semantic-server.log{}",
                DIM, RESET, DIM
            );
            eprintln!();

            if server_healthy() {
                eprintln!("  {}●  already online{}  ·  127.0.0.1:8080", GREEN, RESET);
                eprintln!();
                return 0;
            }

            if !std::path::Path::new(&plist).exists() {
                eprintln!("  {}✗  launchd plist not found{}", RED, RESET);
                eprintln!("  expected: {}", dim!(&plist));
                eprintln!();
                return 1;
            }

            eprint!("  starting");
            let out = std::process::Command::new("launchctl")
                .args(["bootstrap", &domain, &plist])
                .output();

            match out {
                Ok(o) if o.status.success() => {
                    eprintln!("  {}●  online{}  ·  127.0.0.1:8080", GREEN, RESET);
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

    // Resolve model: use config value as-is if absolute or already exists,
    // otherwise look in ~/.provn/models/<name>.
    let model_path = {
        let raw = cfg.layers.semantic.model.trim().to_string();
        let p = std::path::Path::new(&raw);
        if p.is_absolute() || p.exists() {
            raw
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{home}/.provn/models/{raw}")
        }
    };

    if !std::path::Path::new(&model_path).exists() {
        eprintln!(
            "  {}✗  model not found{}  {}",
            RED,
            RESET,
            dim!(&model_path)
        );
        eprintln!("  {}Download it first:", DIM);
        eprintln!("    hf download ashvinctrl/provn-gemma4-e2b-q4km \\");
        eprintln!(
            "      provn-gemma4-e2b-q4km.gguf --local-dir ~/.provn/models{}",
            RESET
        );
        eprintln!();
        return 1;
    }

    // Find llama-server on PATH; fall back to bare name and let the OS error.
    let llama_bin = std::process::Command::new("which")
        .arg("llama-server")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "llama-server".to_string());

    // Extract port from endpoint URL (e.g. "http://localhost:8080" → 8080).
    let port: u16 = cfg
        .layers
        .semantic
        .endpoint
        .rsplit(':')
        .next()
        .and_then(|s| s.trim_matches('/').parse().ok())
        .unwrap_or(8080);

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
            eprintln!();
            if server_healthy() {
                eprintln!("  {}●  already online{}  ·  127.0.0.1:8080", GREEN, RESET);
                eprintln!();
                return 0;
            }
            eprintln!("  {}Layer 3  ·  Semantic AI{}", BOLD, RESET);
            eprintln!(
                "  {}auto-start is not yet supported on this platform{}",
                YELLOW, RESET
            );
            eprintln!(
                "  {}Start llama-server manually, then run {}provn server status{}{}",
                DIM, CYAN, RESET, DIM
            );
            eprintln!(
                "  {}https://github.com/ashvinctrl/Provn#layer-3-semantic-ai{}",
                DIM, RESET
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

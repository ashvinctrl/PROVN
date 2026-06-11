# Changelog

All notable changes to Provn are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-06-11

Deployment release: makes Provn adoptable on existing repos and a first-class
GitHub Code Scanning citizen.

### Added
- **Findings baseline** (`provn baseline [path]`, `.provn/baseline.json`).
  Accept the current state of a repo so only *new* secrets are flagged.
  Fingerprint is `SHA-256(file \0 rule \0 secret)`: the baseline never stores
  a plaintext secret, and because the secret value is in the hash, a different
  or rotated secret is never suppressed. `--no-baseline` ignores it.
- **History scanning** (`provn scan-history [--max-commits N] [--json]`).
  Walks git history in a single pass and reports secrets introduced in past
  commits — the ones already-committed that pre-commit hooks can't catch.
- **SARIF 2.1.0 output** (`provn check --format sarif`). Tier→level mapping
  (T0 error / T1 warning / T2 note / T3 none), rule catalog, physical
  locations, and stable `partialFingerprints`. The raw secret is never
  included. New `provn-sarif.yml` workflow uploads to GitHub Code Scanning.
- **`.gitignore`-aware directory scans** — `provn check <dir>` and
  `provn baseline` skip git-ignored paths (build output, vendored deps) via a
  single `git check-ignore` pass; falls back to scanning all files outside a
  git repo.

### Security
- Baseline and SARIF outputs are covered by tests asserting they contain no
  plaintext secret; the baseline's "a changed secret is never suppressed"
  property is unit- and integration-tested.
- Directory walks no longer follow symlinks, so a symlink committed into a repo
  cannot make `provn check .` read and surface a file outside the tree.
- All subprocess calls use argument arrays (no shell), and the detection regex
  engine (Rust `regex`) is linear-time, so there is no shell-injection or
  ReDoS surface. History scans are bounded by `--max-commits` (default 1000).

## [0.1.0] — 2026-06-11

Substantial detection, reliability, and CI-integration release. Pre-1.0, so
the version reflects a large additive feature set rather than a stable API.

### Added
- **Runtime-loadable pattern set** (`provn-cli/patterns.toml`, embedded at
  compile time, overridable via `layers.regex.patterns_file`) — 45 built-in
  patterns spanning AWS/Azure/GCP/Alibaba/DigitalOcean, Vault/kubeconfig,
  GitHub/GitLab/npm/PyPI, Stripe/Square, Slack/Twilio/SendGrid/Mailgun/
  Telegram/Discord/Shopify/Heroku, OpenAI/Anthropic/HuggingFace/Replicate/Groq,
  BIP39 mnemonics, WIF keys, JWTs, DB connection strings, and basic-auth URLs.
  Each pattern has ≥2 positive and ≥1 negative test.
- **Split-string reassembly** — `"AKIA" + "IOSF..." + "..."` is collapsed and
  re-scanned, defeating concatenation obfuscation.
- **Hex-encoded-secret detection** when a key/secret/token variable holds a
  hex blob (which pure-checksum entropy filtering would otherwise skip).
- **Span-precise redaction** — only the secret substring is replaced, leaving
  the surrounding code (variable name, quotes, assignment) intact.
- **Per-extension entropy thresholds** and a regex **allowlist** in `provn.yml`.
- **Non-interactive / CI support**: `scan --fail-on T0,T1`, `scan --auto-redact`,
  `scan --json` (JSON lines), and automatic TTY detection so hooks never hang.
- **`provn check <directory>`** — recursive working-tree scan.
- **`provn check-range <old> <new>`** and **`provn install --pre-push`** — a
  pre-push gate that scans every outgoing commit range.
- **`.github/workflows/provn-enforce.yml`** — CI hard gate blocking T0/T1 on
  push and PR (the bypass-proof complement to local hooks).
- **Structured audit fields**: `provn_version`, `scan_duration_ms`, and
  `ai_layer` (records `skipped` when Layer 3 was wanted but unavailable).
- TypeScript / TSX parsing via `tree-sitter-typescript`.
- Adversarial integration suite (`provn-cli/tests/adversarial.rs`): 7/7
  obfuscation cases detected, 0 false positives on 5 benign-but-high-entropy
  shapes.

### Fixed
- **AST layer no longer misses JS/TS secrets** — `const`/`let`/`var`
  declarations (`variable_declarator`), `assignment_expression`, and object
  literal pairs are now detected. Previously only the Python `assignment` node
  kind was handled, so `const apiKey = "..."` was silently skipped.
- **AST findings report the correct file line** — rows in the joined diff
  source are mapped back to real file line numbers.
- **`exclude_dirs` matches whole path components**, not substrings — `dist` no
  longer skips `distributed/`, `build` no longer skips `buildkit.py`.
- Dead diff line-counter branch removed; context lines advance the new-file
  counter correctly.

### Changed
- Regex matching uses capture groups, enabling the exact-secret span used by
  redaction.
- Entropy layer reports the highest-entropy token on a line, not the first.
- Dependency hygiene: removed unused `tokio` and `ed25519-dalek`; `libc` is now
  macOS-only; `uuid` moved to dev-dependencies; added `toml` and
  `tree-sitter-typescript`.

### Notes
- Distribution metadata (npm `provn-cli`, Homebrew tap, GitHub release URLs,
  HuggingFace model) still points at the upstream `ashvinctrl/*` namespace.
  Publishing under a different account requires updating those URLs first —
  the version bump alone does not change where binaries are fetched from.

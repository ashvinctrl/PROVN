# Changelog

All notable changes to Provn are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **2 structured infrastructure / IP-disclosure detectors** (63 → 65 rules):
  `cloud_storage_uri` (object-storage URIs — `s3://`, `gs://`, `gcs://`,
  `az://`, `abfss://`, `wasbs://` — pointing at org-controlled buckets) and
  `internal_hostname` (`.internal`, `.corp`, `.intranet`, `.lan`, and k8s
  `.svc.cluster.local`, anchored to a network-authority context so dotted
  package names like `com.corp.internal` are not mistaken for hosts). These
  catch proprietary data-location and network-topology leaks that previously
  only the optional Layer 3 model could, lifting offline IP recall on the
  adversarial corpus from **18.4% (14/76) to 30.3% (23/76)** with no change to
  the false positive rate (still 1.0%, 1/104) — measured, not projected. Both
  ship at medium tier / medium confidence (a review signal, not a hard block)
  with positive/negative unit cases, and the gain is locked by a new IP-recall
  regression gate.
- **18 new built-in secret patterns** (45 → 63 rules): Terraform Cloud,
  Databricks, Doppler, Grafana service accounts, Docker Hub, RubyGems, Stripe
  webhook secrets, Slack app tokens, Postman, Linear, Notion, Atlassian, New
  Relic, Datadog, PlanetScale, Supabase, Google OAuth client secrets, and age
  keys. All prefix- or context-anchored to keep false positives near zero; each
  ships with positive/negative unit cases.
- **AST Layer 2 now covers Go and Java** (`tree-sitter-go`, `tree-sitter-java`)
  in addition to Python/JS/TS/TSX — Go `apiKey := "..."` / `var`/`const` and
  Java field/local declarations now reach the taint layer instead of regex+
  entropy only.
- **18 new-provider fixtures added to `realistic.jsonl`** (now 94 samples: 48
  secrets + 46 clean) so the benchmark exercises the broadened detection;
  measured secret recall 100% (48/48), precision 100%, FPR 0% (0/46).
- **`provn bench [corpus.jsonl]`** — reproducible detection benchmark. Runs the
  deterministic layers (Layer 1+2, semantic off) over a labelled JSONL corpus
  and reports precision, false positive rate, secret recall, IP/prompt recall,
  and per-snippet latency. `--json` for machine output; lists missed leaks and
  false alarms so gaps are visible.
- **Two committed corpora**: `provn-cli/tests/corpus/leakbench.jsonl` (229
  adversarial samples, every leak tagged `secret` vs `ip`) and
  `provn-cli/tests/corpus/realistic.jsonl` (94 samples: 48 real-format secrets
  + 46 secret-adjacent clean snippets — the representative real-world signal).
- **Regression gate** (`provn-cli/tests/leakbench.rs`) — fails CI if recall
  drops or the false positive rate climbs on either corpus.
- `provn.yml` excludes the `corpus` test-fixture directory so Provn's own
  enforcement does not block on its intentionally-fake benchmark secrets.

### Fixed
- **Placeholder false positives**: documentation/template stand-ins like
  `api_key = "your-api-key-here"` and `password = "<YOUR_PASSWORD>"` are no
  longer flagged. A shared placeholder filter now covers `<...>`,
  `your-…-here`, `${…}`, `{{…}}`, `test_`/`fake_` prefixes, and `changeme`, and
  is applied in both the regex and AST layers.
- **Password-only connection strings**: `redis://:password@host` (and other <!-- provn:allow -->
  schemes with an empty username) are now detected — the `database_url` rule
  previously required a `user:pass@` pair.
- **Credential `*_key` variable names**: `encryption_key`, `access_key`,
  `signing_key`, `session_key`, and `master_key` are now tracked by the AST
  layer (benign names such as `primary_key`/`cache_key` stay clean).
- Combined effect on the realistic corpus: secret recall 93.5% → 100%,
  precision 93.5% → 100%, FPR 5.0% → 0%.
- **Dropped findings on multi-finding files**: the medium-confidence (Layer 3
  candidate) pool was capped at 3 *before reporting*, so a file with more than
  three ambiguous findings silently lost the lowest-confidence ones (e.g. an
  `s3://` data-location leak hidden behind several internal-hostname hits). The
  cap now bounds only the expensive semantic-model fan-out; every candidate
  above the reporting floor is surfaced.

### Changed
- README performance numbers are now the values `provn bench` actually produces
  — realistic corpus 100% secret recall / 100% precision / 0% FPR; adversarial
  corpus 97.9% precision / 1.0% FPR / 65.3% secret recall — replacing the
  previous unsubstantiated "97% recall / 1.2% FPR" claim. Reproducible from a
  single command.
- `scripts/run-leakbench.sh` now builds the CLI and runs `provn bench` plus the
  regression gate, instead of referencing scripts that did not exist.

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

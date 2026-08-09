# Provn

<p align="center">
  <img src="https://raw.githubusercontent.com/ashvinctrl/Provn/main/docs/images/provn-logo.png" alt="Provn terminal screenshot" width="560" />
</p>

<p align="center"><strong>AI powered secret and IP leak detection that runs before code leaves your machine.</strong></p>

<p align="center"><code>npm install -g @ashvinctrl/provn</code></p>
<p align="center"><code>brew install ashvinctrl/tap/provn</code></p>

Provn is a local first pre commit scanner that blocks secrets, API keys, tokens, private keys, and proprietary snippets before they land in git. Layer 1 and Layer 2 work immediately. Layer 3 AI is optional and installs separately.

## Install

### CLI only

```bash
npm install -g @ashvinctrl/provn
```

```bash
brew install ashvinctrl/tap/provn
```

```bash
curl -fsSL https://raw.githubusercontent.com/ashvinctrl/Provn/main/install.sh | bash
```

### Quick start without cloning

```bash
cd your-repo
provn install
git add .
git commit -m "first protected commit"
```

### Add the AI layer later

Layer 3 is optional. Layers 1 and 2 do all the work above without it.

```bash
provn model install     # downloads NVIDIA Nemotron 3 Nano 4B (Q4_K_M, 2.8 GB)
provn server start      # runs it on 127.0.0.1:8080
provn server status
```

No Hugging Face account, no `hf` CLI, no login. `provn model list` shows what
is available and what is already on disk. You do need `llama-server`
(llama.cpp) on PATH — `brew install llama.cpp`.


## Quick Start

**1. Install the pre commit hook in your repo**

```bash
cd your-repo
provn install
```

**2. Commit as normal. Provn runs automatically.**

```bash
git add .
git commit -m "add feature"
#   ✓  clean  12ms
```

**3. Watch it catch a real secret**

```bash
echo 'api_key = "<paste-real-api-key-here>"' >> config.py
git add config.py && git commit -m "oops"
#
# Example output when the staged file contains a live key:
#   ✗  blocked  [T1]
#   Matched pattern: generic_api_key  via regex
#   config.py:1
#
#   - api_key = "<paste-real-api-key-here>"
#   + PROVN_REDACTED_API_KEY_1
#
#   Accept redaction? [y/N]
```

## Commands

```
provn                          Status dashboard with layers, hook, and server state
provn check <path>             Scan a file OR directory tree for secrets or IP leaks
provn check --format sarif <p> SARIF 2.1.0 output for GitHub Code Scanning
provn check --json <path>      Machine readable JSON for CI
provn check --fail-on T0,T1    Fail only on the listed tiers (default: any finding)
provn scan                     Scan staged git changes (pre-commit hook mode)
provn scan --fail-on T0,T1     Exit non-zero on listed tiers, never prompt (CI-safe)
provn scan --auto-redact       Redact blocked findings without prompting
provn scan --json              Emit findings as JSON lines
provn check-range <old> <new>  Scan a commit range (pre-push hook mode)
provn check-range --format sarif  SARIF for a diff, for PR-scoped code scanning
provn scan-history             Scan all of git history for secrets ever committed
provn baseline [path]          Accept current findings so only new ones are flagged
provn model list               Show available Layer 3 models and what is installed
provn model install [id]       Download a Layer 3 model into ~/.provn/models
provn server start|stop|status Manage the Layer 3 AI model server
provn install [--pre-push]     Install the pre-commit hook (and optional push gate)
provn verify-audit             Verify the HMAC audit log chain
```

`--fail-on` means different things by design: on `check` / `check-range` it
*narrows* failure to the listed tiers (without it, any finding fails), while on
`scan` it additionally suppresses the interactive redaction prompt so a hook is
safe to run headless.

### Adopting Provn on an existing repo

A repo with historical secrets or noisy fixtures shouldn't bury you in findings
on day one:

```bash
provn baseline .          # accept everything currently present → .provn/baseline.json
git add .provn/baseline.json && git commit -m "provn baseline"
```

From then on only **new** secrets are flagged. The baseline stores one-way
hashes — never the secret itself — and rotating or changing any secret yields a
new fingerprint that is reported again, so a baseline can never hide a *new*
leak. Run `provn scan-history` to audit what's already buried in past commits.

### Securing a repo before you push

```bash
provn install --pre-push   # pre-commit (fast feedback) + pre-push (full outgoing scan)
provn check .              # scan the entire working tree on demand (respects .gitignore)
```

Pre-commit and pre-push hooks are bypassable with `git commit --no-verify`. The hard gate is CI:
[`.github/workflows/provn-enforce.yml`](.github/workflows/provn-enforce.yml) scans every push and PR and
blocks merge on T0/T1 findings, and [`provn-sarif.yml`](.github/workflows/provn-sarif.yml) uploads results
to GitHub Code Scanning — so a bypassed hook never reaches `main`.


## How it works

Provn runs three detection layers in sequence:

| Layer | Method | Latency | Catches |
|-------|--------|---------|---------|
| 1a | Regex patterns — 72 built-in rules + NFKC normalization + split-string reassembly | <5ms | AWS/Azure/GCP keys, GitHub/GitLab tokens, Stripe/Square, Slack/Twilio/SendGrid, OpenAI/Anthropic/HF, Terraform/Databricks/Doppler, Postman/Linear/Notion/Atlassian, PlanetScale/Supabase, DB URLs, private keys, mnemonics, object-storage URIs, internal hostnames, confidentiality notices, prompt-secrecy instructions, private data paths, safety-control overrides, training configs |
| 1b | Shannon entropy analysis with per-extension thresholds + allowlist | <5ms | High-entropy strings in assignments, hex-encoded secrets |
| 2  | Tree-sitter AST analysis | <50ms | `system_prompt = "..."`, `const apiKey = "..."`, `apiKey := "..."` in Python / JS / TS / TSX / Go / Java <!-- provn:allow --> |
| 3  | Gemma 4 E2B (on-device, optional) | <800ms | Ambiguous IP leaks in the 0.4–0.8 confidence band |

Layer 3 only activates for ambiguous cases. Confident detections from L1 and L2 skip it entirely. The built-in
pattern set lives in [`provn-cli/patterns.toml`](provn-cli/patterns.toml) and can be overridden at runtime via
`layers.regex.patterns_file` — no recompile needed.

**Detection coverage** (measured by `provn-cli/tests/adversarial.rs`): 7/7 obfuscated-secret cases detected
(base64, hex, comment, multiline, split-string, homoglyph, BIP39 mnemonic); 0 false positives across SHA-256
checksums, UUIDs, bcrypt hashes, base64 PNG headers, and semver strings.

**Risk tiers:**

| Tier | Action | Examples |
|------|--------|---------|
| T0 | Hard block | Private keys, DB passwords, cloud credentials |
| T1 | Block + optional redaction | API keys, system prompts, model configs |
| T2 | Warn, allow commit | High-entropy tokens |
| T3 | Log only | Low-signal patterns |


## CI / GitHub Actions

Provn ships as a reusable action, so adopting it is three lines. It downloads
the released binary and verifies its published SHA-256 — no Rust toolchain, no
build step:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }   # check-range needs both sides of the diff
- uses: ashvinctrl/Provn@v1
```

By default it scans only what the push or pull request adds and fails on T0/T1.
To scan the whole tree and publish to GitHub Code Scanning:

```yaml
- uses: ashvinctrl/Provn@v1
  with:
    scan: path
    path: .
    sarif-file: provn.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: provn.sarif
```

| Input | Default | Meaning |
|-------|---------|---------|
| `version` | `latest` | Release tag to run |
| `scan` | `diff` | `diff` (push/PR changes) or `path` (full tree) |
| `path` | `.` | What to scan when `scan: path` |
| `fail-on` | `T0,T1` | Tiers that fail the job; empty string reports only |
| `sarif-file` | — | Write SARIF 2.1.0 here |
| `config` | — | provn.yml to use |

It sets two outputs, `findings` and `clean`.

### pre-commit framework

```yaml
repos:
  - repo: https://github.com/ashvinctrl/Provn
    rev: v0.3.0
    hooks:
      - id: provn
```

Install the binary first — the hook runs it rather than building it.


## Layer 3 optional semantic AI

Layer 3 adjudicates the ambiguous 0.4–0.8 confidence band — mostly unmarked
proprietary algorithms, which no regex can recognise. It is optional, and off
until you configure it.

### Run it locally (default, nothing leaves your machine)

```bash
provn model install     # NVIDIA Nemotron 3 Nano 4B, Q4_K_M, 2.8 GB, open weights
provn server start
provn server status
#   ●  Layer 3 online  ·  127.0.0.1:8080
```

Then in `provn.yml`:

```yaml
layers:
  semantic:
    enabled: true
    model: NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf
    endpoint: http://localhost:8080
    timeout_ms: 2000
```

`provn model list` shows every model Provn can fetch. Requires `llama-server`
(llama.cpp) on PATH.

### Or bring your own API key

If you already pay for an OpenAI-compatible endpoint, point Layer 3 at it
instead of hosting a model. Any provider speaking `/v1/chat/completions` works —
NVIDIA NIM, OpenAI, or your own gateway.

```yaml
layers:
  semantic:
    enabled: true
    endpoint: https://integrate.api.nvidia.com/v1
    api_key_env: NVIDIA_API_KEY      # the variable NAME, never the key itself
    api_model: nvidia/nemotron-3-nano-4b
```

```bash
export NVIDIA_API_KEY=...
```

Two things to be clear about, because they cut against Provn's whole premise:

- **This sends code off your machine.** Provn prints a warning the first time a
  scan transmits to a non-loopback host, rather than doing it quietly. Layers 1
  and 2 always stay local.
- **The key is read from the environment, never from `provn.yml`.** The config
  names a variable; it cannot hold a credential. `provn.yml` is committed to the
  repository it protects, and a scanner whose own config file is a place to put
  secrets would be a bad joke.


## Configuration

`provn.yml` in your repo root. All fields are optional and have sensible defaults:

```yaml
mode: enforce          # enforce | warn | shadow

exclude_dirs:
  - node_modules
  - .git
  - dist

layers:
  regex:   { enabled: true }
  entropy: { enabled: true, threshold: 4.5, min_length: 20 }
  ast:
    enabled: true
    sensitive_vars: [system_prompt, api_key, secret, password, token, private_key]
  semantic:
    enabled: false
    model: NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf
    endpoint: http://localhost:8080
    timeout_ms: 2000
    fallback: layer1          # layer1 | clean
    ambiguous_low: 0.4
    ambiguous_high: 0.8
    api_key_env:              # env var NAME for a hosted endpoint (see Layer 3)
    api_model:                # model id to request from a hosted endpoint

audit:
  enabled: true
  path: .provn/audit.jsonl   # HMAC-chained append-only log
```

**Inline overrides:**

```python
secret = os.getenv("SECRET")  # provn:allow
# provn:skip-file  ← at top of file to skip entirely
```


## Performance

Detection accuracy is measured by `provn bench` against two committed corpora.
Reproduce both:

```bash
cd provn-cli
cargo run --release -- bench tests/corpus/realistic.jsonl
cargo run --release -- bench tests/corpus/leakbench.jsonl
# or, with the regression gate: ./scripts/run-leakbench.sh
```

All numbers below are the deterministic layers only (Layer 1+2, semantic model
off), measured 2026-08-09.

**Realistic corpus** ([`realistic.jsonl`](provn-cli/tests/corpus/realistic.jsonl)
— 94 samples: 48 real-format secrets + 46 secret-adjacent clean snippets). This
is the representative real-world signal:

| Metric | Value |
|--------|-------|
| Secret recall | **100%** (48/48) |
| Precision | **100%** |
| False positive rate | 0% (0/46) |
| Engine latency | p50 0.71ms · p95 0.97ms per snippet |

These numbers are on a small representative corpus, not a guarantee of perfect
coverage on every real secret — but the gaps an earlier run surfaced are now
closed: password-only `redis://:pass@…` URLs, `encryption_key`-style variable <!-- provn:allow -->
names, and the `your-api-key-here` / `<YOUR_PASSWORD>` placeholder false
positives are all handled and locked by unit tests.

**Adversarial corpus** ([`leakbench.jsonl`](provn-cli/tests/corpus/leakbench.jsonl)
— 229 samples: 125 leaks + 104 clean). This is the same hard set used to train
the Layer 3 model, so it is deliberately heavy on semantic-IP and obfuscated
cases the offline layers are *not* expected to catch alone:

| Metric | Value |
|--------|-------|
| Precision | 98.8% |
| False positive rate | 1.0% (1/104) |
| Secret recall | 67.3% (33/49) — credential leaks |
| IP / prompt recall | 68.4% (52/76) — most IP now caught offline |

IP recall went 18.4% → 30.3% → **68.4%** over two rounds of detector work, at an
unchanged false positive rate. The first round found proprietary *locations*
(object-storage URIs, internal hostnames). The second finds proprietary
*content*: confidentiality notices, system prompts that instruct the model to
conceal its own instructions, private dataset paths, disabled safety controls,
internal resource identifiers, and fine-tuning hyperparameters. What still
misses is unmarked proprietary algorithms — a scoring function with no comment
saying it is confidential looks like ordinary arithmetic to a regex, and stays a
Layer 3 (semantic) job.

The regression gate in
[`provn-cli/tests/leakbench.rs`](provn-cli/tests/leakbench.rs) fails CI if recall
drops, the false positive rate climbs, or per-snippet latency regresses by an
order of magnitude on either corpus.

End-to-end pre-commit latency (process start + `git diff` + scan) is ~30–50ms on a
clean commit — run `provn scan` in a repo to measure it for your own tree.


## Development

```bash
# Unit tests
cd provn-cli && cargo test

# Lint
cargo clippy -- -D warnings

# Fine-tune Layer 3 on Modal A10G (requires Modal account)
cd aegis-model && modal run modal_finetune.py

# Export fine-tuned GGUF
modal run modal_finetune.py::main_gguf
```


## Credits

- Regex patterns inspired by [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT)
- Layer 3 model: Gemma 4 E2B fine-tuned on LeakBench dataset


MIT License

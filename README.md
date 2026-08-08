# Provn

<p align="center">
  <img src="https://raw.githubusercontent.com/ashvinctrl/Provn/main/docs/images/provn-logo.png" alt="Provn terminal screenshot" width="560" />
</p>

<p align="center"><strong>AI powered secret and IP leak detection that runs before code leaves your machine.</strong></p>

<p align="center"><code>npm install -g provn-cli</code></p>
<p align="center"><code>brew install ashvinctrl/tap/provn</code></p>

Provn is a local first pre commit scanner that blocks secrets, API keys, tokens, private keys, and proprietary snippets before they land in git. Layer 1 and Layer 2 work immediately. Layer 3 AI is optional and installs separately.

## Install

### CLI only

```bash
npm install -g provn-cli
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

You do **not** need to clone the Provn repo to use Layer 3. Install the CLI first, then download the model separately from Hugging Face.

Model page:
[https://huggingface.co/ashvinctrl/provn-gemma4-e2b-q4km](https://huggingface.co/ashvinctrl/provn-gemma4-e2b-q4km)

**macOS / Linux**

```bash
brew install hf
hf auth login
mkdir -p ~/.provn/models
hf download ashvinctrl/provn-gemma4-e2b-q4km provn-gemma4-e2b-q4km.gguf --local-dir ~/.provn/models
llama-server -m ~/.provn/models/provn-gemma4-e2b-q4km.gguf --host 127.0.0.1 --port 8080
provn server status
```

**Windows PowerShell**

```powershell
pip install "huggingface_hub[cli]"
hf auth login
New-Item -ItemType Directory -Force "$HOME\.provn\models"
hf download ashvinctrl/provn-gemma4-e2b-q4km provn-gemma4-e2b-q4km.gguf --local-dir "$HOME\.provn\models"
llama-server -m "$HOME\.provn\models\provn-gemma4-e2b-q4km.gguf" --host 127.0.0.1 --port 8080
provn server status
```


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
provn scan                     Scan staged git changes (pre-commit hook mode)
provn scan --fail-on T0,T1     Exit non-zero on listed tiers, never prompt (CI-safe)
provn scan --auto-redact       Redact blocked findings without prompting
provn scan --json              Emit findings as JSON lines
provn check-range <old> <new>  Scan a commit range (pre-push hook mode)
provn scan-history             Scan all of git history for secrets ever committed
provn baseline [path]          Accept current findings so only new ones are flagged
provn server start|stop|status Manage the Layer 3 AI model server
provn install [--pre-push]     Install the pre-commit hook (and optional push gate)
provn verify-audit             Verify the HMAC audit log chain
```

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
| 1a | Regex patterns — 65 built-in rules + NFKC normalization + split-string reassembly | <5ms | AWS/Azure/GCP keys, GitHub/GitLab tokens, Stripe/Square, Slack/Twilio/SendGrid, OpenAI/Anthropic/HF, Terraform/Databricks/Doppler, Postman/Linear/Notion/Atlassian, PlanetScale/Supabase, DB URLs, private keys, mnemonics, object-storage URIs, internal hostnames |
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

Use the workflow in [`.github/workflows/provn-ci.yml`](.github/workflows/provn-ci.yml) as the current source of truth.

If you want a simple manual CI step today, build from source inside the workflow:

```yaml
- uses: actions/checkout@v4
- uses: actions-rust-lang/setup-rust-toolchain@v1
  with:
    toolchain: stable
- name: Build Provn
  run: cd provn-cli && cargo build --release
- name: Scan changed file
  run: ./provn-cli/target/release/provn check --json path/to/file
```

The built-in workflow can publish the npm package on release when npm publishing is configured.


## Layer 3 optional semantic AI

Layer 3 runs a fine-tuned Gemma 4 E2B model locally. No data leaves your machine.

```bash
# 1. Download the model
mkdir -p ~/.provn/models
# Place provn-gemma4-e2b-q4km.gguf in ~/.provn/models/

# 2. Start the server (auto-restarts at login)
provn server start

# 3. Confirm it's online
provn server status
#   ●  Layer 3 online  ·  127.0.0.1:8080
```

Enable in `provn.yml`:

```yaml
layers:
  semantic:
    enabled: true
    model: provn-gemma4-e2b-q4km.gguf
    endpoint: http://localhost:8080
    timeout_ms: 2000
```


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
    model: provn-gemma4-e2b-q4km.gguf
    endpoint: http://localhost:8080
    timeout_ms: 2000
    fallback: layer1          # layer1 | clean
    ambiguous_low: 0.4
    ambiguous_high: 0.8

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
off), measured 2026-06-27.

**Realistic corpus** ([`realistic.jsonl`](provn-cli/tests/corpus/realistic.jsonl)
— 94 samples: 48 real-format secrets + 46 secret-adjacent clean snippets). This
is the representative real-world signal:

| Metric | Value |
|--------|-------|
| Secret recall | **100%** (48/48) |
| Precision | **100%** |
| False positive rate | 0% (0/46) |
| Engine latency | sub-millisecond per snippet |

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
| Precision | 98.2% |
| False positive rate | 1.0% (1/104) |
| Secret recall | 65.3% (32/49) — credential leaks |
| IP / prompt recall | 30.3% (23/76) — structured IP now offline; the rest needs Layer 3 |

The IP-recall lift (18.4% → 30.3%) comes from two structured detectors —
object-storage URIs (`s3://`, `gs://`, `az://…`) and internal hostnames
(`.internal`, `.corp`, `.svc.cluster.local`) — that catch proprietary
data-location and topology leaks offline. The remaining IP misses are
proprietary algorithms and system prompts, which stay a Layer 3 (semantic) job.

The regression gate in
[`provn-cli/tests/leakbench.rs`](provn-cli/tests/leakbench.rs) fails CI if recall
drops or the false positive rate climbs on either corpus.

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

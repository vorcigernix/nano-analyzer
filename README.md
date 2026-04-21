# Nano-analyzer

**A minimal LLM-powered zero-day vulnerability scanner by [AISLE](https://aisle.com).**

![aisle-nano-analyzer-diagram](aisle-nano-analyzer.png)

> **Research prototype for demonstration purposes.** This tool can detect real zero-day vulnerabilities, but it is still biased toward C/C++ memory safety bugs and will produce false positives. Always verify results manually.

## What It Does

Nano-analyzer is a Go CLI that sends source code through a three-stage LLM pipeline:

1. **Context generation**: a model writes a security briefing about the file, including untrusted data flow and fixed-size buffers.
2. **Vulnerability scan**: the scanner model uses that context to hunt for zero-day bugs function by function and output structured findings.
3. **Skeptical triage**: each finding is challenged over multiple rounds by a reviewer that can grep the codebase for evidence. An arbiter makes the final call.

Results are saved as Markdown, JSON, and SARIF files for human and CI review. The Go implementation was adapted from the original code by Adam Sobotka and Codex. The original repository does not accept contributions, so ongoing work for the Go version lives here.

## Current Limitations

- **C/C++ bias.** Prompts, examples, and heuristics are tuned for C/C++ memory safety bugs. Other languages can be scanned, but results are less reliable.
- **False positives.** Even with triage, expect findings that do not hold up under manual review.
- **False negatives.** A clean scan does not mean the code is safe.
- **Mostly single-file analysis.** Files are scanned independently, with grep-assisted triage for cross-file evidence. Deeper cross-file bugs can still be missed.
- **LLM-dependent.** Different models will find different issues and hallucinate different false positives.

## Setup

### Requirements

- Go 1.22+
- An OpenAI API key or an OpenRouter API key
- Optional: [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) for triage grep lookups

### Run From Source

```bash
git clone https://github.com/vorcigernix/nano-analyzer.git
cd nano-analyzer
go run ./cmd/nano-analyzer scan --help
```

### API Keys

```bash
# For OpenAI models, such as "gpt-4o-mini":
export OPENAI_API_KEY=sk-...

# For OpenRouter models, such as "qwen/qwen3-32b":
export OPENROUTER_API_KEY=sk-or-...
```

By default the scanner determines which key to use from the model name: models containing `/` route through OpenRouter; other models route through OpenAI. Override this with `--provider openai` or `--provider openrouter`.

## Usage

```bash
# Scan a single file
go run ./cmd/nano-analyzer scan ./path/to/file.c

# Scan a directory recursively
go run ./cmd/nano-analyzer scan ./path/to/src/

# Use a different model
go run ./cmd/nano-analyzer scan --model gpt-5.4 ./src

# Control parallelism
go run ./cmd/nano-analyzer scan --parallel 30 ./src

# Point triage grep at the full repo root
go run ./cmd/nano-analyzer scan --repo-dir ./ ./lib/crypto/

# Only surface high-confidence survivors
go run ./cmd/nano-analyzer scan --min-confidence 0.7 ./src

# Fail locally on validated high-or-above findings with at least 70% confidence
go run ./cmd/nano-analyzer scan --fail-mode validated --fail-on high --fail-confidence 0.7 ./src
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `path...` | `.` | One or more files/directories to scan |
| `--model` | `gpt-4o-mini` | Model for context, scan, and triage stages |
| `--provider` | `auto` | `auto`, `openai`, or `openrouter` |
| `--format` | `json,markdown,sarif` | Output formats to write |
| `--parallel` | `50` | Max concurrent scan calls |
| `--max-connections` | `parallel + triage-parallel` | Total API call cap |
| `--scope` | `all` | `all` or `changed`; `changed` uses GitHub event metadata plus `git diff` |
| `--triage` | `enabled` | `enabled` or `disabled` |
| `--triage-threshold` | `medium` | Triage findings at or above this severity |
| `--triage-rounds` | `5` | Triage rounds per finding |
| `--triage-parallel` | `50` | Max concurrent triage findings |
| `--min-confidence` | `0.0` | Only write survivor findings above this confidence |
| `--fail-mode` | `never` | `never`, `validated`, or `raw` |
| `--fail-on` | `high` | Fail on findings at or above this severity when fail mode applies |
| `--fail-confidence` | `0.7` | Minimum validated confidence required to fail |
| `--project` | directory name | Project name used in triage prompts |
| `--repo-dir` | auto | Repo root for grep and changed-file lookups |
| `--output-dir` | `~/nano-analyzer-results/<timestamp>/` | Where to save results |
| `--max-chars` | `200,000` | Skip files larger than this |
| `--verbose-triage` | off | Show extra triage progress |

## GitHub Actions

Use the bundled composite action to scan pull requests as part of your GitHub flow.

### Minimal Workflow

Add an Actions secret named `OPENAI_API_KEY` in the target repository, then create:

`.github/workflows/nano-analyzer.yml`

```yaml
name: nano-analyzer

on:
  pull_request:

permissions:
  contents: read
  security-events: write
  issues: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: vorcigernix/nano-analyzer@v0.2.5
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

That is enough to scan changed files on pull requests, upload SARIF when GitHub code scanning is available, post a PR comment fallback when it is not available, and fail on validated high-or-above findings. The `issues: write` and `pull-requests: write` permissions are used only for the fallback PR comment.

If you are using an organization mirror, replace only the `uses:` line:

```yaml
      - uses: weareaisle/nano-analyzer@v0.2.5
```

The action downloads a release binary by default and falls back to building from source if no matching binary is available. To force one behavior, set `install-mode` to `binary` or `source`.

The default OpenAI model is `gpt-4o-mini` for compatibility with more API projects. If your project has GPT-5 access, set `model` explicitly.

### Common Options

Non-blocking trial:

```yaml
      - uses: vorcigernix/nano-analyzer@v0.2.5
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        with:
          fail-mode: never
```

Explicit PR gate:

```yaml
      - uses: vorcigernix/nano-analyzer@v0.2.5
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        with:
          target: .
          scope: changed
          fail-mode: validated
          fail-on: high
          fail-confidence: "0.7"
```

Use a different OpenAI model:

```yaml
      - uses: vorcigernix/nano-analyzer@v0.2.5
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        with:
          model: gpt-5
```

Stricter gate:

```yaml
with:
  target: .
  scope: changed
  fail-mode: validated
  fail-on: medium
  fail-confidence: "0.8"
```

OpenRouter example:

```yaml
env:
  OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
with:
  provider: openrouter
  model: qwen/qwen3-32b
  target: .
  scope: changed
```

Disable the PR comment fallback:

```yaml
with:
  pr-comment: false
```

Always post or update the PR comment, even when SARIF upload succeeds:

```yaml
with:
  pr-comment: always
```

### Repository Setup

1. Add `OPENAI_API_KEY` in `Settings` -> `Secrets and variables` -> `Actions`.
2. Keep `fetch-depth: 0`; changed-file scans need enough Git history to diff the PR.
3. Start with `fail-mode: never` if you want a non-blocking rollout.
4. Switch to `fail-mode: validated` once the signal looks useful.
5. Enable branch protection and require the `scan` job before merging.

The default PR setup scans changed files, writes a job summary, uploads SARIF when GitHub code scanning is available, and fails only when triage-validated findings meet the configured severity and confidence thresholds. Private repositories need GitHub Code Security or GitHub Advanced Security for SARIF ingestion; when code scanning is unavailable, the action posts the audit result as a PR comment and skips the artifact upload. If GitHub rejects the PR comment because workflow permissions are too restrictive, the action keeps the artifact upload as a fallback.

GitHub does not expose repository secrets to untrusted fork PRs in normal `pull_request` workflows. Keep this workflow on `pull_request`; do not switch it to `pull_request_target` unless you have a separate design that prevents forked code from accessing secrets.

## Output

Results are saved to `~/nano-analyzer-results/<timestamp>/` or `--output-dir`:

```text
<timestamp>/
├── summary.json              # machine-readable scan summary
├── summary.md                # human-readable scan summary
├── pr-comment.md             # compact PR comment fallback
├── results.sarif             # GitHub code scanning output
├── reports/                  # raw scanner output per file
├── contexts/                 # context briefing per file
├── results/                  # full result JSON per file
├── triages/                  # detailed triage reasoning
│   └── T0001_<file>_<title>.md
├── findings/                 # findings that survived triage
│   └── VULN-001_<file>.md
├── triage.json               # all triage verdicts
└── triage_survivors.md       # summary of validated findings
```

## How Triage Works

When a scan finds a medium-or-above severity issue by default:

1. A skeptical reviewer examines the finding against the actual code and can grep the codebase to verify or refute defenses.
2. This repeats for multiple rounds, with each reviewer seeing prior arguments.
3. A final arbiter reads the rounds and makes a VALID/INVALID call.
4. The confidence score reflects the fraction of rounds that said VALID.

Findings that survive triage are written to the `findings/` directory with the reasoning chain.

## Disclaimer

This tool is a research prototype. It is not a replacement for professional security audits, manual code review, or established static analysis tools. Do not rely on it as your sole security assessment. Use at your own risk.

## License

Apache License 2.0

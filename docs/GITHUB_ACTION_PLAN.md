# RakshakAI v2 — GitHub Action Roadmap

> **Vision:** Automated security review on every pull request — vulnerability detection, scoring, patching.

---

## Action overview

| Feature | Priority | Status |
|---------|----------|--------|
| PR vulnerability scan | P0 | 📝 Planned |
| Security score (pass/fail) | P0 | 📝 Planned |
| Inline PR comments | P1 | 📝 Planned |
| Patch suggestions | P1 | 📝 Planned |
| Custom CWE ignore list | P2 | 📝 Planned |
| Baseline diff (new vs existing) | P2 | 📝 Planned |
| SARIF export | P2 | 📝 Planned |
| Dashboard / summary artifact | P2 | 📝 Planned |

---

## Usage

### Minimal

```yaml
# .github/workflows/rakshakai-review.yml
name: RakshakAI Security Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Muneerali1995/rakshakai-github-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Advanced

```yaml
- uses: Muneerali1995/rakshakai-github-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    mode: full              # diff | full | changed (default: diff)
    fail-on: critical       # none | high | critical (default: critical)
    ignore-cwes: |
      CWE-327
      CWE-352
    api-url: https://api.rakshakai.dev/v2/scan
    api-key: ${{ secrets.RAKSHAKAI_API_KEY }}
    sarif-output: true
    max-comments: 20        # prevent excessive comments (default: 10)
```

---

## Architecture

```
GitHub Push/PR
  ↓
GitHub Action worker
  ├── Collect changed files (git diff)
  ├── Send files to RakshakAI backend
  │   ├── Cloud API (default) → POST /v2/review
  │   ├── Self-hosted → POST /v2/review (self URL)
  │   └── Local runner → CLI v2/deploy/cli.py review
  ├── Parse structured findings
  ├── Post PR comments (inline)
  └── Exit with status (pass/fail)
```

### Backend decision tree

```
Action run on:
├── GitHub-hosted runner (no GPU)
│   └── Must use RakshakAI Cloud API or self-hosted backend
│       ├── API key provided? → Cloud API
│       └── Custom URL? → Self-hosted backend
└── Self-hosted runner (GPU capable)
    └── Can use local CLI with GGUF/Ollama (lower latency, no API fees)
```

---

## Review output

### Inline comment

For each vulnerability found, the action posts an inline PR comment:

> **🚨 Vulnerability found: SQL Injection (CWE-89)**
>
> **Severity:** High
> **File:** `src/db/users.py`, line 15
> **Confidence:** 0.92
>
> **Root cause:** User-controlled `uid` is concatenated into a raw SQL string.
>
> **Suggestion:**
> ```python
> # Before
> cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
> # After
> cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
> ```

### Step summary

```
## 🔍 RakshakAI Security Review

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 3 |
| Medium   | 2 |
| Low      | 0 |

✅ 23 files scanned
❌ 1 critical vulnerability found (blocking merge)
```

### SARIF output

For GitHub Advanced Security integration:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "RakshakAI", "version": "2.0.0" }},
    "results": [
      {
        "ruleId": "CWE-89",
        "level": "error",
        "message": { "text": "SQL Injection vulnerability" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/db/users.py" },
            "region": { "startLine": 15 }
          }
        }]
      }
    ]
  }]
}
```

---

## Configuration reference

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github-token` | ✅ | — | `${{ secrets.GITHUB_TOKEN }}` |
| `mode` | ❌ | `diff` | `diff` (only changed lines), `full` (entire files), `changed` (all changed files) |
| `fail-on` | ❌ | `critical` | `none`, `high`, `critical` |
| `ignore-cwes` | ❌ | `""` | Newline-separated CWE IDs to ignore |
| `api-url` | ❌ | `https://api.rakshakai.dev/v2/scan` | Custom backend URL |
| `api-key` | ❌ | `""` | API key (required if using cloud API) |
| `sarif-output` | ❌ | `false` | Generate SARIF file |
| `max-comments` | ❌ | `10` | Max inline comments per run |
| `cli-path` | ❌ | `""` | Path to local `cli.py` (for self-hosted runners) |

---

## Implementation plan

### Phase 1: MVP (2 weeks)

- Action that:
  - Collects changed files from PR diff
  - Sends to RakshakAI Cloud API
  - Posts PR comments
  - Exits with pass/fail
- Docker-based action (runs in `node:18` container, calls API)

### Phase 2: Local mode (1 week)

- Support for self-hosted runners with local CLI backend
- Download/install Ollama model automatically
- No API key required — fully offline

### Phase 3: Enhanced (2 weeks)

- SARIF export
- Custom CWE ignore list
- Baseline diff (only new vulnerabilities, suppress existing)
- Summary dashboard artifact

### Phase 4: Marketplace

- Submit to GitHub Marketplace
- Add `verified creator` badge
- Create landing page with screenshots

---

## Distribution

| Channel | Audience | Priority |
|---------|----------|----------|
| GitHub Marketplace | All GitHub users | P0 |
| GitHub Actions docs | CI/CD users | P1 |
| Security blog posts | DevSecOps teams | P2 |

---

## Competitive comparison

| Feature | RakshakAI Action | Snyk PR Checks | Semgrep CI | CodeQL |
|---------|-----------------|----------------|------------|--------|
| Open source | ✅ Apache 2.0 | ❌ Proprietary | ✅ LGPL | ❌ Proprietary |
| Local mode (no API) | ✅ (Ollama) | ❌ | ✅ | ❌ |
| Inline PR comments | ✅ | ✅ | ✅ | ✅ |
| Patch suggestions | ✅ | ❌ | ❌ | ❌ |
| CWE lookup | ✅ | ✅ | ✅ | ✅ |
| SARIF export | ✅ | ✅ | ✅ | ✅ |
| Custom rules | ❌ (planned) | ✅ | ✅ | ✅ |
| Multi-language | ✅ (13) | ✅ | ✅ | ✅ |
| Cost | Free | $$$ | Free (OSS) | Free (public) |

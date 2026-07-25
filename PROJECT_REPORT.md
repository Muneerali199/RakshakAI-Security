# RakshakAI (रक्षक AI) — Project Report

> India's First Open Security AI
> CPU vulnerability classifier + Security-specialized coding LLM

---

## 1. What is RakshakAI?

A two-tier open-source security analysis platform that detects and fixes code vulnerabilities in real-time. "Rakshak" (रक्षक) means "Protector" in Sanskrit.

| Version | Type | Parameters | Speed | Coverage | Cost |
|---------|------|-----------|-------|----------|------|
| **v1** | CPU Transformer | 1.5M–18M | < 50ms | 21 classes + clean | $0 |
| **v2** | LLM (7B QLoRA) | 7B | < 2.5s | 682 CWEs, 13 languages | ~$22 train |

---

## 2. Problem Statement

- **65%** of vulnerabilities live in application code, not infrastructure
- **28 billion** lines of vulnerable code added yearly
- **$4.45M** average data breach cost (2025)
- **82%** of developers know about security but ship vulnerable code anyway
- **200+ days** average time to discover + fix a critical vuln
- Existing tools: too slow (minutes/hours), too expensive ($10K–$100K/yr), too noisy (30–60% false positives), not private (cloud-based), no fix suggestions

---

## 3. Architecture

```
User Code
    │
    ├──→ v1 (CPU classifier) ─→ Clean? → ✅ Skip (no LLM cost)
    │                             │
    │                             ▼  Suspicious
    │
    └──→ v2 (Security LLM)  ─→ Structured report:
                                ├── vulnerability
                                ├── cwe
                                ├── severity
                                ├── confidence
                                ├── root_cause
                                ├── attack_scenario
                                ├── secure_fix
                                ├── patched_code
                                └── references
```

**v1 (The Reflex):** Custom lightweight transformer. Runs on any CPU. Classifies code snippets into 21 vulnerability types + clean. Acts as fast-path prefilter — clean code never reaches the LLM. 6MB model size.

**v2 (The Brain):** Fine-tuned Qwen2.5-Coder-7B-Instruct using QLoRA (NF4 double-quant, r=64, rsLoRA). Generates structured 9-field security reports. Trained on 96,000+ curated CVE samples.

---

## 4. v1 — CPU Classifier (Production Ready ✅)

| Aspect | Detail |
|--------|--------|
| Architecture | Custom Transformer (6 layers, 256-dim) |
| Parameters | 1.5M (tiny), 7.3M (small), 18M (medium) |
| Model size | 6 MB (vs 500 MB for CodeBERT) |
| Inference | < 50ms on CPU per snippet |
| Classes | 21 vulnerability types + clean |
| Accuracy | 90.3% real-world, 99.88% synthetic |
| Privacy | 100% offline |
| Cost | $0 — runs on laptop |
| Dependencies | Pure PyTorch — no HuggingFace required |

**Detected vulnerabilities:**
SQL_INJECTION, XSS, COMMAND_INJECTION, HARDCODED_SECRET, PATH_TRAVERSAL, WEAK_CRYPTO, SSTI, INSECURE_DESERIALIZATION, JWT_VULNERABILITY, REDOS, CSRF, OPEN_REDIRECT, NULL_DEREFERENCE, MEMORY_LEAK, EMPTY_CATCH, BUFFER_OVERFLOW, RACE_CONDITION, INFINITE_LOOP, LDAP_INJECTION, XXE_INJECTION, CLEAN

---

## 5. v2 — Security LLM (Training Planned)

| Aspect | Detail |
|--------|--------|
| Base model | Qwen2.5-Coder-7B-Instruct (Apache 2.0) |
| Fine-tune method | QLoRA (NF4 double quant, r=64, rsLoRA) |
| Training hardware | 1× AMD MI300X, 192 GB HBM3, ROCm 6.2 |
| Training cost | ~$22 planned ($100 worst-case) |
| Training time | ~11.5 hours (3 SFT phases) |
| Sequence length | 4096 tokens, sample-packed |
| Output | Structured 9-field JSON report |
| Quantization | AWQ 4-bit (vLLM) or GGUF Q5_K_M (llama.cpp) |
| Latency p95 | ≤ 2.5s on 1× MI300X with vLLM |
| CWE coverage | 682 CWE classes |
| Languages | Python, JavaScript, TypeScript, Java, Go, Rust, C, C++, PHP, Ruby, C#, Swift, Kotlin |
| Training data | 96,000+ curated CVE samples |

**Output schema:**
```json
{
  "vulnerability": "SQL Injection",
  "cwe": "CWE-89",
  "severity": "high",
  "confidence": 0.92,
  "root_cause": "User-controlled input concatenated into SQL string...",
  "attack_scenario": "Attacker submits ' OR '1'='1 as user id...",
  "secure_fix": "Use parameterized query with bound parameters.",
  "patched_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
  "references": ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

---

## 6. VS Code Extension

**Location:** `~/Desktop/Rakshak/` (compiled, ready)
**Branding:** Rakshak (was Code Guardian, updated)

### Features

| Feature | Description |
|---------|-------------|
| Real-time scanning | On type (1s debounce), on save, on file switch |
| Manual scan | Command: `Rakshak: Scan Current File` |
| Languages supported | Python, JavaScript, TypeScript, Java, PHP, Go, C#, Ruby |
| Inline diagnostics | Squiggly underlines + Problems panel |
| Hover provider | Rich card: CWE link, OWASP category, description, fix code, "Apply Fix" button |
| Quick-fix (lightbulb) | One-click apply model's patched code |
| Status bar | Shield icon + error/warning counts. Click to scan. Background turns red/yellow |
| Tree view | Dedicated Rakshak tab in Activity Bar. File list with status icons. Expand to see issues. Click to jump to line |
| Configuration | `rakshak.autoScan`, `rakshak.scanDelay`, `rakshak.backendUrl` |

### How it connects
- Sends `POST {backendUrl}/api/scan` with `{ code, filename, language }`
- Backend URL: default `http://127.0.0.1:3000`
- Backend responds with `{ issues: [{ line, message, severity, description, category, cweId, owaspCategory, remediation: { description, example } }], total_issues, scan_time_ms }`

---

## 7. Backend Server

**File:** `server.py` — FastAPI server

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ml/scan` | POST | Scan code (original) |
| `/api/scan` | POST | Scan code (alias for extension) |
| `/ml/health` | GET | Health check |

**Server modes:**
- **Lightweight** — Uses actual ML model (2.7M params, 90.3% accuracy)
- **Mock** — Keyword-based pattern matching for predictable demo results
- Toggle with `RAKSHAK_MOCK=1` environment variable

**Default port:** 3000 (configurable with `--port`)

---

## 8. Demo Setup

### One-command launch:
```bash
cd ~/Desktop/RakshakAI && ./hackathon.sh
```

This starts the server + opens VS Code with extension loaded.

### Manual steps:
```bash
# Terminal 1: Start server
RAKSHAK_MOCK=1 python3 -m uvicorn server:app --port 3000 --host 0.0.0.0

# Terminal 2: Open extension in VS Code dev mode
code ~/Desktop/Rakshak && press F5
```

### Demo files:
- `demo_vulnerable.py` — Contains 5 vulnerabilities (SQLi, CMD inj, hardcoded secrets, XSS, path traversal)

---

## 9. Performance Metrics

| Metric | v1 | v2 Target |
|--------|----|-----------|
| Accuracy | 90.3% (real-world) | — |
| CWE Top-1 accuracy | — | ≥ 78% |
| FPR @ 0.95 recall | — | ≤ 8% |
| Fix success rate | — | ≥ 65% |
| Inference speed | < 50ms | ≤ 2.5s (p95) |
| Parameters | 1.5M–18M | 7B |
| Training cost | $0 | ~$22 |

---

## 10. Integrations

| Integration | Status | Location |
|-------------|--------|----------|
| VS Code Extension | ✅ Compiled, ready | `~/Desktop/Rakshak/` |
| GitHub Action | 🟡 Scaffolded | `v2/integrations/github-action/` |
| CLI | 🟡 Planned | `v2/deploy/cli.py` |
| Ollama | 🟡 Planned | `v2/deploy/Modelfile.rakshakai-v2` |
| FastAPI Server | ✅ Ready | `server.py` |
| PyPI Package | ✅ Published | `rakshakai` |

---

## 11. USPs vs Competition

| Feature | Snyk Code | Semgrep | GitHub Copilot | RakshakAI |
|---------|-----------|---------|----------------|-----------|
| Price | $10K–$100K/yr | Free tier limited | $10–$39/mo | **Free (Apache 2.0)** |
| Privacy | Cloud | Cloud/hybrid | Cloud | **100% offline** |
| Fix suggestions | Basic | None | None | **Patched code + apply** |
| Scan speed | Minutes | Seconds | N/A | **< 50ms (v1)** |
| Languages | 5+ | 8+ | All | **13 (v2)** |
| Root cause analysis | ❌ | ❌ | ❌ | **✅ 9-field report** |
| Open source | ❌ | ✅ (LGPL) | ❌ | **✅ Apache 2.0** |
| CWE coverage | ~100 | ~500 | N/A | **682** |

---

## 12. Roadmap

| Phase | Timeline | Deliverables |
|-------|----------|-------------|
| v1.0 ✅ | Done | CPU classifier, FastAPI server, VS Code extension |
| v2.0.0 🔄 | 2026 H2 | Dataset pipeline, training configs, benchmark |
| v2.0.0-train 🔄 | GPU available | Phase A/B/C training, HuggingFace release |
| v2.0.x 📅 | 2026 H2 | VS Code extension v2, GitHub Action, public API |
| v2.1.x 📅 | 2027 H1 | DPO preference tuning, 14B ablation |
| v3.x 📅 | 2027+ | Multi-file analysis, SBOM, IaC, security education |

---

## 13. Links

- **GitHub:** https://github.com/Muneerali199/RakshakAI
- **License:** Apache 2.0
- **PyPI:** `rakshakai`

---

## 14. Presentation

10-slide Slidev presentation at `presentation/slides.md` with dark cyber-security theme, gradient accents, animated transitions.

**Slides:**
1. Title — India's First Open Security AI
2. The Vulnerability Crisis (problem stats)
3. Why Existing Tools Fail (6 pain points)
4. Solution — Two-Tier Architecture
5. How It Works (pipeline diagram)
6. Performance By Numbers (metrics)
7. VS Code Extension Demo (features)
8. USPs & Competition Comparison
9. Roadmap & Vision
10. Thank You + Call to Action

To view: `cd presentation && npm run dev`

---

*Made in India 🇮🇳*

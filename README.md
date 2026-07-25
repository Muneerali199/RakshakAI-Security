# RakshakAI - AI-Powered Security Code Review Platform

**One platform. Every language. Every vulnerability. Every tool.**

RakshakAI is a full-stack security platform that catches vulnerabilities before they ship. It combines a fine-tuned 7B model with 12+ LLM providers, a rich CLI with multi-agent orchestration, a VSCode extension with one-click fixes, and automatic Notion integration for team reporting.

---

## Demo

**Live scan with Groq (1.3s, 100% confidence):**

```
$rakshakai
$rakshak> /scan demo_vulnerable.py

  [+] Command Injection (CWE-78) — CRITICAL
      Confidence: 100%
      Fix: Replace os.system() with subprocess.run([...])
```

**VSCode Extension:** Right-click red squiggly → "Fix with RakshakAI" → diff preview → apply fix.

**Notion Reports:** Vulnerability reports auto-sync to your team's Notion Security Center dashboard.

---

## Features

### Core Engine
- **12+ LLM Providers** — Groq, Nebius (Kimi K2.7, Qwen 3.5, DeepSeek V4), Ollama, HuggingFace, Fireworks, OpenAI, NVIDIA NIM, and more
- **Sub-second Scanning** — Groq detects CWE-78 in 1.3s with 100% confidence
- **Multi-Agent Swarm** — `/swarm` for parallel analysis across multiple models
- **Self-Consistency Voting** — 3 rounds per scan for reliable detection
- **40+ Language Support** — Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Solidity, Ruby, PHP, and more

### CLI
- **Interactive REPL** with animated UI, tab completion, and streaming responses
- **One-click Fixes** — `/fix` generates patched code with explanations
- **Dashboard** — `/dashboard` for interactive visualizations of scan stats
- **Session History** — `/history` to search past analyses
- **Watch Mode** — `/watch` for continuous file monitoring
- **Git Integration** — `/diff` to scan git changes, `/precommit` for hooks
- **CI Mode** — JSON/SARIF output for GitHub Actions pipelines
- **MCP Server** — Works with Cursor, Claude Code, and any MCP client

### VSCode Extension
- **Dashboard Panel** — Dark-themed security overview with stats cards and severity badges
- **One-click Fix** — Right-click diagnostic → "Fix with RakshakAI" → diff preview → apply
- **Notion Report** — Right-click diagnostic → "Create Notion Report" to sync to your Security Center
- **Provider Picker** — `/chooseProvider` to switch between Groq, Nebius, Ollama, etc.
- **Model Selector** — Pick the right model for your use case (speed vs accuracy)
- **Real-time Scanning** — Code is sent to the local backend on save

### Notion Integration
- **Security Center Dashboard** — Auto-created database with Name, Severity, Status, CWE, Language properties
- **Rich Reports** — Callouts, tables, code blocks, toggles, checklists, severity badges
- **API Endpoints** — `/v2/notion/*` for health, setup, report, status, stats, dashboard
- **Bidirectional Sync** — Local ↔ Notion with queue-based sync

---

## Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+ (for VSCode extension)
- A Groq API key (free tier available)

### 1. Clone and Install

```bash
git clone https://github.com/Muneerali199/RakshakAI-Security.git
cd RakshakAI-Security
pip install -e .
```

### 2. Configure API Keys

```bash
# Required: Groq (free, fast)
echo "GROQ_API_KEY=gsk_your_key_here" > .env

# Optional: Nebius (Kimi K2.7, Qwen 3.5, DeepSeek V4)
echo "NEBIUS_API_KEY=your_key" >> .env

# Optional: Notion
echo "NOTION_TOKEN=ntn_your_token" >> .env
echo "NOTION_DATABASE_ID=your_db_id" >> .env
```

### 3. Start the Server

```bash
python3 -m v2.deploy.server
# Server runs on http://localhost:8080
```

### 4. Run the CLI

```bash
python3 -m v2.cli.main
```

### 5. Install the VSCode Extension

```bash
cd v2/integrations/vscode
npm install
npm run compile
# Press F5 in VSCode to launch the extension
```

---

## Commands

| Command | Description |
|---|---|
| `/scan <file>` | Scan a file for vulnerabilities |
| `/fix <file>` | Generate a security fix |
| `/batch <dir>` | Scan entire directory |
| `/diff` | Scan git diff |
| `/precommit` | Install git pre-commit hook |
| `/watch <dir>` | Watch for file changes |
| `/test [file]` | Run tests (pytest, jest, cargo, go) |
| `/agent <task>` | Run autonomous security agent |
| `/swarm <task>` | Multi-agent orchestration |
| `/index [dir]` | Index codebase for semantic search |
| `/search <query>` | Semantic code search |
| `/models` | List available models |
| `/notion setup` | Connect to Notion Security Center |
| `/notion report` | Generate Notion vulnerability report |
| `/dashboard` | Interactive statistics dashboard |
| `/stats` | Session statistics |
| `/history` | Search past analyses |
| `/help` | Show all commands |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    RakshakAI Platform                    │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│   CLI    │  VSCode  │  Server   │  Notion   │  CI/CD   │
│  (REPL)  │Extension│ (FastAPI) │  (Hub)    │ (GitHub)  │
├──────────┴──────────┴───────────┴───────────┴───────────┤
│              Multi-Provider LLM Router                   │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│  Groq    │  Nebius  │  Ollama   │   HF      │ Fireworks │
│ 1.3s     │ 3.5s     │  local    │  free     │  fast     │
└──────────┴──────────┴───────────┴───────────┴───────────┘
```

### Provider Comparison

| Provider | Speed | Cost | Models |
|----------|-------|------|--------|
| **Groq** | 1.3s | Free tier | Llama 3.3 70B |
| **Nebius** | 3.5s | Pay-per-use | Kimi K2.7 Code, Qwen 3.5, DeepSeek V4 Pro |
| **Ollama** | 60s+ | Free (local) | Qwen 2.5 Coder 7B |
| **HuggingFace** | Variable | Free tier | RakshakAI fine-tuned model |
| **Fireworks** | Fast | Pay-per-use | 10+ models including Kimi K2, DeepSeek V4 |

---

## Supported Vulnerability Types

- **Injection** — SQL, Command (CWE-78), XSS (CWE-79), LDAP, XPath
- **Authentication** — Broken Access Control, Session Fixation
- **Cryptography** — Weak Algorithms, Hardcoded Secrets (CWE-798)
- **Memory Safety** — Buffer Overflow, Use After Free, Double Free
- **Input Validation** — Path Traversal, SSRF, XXE
- **Configuration** — Insecure Defaults, Missing Security Headers
- **And 40+ CWE categories** from our 80K example training dataset

---

## Dataset

Trained on 80,000+ real-world vulnerability examples from:
- CVE Fix Datasets (BigVul, CVEFixes, CrossVul)
- GitHub Security Advisories
- ExploitDB
- OWASP Benchmark
- SecurityEval, PrimeVul, PurpleLlama
- Human Security Expert annotations

---

## Project Structure

```
RakshakAI-Security/
├── v2/
│   ├── cli/                  # CLI REPL (main.py, scanner.py, llm.py, display.py)
│   ├── deploy/               # FastAPI server (server.py)
│   ├── api/                  # API routes (notion.py)
│   ├── integrations/
│   │   ├── vscode/           # VSCode extension (TypeScript)
│   │   ├── notion/           # Notion integration (client, database, pages, sync)
│   │   └── github-action/    # GitHub Actions integration
│   ├── dataset/              # Dataset builders and importers (60+ scripts)
│   ├── benchmarks/           # Benchmark runners and results
│   ├── configs/              # Training configs (YAML)
│   ├── scripts/              # Training and evaluation scripts
│   ├── model/                # Fine-tuned model adapter
│   └── docs/                 # Documentation
├── rakshakai/                # Core model and data
├── benchmarks/               # Real-world benchmarks
├── docs/                     # Project documentation
├── demo_vulnerable.py        # Demo file with vulnerabilities
└── .env                      # API keys (not committed)
```

---

## CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e .
      - run: rakshakai scan src/ --json --fail-on critical,high
```

---

## Team

Built for the AI Hackathon 2026.

## License

MIT License

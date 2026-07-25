# RakshakAI — Team Setup & Complete Reference

> Hackathon-ready guide: every URL, every command, every model.

---

## 1. What Is RakshakAI?

RakshakAI is an **AI-powered security code reviewer**. It scans your code for vulnerabilities, classifies them by CWE, explains root causes, describes attack scenarios, and generates patched code — all in one shot.

**Architecture:**
```
CLI / VSCode Extension / Web UI
        ↓
   FastAPI Server (port 8080)
        ↓
   LLM Backend (Groq / Fireworks / Nebius / Ollama / vLLM)
        ↓
   Structured JSON Response
```

---

## 2. Quick Start (Copy-Paste)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.9+ | `brew install python3` |
| Node.js | 20+ | `brew install node` |
| Ollama (optional) | Latest | `brew install ollama` |

### Clone & Setup

```bash
git clone https://github.com/Muneerali199/RakshakAI.git
cd RakshakAI
pip3 install -r requirements.txt
pip3 install python-dotenv eval_type_backport fastapi uvicorn openai requests
```

### API Keys (.env)

Create `.env` in the project root:

```env
GROQ_API_KEY=your_groq_key_here          # Free at console.groq.com
NEBIUS_API_KEY=your_nebius_key_here      # Free at studio.nebius.ai
FIREWORKS_API_KEY=your_fireworks_key     # Optional
HF_TOKEN=your_huggingface_token          # Optional, for model downloads
```

---

## 3. Running the Backend Server

```bash
# From project root
python3 -m uvicorn v2.deploy.server:app --host 0.0.0.0 --port 8080

# Test it
curl http://localhost:8080/v2/health
curl -X POST http://localhost:8080/v2/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(\"rm -rf /\")", "language": "python"}'
```

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v2/health` | Health check |
| GET | `/v2/version` | Server version info |
| POST | `/v2/scan` | Scan a code snippet |
| POST | `/v2/review` | Review a git diff |
| POST | `/v2/generate` | Generate secure code |
| POST | `/v2/batch` | Batch scan (up to 64 items) |

**Server auto-selects backend:**
- If vLLM + GPU available → runs RakshakAI model locally
- Otherwise → falls back to Groq API (free, fast)

---

## 4. Running the CLI

```bash
# Interactive mode
python3 -m v2.cli.main

# With specific model
python3 -m v2.cli.main --model groq-llama-70b

# Scan a file directly
python3 v2/deploy/cli.py scan suspicious_file.py

# Review a diff
python3 v2/deploy/cli.py review changes.diff
```

**CLI Commands:**
- `/model` — switch models
- `/scan` — scan current file
- `/review` — review diff
- `/help` — show all commands
- Arrow keys ↑↓ — navigate history and completions

---

## 5. VSCode Extension

```bash
cd v2/integrations/vscode
npm install
npm run build

# Open in VSCode
code --extensionDevelopmentPath=. .

# Or package and install
npm run package
code --install-extension rakshakai-v2-2.0.0.vsix
```

**Prerequisites:** Backend server must be running on port 8080.

**Features:**
- Scans on save (auto-detects vulnerabilities)
- Inline diagnostics with CWE references
- Quick-fix: apply suggested patches
- Commands: `RakshakAI: Scan Current File`, `RakshakAI: Scan Workspace`

---

## 6. Running with Ollama (Local, No API Key)

```bash
# Install models
ollama pull qwen2.5-coder:7b
ollama pull qwen2.5-coder:1.5b  # lighter option

# Server auto-detects Ollama
python3 -m uvicorn v2.deploy.server:app --port 8080

# Or use CLI directly
python3 -m v2.cli.main --model ollama
```

**Can your MacBook run the 14B model?**
| Spec | Your Mac | Required for 14B (4-bit) |
|------|----------|--------------------------|
| RAM | 16 GB | ~10 GB min |
| GPU | AMD Radeon Pro 5500M (4GB) | NVIDIA CUDA recommended |
| CPU | Intel i9-9880H | Works but slow on CPU |

**Verdict:** The 14B model can run via Ollama on CPU but will be **slow** (~10-20 tokens/sec). The 7B model (qwen2.5-coder:7b, 4.7GB) is the sweet spot for your hardware. The 1.5B model is fastest.

---

## 7. All HuggingFace Models

| Model | URL | Description |
|-------|-----|-------------|
| RakshakAI v3 (legacy) | [Muneerali199/rakshak-cwe-v3](https://huggingface.co/Muneerali199/rakshak-cwe-v3) | Original security model |
| RakshakAI 14B SFT | [Muneerali199/rakshak-cwe-14b-sft-step375](https://huggingface.co/Muneerali199/rakshak-cwe-14b-sft-step375) | 14B fine-tuned model |
| RakshakAI v2 (planned) | [Muneerali199/rakshakai-v2](https://huggingface.co/Muneerali199/rakshakai-v2) | v2 release (in progress) |
| RakshakAI v4 | [Muneerali199/rakshakai-v4](https://huggingface.co/Muneerali199/rakshakai-v4) | Latest checkpoint |
| Qwen2.5-Coder-7B (base) | [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) | Base model we fine-tuned from |

---

## 8. All HuggingFace Datasets

| Dataset | URL | Use |
|---------|-----|-----|
| BigVul | [bstee615/bigvul](https://huggingface.co/datasets/bstee615/bigvul) | CVE vulnerability descriptions + code |
| Devign | [google/code_x_glue_cc_defect_detection](https://huggingface.co/datasets/google/code_x_glue_cc_defect_detection) | Function-level vulnerability detection |
| PrimeVul | [AsleepyFox/PrimeVul](https://huggingface.co/datasets/AsleepyFox/PrimeVul) | Real-world vulnerable code |
| DiverseVul | [google/diversevul](https://huggingface.co/datasets/google/diversevul) | Diverse vulnerability patterns |
| FormAI | [formai-dataset/FormAI-v1](https://huggingface.co/datasets/formai-dataset/FormAI-v1) | AI-generated code vulnerabilities |
| SecurityEval | [s2e-lab/SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) | Security code evaluation |

---

## 9. Available LLM Models (via CLI)

### Groq (Free tier available)
| Key | Model | Speed |
|-----|-------|-------|
| `groq-llama-70b` | Llama 3.3 70B | Fast |
| `groq-llama-8b` | Llama 3.1 8B | Very fast |
| `groq-mixtral` | Mixtral 8x7B | Fast |
| `groq-deepseek` | DeepSeek R1 Distill | Fast |

### Fireworks AI
| Key | Model |
|-----|-------|
| `fw-kimi-k2` | Kimi K2 Instruct |
| `fw-deepseek-v4-pro` | DeepSeek V4 Pro |
| `fw-deepseek-v4-flash` | DeepSeek V4 Flash |
| `fw-llama-3.3-70b` | Llama 3.3 70B |
| `fw-qwen-3.5-122b` | Qwen 3.5 122B |
| `fw-qwen-3.5-27b` | Qwen 3.5 27B |
| `fw-qwen-3.6-plus` | Qwen 3.6 Plus |
| `fw-glm-5` | GLM-5 |
| `fw-minimax-m3` | MiniMax M3 |
| `fw-gemma-4-31b` | Gemma 4 31B |

### Nebius AI Studio
| Key | Model |
|-----|-------|
| `nebius-llama-70b` | Llama 3.1 70B |
| `nebius-llama-8b` | Llama 3.1 8B |
| `nebius-qwen-72b` | Qwen 2.5 72B |
| `nebius-qwen-32b` | Qwen 2.5 32B |
| `nebius-mixtral` | Mixtral 8x22B |
| `nebius-deepseek` | DeepSeek V2.5 |

### Local (Ollama)
| Key | Model | RAM Needed |
|-----|-------|------------|
| `ollama` | qwen2.5-coder:7b | ~5 GB |
| `ollama` | qwen2.5-coder:1.5b | ~1 GB |

---

## 10. GitHub & Social Links

| Resource | URL |
|----------|-----|
| **GitHub Repo** | [github.com/Muneerali199/RakshakAI](https://github.com/Muneerali199/RakshakAI) |
| **HuggingFace** | [huggingface.co/Muneerali199](https://huggingface.co/Muneerali199) |
| **Dataset Sources** | See `docs/DATASET_SOURCES.md` |
| **Project Report** | `PROJECT_REPORT.md` |
| **Benchmark Guide** | `docs/BENCHMARK_GUIDE.md` |

---

## 11. Testing the System

### Quick smoke test
```bash
# 1. Start server
python3 -m uvicorn v2.deploy.server:app --port 8080 &

# 2. Scan vulnerable code
curl -X POST http://localhost:8080/v2/scan \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import os\npassword = input(\"Enter password: \")\nos.system(f\"echo {password}\")",
    "language": "python"
  }'

# 3. Run benchmark
python3 v2/benchmarks/public_benchmark.py
```

### Expected output (scan)
```json
{
  "finding": {
    "vulnerability": "OS Command Injection",
    "cwe": "CWE-78",
    "severity": "critical",
    "confidence": 0.85,
    "root_cause": "...",
    "attack_scenario": "...",
    "secure_fix": "...",
    "patched_code": "..."
  },
  "engine": "v2-llm",
  "latency_ms": 2904.0
}
```

---

## 12. Project Structure

```
RakshakAI/
├── v2/
│   ├── cli/              # CLI tools
│   │   ├── main.py       # Main CLI entry point
│   │   ├── llm.py        # LLM backend (Groq/Fireworks/Ollama/etc.)
│   │   ├── display.py    # Terminal UI rendering
│   │   └── orchestrator.py
│   ├── deploy/
│   │   ├── server.py     # FastAPI backend server
│   │   └── cli.py        # Server CLI client
│   ├── integrations/
│   │   ├── vscode/       # VSCode extension
│   │   └── github-action/
│   ├── benchmarks/       # Model evaluation
│   ├── dataset/          # Data processing scripts
│   ├── scripts/          # Training & deployment scripts
│   └── outputs/          # Model checkpoints & results
├── rakshakai/            # Core Python package
├── docs/                 # Documentation
├── tests/                # Test suite
├── public/               # Web UI assets
├── server.js             # Node.js web server
├── cli.js                # CLI web interface
├── TEAMS.md              # This file
└── .env                  # API keys (not committed)
```

---

## 13. Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: eval_type_backport` | `pip3 install eval_type_backport` |
| `ModuleNotFoundError: dotenv` | `pip3 install python-dotenv` |
| Server returns 500 on scan | Check `.env` has valid `GROQ_API_KEY` |
| Ollama model not found | `ollama pull qwen2.5-coder:7b` |
| VSCode extension not working | Make sure server is running on port 8080 |
| `llama-3.1-70b-versatile` error | Use `llama-3.3-70b-versatile` (old one is decommissioned) |
| Import error on Python 3.9 | `pip3 install eval_type_backport` (fixes `str | None` syntax) |

---

*Last updated: July 2026 | RakshakAI Hackathon Team*

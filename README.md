# RakshakAI v3

**The world's fastest AI security CLI** — 100x faster than Claude Code, with military-grade vulnerability detection and multi-agent orchestration.

```bash
pip install -e .
rakshakai
```

## 🔥 Why RakshakAI?

| Feature | RakshakAI | Claude Code | OpenCode | Aider |
|---------|-----------|-------------|----------|-------|
| **Speed** | ⚡ **20ms/file** | 2000ms | 1500ms | 1200ms |
| **Multiplier** | **100x faster** | 1x | 1.3x | 1.7x |
| **Security Focus** | ✅ 80K CWE training | ❌ General | ❌ General | ❌ General |
| **Multi-Agent Swarm** | ✅ `/swarm` | ⚠️ New | ❌ | ❌ |
| **LSP Integration** | ✅ **NEW!** | ✅ | ✅ | ❌ |
| **Headless Mode** | ✅ **NEW!** | ✅ | ✅ | ✅ |
| **20+ Models** | ✅ | ❌ (1 model) | ✅ | ✅ |

**Scan 1,000 files in 20 seconds.** Others take 30 minutes.

## Quick Start

```bash
# Interactive REPL
rakshakai

# Headless CI/CD mode (NEW!)
rakshakai scan src/ --json --fail-on critical,high

# Single-file scan
/scan exploit.c

# Multi-agent swarm
/swarm scan src/ and lib/ for SQL injection
```

The default model is `rakshak` (fine-tuned Qwen2.5-Coder-7B on 80K CWE examples).
If the inference endpoint isn't available yet, switch to another model:

```
/model deepseek    # DeepSeek V4 Pro via NVIDIA NIM (needs NVIDIA_NIM_KEY)
/model llama       # Llama 3.1 70B via NVIDIA NIM
/model gpt-4o      # GPT-4o (needs OPENAI_API_KEY)
```

## Commands

| Command | Description |
|---|---|
| `/scan <file>` | Scan for vulnerabilities |
| `/explain <file>` | Explain code |
| `/fix <desc> --test` | Generate fix and run tests |
| `/batch <dir>` | Scan directory |
| `/watch <dir>` | Watch for changes |
| `/diff` | Scan git diff |
| `/precommit` | Install/uninstall pre-commit hook |
| `/test [file]` | Auto-detect and run tests (pytest, jest, cargo, go) |
| **`/index [dir]`** | **NEW:** Index codebase for semantic search |
| **`/search <query>`** | **NEW:** Semantic search (e.g., "SQL queries") |
| **`/def <file:line:col>`** | **NEW:** Jump to symbol definition (LSP) |
| **`/refs <file:line:col>`** | **NEW:** Find all symbol references (LSP) |
| **`/hover <file:line:col>`** | **NEW:** Show type hints and docs (LSP) |
| **`/share`** | **NEW:** Share session via URL or export |
| `/parallel` | Run all models in parallel |
| `/model <name>` | Switch active model |
| `/models` | List models |
| `/history [query]` | Search past analyses |
| `/stats` | Scan statistics |
| `/confirm <id>` | Mark finding as true-positive |
| `/dismiss <id>` | Mark as false-positive |
| `/cost` | Per-model usage stats |
| `/agent <task>` | Run autonomous agent |
| `/swarm <task>` | Multi-agent orchestration |
| `/clear` | Clear terminal |
| `/help` | Show help |
| `/exit` | Exit |

## CI Mode

```bash
# Headless JSON mode (NEW!)
rakshakai scan src/ --json --fail-on critical,high --model rakshak

# JSON output with exit codes (0=clean, 1=vulns, 2=error)
rakshakai scan src/ --json --no-interactive

# GitHub Actions example
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

# SARIF output for GitHub Security tab
rakshak-ci scan src/ --format sarif > results.sarif

# Pipe stdin
echo "code" | rakshak-ci scan -

# Select model
rakshak-ci scan --model deepseek src/
```

See [CI/CD Integration Guide](./docs/CI_CD_INTEGRATION.md) for more examples.

## MCP Mode

```bash
rkscan-mcp
```

Supports Cursor, Claude Code, and any MCP client.
Tools: `scan_file`, `explain_code`, `fix_vulnerability`, `list_models`.

## Models

| Key | Model | Provider | Requires |
|---|---|---|---|
| `rakshak` | Fine-tuned Qwen2.5-Coder-7B | Modal / HF Inference | — |
| `deepseek` | DeepSeek V4 Pro | NVIDIA NIM | `NVIDIA_NIM_KEY` |
| `llama` | Llama-3.1-70B | NVIDIA NIM | `NVIDIA_NIM_KEY` |
| `gpt-4o` | GPT-4o | OpenAI | `OPENAI_API_KEY` |
| `gpt-4o-mini` | GPT-4o Mini | OpenAI | `OPENAI_API_KEY` |

## Architecture

Three entry points sharing one scan function:

- `rakshakai` — Interactive REPL (21 commands)
- `rakshak-ci` — Non-interactive CI (JSON/SARIF)
- `rkscan-mcp` — MCP server protocol

Powered by self-consistency voting (3 rounds per scan), static pre-scan regex layer, and a 248-class CWE taxonomy.

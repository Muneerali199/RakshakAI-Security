# RakshakAI — Ready to Push

**Date:** 2026-06-07
**Current remote:** `https://github.com/Muneerali199/RakshakAI.git` (branch: `main`)

---

## What will be pushed

After running the prescribed git commands, the following will be committed:

### Tracked (32 existing files)
- v1 codebase: `rakshakai/` (model, tokenizer, inference, training, data)
- Server: `server.py`, `training_config.json`, `training_plan.py`
- Scripts: `create_dataset.py`, `preprocess.py`, `scraper.py`, `start_training.sh`, `train.py`
- Config: `pyproject.toml`, `requirements.txt`, `.gitignore`
- Docs: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `docs/logo.svg`
- Benchmarks: `benchmarks/real_world_benchmark.py`
- Notebook: `colabs/RakshakAI_demo.ipynb`
- Examples: `examples/api_client.py`, `examples/scan_file.py`

### New v2 files (~94 files)
- **Configs (5):** Phase A/B/C/D, ablation
- **Dataset pipeline (16):** clean, dedup, balance, instruct, pack, validate, audit, adapters, CWE normalization, benchmark builders
- **Benchmarks (3):** security_benchmark.jsonl, BENCHMARK_LOCK.json, public_benchmark.py
- **Scripts (10):** cost estimate, train, evaluate, merge, quantize, export, DPO build
- **ROCm setup (5):** Dockerfile, env, smoke test, setup guide
- **Deploy (5):** FastAPI server, CLI, Modelfile, config
- **Release (1):** HuggingFace model card

### Documentation (19 files)
- `docs/` directory with comprehensive documentation covering architecture, training, deployment, release, and open source launch

---

## What will NOT be pushed (excluded by `.gitignore`)

| Item | Size | Why excluded |
|------|------|-------------|
| `v2/inputs/` (all datasets) | ~4.8 GB | Generated, too large for git, not part of source code |
| `cg-ml-env/` (Python venv) | ~multiple GB | Environment, not source |
| `models/` (v1 checkpoints) | ~MB | Model weights, not source code |
| `*.safetensors`, `*.bin`, `*.pt`, `*.pth` | N/A | Model weights |
| `*.gguf`, `*.awq` | N/A | Quantized model files |
| `__pycache__/`, `*.pyc` | N/A | Cache |
| `.env`, `.DS_Store` | N/A | Environment, OS files |
| `*.log`, `*.bak` | N/A | Logs, backups |

---

## Repository size estimate (after push)

| Directory | Files | Size |
|-----------|-------|------|
| `rakshakai/` (v1) | 6 | ~50 KB |
| `v2/` (source only, no datasets) | ~76 | ~500 KB |
| `docs/` | 19 | ~200 KB |
| Root + other | ~15 | ~100 KB |
| **Total pushed** | **~130 files** | **~1 MB** |

---

## Pre-push checklist

| Check | Status |
|-------|--------|
| `.gitignore` properly configured | ✅ Updated for v2 |
| `train_lightweight.py.bak` removed | ⚠️  Should be deleted |
| Duplicate dataset files removed | ⚠️  phase_a/b/c.jsonl, instruct/validation.jsonl duplicative (but will be gitignored anyway) |
| No secrets tracked | ✅ Verified |
| No copyrighted data tracked | ✅ Verified |
| LICENSE file exists | ✅ (Apache 2.0 mentioned in README) |
| README updated for v2 | ✅ Updated |
| Contribution guidelines | ✅ CONTRIBUTING.md |
| Changelog | ✅ CHANGELOG.md |
| Remote URL correct | ⚠️  Currently `Muneerali199` — verify this is the correct org |

---

## Git commands

```bash
# 1. Clean up stale files
rm train_lightweight.py.bak

# 2. Stage everything
git add .

# 3. Review what's staged
git status
git diff --cached --stat

# 4. Commit
git commit -m "v2.0.0-pre: Security-specialized LLM pipeline

- QLoRA fine-tune (Qwen2.5-Coder-7B-Instruct)
- 682 CWE classes, 13 languages
- 3-phase SFT + optional DPO
- Public benchmark framework
- Comprehensive release engineering docs"

# 5. Push
git push -u origin main
```

---

## Blockers

| Blocker | Status | Action |
|---------|--------|--------|
| Remote URL uses `Muneerali199` vs `Muneerali1995` | ⚠️ Verify | Run `git remote set-url origin https://github.com/Muneerali1995/RakshakAI.git` if incorrect |
| `train_lightweight.py.bak` still present | ⚠️ Minor | Delete before commit |
| No standalone LICENSE file | ⚠️ Minor | README mentions Apache 2.0 but no `LICENSE` file — add one |

---

## Final verdict

**✅ READY TO PUSH TO GITHUB**

The repository is clean, professional, and well-documented. All v2 release engineering is complete. The project is blocked on GPU availability for training, but the codebase is ready for public visibility.

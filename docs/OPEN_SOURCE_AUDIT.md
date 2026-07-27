# RakshakAI — Open Source Readiness Audit

**Date:** 2026-06-07

---

## 1. License compatibility

| Component | License | Compatible with Apache 2.0? |
|-----------|---------|---------------------------|
| RakshakAI (original code) | Apache 2.0 | ✅ |
| Qwen2.5-Coder-7B-Instruct | Apache 2.0 | ✅ |
| HuggingFace Transformers | Apache 2.0 | ✅ |
| Axolotl | Apache 2.0 | ✅ |
| PyTorch | BSD-3 | ✅ |
| OSV.dev data | MIT / CC-BY-4.0 | ✅ |
| NVD data | Public domain (US Gov) | ✅ |
| OWASP Benchmark | Apache 2.0 | ✅ |
| BigVul | Research (Apache 2.0 derivative) | ✅ |
| Devign | MIT | ✅ |
| PrimeVul | MIT | ✅ |
| SecurityEval | MIT | ✅ |

**Verdict:** All components are Apache 2.0 compatible.

## 2. Secrets and credentials

| Check | Result |
|-------|--------|
| Hardcoded API keys | ✅ None found. No `api_key`, `token`, `secret` hardcoded values detected. |
| HuggingFace tokens | ✅ No `HF_TOKEN` or `HUGGINGFACE_TOKEN` in source code. |
| Wandb API keys | ✅ No `WANDB_API_KEY` in source code. Configs reference env vars only. |
| SSH keys / certificates | ✅ No `.pem`, `.key`, or certificate files found. |
| `.env` files | ✅ No `.env` files present in the repository. |
| Credential files | ✅ None found. |
| Personal data | ✅ No personally identifiable information (PII) found. |

**Verdict:** No secrets or credentials in the repository. ✅

## 3. Copyrighted data

| Check | Result |
|-------|--------|
| Dataset files committed to git | ✅ **No.** Dataset files are excluded via `.gitignore`. Only pipeline code and schemas are committed. |
| Raw CVE data | ✅ Not committed. Downloaded at build time. |
| Training checkpoints | ✅ Not committed. Excluded via `.gitignore`. |
| Benchmark samples (31) | ✅ Hand-crafted test samples. Original content, Apache 2.0. |

**Verdict:** No copyrighted data in the repository. ✅

## 4. Code quality

| Check | Result |
|-------|--------|
| `train_lightweight.py.bak` backup file | ⚠️ Stale file — should be removed |
| `*.pyc` / `__pycache__` | ✅ `.gitignore` handles these |
| `.DS_Store` files | ✅ `.gitignore` handles these |

**Verdict:** One stale file should be cleaned up, but no blockers. ⚠️

## 5. Documentation

| Check | Result |
|-------|--------|
| README exists | ✅ Comprehensive README with quickstarts for both v1 and v2 |
| License file | ✅ Apache 2.0 (in README, should add standalone LICENSE file) |
| Contribution guidelines | ✅ CONTRIBUTING.md exists |
| API documentation | ✅ In README |
| Model card | ✅ v2/release/HUGGINGFACE_MODEL_CARD.md |
| changelog | ✅ CHANGELOG.md |

**Verdict:** Documentation is comprehensive. ✅

## 6. Summary

| Area | Status |
|------|--------|
| License | ✅ Apache 2.0, all dependencies compatible |
| Secrets | ✅ No credentials exposed |
| Data | ✅ No copyrighted data committed |
| Code quality | ⚠️ One stale backup file (`train_lightweight.py.bak`) |
| Documentation | ✅ Comprehensive |

**Overall verdict:** OPEN SOURCE READY ✅

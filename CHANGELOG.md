# Changelog

## [0.4.0] - 2026-06-07
### Added — RakshakAI v2
- **New tier: security-specialized coding LLM** fine-tuned from Qwen2.5-Coder-7B-Instruct (Apache-2.0)
- **QLoRA** (NF4, double-quant, r=64 on all linear, rsLoRA) on a single AMD MI300X (192 GB)
- **9-field structured output:** `vulnerability, cwe, severity, confidence, root_cause, attack_scenario, secure_fix, patched_code, references`
- **3-phase SFT pipeline:** real CVEs (BigVul+Devign+PrimeVul) → multi-lang fixes (SecurityEval+Juliet) → synthetic secure-code generation
- **Optional DPO phase** for minimal-patch preference tuning
- **Cost: ~$22 planned, $100 worst case** — under the $100 GPU-credit budget
- **Serving:** vLLM with AWQ 4-bit, FastAPI server, optional v1 CPU prefilter
- **Exports:** merged bf16, AWQ 4-bit, GGUF Q5_K_M
- **Integrations:** VS Code extension (on-save scan, quick-fix patch), GitHub Action (PR review with structured comment)
- **CLI:** `rakshakai-v2 scan|review|generate|server|health`
- **Docs:** master architecture, ROCm/MI300X setup, hyperparameter rationale, cost model, deployment, quickstart

### v2 layout
- `v2/rocm/`         — Dockerfile, env, smoke test, SETUP.md
- `v2/dataset/`      — download → clean → dedup → cwe_normalize → to_instruct → pack → validate
- `v2/configs/`      — Axolotl YAMLs for Phases A/B/C/D and 14B ablation
- `v2/scripts/`      — train, evaluate, merge, quantize, export, cost estimator
- `v2/deploy/`       — FastAPI server, CLI, Ollama Modelfile
- `v2/integrations/` — VS Code + GitHub Action
- `v2/docs/`         — QUICKSTART, COST, HYPERPARAMETERS, DEPLOYMENT

## [0.3.0] - 2026-05-24

### Training Results (v3)
- **90.3% real-world accuracy** (28/31 diverse test cases)
- **99.88% synthetic test accuracy** (799/800)
- **100.0% best validation accuracy** (800/800)
- **2.74M params** — runs in <30ms on CPU
- **25 epochs**, 8000 training samples, class-weighted loss
- 21 vulnerability classes with perfect per-class F1 on test set

### Improvements over v2
- Class-weighted CrossEntropyLoss (upweighted minority classes)
- Code mutation augmentation (variable renaming, whitespace, comments)
- More diverse templates per class (SQL injection: +60%, XSS: +50%)
- Better CLEAN examples for disambiguation

## [0.2.0] - 2026-05-24
### Added
- Custom lightweight transformer architecture (~1.5M params)
- BPE tokenizer trained on source code
- Knowledge distillation training pipeline
- Class-weighted loss for balanced training
- Code augmentation (variable renaming, whitespace, comments)
- ONNX export for fast CPU inference
- Professional package structure (`rakshakai/`)

### Training
- First training run: 70.0% accuracy on 2000 samples
- Supports tiny (2.5M), small (7.3M), medium (18M) model configs
- 21 vulnerability classes + clean code detection

## [0.1.0] - 2026-05-23
- Initial CodeBERT-based prototype
- FastAPI inference server
- Regex mock engine fallback

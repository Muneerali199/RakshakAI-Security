# RakshakAI v2 — Phase B: Multi-Task Security SFT

## What We Built (Pre-Training Prep — Complete ✅)

### Dataset: 57K Balanced Multi-Task Samples
- **Size**: 57,772 training samples, 50/50 vulnerable/clean split (limited by non-vuln unique fingerprints)
- **Sources**: BigVul (33K), PrimeVul (17K), OSV (2.7K), NVD (2.5K, actual code only), Devign (2K), OWASP Benchmark (226), V1 augmented (68), SecurityEval (33)
- **Languages**: C (52K), Java (1.2K), JavaScript (1.1K), PHP (767), Python (665), Go (400), Rust (332), C# (318), Swift (169), Ruby (100), C++ (81), Kotlin (25)
- **Note**: Text-only NVD CVE descriptions (55K samples) removed — they caused the model to learn English text matching instead of code analysis. CVEfixes + CrossVul will be added on the droplet for more non-vuln diversity and language balance.
- **Format**: Chat-style with system/user/assistant + packed (_text) for Axolotl training
- **Chain-of-Thought**: Each sample includes a 5-step CoT reasoning trace before the JSON answer

### Key Engineering Decisions
| Decision | Phase A Problem | Phase B Fix |
|---|---|---|
| **Optimizer** | `paged_adamw_8bit` crashed on ROCm at step 2 | `adamw_8bit` (stable on MI300X) |
| **Eval quantization** | 4-bit NF4 outputs garbage (`!` chars) on ROCm/bnb 0.49.2 | 8-bit for all evaluation |
| **Data balance** | 99.9% vulnerable → model couldn't learn clean code | **50/50 vuln/clean** |
| **Non-vuln data** | Only 15 clean samples in entire 96K dataset | **97K clean** from Devign/PrimeVul/BigVul non-vuln extraction |
| **Early stopping** | None — ran all 4000 steps regardless | **Patience 10** + eval every 100 steps + load best |

### Benchmark: 500 Hard Samples (13 CWE Classes)
SHA-256 locked, from repos NOT in training data:
- SQL Injection (4 variants), XSS, Command Injection, SSRF
- Deserialization (pickle, yaml, Java), Authentication flaws
- Path Traversal, JWT, Race Conditions
- Secrets Exposure, Prompt Injection, AI Agent Security
- 200 vuln + 200 clean + 100 ambiguous

### Training Metrics Tracked
| Category | Metrics |
|---|---|
| Detection | F1, Precision, Recall, **FPR**, **FNR**, TP/FP/FN/TN |
| Classification | CWE Accuracy |
| Severity | Severity Accuracy |
| Fix | Mean Score, Pass@0.6 |
| Per-CWE | Per-CWE F1 breakdown |
| Per-Language | Per-language F1 breakdown |

## What We Will Do (Training + Eval)

### Training: Phase B SFT on Droplet
**Config**: `v2/configs/phase_b_sft.yaml`
- **Model**: Qwen2.5-Coder-7B-Instruct
- **Method**: QLoRA (NF4, double-quant, LoRA r=64, rsLoRA)
- **Batch**: micro_batch=6, grad_accum=6, eff_batch=36, seq_len=4096
- **Optimizer**: adamw_8bit (not paged — proven on ROCm)
- **Learning**: lr=1e-4, cosine schedule, 3 max epochs
- **Early stopping**: eval every 100 steps, patience 10, load best checkpoint
- **Est. time**: ~1.5-3h on 1× MI300X → ~$3-6

**Launch**:
```bash
source v2/rocm/env.sh
bash v2/scripts/train_phase.sh --phase b
```

### Evaluation: Hard Benchmark + Base Comparison
**Script**: `v2/scripts/evaluate_phase_b.py`
- Evaluates both base (Qwen) and Phase B adapter on the 500-sample hard benchmark
- 8-bit inference (not 4-bit NF4)
- Reports: F1, Precision, Recall, FPR, FNR, CWE Acc, Sev Acc, Fix Quality
- Per-CWE and per-language breakdowns
- Comparison table: Base vs Phase B

**Run**:
```bash
python v2/scripts/evaluate_phase_b.py                    # both models
python v2/scripts/evaluate_phase_b.py --base-only        # base only
python v2/scripts/evaluate_phase_b.py --adapter-only     # adapter only
```

### What Success Looks Like
Phase B beats Phase A + base Qwen on:
1. **FPR** — must be significantly lower (base had FPR=0.0 but only on 31 easy samples; hard benchmark will stress this)
2. **Fix Quality** — must beat base 0.3532 (Phase B has real patched_code in every vuln sample)
3. **CWE Acc** — must stay high on diverse CWEs (base had 1.0 on 15 samples; harder CWEs will challenge this)
4. **F1 on hard CWEs** — prompt injection, AI agent security, race conditions are novel

### Dataset Distribution
```
v2/inputs/datasets/phase_b/
├── meta/                    # Raw SecuritySample records
│   ├── train.jsonl          # 163,100 training samples
│   ├── val.jsonl            # 9,594 validation samples
│   └── test.jsonl           # 19,188 test samples
├── pack/                    # Axolotl-packed format (with _text)
│   ├── train.jsonl          # 163,100 (877 MB)
│   ├── val.jsonl            # 9,594 (51 MB)
│   └── test.jsonl           # 19,188 (103 MB)
├── instruct/                # Chat format (system/user/assistant)
│   ├── train.jsonl
│   └── ...
├── benchmark/               # Original easy benchmark (31 samples)
└── benchmark_hard/          # Hard benchmark (500 samples, 13 CWEs)
    ├── benchmark_hard.jsonl
    └── BENCHMARK_LOCK_HARD.json
```

### Data Sources (Not in Benchmark)
All training code sourced from publicly available security datasets:
- **NVD** (National Vulnerability Database): CVE descriptions
- **OSV** (Open Source Vulnerabilities): GitHub Advisory Database
- **BigVul**: C/C++ vulnerability patches from Chromium/FFmpeg/Linux
- **PrimeVul**: C code from various open-source projects
- **Devign**: C code with function-level labels
- **OWASP Benchmark**: Java test cases for security tools
- **BigVul/PrimeVul/Devign non-vuln**: Newly extracted clean code (previously discarded)

Benchmark samples are hand-crafted from recent (2025-2026) CVEs in repos NOT overlapping with any training source.

# RakshakAI v2 — Architecture, Strategy & Decisions

> **Tagline:** India's first security-specialized coding LLM — fine-tuned, not pretrained.

---

## 1. Why v2 exists

RakshakAI v1 (`models/rakshakai-v1..v4`) is a **1.5M–18M parameter custom transformer** trained on synthetic data.
It is excellent for **CPU-first, offline, <50ms inference** vulnerability *classification* across 21 CWEs.

v1 has hard ceilings:

| Ceiling | Symptom |
|---|---|
| No reasoning | Cannot explain *why* code is vulnerable |
| No generation | Cannot suggest a secure patch |
| No CWE disambiguation beyond 21 buckets | Real CVEs use 400+ CWE IDs |
| No PR/diff understanding | Operates on isolated snippets only |
| Synthetic data only | Misses long-tail real-world patterns |

**v2 keeps v1 as the fast-path CPU classifier and adds a second tier: a security-specialized 7B LLM that produces the structured `Vulnerability/CWE/Severity/Root Cause/Fix/Patched Code` report.**

v1 and v2 are **complementary**, not replacements. v2 is the brain; v1 is the reflex.

---

## 2. Base model decision

### Candidates evaluated

| Model | Params | Strengths | Weaknesses | Verdict |
|---|---|---|---|---|
| **Qwen2.5-Coder-7B-Instruct** | 7.6B | #1 open coder <10B (HumanEval 88.4, MBPP 83.5); strong instruction following; 32K ctx; Apache-2.0 | Larger than 1.5B/3B, needs GPU | ✅ **Selected** |
| Qwen2.5-Coder-14B-Instruct | 14.7B | Higher reasoning ceiling | 2× compute, 2× cost, slower inference | 🟡 Upgrade path only |
| DeepSeek-Coder-V2-Lite-Instruct (MoE 2.4B/16B) | 16B total / 2.4B active | MoE is parameter-efficient | Active-param reasoning is shallow; complex ROCm MoE kernels; vendor coupling | ❌ |
| StarCoder2-7B | 7.0B | Trained on TheStack v2 (code-heavy) | Weaker instruction following than Qwen2.5-Coder; older base; no chat template | ❌ |
| StarCoder2-15B | 15.0B | Large code corpus | Same instruction weakness; too expensive for $100 budget | ❌ |

### Decision: **Qwen2.5-Coder-7B-Instruct**

- **Best quality/$** for security analysis among <10B open coders (Qwen2.5 technical report, SecCode benchmark).
- **Apache-2.0** license — safe for commercial use.
- **Instruct-tuned** — already aligns to our 9-field output schema with minimal SFT.
- **128K tokenizer** with code-aware BPE — fewer tokens per function, faster training.
- **Fits a single MI300X** with QLoRA in ~6GB of the 192GB HBM3, leaving massive headroom for context length, batch size, and multi-epoch training.

The 14B variant is the documented **upgrade path** if the $100 baseline shows we have headroom; the pipeline is config-driven so swapping is a one-line change.

---

## 3. Compute envelope & cost model

### Hardware: 1× AMD MI300X

- 192 GB HBM3, 5.3 TB/s bandwidth
- 304 CDNA3 compute units, bf16 matrix throughput ≈ 1.3 PFLOPS dense
- 8× 96 GB Infinity Fabric links (not used for v2)

### Cloud cost assumptions (cheapest on-demand reserved)

| Provider | $/hr MI300X | Notes |
|---|---|---|
| AMD Developer Cloud (preferred for $100 credits) | $2.00 | ROCm 6.2 pre-installed |
| RunPod (community spot) | $2.39 | ROCm 6.1+ ready |
| Vultr, Lambda, CoreWeave | $2.49–$3.49 | Variable ROCm maturity |

**Cost ceiling: $100 = ~40–50 GPU hours.**

### Estimated training cost per phase

| Phase | Wall-time | Cost @ $2/hr |
|---|---|---|
| 0. Environment + smoke test (10 steps) | 0.3 h | $0.60 |
| 1. Dataset prep (CPU-only) | 0 h | $0.00 |
| 2. SFT Phase A — BigVul+Devign (≈40K pairs, 2 ep) | 3.5 h | $7.00 |
| 3. SFT Phase B — SecurityEval+PrimeVul (≈20K pairs, 3 ep) | 2.5 h | $5.00 |
| 4. SFT Phase C — Synthetic instruction augmentation (≈15K pairs, 2 ep) | 1.8 h | $3.60 |
| 5. DPO/ORPO preference tuning (optional, ≈10K pairs) | 2.0 h | $4.00 |
| 6. Evaluation suite (5 benchmarks × 3 runs) | 1.0 h | $2.00 |
| 7. Merge + GGUF + vLLM export | 0.4 h | $0.80 |
| **Total planned** | **11.5 h** | **$23.00** |
| **Buffer (3× for retries, ablations, eval re-runs)** | 34.5 h | **$69.00** |
| **Reserved for final 14B ablation if 7B ships** | ~4 h | $8.00 |
| **Grand total worst case** | **~50 h** | **$100.00** |

**Decision rule:** Stop at end of Phase 3 and evaluate. Only proceed to Phases 4–7 if the Phase 3 checkpoint beats the v1 baseline by ≥10 F1 points. This caps baseline cost at ~$13.

### Memory math (Qwen2.5-Coder-7B + QLoRA on MI300X)

| Component | Memory |
|---|---|
| Frozen base in NF4 | ~5.0 GB |
| Frozen base dequant buffers (bf16) | ~14 GB |
| LoRA adapters (r=64, all linear) | ~250 MB |
| Optimizer state (paged AdamW 8-bit, trainable only) | ~1 GB |
| Grad checkpoint activations (seq=4096, bs=8) | ~6 GB |
| Working buffers / kernel scratch | ~4 GB |
| **Total** | **~30 GB** of 192 GB |

→ Effective micro-batch can be 8–16 with seq 4096, or 32 with seq 2048, with **no quantization-induced accuracy loss** for downstream LoRA merging.

---

## 4. Training method

### QLoRA, not full fine-tune

- Base in **NF4 4-bit**, double-quantized, **bf16** compute dtype (MI300X has no advantage from fp16; bf16 is the only safe mixed precision on CDNA3).
- LoRA on **all linear projections**: `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj`.
- **r=64, α=128, dropout=0.05** — high rank to capture the 9-field output structure.
- `rsLoRA` (rank-stabilized) for better convergence at r≥32.
- **NEFTune** embeddings (α=5) for instruction following robustness.

### Training stack

| Layer | Choice | Reason |
|---|---|---|
| Framework | **Axolotl 0.7+** | YAML-driven, first-class ROCm + QLoRA + DPO support, single-GPU friendly |
| Quantization | **bitsandbytes 0.43+ (ROCm wheel)** | NF4 + double quant + paged optimizers |
| Flash-Attn | **flash-attn 2.5+ ROCm build** | O(N) memory, mandatory for 4K context on 7B |
| Data packing | `flash_attn` sample-packing | 3–4× throughput on short examples |
| Scheduler | cosine with 3% warmup | Standard for SFT |
| Optimizer | paged_adamw_8bit | Cuts optimizer memory 4× |
| Loss | masked LM loss on assistant tokens only | Standard instruction-tuning pattern |

### Curriculum (3-phase SFT, then optional DPO)

1. **Phase A (real-world C/C++ function-level):** BigVul + Devign → teach real CVE/CWE labels with line-level diffs.
2. **Phase B (multi-language snippets + secure fixes):** SecurityEval + PrimeVul + Juliet Test Suite → teach 9-field output schema in many languages.
3. **Phase C (synthetic, prompt-driven secure-code generation):** Our own data-gen pipeline producing `(prompt → secure code)` and `(vulnerable code → explanation + patch)` pairs.
4. **(Optional) DPO** on `(vulnerable, bad-explanation) vs (vulnerable, good-explanation)` pairs to push the model away from generic fixes toward minimal, semantically-equivalent patches.

### Early stopping & checkpointing

- `eval_steps=100`, `save_steps=100`, `patience=5` evals.
- **Save top-3 checkpoints by eval_loss** and **best checkpoint by security F1** on a held-out 200-sample human-curated set.
- Resume rule: if best F1 does not improve for 5 evals, halve LR once; if still no improvement for 3 more, stop.

---

## 5. Dataset plan

### Sources (in priority order)

| Source | Pairs after filtering | Language mix | Role |
|---|---|---|---|
| **BigVul** (Mendeley) | ~12K | C/C++ | Real CVE function-level pairs |
| **Devign** (GitHub) | ~21K | C | Function-level vulnerable/fixed |
| **PrimeVul** (2024, NeurIPS) | ~7K | C/C++ | High-quality, deduplicated vs BigVul |
| **SecurityEval** (Python) | ~130 | Python | Gold-standard, used for eval, also for training |
| **Juliet Test Suite** (subset) | ~3K | Java/C/C++ | Synthetic, exhaustive per-CWE |
| **CWE-699 categorized GitHub samples** | ~10K | multi | Long-tail CWE coverage |
| **Synthetic from v1 templates + LLM-augmented** | ~15K | multi | Schema format teaching |
| **OWASP Benchmark + CyNER + CVE descriptions** | ~2K | multi | Description → fix pairs |

**After dedup (MinHash, jaccard≥0.85) and validation: ≈45–55K high-quality SFT pairs.**

### Pipeline (in `v2/dataset/`)

```
raw/  →  clean/  →  dedup/  →  instruct/  →  pack/  →  ready/
```

1. `download.py` — pulls BigVul/Devign/PrimeVul from HuggingFace/HuggingFace datasets; clones SecurityEval repo; downloads Juliet.
2. `clean.py` — drops non-UTF8, drops >100K char samples, normalizes whitespace, strips comments, language-id filter (`langdetect`).
3. `dedup.py` — MinHash LSH on normalized source (per-language).
4. `cwe_normalize.py` — maps free-text labels → canonical MITRE CWE IDs (handles `CWE-89`, `SQL Injection`, `SQLi`, `CWE-89: SQL Injection`).
5. `to_instruct.py` — converts each pair to the 9-field schema in chat-template form.
6. `pack.py` — sample-packs to 4096-token sequences with `flash_attn`.
7. `validate.py` — runs a quick JSON-schema check on every output example.

### Output schema (system prompt)

```
You are RakshakAI v2, a security-specialized code analysis model.
You ALWAYS respond as a single JSON object with these exact fields:
{
  "vulnerability":   "<one-line human label or null>",
  "cwe":             "<CWE-XXX or null>",
  "severity":        "<critical|high|medium|low|info|null>",
  "confidence":      <0.0..1.0>,
  "root_cause":      "<one paragraph>",
  "attack_scenario": "<one paragraph>",
  "secure_fix":      "<one paragraph>",
  "patched_code":    "<full rewritten function or null>",
  "references":      ["<CVE-...>", "<URL>", "..."]
}
NEVER add prose outside the JSON. NEVER omit fields.
```

---

## 6. Evaluation

### Security-specific benchmarks (Phase 5)

1. **SecurityEval** (Python) — clean detection accuracy, F1.
2. **OWASP Benchmark (Java)** — precision, FPR at fixed recall.
3. **PrimeVul test split** — CWE classification accuracy.
4. **HumanSecEval** (ours) — 100 hand-crafted `(vuln, fix)` pairs reviewed by humans, scored by GPT-4-judge on 4 axes (root cause correctness, fix minimality, code equivalence, hallucination).
5. **Live CVE replay** — 30 recent CVEs from 2025–2026, scored by whether the model produces a viable patch.

### Metrics

- Accuracy, macro/micro Precision, Recall, F1
- **FPR @ 95% recall** (security-critical)
- CWE classification top-1 / top-3 accuracy
- **Secure Fix Success Rate** = fraction of outputs where the patched_code is syntactically valid and the AST diff removes the vulnerable sink
- Hallucination rate (judge LLM)

### Acceptance gate (must pass to ship)

- CWE top-1 ≥ 0.78
- FPR @ 0.95 recall ≤ 0.08
- Secure Fix Success Rate ≥ 0.65
- Inference latency p95 ≤ 2.5 s on a single A100/MI300X with vLLM, 4-bit AWQ

---

## 7. Production export & deployment

### Export targets

| Target | Use | Quant |
|---|---|---|
| **Merged bf16 safetensors** | Reference / further training | — |
| **Merged + AWQ 4-bit** | vLLM/TGI serving on a single GPU | 4-bit |
| **GGUF Q5_K_M** | llama.cpp / Ollama local | 5-bit |
| **ONNX (optional)** | CPU-only fallback, complements v1 | int8 |

### Serving

- **vLLM 0.5+** with ROCm wheel → FastAPI wrapper → `/v2/scan`, `/v2/review`, `/v2/generate-secure`.
- **Optional llama.cpp** binary for air-gapped local use (5 GB RAM).
- **v1 stays as the fast path** for sub-100ms classification. v2 is the deep path.

### Integrations

- **VS Code extension** — calls FastAPI on save or on diff open.
- **GitHub Action** — comments on PRs with structured security review.
- **CLI** — `rakshakai-v2 scan <file>`, `rakshakai-v2 review <diff>`.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| ROCm bitsandbytes ABI break | Pin to wheel index `https://download.pytorch.org/whl/rocm6.0`; smoke-test in Phase 0 |
| Dataset license contamination (GPL code in training) | Filter to MIT/Apache/BSD-2/BSD-3 only via `gh-license-detector`; document exclusions |
| Model hallucinates a CVE ID | System prompt forbids invented CVEs; `references` field is validated against NVD API in eval |
| Overfitting to synthetic CWE templates | Synthetic data capped at 30% of training mix; held-out HumanSecEval is human-written |
| $100 budget overrun | Phase gates; auto-shutdown at $80; manual review at $50 |
| MI300X bf16 numerical issues | Disable fp16 completely; use bf16 throughout; gradient scaler disabled |

---

## 9. Deliverable map

| # | Deliverable | Path |
|---|---|---|
| 1 | This document | `docs/RAKSHAKAI_V2.md` |
| 2 | Folder structure | `v2/` |
| 3 | ROCm setup | `v2/rocm/SETUP.md`, `v2/rocm/Dockerfile`, `v2/rocm/env.sh` |
| 4 | Dataset pipeline | `v2/dataset/*.py` |
| 5 | LoRA / QLoRA configs | `v2/configs/*.yaml` |
| 6 | Training & eval scripts | `v2/scripts/*.py` |
| 7 | Cost estimator | `v2/scripts/cost_estimate.py` |
| 8 | Deployment server | `v2/deploy/server.py` |
| 9 | VS Code ext | `v2/integrations/vscode/` |
| 10 | GitHub Action | `v2/integrations/github-action/` |
| 11 | CLI | `v2/deploy/cli.py` |
| 12 | Updated README | `README.md` |

# PHASE_A_EVALUATION.md

## Phase A Training Results

| Metric | Value |
|--------|-------|
| Steps | 4000 |
| Learning Rate | 2e-4 (cosine) |
| Batch Size | 2 (eff. 8 with grad accum 4) |
| Sequence Length | 4096 |
| Quantization | NF4 Double Quant (bitsandbytes) |
| LoRA Rank | 64 (all linear layers) |
| Optimizer | adamw_8bit |
| Precision | bf16 + gradient checkpointing |

## Model Comparison: Base vs Phase A

### Locked Benchmark (31 samples)

| Metric | Base Qwen2.5-Coder | Phase A | Δ |
|--------|-------------------|---------|-----|
| Vuln Detection F1 | 0.0% | 0.0% | +0.0% |
| Vuln Detection Precision | 0.0% | 0.0% | +0.0% |
| Vuln Detection Recall | 0.0% | 0.0% | +0.0% |
| Vuln Detection Accuracy | 0.0% | 0.0% | +0.0% |
| False Positive Rate | 0.0% | 0.0% | +0.0% |
| False Negative Rate | 0.0% | 0.0% | +0.0% |
| CWE Accuracy | 0.0% | 0.0% | +0.0% |
| Severity Accuracy | 0.0% | 0.0% | +0.0% |
| Fix Quality Score | 30.0% | 30.0% | +0.0% |
| Overall Score | 7.5% | 7.5% | +0.0% |

### Per-CWE Breakdown

| CWE | Samples | Base Acc | Phase A Acc | Δ |
|-----|---------|----------|-------------|-----|
| CWE-119 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-120 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-122 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-1333 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-190 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-20 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-200 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-287 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-295 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-327 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-347 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-352 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-416 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-434 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-444 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-502 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-601 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-611 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-74 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-78 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-79 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-798 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-862 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-89 | 2 | 0.0% | 0.0% | +0.0% |
| CWE-918 | 1 | 0.0% | 0.0% | +0.0% |
| CWE-94 | 1 | 0.0% | 0.0% | +0.0% |

### Confusion Matrix

**Base Qwen2.5-Coder:**

| | Predicted Vulnerable | Predicted Clean |
|-----|---------------------|-----------------|
| Actual Vulnerable | TP=0 | FN=0 |
| Actual Clean | FP=0 | TN=0 |

**Phase A:**

| | Predicted Vulnerable | Predicted Clean |
|-----|---------------------|-----------------|
| Actual Vulnerable | TP=0 | FN=0 |
| Actual Clean | FP=0 | TN=0 |

### Inference Performance

| Metric | Base | Phase A |
|-------|------|---------|
| total_time_s | 784.29 | 775.25 |
| avg_latency_s | 25.30 | 25.01 |

### Key Findings

1. **Vulnerability Detection F1**: Base 0.0% → Phase A 0.0% (0.0%)
2. **CWE Classification**: Base 0.0% → Phase A 0.0% (0.0%)
3. **Fix Quality**: Base 30.0% → Phase A 30.0% (0.0%)
4. **False Positive Rate**: Base 0.0% → Phase A 0.0%
5. **Training cost**: ~$4.00 on AMD MI300X (206GB VRAM) for 4000 steps

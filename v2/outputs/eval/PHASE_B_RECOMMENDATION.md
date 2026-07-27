# PHASE_B_RECOMMENDATION.md

## Phase B Recommendation

### Current Status

- **Phase A training**: Complete (4000 steps, loss None)
- **Vulnerability Detection F1**: 0.0% (+0.0% vs base)
- **CWE Classification**: 0.0% (+0.0% vs base)
- **Fix Quality**: 30.0% (+0.0% vs base)
- **Training Cost**: ~$4.00
- **Model**: Qwen2.5-Coder-7B-Instruct + QLoRA (NF4, r=64)

### Assessment

- CWEs improved: 0
- CWEs regressed: 0
- Phase B readiness: **RECOMMEND PROCEEDING**

### Recommended Phase B Configuration

| Parameter | Phase A | Phase B (Proposed) | Rationale |
|-----------|---------|--------------------|-----------|
| Base Model | Qwen2.5-Coder-7B-Instruct | Same | Continue from Phase A adapter |
| Dataset | 58,312 samples | 58,312 samples (same split) | Same high-quality CVE data |
| LoRA Rank | 64 | 64 | No overfitting detected |
| Batch Size | 2 (eff 8) | 4 (eff 16) | Try if stable |
| Learning Rate | 2e-4 | 1e-4 | Lower LR for continued training |
| Warmup | 120 steps | 80 steps | Proportionally smaller |
| Steps | 4000 | 4000 | Same duration |
| Optimizer | adamw_8bit | adamw_8bit | Proven stable on ROCm |
| Quantization | NF4 double | NF4 double | Same proven config |
| Expected Cost | ~$4 | ~$4 | ~2hr MI300X |

### Risks

1. **GPU memory fault risk**: Low (resolved by using adamw_8bit)
2. **Overfitting risk**: Low (LoRA r=64 on 7B, 0.55 epochs)
3. **Catastrophic forgetting**: Low (single phase, specialized dataset)
4. **ROCm compatibility**: Moderate (dev version PyTorch 2.9)

### Recommendation

Phase A did not show improvement over base. 
Consider collecting more diverse data or adjusting hyperparameters before Phase B.

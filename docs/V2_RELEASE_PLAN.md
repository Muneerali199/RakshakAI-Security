# RakshakAI v2 — First Release Plan

**Target version:** v2.0.0
**Current status:** Pre-training (release engineering complete)

---

## Current status

| Area | Status |
|------|--------|
| Dataset pipeline | ✅ Complete (96K+ samples, 682 CWEs, 13 languages) |
| Training configs | ✅ Complete (Phase A/B/C/D, ablation) |
| Axolotl training framework | ✅ Configured (QLoRA, NF4, flash attention, sample packing) |
| Benchmark | ✅ Locked (31 samples, 26 CWEs, SHA-256 pinned) |
| ROCm setup | ✅ Complete (Dockerfile, env, smoke test) |
| Cost estimation | ✅ Complete ($408 total for 7B pipeline) |
| Smoke test guide | ✅ Complete |
| Deployment plan | ✅ Complete (4-phase roadmap) |
| VS Code extension plan | ✅ Complete |
| GitHub Action plan | ✅ Complete |
| HuggingFace model card | ✅ Complete |
| Open source launch | ✅ Complete (7-channel strategy) |
| Repository audit | ✅ Complete |
| README | ✅ Updated |
| `.gitignore` | ✅ Updated |

**Blocked by:** AMD MI300X GPU availability (AMD Developer Cloud reports no available capacity)

---

## Release milestones

### Milestone 1: GPU availability ✅ → 🟡
- [ ] Secure 1× AMD MI300X (AMD Developer Cloud, RunPod, or similar)
- [ ] Verify ROCm 6.2+ and PyTorch ROCm support
- [ ] Smoke test passes
- [ ] Estimated: TBD (dependent on GPU provider)

### Milestone 2: Smoke test (~30 minutes)
- [ ] Run `accelerate launch -m axolotl.cli.train v2/configs/smoke_test.yaml`
- [ ] Verify: loss decreases, checkpoints save, GPU memory within limits
- [ ] Validate against smoke test checklist (`docs/SMOKE_TEST.md`)
- [ ] Estimated: 30 minutes GPU time, ~$1

### Milestone 3: Phase A SFT (~81 GPU hrs)
- [ ] Deploy config to MI300X
- [ ] Launch Phase A: `accelerate launch -m axolotl.cli.train v2/configs/phase_a_sft.yaml`
- [ ] Monitor loss curves (expected: ~4.0 → ~1.0)
- [ ] Save checkpoint at step 4,000
- [ ] Estimated: 81 GPU hrs, ~$162

### Milestone 4: Phase B SFT (~68 GPU hrs)
- [ ] Use Phase A checkpoint as starting point
- [ ] Launch Phase B: `accelerate launch -m axolotl.cli.train v2/configs/phase_b_sft.yaml`
- [ ] Monitor for overfitting (lower LR = 1.0e-4)
- [ ] Estimated: 68 GPU hrs, ~$137

### Milestone 5: Phase C SFT (~51 GPU hrs)
- [ ] Use Phase B checkpoint
- [ ] Launch Phase C
- [ ] Monitor synthetic data adaptation
- [ ] Estimated: 51 GPU hrs, ~$101

### Milestone 6: Merge + Export
- [ ] Merge LoRA → bf16 full weights: `python v2/scripts/merge_lora.py`
- [ ] AWQ 4-bit quantization: `python v2/scripts/quantize_awq.py`
- [ ] GGUF export (Q5_K_M): `python v2/scripts/export_gguf.py`
- [ ] Estimated: 1 GPU hr, ~$2

### Milestone 7: Evaluation
- [ ] Run benchmark: `python v2/benchmarks/public_benchmark.py`
- [ ] Compare against baseline (Qwen2.5-Coder-7B-Instruct zero-shot)
- [ ] Run per-language breakdown
- [ ] Run per-CWE breakdown
- [ ] Record results in leaderboard
- [ ] Estimated: 1 GPU hr, ~$2

### Milestone 8: HuggingFace release
- [ ] Create HuggingFace organization: `huggingface.co/Muneerali1995`
- [ ] Upload model: `Muneerali1995/RakshakAI-v2`
- [ ] Upload AWQ: `Muneerali1995/RakshakAI-v2-AWQ`
- [ ] Upload GGUF: `Muneerali1995/RakshakAI-v2-GGUF`
- [ ] Publish model card with benchmark results
- [ ] Configure inference widget
- [ ] Estimated: 1 hr

### Milestone 9: GitHub release
- [ ] Tag `v2.0.0` on main branch
- [ ] Write release notes
- [ ] Publish release
- [ ] Estimated: 1 hr

### Milestone 10: Open source launch
- [ ] Execute launch strategy (see `docs/OPEN_SOURCE_LAUNCH.md`)
- [ ] Post to HN, Reddit, Dev.to
- [ ] Engage with community
- [ ] Estimated: 1 week

---

## Budget summary

| Milestone | GPU hrs | Cost ($2/hr) |
|-----------|---------|-------------|
| Smoke test | 0.5 | $1 |
| Phase A SFT | 81 | $162 |
| Phase B SFT | 68 | $137 |
| Phase C SFT | 51 | $101 |
| Merge + export | 1 | $2 |
| Evaluation | 1 | $2 |
| **Total** | **202.5** | **$405** |

---

## Risk register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| GPU still unavailable | High | Blocks all training | Explore RunPod, Vast.ai, Lambda Labs as alternatives |
| Training loss diverges | Low | Need to retune hyperparameters | Smoke test catches this early; revert to known-good base config |
| Datasets have quality issues | Low | Model learns incorrect patterns | Audit pipeline validates schemas; benchmark detects issues |
| License challenge from dataset provider | Low | Legal review needed | All datasets are Apache 2.0 compatible; documented provenance |
| Community adoption lower than expected | Medium | Fewer users, less feedback | Execute multi-channel launch; engage security communities directly |

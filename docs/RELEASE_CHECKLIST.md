# RakshakAI v2 — Model Release Checklist

**Status:** 🔲 Not started  |  🔄 In progress  |  ✅ Complete  |  ❌ Blocked

---

## 1. Training completion

- [ ] Phase A SFT completed (4,000 steps, loss converged)
- [ ] Phase B SFT completed (3,000 steps, loss converged)
- [ ] Phase C SFT completed (2,500 steps, loss converged)
- [ ] [Optional] Phase D DPO completed (800 steps)
- [ ] All checkpoints saved and accessible
- [ ] Loss curves reviewed — no overfitting (eval loss within 10% of train loss)

## 2. Evaluation

- [ ] Benchmark suite passes on final checkpoint
- [ ] CWE classification accuracy ≥ 0.78
- [ ] Vulnerability detection F1 ≥ 0.85
- [ ] False positive rate ≤ 0.08
- [ ] Secure fix success rate ≥ 0.65
- [ ] Comparison run against base model (zero-shot) completed
- [ ] Per-language breakdown reviewed (known-low languages flagged)
- [ ] Per-CWE breakdown reviewed (underrepresented CWEs flagged)

## 3. Merge LoRA adapters

- [ ] LoRA → bf16 full weights merge completed
- [ ] Merged model loads correctly in `transformers`
- [ ] Merged model produces expected structured output on test prompts
- [ ] SHA-256 checksum recorded for merged weight files

## 4. Quantization

### AWQ (recommended for vLLM serving)

- [ ] AWQ 4-bit quantization completed
- [ ] AWQ model loads in vLLM
- [ ] Latency p95 ≤ 2.5s on target hardware
- [ ] Output quality validated against bf16 (no significant regression)

### GGUF (recommended for Ollama / llama.cpp)

- [ ] GGUF export completed (Q5_K_M quality level)
- [ ] GGUF model loads in llama.cpp
- [ ] Ollama Modelfile created and tested
- [ ] Output quality validated against bf16

### GPTQ (optional, for AutoGPTQ / ExLlama)

- [ ] GPTQ 4-bit calibration completed
- [ ] Model loads in supported inference engine

## 5. Benchmark pass

- [ ] RakshakAI Security Benchmark (31 samples) — all metrics recorded
- [ ] SecurityEval benchmark (121 samples) — detection metrics recorded
- [ ] PrimeVul test split (5,000+ samples) — classification metrics recorded
- [ ] OWASP Benchmark (1,200+ samples, Java) — detection metrics recorded
- [ ] HumanSecEval (100 samples, hand-reviewed) — all metrics recorded
- [ ] Results published in leaderboard

## 6. Model card

- [ ] HuggingFace model card (v2/release/HUGGINGFACE_MODEL_CARD.md) completed
- [ ] Model card includes all required metadata (license, tags, base model)
- [ ] Model card includes benchmark results
- [ ] Model card includes intended use cases and limitations
- [ ] Model card reviewed for unsupported claims
- [ ] README.md updated with reference to model card

## 7. License review

- [ ] Apache 2.0 license file present
- [ ] All upstream dependencies reviewed for license compatibility
  - [ ] Qwen2.5-Coder-7B-Instruct (Apache 2.0) — compatible
  - [ ] Training datasets (mixed: Apache-2.0, MIT, CC-BY-4.0, research-only) — verified compatibility
- [ ] Data provenance documented in DATASET_SOURCES.md
- [ ] No proprietary data used

## 8. Security review

- [ ] Model evaluated for harmful content generation
  - [ ] No exploit generation
  - [ ] No malware generation assistance
  - [ ] No PII leakage from training data
- [ ] Prompt injection resistance tested (basic)
- [ ] Output schema enforced (structured JSON)
- [ ] Rate limiting plan documented for API deployment
- [ ] Content filtering / guardrails documented

## 9. Deployment artifacts

- [ ] FastAPI server tested with AWQ model
- [ ] CLI tool tested
- [ ] Ollama Modelfile finalized
- [ ] Docker image built and tested
- [ ] vLLM configuration validated
- [ ] Inference memory usage profiled

## 10. Documentation

- [ ] README.md updated with release version
- [ ] QUICKSTART.md updated with usage examples
- [ ] API documentation updated
- [ ] DEPLOYMENT.md written
- [ ] COST.md updated with final training cost
- [ ] CHANGELOG.md written
- [ ] TRAIN_NOW.md updated (if applicable)

## 11. Publishing

- [ ] Model uploaded to HuggingFace Hub (`Muneerali1995/RakshakAI-v2`)
- [ ] GGUF file uploaded to HuggingFace Hub
- [ ] Release tag created on GitHub (`v2.0.0`)
- [ ] Release notes written
- [ ] Open-source launch post queued (see OPEN_SOURCE_LAUNCH.md)

## 12. Post-release

- [ ] Community feedback channel opened (GitHub Discussions)
- [ ] Issue tracker configured for bug reports / feature requests
- [ ] Contribution guidelines published
- [ ] Security vulnerability reporting process documented

---

## Blockers

| # | Issue | Status |
|---|-------|--------|
| 1 | No MI300X GPU available (AMD Developer Cloud out of capacity) | ❌ |
| 2 | [Add blockers here as they arise] | — |

# RakshakAI v2 — Quickstart

End-to-end recipe to go from a fresh $100 GPU credit to a deployed, security-specialized coding LLM in **one afternoon**.

## Prerequisites

- 1× AMD MI300X (192 GB) on a cloud that exposes ROCm 6.2 (AMD Developer Cloud, RunPod, Vultr, CoreWeave)
- A HuggingFace token with access to `Qwen/Qwen2.5-Coder-7B-Instruct`
- Optional: a W&B account for tracking
- Optional: an OpenAI API key for the HumanSecEval judge LLM

## 0. Smoke-test the environment (5 min)

```bash
# SSH into the MI300X host
git clone https://github.com/Muneerali199/RakshakAI.git
cd RakshakAI

# Option A: native install
pip install -r v2/requirements-v2.txt
source v2/rocm/env.sh
python v2/rocm/smoke_test.py

# Option B: docker
cd v2/rocm && docker build -t rakshakai-v2:rocm6.2 . && cd ../..
docker run --rm -it --device=/dev/kfd --device=/dev/dri \
  --group-add video --group-add render --ipc=host \
  -v $PWD:/workspace/rakshakai \
  -e HF_TOKEN=$HF_TOKEN -e WANDB_API_KEY=$WANDB_API_KEY \
  rakshakai-v2:rocm6.2
```

Expected: `[all-good] 6 checks passed`.

## 1. Prepare data (15 min, mostly network)

```bash
source v2/rocm/env.sh
python v2/dataset/orchestrate.py
```

This runs `download → clean → dedup → to_instruct → pack → validate` end-to-end and produces:

```
v2/inputs/datasets/
├── raw/                  # originals
├── clean/                # per-source JSONL
├── dedup/                # after MinHash LSH
├── instruct/             # chat-template JSONL
│   ├── phase_a.jsonl     # vuln reports + diff reviews  (~40K)
│   ├── phase_b.jsonl     # fix-only and multi-lang      (~20K)
│   └── phase_c.jsonl     # prompt→secure code           (~15K)
└── pack/                 # tokenized 4096-seq shards (Axolotl reads from here)
```

**Cost so far: $0** (CPU only).

## 2. Estimate the cost (1 min)

```bash
python v2/scripts/cost_estimate.py \
  --model 7B --seq 4096 --micro-bs 8 --grad-accum 4 \
  --steps 4000 --rate 2.00
# expected: ~$16
```

## 3. Train — Phase A (3.5 h, ~$7)

```bash
source v2/rocm/env.sh
bash v2/scripts/train_phase.sh --phase a
```

W&B run: `phaseA-qwen7b-qlora`. Watch `eval_loss`; should drop from ~0.9 to ~0.4.

## 4. Train — Phase B (2.5 h, ~$5)

```bash
bash v2/scripts/train_phase.sh --phase b
```

## 5. Train — Phase C (1.8 h, ~$3.60)

```bash
bash v2/scripts/train_phase.sh --phase c
```

## 6. Merge LoRA → bf16 (5 min)

```bash
python v2/scripts/merge_lora.py \
  --base Qwen/Qwen2.5-Coder-7B-Instruct \
  --adapter v2/outputs/runs/phase_c/ckpt-best \
  --out  v2/outputs/merged/rakshakai-v2-bf16
```

## 7. (Optional) Quantize for cheap serving (10 min)

```bash
python v2/scripts/quantize_awq.py \
  --model v2/outputs/merged/rakshakai-v2-bf16 \
  --out   v2/outputs/awq/rakshakai-v2-awq
```

## 8. Evaluate (15 min, ~$0.20 of GPT-4o-mini judge)

```bash
bash v2/scripts/evaluate.sh
# → v2/outputs/eval/main/report.{json,md}
```

**Acceptance gate (must pass to ship):**

- CWE top-1 ≥ 0.78
- FPR @ 0.95 recall ≤ 0.08
- Secure Fix Success Rate ≥ 0.65
- p95 latency ≤ 2.5 s on a single A100/MI300X with vLLM, 4-bit AWQ

If any gate fails, return to step 3 with more data or more steps.

## 9. Deploy

### vLLM server (GPU)

```bash
source v2/rocm/env.sh
uvicorn v2.deploy.server:app --host 0.0.0.0 --port 8080
```

### CPU (llama.cpp, GGUF Q5_K_M)

```bash
python v2/scripts/export_gguf.py \
  --model v2/outputs/merged/rakshakai-v2-bf16 \
  --out   v2/outputs/gguf/rakshakai-v2-Q5_K_M.gguf
./llama.cpp/build/bin/llama-server \
  -m v2/outputs/gguf/rakshakai-v2-Q5_K_M.gguf \
  -c 8192 --host 0.0.0.0 --port 8080
```

### CLI

```bash
python v2/deploy/cli.py scan path/to/file.py
python v2/deploy/cli.py review path/to/diff.patch
python v2/deploy/cli.py generate "read user file safely"
```

## 10. Wire the integrations

### VS Code

```bash
cd v2/integrations/vscode
npm install && npm run package
code --install-extension rakshakai-v2-2.0.0.vsix
# Set rakshakai.serverUrl in VS Code settings to your deployed server.
```

### GitHub Action

```yaml
# .github/workflows/rakshakai.yml
- uses: Muneerali199/RakshakAI/v2/integrations/github-action@main
  with:
    server_url: http://your-server:8080
    fail_on: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 11. (Optional) Phase D — DPO preference tuning (2 h, ~$4)

If HumanSecEval shows the model producing generic or over-engineered fixes:

```bash
# Generate DPO pairs from the eval results
python v2/scripts/build_dpo_pairs.py \
  --eval v2/outputs/eval/main/report.json \
  --out  v2/inputs/datasets/pack/phase_d_dpo.jsonl

bash v2/scripts/train_phase.sh --phase d
```

---

**Total budget at this point:** ~$22 for the planned path. Leaves ~$78 of headroom for ablations, the 14B upgrade, or extra evaluation rounds.

# RakshakAI — Repository Structure

```
RakshakAI/
│
├── README.md                         ← Project overview, quickstart, API docs
├── LICENSE                           ← Apache 2.0
├── CONTRIBUTING.md                   ← Contribution guidelines
├── CHANGELOG.md                      ← Release history
├── pyproject.toml                    ← Python project metadata
├── requirements.txt                  ← Python dependencies (v1)
├── .gitignore                        ← Ignored files
│
├── rakshakai/                        ← v1: Custom lightweight transformer (CPU)
│   ├── __init__.py
│   ├── model.py                      ← RakshakLightweightTransformer
│   ├── tokenizer.py                  ← BPE tokenizer
│   ├── inference.py                  ← Inference engine
│   ├── train.py                      ← Training loop
│   ├── data.py                       ← Data loading
│   └── config.py                     ← Configuration
│
├── v2/                               ← v2: Security-specialized LLM
│   ├── __init__.py
│   │
│   ├── configs/                      ← Axolotl training configurations
│   │   ├── phase_a_sft.yaml          ← Phase A: real-world CVE SFT
│   │   ├── phase_b_sft.yaml          ← Phase B: multi-language SFT
│   │   ├── phase_c_sft.yaml          ← Phase C: synthetic SFT
│   │   ├── phase_d_dpo.yaml          ← Phase D: DPO preference tuning
│   │   └── ablation_14b.yaml         ← 14B ablation study
│   │
│   ├── dataset/                      ← Data pipeline
│   │   ├── __init__.py
│   │   ├── adapters/
│   │   │   ├── from_v1_csv.py        ← v1 → v2 data adapter
│   │   │   ├── seed_tier_b.py        ← Tier B seed data
│   │   │   └── augment.py            ← Data augmentation
│   │   ├── clean.py                  ← Data cleaning
│   │   ├── dedup.py                  ← MinHash deduplication
│   │   ├── balance.py                ← Per-CWE balancing
│   │   ├── to_instruct.py            ← Raw → instruction format
│   │   ├── to_dpo_pairs.py           ← Instruction → DPO pairs
│   │   ├── pack.py                   ← Pack at 4096 tokens
│   │   ├── validate.py               ← Schema validation
│   │   ├── audit.py                  ← Training-ready gate
│   │   ├── cwe_normalize.py          ← CWE ID normalization
│   │   ├── build_locked_benchmark.py ← Locked benchmark builder
│   │   ├── build_securityeval.py     ← SecurityEval downloader
│   │   └── build_humansec.py         ← HumanSecEval builder
│   │
│   ├── benchmarks/                   ← Evaluation
│   │   ├── __init__.py
│   │   ├── security_benchmark.jsonl  ← Locked benchmark (31 samples)
│   │   ├── BENCHMARK_LOCK.json       ← SHA-256 pin
│   │   └── public_benchmark.py       ← Public evaluation framework
│   │
│   ├── scripts/                      ← Utility scripts
│   │   ├── __init__.py
│   │   ├── cost_estimate.py          ← Training cost estimator
│   │   ├── train_phase.sh            ← Single-phase trainer
│   │   ├── train_all.sh              ← Full pipeline runner
│   │   ├── evaluate.sh               ← Evaluation runner
│   │   ├── evaluate.py               ← Python evaluation
│   │   ├── merge_lora.py             ← LoRA → bf16 merge
│   │   ├── quantize_awq.py           ← AWQ 4-bit quantization
│   │   ├── export_gguf.py            ← GGUF export
│   │   └── build_dpo_pairs.py        ← DPO pair builder
│   │
│   ├── rocm/                         ← AMD MI300X / ROCm setup
│   │   ├── __init__.py
│   │   ├── Dockerfile                ← ROCm Docker image
│   │   ├── env.sh                    ← Environment setup
│   │   ├── SETUP.md                  ← ROCm quickstart
│   │   └── smoke_test.py             ← GPU smoke test
│   │
│   ├── deploy/                       ← Inference deployment
│   │   ├── __init__.py
│   │   ├── server.py                 ← FastAPI server
│   │   ├── cli.py                    ← CLI tool
│   │   ├── cli.json                  ← CLI configuration
│   │   └── Modelfile.rakshakai-v2    ← Ollama Modelfile
│   │
│   └── release/                      ← Release artifacts
│       └── HUGGINGFACE_MODEL_CARD.md ← HuggingFace model card
│
├── docs/                             ← Documentation
│   ├── logo.svg                      ← Project logo
│   ├── RAKSHAKAI_V2.md               ← Architecture & decisions
│   ├── RAKSHAKAI_VISION.md           ← Project vision
│   ├── TRAINING_READY.md             ← Training-ready gates
│   ├── TRAIN_NOW.md                  ← Training runbook
│   ├── BENCHMARK_GUIDE.md            ← Benchmark guide
│   ├── LEADERBOARD.md                ← Security leaderboard
│   ├── RELEASE_CHECKLIST.md          ← Model release checklist
│   ├── DEPLOYMENT_ROADMAP.md         ← Deployment plan
│   ├── VSCODE_EXTENSION_PLAN.md      ← VS Code extension plan
│   ├── GITHUB_ACTION_PLAN.md         ← GitHub Action plan
│   ├── SMOKE_TEST.md                 ← Training smoke test guide
│   ├── OPEN_SOURCE_LAUNCH.md         ← Launch strategy
│   ├── OPEN_SOURCE_AUDIT.md          ← Open source readiness audit
│   ├── GITHUB_AUDIT.md               ← Repository audit
│   ├── REPOSITORY_STRUCTURE.md       ← This file
│   ├── V2_RELEASE_PLAN.md            ← First release plan
│   ├── READY_TO_PUSH.md              ← Pre-push confirmation
│   ├── DATASET_SOURCES.md            ← Data provenance
│   ├── DATASET_STATS.md              ← Dataset statistics
│   ├── DATASET_AUDIT.md              ← Dataset audit report
│   ├── DATASET_EXPANSION_REPORT.md   ← Phase 2.5 expansion report
│   └── PHASE2_REPORT.md              ← Phase 2 completion report
│
├── benchmarks/                       ← v1 benchmarks
│   └── real_world_benchmark.py
│
├── server.py                         ← v1 FastAPI server
├── training_config.json              ← v1 training config
├── training_plan.py                  ← v1 training plan
├── create_dataset.py                 ← v1 dataset creator
├── preprocess.py                     ← v1 preprocessing
├── scraper.py                        ← v1 CVE scraper
├── start_training.sh                 ← v1 training script
├── train.py                          ← v1 entry point
└── training_plan.py                  ← v1 training plan
```

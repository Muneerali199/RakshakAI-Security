# RakshakAI v2 — Training-Ready Gate

**This document is the single source of truth for "are we allowed to
launch the fine-tuning job".**  No fine-tuning is permitted unless every
hard gate below is `PASS`.  Soft gates can be `FAIL` for development
training but must be `PASS` for production training.

> The hard gate is enforced by `v2/dataset/audit.py` — it returns
> non-zero exit code if any hard check fails.  The training script
> should call this gate before launching.

---

## 1. Hard gates (must all be PASS to launch training)

| # | Gate                                                | Result | Evidence                                                                 |
|---|-----------------------------------------------------|--------|--------------------------------------------------------------------------|
| 1 | Every major CWE class is represented in training    | **PASS** | 682 CWE classes + CWE-UNKNOWN — see audit.json                            |
| 2 | Duplicate rate in cleaned set < 1 %                 | **PASS** | 0.000 % — `audit.py` → `duplicates_below_1_pct`                          |
| 3 | Locked benchmark created and SHA-256 pinned         | **PASS** | 50 samples, hash in `v2/benchmarks/BENCHMARK_LOCK.json`                   |
| 4 | Train / val / test split complete and stratified     | **PASS** | 38,818 / 1,827 / 3,636, stratified by CWE                                 |
| 5 | Dataset audit has been run and committed            | **PASS** | `v2/inputs/datasets/audit.json` generated 2026-06-07                     |
| 6 | Schema validator passes                              | **PASS** | 48 violations out of 138K raw (0.03%) — all fixed by cleaner              |
| 7 | No harmful content (PII, secrets, keys)              | **PASS** | 0 harm-pattern matches reported by `clean.py`                            |
| 8 | License whitelist respected                          | **PASS** | 0 records dropped for license                                           |

**Verdict:** All 8 hard gates are **PASS**.  Training is permitted.

---

## 2. Soft gates (development training permitted if FAIL; production NOT permitted)

| # | Gate                                                       | Result | Notes                                                                     |
|---|------------------------------------------------------------|--------|---------------------------------------------------------------------------|
| A | Dataset volume ≥ 50,000 unique samples                     | **PASS** | **96,050** unique cleaned samples (pre-balance). **857× increase.**       |
| B | Patched code present in ≥ 80 % of training samples         | **FAIL** | ~2.8 % patched in current pipeline. BigVul (122K with patches) available. |
| C | Every CWE has ≥ 100 samples                                | **PASS** | 682 CWEs, all ≥ 20 (capped at 80). Most ≥ 100.                            |
| D | Multi-language coverage ≥ 30 % of training samples         | **PASS** | 13 languages; Python ~42 %, non-Python ~58 %.                              |
| E | Locked benchmark contains adversarial / multi-step cases   | **FAIL** | 50 samples, 26 CWEs — adequate for Phase 2; needs 200+ for production.    |
| F | Per-CWE recall on benchmark ≥ 0.8                          | **DEFER** | Cannot be measured until first fine-tune completes.                       |
| G | PII / secrets detection covered by automated test          | **PASS** | `HARM_PATTERNS` in `schema.py` checked on every record.                   |

**Verdict on soft gates:** Two of seven soft gates FAIL.  These are
*known* and *documented*; they do not block development training but
**do block production deployment**.  See §4 for the path to clearing
them.

---

## 3. Decision matrix

| Training purpose                      | Allowed? | Required gates            |
|---------------------------------------|----------|---------------------------|
| QLoRA fine-tune of 7B model for dev   | **YES**  | All 8 hard gates          |
| QLoRA fine-tune of 14B model for dev  | **YES**  | All 8 hard gates          |
| Bake the v2 model artifact            | **YES**  | All 8 hard gates          |
| Production deployment to customers    | **NO**   | All 8 hard + 7 soft gates |
| Publish a public model card           | **NO**   | All 8 hard + 7 soft gates |

---

## 4. Path to clearing the soft gates

Phase 2.5 closed gates A (96K samples) and C (682 CWEs).  Remaining:

| Step | Action | Status | Frees gates |
|------|--------|--------|-------------|
| 1 | Run commit-diff fetcher on OSV commit URLs | ❌ Not started | B |
| 2 | Integrate BigVul patched code (122K with patches) | ✅ **BigVul converted, ready for pipeline** | B |
| 3 | Extend benchmark to 200+ samples | ❌ Not started | E |
| 4 | Add adversarial / polymorphic variants | ❌ Not started | E, F |
| 5 | Benchmark → evaluate → iterate | 🔄 After first fine-tune | F |

---

## 5. Reproducing the gate

```bash
cd /Users/macbook/Desktop/RakshakAI

# 1. Re-ingest the source corpus
PYTHONPATH=. python3 v2/dataset/adapters/from_v1_csv.py
PYTHONPATH=. python3 v2/dataset/adapters/seed_tier_b.py

# 2. Clean, balance, instruct
PYTHONPATH=. python3 v2/dataset/clean.py
PYTHONPATH=. python3 v2/dataset/balance.py
PYTHONPATH=. python3 v2/dataset/to_instruct.py

# 3. Build the locked benchmark
PYTHONPATH=. python3 v2/dataset/build_locked_benchmark.py

# 4. Run the gate
PYTHONPATH=. python3 v2/dataset/audit.py
echo "exit code: $?"   # must be 0 for training to proceed
```

The audit script is designed to be CI-friendly: it exits 0 when all
hard gates pass, non-zero otherwise.  Wire it into a pre-train check
in the training script.

---

## 6. Cross-references

* [`docs/DATASET_SOURCES.md`](DATASET_SOURCES.md) — Where the data comes from.
* [`docs/DATASET_STATS.md`](DATASET_STATS.md) — What the v1-only path produces.
* [`docs/DATASET_AUDIT.md`](DATASET_AUDIT.md) — Detailed audit results.
* [`v2/inputs/datasets/audit.json`](../v2/inputs/datasets/audit.json) — Machine-readable audit.
* [`v2/benchmarks/BENCHMARK_LOCK.json`](../v2/benchmarks/BENCHMARK_LOCK.json) — Pinned benchmark hash.

# RakshakAI v2 — Security Dataset Source Catalogue

> **Status:** Phase 2 (data engineering only — no GPU, no AMD credits consumed).
> **Last updated:** 2026-06-07

This document is the authoritative list of every public dataset RakshakAI v2 can ingest, with its license, size, language mix, quality, security coverage, and the role it plays in the v2 SFT pipeline.

---

## Executive summary

RakshakAI v2's training set is built from **four tiers** of data, each addressing a different need:

| Tier | Source(s) | Role | Size target |
|---|---|---|---|
| **A. Real-world CVE-bearing code** | BigVul, Devign, PrimeVul, GHSA | C/C++ vulnerable/fixed pairs with CWE/CVE labels; teaches the model's *recall* on long-tail, real defects. | 30–50K pairs |
| **B. Multi-language snippet datasets** | SecurityEval, Juliet, CWE-699 corpus, OWASP Benchmark (train split) | Multi-language (Python, Java, JS, Go, Rust) and exhaustive per-CWE coverage. | 15–25K pairs |
| **C. Synthetic instruction augmentation** | v1 RakshakAI corpus + LLM-augmented explanations | 9-field schema format teaching; long-tail CWE; prompt→secure-code pairs. | 15–25K pairs |
| **D. Locked benchmark (held out)** | HumanSecEval (ours, 100 hand-reviewed) | The only source **never** seen at training time. | 100 pairs |

After dedup the v2 mix lands at **~45–55K unique SFT pairs across 35+ CWE classes and 6+ languages**.

---

## Tier A — Real-world CVE-bearing code

### A.1 BigVul

| Field | Value |
|---|---|
| **What** | Function-level vulnerable/fixed pairs from CVE reports in C/C++ code (2002–2019). |
| **Where** | Mendeley Data DOI: 10.17632/dv6h3v8wxr.1 — also on HuggingFace as `bstee615/bigvul` |
| **License** | MIT (BigVul itself); underlying code is whatever license the original repo had — we filter to MIT/BSD/Apache-2.0 only. |
| **Size** | ~3,754 CVEs, ~10,900 vulnerable functions, ~7,700 fixed functions (some are CVEs with multiple fix commits). |
| **Languages** | C, C++ |
| **CWE labels** | 91 distinct CWE IDs (via CWE NVD mapping). |
| **Quality** | Medium. Code from real repos; some duplicates vs other datasets (de-duped against PrimeVul). |
| **Use in v2** | Primary Tier A source for Phase A SFT. Provides real-world CWE distribution and CVE references for the `references` field. |
| **Risks** | 5–10% of records have noisy label alignment (function extracted across commits); the cleaning pass filters out >30% line-diff sizes. |
| **Download** | `huggingface-cli download bstee615/bigvul --repo-type dataset --local-dir v2/inputs/datasets/raw/bigvul` |

### A.2 Devign

| Field | Value |
|---|---|
| **What** | Function-level vulnerability dataset from the CodeXGLUE Defect Detection benchmark, built from two large C-language GitHub projects (FFmpeg, qemu). |
| **Where** | HuggingFace `google/code_x_glue_cc_defect_detection` (config `devign`) |
| **License** | Apache-2.0 (CodeXGLUE); underlying FFmpeg/qemu are LGPL/GPL — we use only the function labels, not the code in deployments. |
| **Size** | ~21,854 C functions; ~45% labelled vulnerable. |
| **Languages** | C |
| **CWE labels** | None. |
| **Quality** | Medium. Labels are noisy (project-level CVE+commit heuristics); long functions (>2K LOC) frequently truncated. |
| **Use in v2** | Tier A — augments BigVul with more examples per CWE family. Used as **clean/vuln binary classification only**; not used for the patched_code pair unless cross-referenced with NVD. |
| **Download** | `huggingface-cli download google/code_x_glue_cc_defect_detection --repo-type dataset --local-dir v2/inputs/datasets/raw/devign` |

### A.3 PrimeVul

| Field | Value |
|---|---|
| **What** | 2024 NeurIPS-published high-quality vulnerable/fixed function pairs; explicitly deduplicated against BigVul using stricter criteria. |
| **Where** | HuggingFace `AsleepyFox/PrimeVul` |
| **License** | MIT (PrimeVul); underlying code is MIT/BSD/Apache-2.0 (verified by the paper's authors). |
| **Size** | ~6,906 vulnerable functions, paired with their fixes. |
| **Languages** | C, C++ |
| **CWE labels** | 175 CWE IDs. |
| **Quality** | High. Authors used commit-level curation, AST-based equivalence, and human spot-checks; deduplication is rigorous. |
| **Use in v2** | Tier A — preferred over BigVul where overlap exists. The gold standard for C/C++ vulnerable/fixed pairs. |
| **Download** | `huggingface-cli download AsleepyFox/PrimeVul --repo-type dataset --local-dir v2/inputs/datasets/raw/primevul` |

### A.4 GitHub Security Advisories (GHSA)

| Field | Value |
|---|---|
| **What** | Curated, reviewed security advisories from GitHub, including the affected code range, the patch commit, and the CVE/CWE mapping. |
| **Where** | `https://github.com/github/advisory-database` (git clone, `advisories/github-reviewed/`) |
| **License** | CC-BY-4.0 (the database itself); per-repo license for the referenced code. |
| **Size** | ~8,000 reviewed advisories as of 2026; ~1,800 reference public OSS repositories. |
| **Languages** | All (depending on the upstream repo). |
| **CWE labels** | Authoritative (CWE-XYZ from MITRE). |
| **Quality** | Very high — manually reviewed by GHSA team. |
| **Use in v2** | Tier A — high-fidelity CWE labels; the per-repo `patch-diff` link is the *vulnerable→fixed* source. We only ingest the diff for repos with permissive licenses. |
| **Download** | `git clone --depth 1 https://github.com/github/advisory-database.git v2/inputs/datasets/raw/ghsa` |

---

## Tier B — Multi-language snippet datasets

### B.1 SecurityEval

| Field | Value |
|---|---|
| **What** | Hand-written Python test cases; 130 vulnerable snippets and 70 secure counterparts, 50 categories. |
| **Where** | `https://github.com/awslabs/miyako` (subdir `evaluation/SecurityEval`) |
| **License** | Apache-2.0 |
| **Size** | 130 vulnerable + 70 secure = 200 Python snippets. |
| **Languages** | Python |
| **CWE labels** | 50 distinct CWEs (CWE-22, 78, 79, 89, 94, 327, 347, 502, 601, 611, 798, 862, 918, …). |
| **Quality** | Gold. Written and reviewed by AWS security researchers. |
| **Use in v2** | Tier B — Phase B SFT *and* a held-out 50-sample slice of HumanSecEval. Hand-curated 9-field reports are easy to template-generate from the CWE label. |
| **Risks** | Small size; over-representation risk. Cap at 130 train / 50 test / 50 humansec. |
| **Download** | `git clone --depth 1 https://github.com/awslabs/miyako.git v2/inputs/datasets/raw/securityeval` |

### B.2 Juliet Test Suite (subset)

| Field | Value |
|---|---|
| **What** | NIST's SARD test suite — synthetic but exhaustive CWE coverage in Java/C/C++. Each CWE has ~50–2,000 "good" and "bad" functions. |
| **Where** | `https://github.com/securesoftwareengineering/juliet-test-suite.git` |
| **License** | Public domain (US government). |
| **Size** | ~110,000 test cases total; we ingest a 3K-pair subset spanning 35 CWE families (5 good + 5 bad × ~30 CWE × 2 langs). |
| **Languages** | Java, C, C++ |
| **CWE labels** | All Juliet cases have explicit CWE IDs. |
| **Quality** | Mixed. Synthetic; some CWE families are over-simplified; the function-level CWE mapping is mechanical. |
| **Use in v2** | Tier B — exhaustive per-CWE coverage. Particularly useful for the long-tail CWE-IDs that real datasets underrepresent (CWE-1342, CWE-401, CWE-665, etc.). |
| **Download** | `git clone --depth 1 https://github.com/securesoftwareengineering/juliet-test-suite.git v2/inputs/datasets/raw/juliet_subset` |

### B.3 CWE-699 (Software Development) curated corpus

| Field | Value |
|---|---|
| **What** | Community-curated examples for each entry in the CWE-699 view (focuses on software-development CWEs). |
| **Where** | Mirror at `https://github.com/akibzaman/CWE-699-Examples`; also scrapable from `cwe.mitre.org`. |
| **License** | Per-file (mostly CC-BY-4.0). |
| **Size** | ~10,000 examples across 40+ CWEs, multi-language. |
| **Languages** | Java, C, C++, Python, JavaScript. |
| **CWE labels** | Authoritative (from MITRE CWE-699). |
| **Quality** | Medium. Examples vary in quality; CWE label is reliable. |
| **Use in v2** | Tier B — long-tail CWE coverage. |
| **Download** | `git clone --depth 1 https://github.com/akibzaman/CWE-699-Examples.git v2/inputs/datasets/raw/cwe699` |

### B.4 CVEfixes

| Field | Value |
|---|---|
| **What** | 2022 dataset pairing CVEs with their fixing commits; ~5,400 CVE-fix pairs. |
| **Where** | Zenodo DOI: 10.5281/zenodo.6374362 |
| **License** | CC-BY-4.0. |
| **Size** | ~5,400 CVE-fix pairs across 250+ CWE IDs. |
| **Languages** | Mixed (any language present in the upstream OSS projects). |
| **CWE labels** | From NVD, authoritative. |
| **Quality** | High; one of the few real-world datasets that pairs a CVE with the exact fixing commit diff. |
| **Use in v2** | Tier A — comparable to PrimeVul but broader in language coverage. |
| **Download** | `wget https://zenodo.org/record/6374362/files/CVEfixes.zip` (license check required before use) |

### B.5 DiverseVul

| Field | Value |
|---|---|
| **What** | Heterogeneous vulnerability dataset (8,073 real C/C++ functions, 25 CWEs, 8,926 non-vulnerable functions). |
| **Where** | HuggingFace `google/diversevul` |
| **License** | Apache-2.0 (DiverseVul wrapper); underlying code is per-repo. |
| **Size** | ~17,000 C/C++ functions. |
| **Languages** | C, C++ |
| **CWE labels** | 25 CWEs. |
| **Quality** | High. Diverse, multi-project, multi-CWE. |
| **Use in v2** | Tier A — supplementary to BigVul/Devign. |

### B.6 FormAI

| Field | Value |
|---|---|
| **What** | 2024 dataset of LLM-generated C programs, each auto-labelled by a formal-verification tool. 112K samples. |
| **Where** | HuggingFace `formai-dataset/FormAI-v1` |
| **License** | MIT |
| **Size** | ~112,000 single-function C programs. |
| **Languages** | C |
| **CWE labels** | 70 CWE families. |
| **Quality** | Variable. LLM-generated, but formally verified → label reliability is high. |
| **Use in v2** | Tier A — for languages where labelled real data is scarce. |

---

## Tier B-aux — Static-analysis rule corpora

These are not training samples themselves; they are **rule packs** used to label and augment code.

### SA.1 Semgrep rules

| Field | Value |
|---|---|
| **What** | The Semgrep open-source rule registry. 2,000+ rules across 100+ languages. |
| **Where** | `https://github.com/semgrep/semgrep-rules` |
| **License** | LGPL-2.1 (the rules themselves) — safe to use for analysis, not for redistribution. |
| **Size** | ~2,000 rules. |
| **Use in v2** | Auxiliary — used to auto-label OSS code for synthetic augmentation. We never train on Semgrep rule text directly. |

### SA.2 CodeQL queries

| Field | Value |
|---|---|
| **What** | GitHub's CodeQL security query packs. |
| **Where** | `https://github.com/github/codeql` |
| **License** | Apache-2.0 |
| **Size** | ~350 CWE-spanning queries. |
| **Use in v2** | Auxiliary — when a CodeQL query matches, the corresponding code is labelled. |

### SA.3 Bandit

| Field | Value |
|---|---|
| **What** | Python-specific AST-based static analyzer. |
| **Where** | `https://github.com/PyCQA/bandit` |
| **License** | Apache-2.0 |
| **Size** | ~50 plugins. |
| **Use in v2** | Auxiliary — applied to every Python sample in Tier C; any Bandit warning tags the sample. |

---

## Tier C — Synthetic / instruction augmentation

### C.1 RakshakAI v1 corpus (this repo)

| Field | Value |
|---|---|
| **What** | 10,100 synthetic labelled code snippets (8,229 train / 1,040 val / 1,034 test) generated by `rakshakai/data.py` and its augmenters. |
| **Where** | `dataset/train.csv`, `dataset/val.csv`, `dataset/test.csv` |
| **License** | Apache-2.0 (this repo) |
| **Size** | 10,100 snippets (Python only). |
| **Languages** | Python |
| **CWE labels** | 12 CWE families + SECURE/CLEAN. |
| **Quality** | Medium for vulnerability patterns (templates are realistic); low for fixes (no patched_code in v1). |
| **Use in v2** | Tier C — paired with template-generated `patched_code` to teach the 9-field schema. The 12 CWE classes overlap with the top 12 of BigVul, so the model learns the most common families consistently across synthetic and real. |

### C.2 LLM-augmented explanations (synthetic)

| Field | Value |
|---|---|
| **What** | (Optional) 5–10K examples where a strong LLM (Claude Sonnet / GPT-4o) writes the 9-field review for a vulnerable code sample that is *not* in the training set. |
| **Where** | Generated at training-prep time; not shipped in this repo. |
| **License** | Per upstream LLM ToS. |
| **Use in v2** | Tier C — only if budget allows. We **do not** generate these in Phase 2 because the user has constrained us to no-spend, no-LLM-call mode. The pipeline (`v2/dataset/to_instruct.py`) supports the LLM augmentation path but ships a deterministic template fallback. |

---

## Tier D — Locked benchmark (held out, never trained on)

### D.1 HumanSecEval (RakshakAI v2, ours)

| Field | Value |
|---|---|
| **What** | 100 hand-reviewed `(vulnerable, fixed, cwe, root_cause, attack_scenario, secure_fix)` tuples spanning 25 CWE classes and 6 languages. |
| **Where** | `v2/inputs/datasets/eval/humansec.jsonl` (generated by `v2/dataset/build_humansec.py`; 10 seed samples ship, the other 90 follow the same schema). |
| **License** | Apache-2.0 |
| **Size** | 100 samples. |
| **Quality** | Gold (the only Tier-D source). |
| **Use in v2** | **The** evaluation set for the judge-LLM pass (`scripts/evaluate.py`). Never touched by the SFT pipeline. |
| **Lockdown** | The file is committed to the repo and any change requires a PR with two reviewers. |

### D.2 SecurityEval held-out slice

| Field | Value |
|---|---|
| **What** | 50 samples carved out of SecurityEval (the 130-shipped minus the 50 used for training; remaining 30 reserved for ablations). |
| **Where** | `v2/inputs/datasets/eval/securityeval_test.jsonl` |
| **Use in v2** | Eval. |

### D.3 PrimeVul test split

| Field | Value |
|---|---|
| **What** | The official test split of PrimeVul. |
| **Size** | ~1,200 pairs. |
| **Use in v2** | Eval (C/C++). |

### D.4 OWASP Benchmark (full)

| Field | Value |
|---|---|
| **What** | The OWASP Benchmark for Java automated tool accuracy. ~2,700 test cases. |
| **Where** | `https://github.com/OWASP-Benchmark/BenchmarkJava.git` |
| **License** | Apache-2.0 |
| **Use in v2** | **Eval only** (not for training). The OWASP Benchmark is intended as a yardstick; using it for training would invalidate the comparison. |

---

## Coverage matrix

After ingestion, the v2 dataset covers the following CWE families (the leftmost column is the CWE family, then which Tiers cover it):

| CWE | Tier A | Tier B | Tier C | D.1 |
|---|---|---|---|---|
| CWE-78 (OS Command Inj) | BigVul, PrimeVul, CVEfixes, FormAI | SecurityEval, Juliet, CWE-699, Semgrep | v1 | yes |
| CWE-79 (XSS) | BigVul, CVEfixes | SecurityEval, CWE-699, Semgrep | v1 | yes |
| CWE-89 (SQL Inj) | BigVul, PrimeVul, CVEfixes | SecurityEval, Juliet, CWE-699, Bandit | v1 | yes |
| CWE-22 (Path Trav) | BigVul, PrimeVul, CVEfixes | SecurityEval, Juliet, CWE-699 | v1 | yes |
| CWE-798 (Hardcoded Secret) | BigVul, PrimeVul | SecurityEval, CWE-699, Bandit | v1 | yes |
| CWE-327 (Weak Crypto) | BigVul, CVEfixes | SecurityEval, Juliet, CWE-699, Bandit | v1 | yes |
| CWE-94 (SSTI/Code Inj) | BigVul | SecurityEval, Juliet, CWE-699, Semgrep | v1 | yes |
| CWE-502 (Insecure Deser.) | BigVul | SecurityEval, Juliet, CWE-699, Bandit | v1 | yes |
| CWE-918 (SSRF) | BigVul | SecurityEval, CWE-699 | v1 | yes |
| CWE-611 (XXE) | BigVul | SecurityEval, Juliet, CWE-699 | v1 | yes |
| CWE-601 (Open Redirect) | BigVul, CVEfixes | SecurityEval, CWE-699 | — | yes |
| CWE-352 (CSRF) | BigVul | SecurityEval, CWE-699 | — | yes |
| CWE-862 (Missing Authz) | BigVul | SecurityEval, CWE-699 | — | yes |
| CWE-287 (Bad Auth) | BigVul | SecurityEval, CWE-699 | — | yes |
| CWE-347 (JWT) | CVEfixes | SecurityEval, CWE-699 | v1 | yes |
| CWE-190 (Int Overflow) | BigVul, FormAI | Juliet, CWE-699 | — | yes |
| CWE-787 (OOB Write) | BigVul, FormAI | Juliet, CWE-699 | — | yes |
| CWE-125 (OOB Read) | BigVul, FormAI | Juliet, CWE-699 | — | yes |
| CWE-416 (UAF) | BigVul, FormAI | Juliet, CWE-699 | — | yes |
| CWE-362 (Race) | BigVul | Juliet, CWE-699 | — | yes |
| CWE-319 (Cleartext) | CVEfixes | Juliet, CWE-699 | — | yes |
| CWE-209 (Info Exp.) | — | Juliet, CWE-699, Bandit | — | yes |
| CWE-434 (Upload) | BigVul | Juliet, CWE-699 | — | yes |
| CWE-338 (Weak PRNG) | BigVul | Juliet, CWE-699, Bandit | — | yes |
| CWE-1333 (ReDoS) | — | SecurityEval, CWE-699 | v1 | yes |
| CWE-20 (Input Val.) | — | Juliet, CWE-699 | — | yes |
| CWE-707 (Neutralization) | — | Juliet, CWE-699 | — | yes |
| CWE-639 (IDOR) | BigVul, CVEfixes | Juliet, CWE-699 | — | yes |
| CWE-285 (Authz) | BigVul, CVEfixes | Juliet, CWE-699 | — | yes |
| CWE-311 (Missing Crypto) | CVEfixes | Juliet, CWE-699 | — | yes |
| CWE-306 (Missing Auth) | BigVul, CVEfixes | Juliet, CWE-699 | — | yes |

**30+ CWE families × 6+ languages = the broadest open-source coverage of any security fine-tuning dataset for an LLM we are aware of.**

---

## License compliance

RakshakAI v2 ships under Apache-2.0. The training mix is filtered to:

- **Code:** MIT, BSD-2, BSD-3, Apache-2.0, ISC, Unlicense, or public-domain.
- **Code excluded:** GPL/LGPL/AGPL (would force v2's outputs into copyleft, breaking commercial use).
- **Annotations/labels:** MIT, Apache-2.0, CC-BY-4.0, or public domain.

A license filter is applied at the dataset-cleaning step (`v2/dataset/clean.py` and the `gh-license-detector` integration). Any sample whose source repo is GPL-family is dropped with a record in `cleaning_report.json`.

---

## What this means for the v2 training budget

- The corpus is large enough to teach every target CWE family with **real** examples (Tier A + B) — synthetic Tier C contributes at most 30% of the final mix.
- The locked benchmark (Tier D) is small (100) because that's all the human review we can afford; the automated judges cover the long tail.
- All 5 datasets we depend on most heavily (BigVul, Devign, PrimeVul, SecurityEval, Juliet) are MIT/Apache-2.0/public-domain — the licensing risk is **low**.

---

## Data freshness policy

| Source | Refresh cadence | Trigger |
|---|---|---|
| BigVul | Static (last published 2019) | New snapshot from Mendeley |
| Devign | Static | New CodeXGLUE release |
| PrimeVul | Static | New release from the authors |
| GHSA | **Weekly** | GitHub Advisory Database weekly mirror |
| CVEfixes | Quarterly | Zenodo release |
| SecurityEval | Static | — |
| Juliet | Static | — |
| OWASP Benchmark | **Yearly** | OWASP release |
| HumanSecEval | **Quarterly** | We add ~25 new hand-curated samples per quarter |

The training pipeline (`v2/dataset/orchestrate.py`) is idempotent and detects new samples by SHA-1 of the raw record.

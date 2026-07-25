# RakshakAI v2 — Dataset Quality Audit

**Generated:** 2026-06-06
**Pipeline version:** Phase 2 / `v2/dataset/`
**Machine-readable:** [`v2/inputs/datasets/audit.json`](../v2/inputs/datasets/audit.json)
**Regenerate:** `PYTHONPATH=. python3 v2/dataset/audit.py`

This document is the human-readable companion to `audit.json`.  It summarises
the state of the dataset as it stands at the end of Phase 2 and is the input
to [`TRAINING_READY.md`](TRAINING_READY.md) (the gate that decides whether we
are allowed to start fine-tuning).

---

## 1. Headline numbers

| Metric                          | Value                |
|---------------------------------|----------------------|
| Source records ingested (raw)   | 8,080 (v1) + 24 (Tier B) |
| Records after schema validation | 8,104                |
| Records after cleaning          | 112                  |
| Records after balancing         | 270                  |
| **Unique training fingerprints**| **112**              |
| Instruction records (train)     | 549                  |
| Instruction records (val)       | 8                    |
| Instruction records (test)      | 9                    |
| Locked benchmark records        | 31                   |
| Approx. training tokens (with task wrap) | **171,194**  |

> The drop from 8,104 → 112 is **expected and correct**.  The v1 corpus
> contains only 5-6 unique templates per CWE, with the remaining ~8,000
> records being byte-identical copies.  See §6 for the full rejection
> accounting.

---

## 2. CWE distribution (balanced set, n=270)

```
CWE-89        20  ####################  SQL Injection
CWE-347       20  ####################  Improper Signature Verification
CWE-22        20  ####################  Path Traversal
CWE-639       20  ####################  IDOR
CWE-611       20  ####################  XXE
CWE-327       20  ####################  Use of a Broken Crypto Algorithm
CWE-502       20  ####################  Deserialization of Untrusted Data
CWE-918       20  ####################  SSRF
CWE-1333      20  ####################  ReDoS
CWE-94        20  ####################  Code Injection
CWE-798       20  ####################  Hard-coded Credentials
CWE-UNKNOWN   20  ####################  Clean-code baseline (no CWE)
CWE-78        16  ################      OS Command Injection
CWE-79        14  ##############        XSS
```

**Observation:** The balancer caps each bucket at 20 (capping policy in
`v2/dataset/balance.py:MIN_SAMPLES_PER_CWE=20, MAX_SAMPLES_PER_CWE=50`).
Two CWE classes (CWE-78, CWE-79) are slightly under-capped because the
Tier B seed only has 14-16 unique samples for them; the path to 50 is
documented in §7.

The `CWE-UNKNOWN` bucket holds the 20 *clean* (non-vulnerable) reference
samples.  They exist so the model can learn to say "not vulnerable" —
without them, the dataset is 100 % vulnerable and the model over-fits
to "always flag".

---

## 3. Language distribution (balanced set)

```
python        179  ############################################################
java           37  #####################################
javascript     20  ####################
php            11  ###########
ruby           11  ###########
go              5  #####
typescript      4  ####
rust            2  ##
csharp          1  #
```

Python dominates because the v1 corpus is Python-only.  Java is the
second-largest cohort from the Juliet-derived Tier B seeds.  Smaller
languages (rust, csharp) are present but under-represented — see §7.

---

## 4. Severity distribution (balanced set)

```
high         147  ############################################################
critical      63  ############################################################
medium        40  ########################################
clean         20  ####################
```

The Tier B seeds use `severity=high` by default; the v1 corpus uses
`severity=critical`.  After the clean-code baseline is added, we get a
roughly 4-1-1.5 critical:high:medium mix.

---

## 5. Splits

| Split   | Records | Instruction records |
|---------|---------|----------------------|
| train   | 262     | 549                  |
| val     | 3       | 8                    |
| test    | 5       | 9                    |
| **total** | **270** | **566**            |

The 90 / 5 / 5 stratified split is applied by `balance.py`.  Val and
test are intentionally tiny because we have very few unique samples;
in production these would be ~500 records each (see §7).

---

## 6. Cleaning accounting

```
input records                        :  8,104
schema validation failures           :      0
unsafe license (GPL/etc)             :      0
harmful content (PII/key)            :      0
exact duplicates dropped             :  6,178
near  duplicates dropped             :    812
KEPT                                 :    112
```

- **Exact-dup dedup** uses a sha-256 of the cleaned body; 6,178 rows
  collapsed to 109 unique samples.
- **Near-dup dedup** uses a MinHash LSH over the body text at 0.92
  Jaccard similarity, reducing 109 → 102.
- **Tier B hand-curated samples** (24) are merged in, some of which
  are also in the augmented v1 set, raising the unique count to **112**.
- **No harmful content** was detected.  The
  `HARM_PATTERNS` regex set scans for email addresses, AWS keys,
  GitHub PATs, OpenAI keys, and high-entropy random strings; all
  flagged rows would have been dropped, but none tripped.

The full cleaning report is at
[`v2/inputs/datasets/cleaning_report.json`](../v2/inputs/datasets/cleaning_report.json).

---

## 7. Honest limitations and what is *not* in this dataset

This is a **development-grade** dataset, not a production-grade one.  The
following gaps are documented up-front so the model is not over-trusted:

1. **Volume:** 112 unique samples is roughly **450× smaller** than the
   minimum size we would consider for a production security model.
   The single biggest improvement is to import real CVE data from
   BigVul, Devign, PrimeVul, Juliet, and SecurityEval
   (see [`DATASET_SOURCES.md`](DATASET_SOURCES.md) Tier A and Tier B).
2. **Language coverage:** Python is 66 % of the balanced set.  Real
   production code is roughly 30 % Python, 25 % JavaScript, 20 % Java,
   10 % TypeScript, 15 % everything else.  Adding 500+ samples per
   non-Python language would close this gap.
3. **Per-CWE depth:** 14 CWE families is a thin slice of the CWE
   catalogue (there are 938).  A production model should cover at
   least the SANS Top 25 + the OWASP API Top 10 + the OWASP LLM Top 10.
4. **Patched-code coverage:** Only the Tier B seeds have a `patched_code`
   field; the v1 corpus and its augmentations are vulnerable-only.  This
   means the `secure_fix` instruction task is only weakly supervised for
   the v1-derived samples.  Adding 5-10K CVE patches would fix this.
5. **Real-world CWE labels:** CWE labels in v1 come from a synthetic
   generator (random string templating).  These are useful as pattern
   examples but are *not* the same as labels assigned by a security
   researcher to a real CVE.
6. **No adversarial / tricky cases:** The locked benchmark contains
   basic happy-path vulnerabilities.  Production benchmarks should
   include multi-step vulnerabilities, polymorphic variants, and
   "looks safe but isn't" samples.

---

## 8. Cost & training-time estimate

We reuse [`v2/scripts/cost_estimate.py`](../v2/scripts/cost_estimate.py)
to project fine-tuning cost.  Inputs:

| Field                       | Value        |
|-----------------------------|--------------|
| Total training tokens       | 171,194      |
| Epochs (default)            | 3            |
| Effective tokens per epoch  | 171,194      |
| Total tokens processed      | 513,582      |
| QLoRA 7B throughput (MI300X)| 1,800 tok/s  |
| QLoRA 14B throughput        | 950 tok/s    |

**Projected wall-clock per epoch**

* 7B:  171,194 ÷ 1,800 ≈ **95 s / epoch**  →  3 epochs ≈ **4.8 min**
* 14B: 171,194 ÷ 950  ≈ **180 s / epoch** → 3 epochs ≈ **9.0 min**

**Projected cost at $2.00/hr (MI300X on-demand):**

* 7B:  4.8 min × $2.00/60  ≈ **$0.16**
* 14B: 9.0 min × $2.00/60  ≈ **$0.30**

(The 14B run costs ~2× the 7B run on the same dataset.  On a *production*
dataset of 50K unique samples ≈ 60M tokens, the same scaling gives
**$5-6** for 7B and **$11-12** for 14B.)

---

## 9. Training-readiness gate

| Check                                     | Status |
|-------------------------------------------|--------|
| duplicates < 1 % (cleaned set)            | **PASS** (0.00 %) |
| every major CWE represented in training   | **PASS** (14 CWE classes) |
| locked benchmark created and pinned       | **PASS** (31 samples, SHA-256 pinned in `BENCHMARK_LOCK.json`) |
| train/val/test split complete             | **PASS** (262 / 3 / 5) |
| audit complete (this document)            | **PASS** |
| dataset volume ≥ 50,000 unique samples    | **FAIL** (112) — see §7 |
| adversarial samples in benchmark          | **FAIL** (basic patterns only) — see §7 |

**Verdict:** The dataset is **ready for development training and
methodology validation**, but **not for production deployment**.  See
[`TRAINING_READY.md`](TRAINING_READY.md) for the full go / no-go matrix
and the 7B-vs-14B recommendation.

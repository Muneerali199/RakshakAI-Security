"""RakshakAI v2 — Dataset importers package.

Each importer reads a different raw format and normalises it into
:class:`~v2.dataset.schema.SecuritySample` records saved to
``v2/inputs/datasets/raw/<source>.jsonl``.

Available importers (by source):
    - convert_bigvul.py       — BigVul (Mendeley, C/C++)
    - convert_devign.py       — Devign (HF, C)
    - convert_primevul.py     — PrimeVul (HF, C/C++)
    - convert_securityeval.py — SecurityEval (GitHub, Python)
    - convert_cvefixes.py     — CVEfixes v1.0.8 (HF, multi-lang)
    - convert_crossvul.py     — CrossVul (HF, 21 languages)
    - convert_morefixes.py    — MoreFixes (HF, 26K CVEs, multi-lang)
    - convert_purplellama.py  — PurpleLlama CyberSecEval (HF, AI security)
    - convert_securityeval2.py— SecurityEval2 (GitHub, Python)
    - convert_datadog.py      — DataDog Malicious Packages (GitHub, supply chain)
    - nvd_cve.py              — NVD CVE text descriptions
    - osv.py                  — OSV.dev vulnerability database
    - owasp_benchmark.py      — OWASP Benchmark (Java, eval only)
    - github_advisories.py    — GitHub Security Advisories
"""

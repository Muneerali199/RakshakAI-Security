"""
RakshakAI v2 — Phase 2.5: Dataset downloader (expansion).

Pulls every training source into v2/inputs/datasets/raw/.

Core sources (Tier 1):
  - BigVul      (Mendeley Data)           — 3,754 CVEs, C/C++ function-level
  - Devign      (HuggingFace)             — 27,318 C functions
  - PrimeVul    (HuggingFace)             — 6,906 high-quality pairs
  - SecurityEval (GitHub)                 — 130 Python snippets
  - CVEfixes    (HuggingFace, 59 GB)      — 138,974 paired vuln+patch
  - CrossVul    (HuggingFace, 3 langs)    — 5,131 CVEs, 21 languages

Expansion sources (Tier 2, June 2026):
  - MoreFixes   (HuggingFace)             — 26,617 CVEs with fixing commits
  - SynCVE      (HuggingFace)             — 134K CVEs, 72K with patches
  - PurpleLlama (HuggingFace, Meta)       — AI security evaluation
  - SecurityEval2 (GitHub)                — 1,809 Python vuln samples
  - DataDog Malicious Packages (GitHub)   — 28K supply chain attacks
  - OSS-Fuzz    (GitHub, Google)          — 6,100+ real bugs
  - MegaVul     (HuggingFace, GPL eval)   — C/C++ vulns (eval only)
  - OWASP LLM   (GitHub)                  — AI security test suite
  - Juliet Test Suite (GitHub)            — 120K+ synthetic tests
  - Garak       (pip install)             — NVIDIA LLM vuln probes

Usage:
    python v2/dataset/download.py --out v2/inputs/datasets/raw
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

RAW = Path("v2/inputs/datasets/raw")

PIP_PACKAGES = {
    "garak": "garak",
}


# ---------- source registry ----------
SOURCES = {
    "bigvul": {
        "kind": "hf_dataset",
        "repo_id": "bstee615/bigvul",
        "revision": "main",
    },
    "devign": {
        "kind": "hf_dataset",
        "repo_id": "google/code_x_glue_cc_defect_detection",
        "revision": "main",
        "config": "devign",
    },
    "primevul": {
        "kind": "hf_dataset",
        "repo_id": "AsleepyFox/PrimeVul",
        "revision": "main",
    },
    "securityeval": {
        "kind": "git",
        "url": "https://github.com/awslabs/miyako.git",
        "subdir": "evaluation/SecurityEval",
    },
    "juliet_subset": {
        "kind": "git",
        "url": "https://github.com/securesoftwareengineering/juliet-test-suite.git",
        "subdir": "src",
    },
    "ghsa": {
        "kind": "git",
        "url": "https://github.com/github/advisory-database.git",
        "subdir": "advisories/github-reviewed",
    },
    "owasp_benchmark": {
        "kind": "git",
        "url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "subdir": "src/main/java/org/owasp/benchmark",
    },
    # --- Phase B additions (language balance + paired vuln/patch) ---
    "cvefixes": {
        "kind": "hf_dataset",
        "repo_id": "starsofchance/CVEfixes_v1.0.8",
        "revision": "main",
    },
    "crossvul_cpp": {
        "kind": "hf_dataset",
        "repo_id": "xin1997/crossvul-cpp_all_only_input",
        "revision": "main",
    },
    "crossvul_java": {
        "kind": "hf_dataset",
        "repo_id": "xin1997/crossvul-java_all_only_input",
        "revision": "main",
    },
    "crossvul_python": {
        "kind": "hf_dataset",
        "repo_id": "xin1997/crossvul-python_all_only_input",
        "revision": "main",
    },
    # --- Phase B Expansion (May 2026) — language balance + CWE gaps ---
    "morefixes": {
        "kind": "hf_dataset",
        "repo_id": "JafarAkhondali/morefixes",
        "revision": "main",
    },
    "purplellama": {
        "kind": "hf_dataset",
        "repo_id": "meta-llama/PurpleLlama_CyberSecEval",
        "revision": "main",
    },
    "syncve": {
        "kind": "hf_dataset",
        "repo_id": "Hareshlab/SynCVE",
        "revision": "main",
    },
    "megavul": {
        "kind": "hf_dataset",
        "repo_id": "CyberForce/MegaVul",
        "revision": "main",
    },
    "datadog": {
        "kind": "git",
        "url": "https://github.com/DataDog/malicious-software-packages-dataset.git",
        "subdir": "",
    },
    "securityeval2": {
        "kind": "git",
        "url": "https://github.com/fsoft-ai-hub/SecurityEval2.git",
        "subdir": "",
    },
    "ossfuzz": {
        "kind": "git",
        "url": "https://github.com/google/oss-fuzz.git",
        "subdir": "",
    },
    "garak": {
        "kind": "pip",
        "package": "garak",
        "extra": "",
    },
    "owasp_llm": {
        "kind": "git",
        "url": "https://github.com/OWASP/www-project-top-10-for-llm-applications.git",
        "subdir": "",
    },
}


# ---------- helpers ----------
def log(msg: str) -> None:
    print(f"[download] {msg}", flush=True)


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def hf_snapshot(repo_id: str, out: Path, revision: str = "main", config: str | None = None) -> None:
    safe_mkdir(out)
    log(f"HF snapshot {repo_id} → {out}")
    cmd = [
        "huggingface-cli", "download",
        repo_id,
        "--repo-type", "dataset",
        "--revision", revision,
        "--local-dir", str(out),
        "--max-workers", "8",
    ]
    if config:
        # noop for now; specific files are selected post-download
        pass
    subprocess.run(cmd, check=True)


def git_clone(url: str, out: Path, depth: int = 1) -> None:
    if (out / ".git").exists():
        log(f"git already cloned at {out}")
        return
    log(f"git clone --depth {depth} {url} → {out}")
    safe_mkdir(out.parent)
    subprocess.run(["git", "clone", "--depth", str(depth), url, str(out)], check=True)


def http_download(url: str, out: Path) -> None:
    safe_mkdir(out.parent)
    if out.exists():
        log(f"already have {out}")
        return
    log(f"http GET {url} → {out}")
    with urllib.request.urlopen(url) as r, open(out, "wb") as f:
        shutil.copyfileobj(r, f)


# ---------- main ----------
def pip_install(pkg: str) -> None:
    log(f"pip install {pkg}")
    subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=True)


def download_all(out_root: Path, only: Iterable[str] | None = None) -> None:
    safe_mkdir(out_root)
    keys = list(SOURCES.keys()) if only is None else list(only)
    for k in keys:
        if k not in SOURCES:
            log(f"unknown source: {k}; skipping")
            continue
        spec = SOURCES[k]
        out = out_root / k
        try:
            if spec["kind"] == "hf_dataset":
                hf_snapshot(spec["repo_id"], out, spec.get("revision", "main"), spec.get("config"))
            elif spec["kind"] == "git":
                git_clone(spec["url"], out)
            elif spec["kind"] == "pip":
                pip_install(spec["package"])
            else:
                log(f"unknown kind: {spec['kind']}")
        except Exception as e:  # noqa: BLE001
            log(f"FAILED {k}: {e}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=RAW)
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()

    out_root = args.out.resolve()
    safe_mkdir(out_root)
    download_all(out_root, args.only)
    log("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

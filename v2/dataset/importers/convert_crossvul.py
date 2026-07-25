"""RakshakAI v2 — CrossVul importer (15-language expansion).

Source:  https://huggingface.co/datasets/xin1997/crossvul
Configs: crossvul-cpp, crossvul-java, crossvul-python, crossvul-javascript,
         crossvul-typescript, crossvul-go, crossvul-rust, crossvul-php,
         crossvul-ruby, crossvul-csharp, crossvul-swift, crossvul-kotlin,
         crossvul-scala, crossvul-perl

Output: v2/inputs/datasets/raw/crossvul_converted.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, write_samples
from v2.dataset.schema import SecuritySample

SOURCE = "crossvul"
MAX_SAMPLES = 200_000

# CrossVul per-language repos on HuggingFace (only 3 available)
CROSSVUL_LANGS = {
    "cpp": "xin1997/crossvul-cpp_all_only_input",
    "java": "xin1997/crossvul-java_all_only_input",
    "python": "xin1997/crossvul-python_all_only_input",
}

LANG_MAP = {
    "cpp": "cpp", "c++": "cpp", "c": "c",
    "java": "java", "python": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "go": "go", "golang": "go",
    "rust": "rust", "rs": "rust",
    "ruby": "ruby", "rb": "ruby",
    "php": "php",
    "csharp": "csharp", "c#": "csharp",
    "swift": "swift",
    "kotlin": "kotlin", "kt": "kotlin",
    "scala": "scala",
    "perl": "perl", "pl": "perl",
}


def main() -> int:
    stats = ImportStats(source=SOURCE)
    samples: list[SecuritySample] = []

    try:
        from datasets import load_dataset
    except ImportError:
        print("[crossvul] ERROR: datasets not installed. Run: pip install datasets")
        stats.error = "datasets not installed"
        write_samples(SOURCE, samples, stats)
        return 1

    for canonical_lang, repo_id in CROSSVUL_LANGS.items():
        if len(samples) >= MAX_SAMPLES:
            break

        print(f"[crossvul] Loading {canonical_lang} from {repo_id}...")
        try:
            dataset = load_dataset(repo_id, split="train", trust_remote_code=True)
        except Exception as e:
            print(f"  [crossvul] Failed to load {repo_id}: {e}")
            continue

        lang_code = LANG_MAP.get(canonical_lang, canonical_lang)
        lang_count = 0

        for row in dataset:
            if len(samples) >= MAX_SAMPLES:
                break
            stats.requested += 1

            code = row.get("content") or row.get("code") or row.get("func") or row.get("source") or ""
            rid = row.get("id") or ""
            path = row.get("max_stars_repo_path") or ""

            # Label from id field: "good" → non-vuln, "bad" → vuln
            is_vuln = "/bad_" in path or "_bad_" in rid or "_data_bad_" in rid

            # CWE from path: ./CrossVul/dataset_final_sorted/CWE-754/c/good_718_0
            cwe_str = path
            cve_id = row.get("cve") or row.get("cve_id") or ""

            if len(code) < 30:
                stats.skipped_too_short += 1
                continue
            if len(code) > 100_000:
                stats.skipped_no_code += 1
                continue

            cwe = None
            if cwe_str:
                m = re.search(r"CWE-(\d+)", str(cwe_str), re.I)
                if m:
                    cwe = f"CWE-{int(m.group(1))}"

            sev = "high" if is_vuln else "clean"

            try:
                s = SecuritySample.build(
                    language=lang_code,
                    vulnerable_code=code[:8000],
                    patched_code=None,
                    cwe=cwe if is_vuln else "CWE-UNKNOWN",
                    severity=sev,
                    explanation=(
                        f"CrossVul {canonical_lang} {'vulnerable' if is_vuln else 'secure'} code."
                    )[:5000],
                    attack_scenario=f"CVE: {cve_id}" if is_vuln and cve_id else "",
                    secure_fix=f"Fix {cwe}" if is_vuln and cwe else "No fix needed.",
                    source=f"crossvul:{cve_id}" if cve_id else f"crossvul:{canonical_lang}:{stats.requested}",
                    source_license="MIT",
                    cve=cve_id or None,
                    is_vulnerable=is_vuln,
                    split="train",
                )
            except Exception:
                stats.skipped_no_code += 1
                continue

            samples.append(s)
            stats.built += 1
            lang_count += 1

        print(f"  [crossvul] {canonical_lang}: {lang_count} samples")

    write_samples(SOURCE, samples, stats)
    lang_dist = {}
    for s in samples:
        lang_dist[s.language] = lang_dist.get(s.language, 0) + 1
    print(f"[crossvul] total: {len(samples)} samples")
    print(f"[crossvul] language distribution: {json.dumps(lang_dist, indent=2)}")
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

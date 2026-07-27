"""
RakshakAI v2 — Fix converters + relabel dataset.

Root cause: convert_primevul.py and convert_devign.py both forget to pass
`is_vulnerable` to SecuritySample.build(), so all non-vuln samples default
to is_vulnerable=True. This causes 18,363 non-vuln samples to appear as
vulnerable with CWE-UNKNOWN.

Fix: re-convert both sources with correct labels, then run the existing
pipeline (clean.py → build_phase_b.py → pack.py) to produce corrected data.

Usage:
    python v2/dataset/fix_phase_b.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, write_jsonl

REPO = Path(__file__).resolve().parents[2]
PY = sys.executable
RAW = Path("v2/inputs/datasets/raw")


def fix_primevul() -> None:
    """Re-convert PrimeVul with correct is_vulnerable and cve fields."""
    in_path = RAW / "primevul.jsonl"
    out_path = RAW / "primevul_converted.jsonl"

    if not in_path.exists():
        print("[fix] primevul.jsonl not found, skipping")
        return

    samples = []
    total = skipped_no_cwe = skipped_short = 0

    with in_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            row = json.loads(line)

            func = (row.get("func") or "").strip()
            if len(func) < 30:
                skipped_short += 1
                continue

            target = row.get("target", 0)
            # PrimeVul stores cwe as a list under the "cwe" key
            cwe_list = row.get("cwe") or row.get("cwes") or []
            cve_id = (row.get("cve") or "").strip()
            cve_desc = (row.get("cve_desc") or "").strip()[:5000]
            project = (row.get("project") or "").strip()

            is_vuln = target == 1

            if is_vuln and not cwe_list:
                skipped_no_cwe += 1
                continue

            cwe = cwe_list[0] if cwe_list else "CWE-UNKNOWN"

            try:
                s = SecuritySample.build(
                    language="c",
                    vulnerable_code=func[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity="high" if is_vuln else "clean",
                    explanation=(cve_desc if cve_desc else
                                 f"{'Vulnerable' if is_vuln else 'Secure'} code from {project}"),
                    attack_scenario=(cve_desc if is_vuln else ""),
                    secure_fix=(f"Fix {cwe} in {project}." if is_vuln else "No fix needed."),
                    source=f"primevul:{cve_id}" if cve_id else f"primevul:{project}",
                    source_license="MIT",
                    cve=cve_id if cve_id else None,
                    is_vulnerable=is_vuln,
                    split="train",
                )
                samples.append(s)
            except Exception:
                continue

    n = write_jsonl(out_path, samples)
    vuln_count = sum(1 for s in samples if s.is_vulnerable)
    clean_count = sum(1 for s in samples if not s.is_vulnerable)
    cwe_unknown = sum(1 for s in samples if s.is_vulnerable and s.cwe == "CWE-UNKNOWN")

    print(f"[fix] PrimeVul: total={total} → {n} records")
    print(f"       vuln={vuln_count} clean={clean_count} cwe_unknown={cwe_unknown}")
    print(f"       skipped: no_cwe={skipped_no_cwe} too_short={skipped_short}")
    print(f"       written → {out_path}")
    print()


def fix_devign() -> None:
    """Re-convert Devign with correct is_vulnerable field."""
    in_path = RAW / "devign.jsonl"
    out_path = RAW / "devign_converted.jsonl"

    if not in_path.exists():
        print("[fix] devign.jsonl not found, skipping")
        return

    samples = []
    total = skipped_short = 0

    with in_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            row = json.loads(line)

            func = (row.get("func") or "").strip()
            if len(func) < 30:
                skipped_short += 1
                continue

            target = row.get("target", 0)
            project = (row.get("project") or "").strip()
            commit_id = (row.get("commit_id") or "").strip()

            is_vuln = target == 1
            cwe = "CWE-119" if is_vuln else "CWE-UNKNOWN"

            try:
                s = SecuritySample.build(
                    language="c",
                    vulnerable_code=func[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity="high" if is_vuln else "clean",
                    explanation=(
                        f"Devign: {project} (commit {commit_id[:8]}). "
                        f"{'Vulnerable' if is_vuln else 'Secure'} code."
                    )[:5000],
                    attack_scenario=f"C in {project} exploit." if is_vuln else "",
                    secure_fix=(
                        "Apply memory safety fixes." if is_vuln else "No fix needed."
                    ),
                    source=f"devign:{project}:{commit_id[:12]}",
                    source_license="MIT",
                    is_vulnerable=is_vuln,
                    split="train",
                )
                samples.append(s)
            except Exception:
                continue

    n = write_jsonl(out_path, samples)
    vuln_count = sum(1 for s in samples if s.is_vulnerable)
    clean_count = sum(1 for s in samples if not s.is_vulnerable)

    print(f"[fix] Devign: total={total} → {n} records")
    print(f"       vuln={vuln_count} clean={clean_count}")
    print(f"       skipped_short={skipped_short}")
    print(f"       written → {out_path}")
    print()


def fix_crossvul() -> None:
    """Re-convert CrossVul with all 3 languages, correct is_vulnerable."""
    samples = []
    lang_dirs = {
        "cpp": (RAW / "crossvul_cpp", "cpp"),
        "java": (RAW / "crossvul_java", "java"),
        "python": (RAW / "crossvul_python", "python"),
    }

    for lang, (data_dir, lang_code) in lang_dirs.items():
        if not data_dir.exists():
            continue

        for pq_file in sorted(data_dir.rglob("*.parquet")):
            try:
                import pyarrow.parquet as pq
                table = pq.read_table(str(pq_file))
                rows = table.to_pylist()
            except Exception as e:
                print(f"[crossvul] skip {pq_file}: {e}")
                continue

            for i, row in enumerate(rows):
                code = (row.get("code") or row.get("func") or row.get("source") or "").strip()
                label = row.get("label") or row.get("target") or row.get("vul") or 0
                cwe_str = (row.get("cwe") or row.get("cwe_id") or "").strip()
                cve_id = (row.get("cve") or row.get("cve_id") or "").strip()

                if len(code) < 30 or len(code) > 100_000:
                    continue

                try:
                    is_vuln = bool(int(label))
                except (ValueError, TypeError):
                    is_vuln = bool(label)

                cwe = None
                if cwe_str:
                    m = re.search(r"CWE-(\d+)", str(cwe_str), re.I)
                    if m:
                        cwe = f"CWE-{int(m.group(1))}"

                try:
                    s = SecuritySample.build(
                        language=lang_code,
                        vulnerable_code=code[:8000],
                        patched_code=None,
                        cwe=cwe if is_vuln else "CWE-UNKNOWN",
                        severity="high" if is_vuln else "clean",
                        explanation=(
                            f"CrossVul {lang} {'vulnerable' if is_vuln else 'secure'} code."
                        )[:5000],
                        attack_scenario=f"CVE {cve_id}" if is_vuln and cve_id else "",
                        secure_fix=f"Fix {cwe}" if is_vuln and cwe else "No fix needed.",
                        source=f"crossvul:{cve_id}" if cve_id else f"crossvul:{lang}:{i}",
                        source_license="MIT",
                        cve=cve_id if cve_id else None,
                        is_vulnerable=is_vuln,
                        split="train",
                    )
                    samples.append(s)
                except Exception:
                    continue

        lang_count = sum(1 for s in samples if s.language == lang_code)
        print(f"  [crossvul] {lang}: {lang_count} samples")

    out_path = RAW / "crossvul_converted.jsonl"
    n = write_jsonl(out_path, samples)
    vuln_count = sum(1 for s in samples if s.is_vulnerable)
    clean_count = sum(1 for s in samples if not s.is_vulnerable)
    print(f"[fix] CrossVul: {n} records (vuln={vuln_count} clean={clean_count})")
    print(f"       written → {out_path}")
    print()


def remove_old_clean_files() -> None:
    """Remove old clean/ files for sources being rebuilt."""
    CLEAN = Path("v2/inputs/datasets/clean")
    patterns = ["primevul", "devign", "crossvul"]

    removed = 0
    for pat in patterns:
        for p in CLEAN.glob(f"{pat}*.jsonl"):
            p.unlink()
            removed += 1
    if removed:
        print(f"[fix] Removed {removed} old files from clean/")
    print()


def main() -> int:
    print("=" * 60)
    print("  RakshakAI v2 — Fix Phase B Dataset")
    print("=" * 60)
    print()

    print("Stage 1: Fix converters (relabel with correct is_vulnerable)")
    print("-" * 40)
    fix_primevul()
    fix_devign()
    fix_crossvul()

    print("Stage 2: Remove old incorrect data from clean/")
    print("-" * 40)
    remove_old_clean_files()

    print("Stage 3: Re-run clean.py on corrected raw data")
    print("-" * 40)
    print("Running: python v2/dataset/clean.py ...")
    env = dict(PYTHONPATH=str(REPO))
    subprocess.run([PY, "v2/dataset/clean.py"], cwd=str(REPO), env={**__import__("os").environ, **env}, check=True)

    print("\nStage 4: Re-run build_phase_b.py on corrected clean data")
    print("-" * 40)
    print("Running: python v2/dataset/build_phase_b.py ...")
    subprocess.run([PY, "v2/dataset/build_phase_b.py"], cwd=str(REPO), env={**__import__("os").environ, **env}, check=True)

    print("\n" + "=" * 60)
    print("  FIX COMPLETE — Dataset rebuilt with corrected labels")
    print("=" * 60)
    print()
    print("Next: run audit_quality.py to verify improvements")

    return 0


if __name__ == "__main__":
    sys.exit(main())
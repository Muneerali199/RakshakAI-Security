"""
RakshakAI v2 — One-shot orchestrator for Phases 2 and 3 of the dataset pipeline.

Runs:
  download → clean → cwe_normalize (inline) → dedup → to_instruct → pack → validate

Idempotent. Re-runnable. Skips stages whose output already exists.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PY = sys.executable


def run(cmd: list[str]) -> None:
    print(f"\n>>> {' '.join(cmd)}\n", flush=True)
    res = subprocess.run(cmd, cwd=str(REPO))
    if res.returncode != 0:
        sys.exit(res.returncode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--skip-pack", action="store_true")
    ap.add_argument("--only", nargs="*", default=None,
                    help="restrict to one or more of: download, import, clean, dedup, instruct, pack, validate")
    ap.add_argument("--skip-import", action="store_true",
                    help="skip the import stage (useful during iterative development)")
    args = ap.parse_args()

    stages = ["download", "import", "clean", "dedup", "instruct", "pack", "validate"]
    if args.only:
        stages = [s for s in stages if s in args.only]

    if "download" in stages and not args.skip_download:
        run([PY, "v2/dataset/download.py"])

    if "import" in stages and not args.skip_import:
        importers = [
            ("bigvul",  "v2/dataset/importers/convert_bigvul.py"),
            ("devign",  "v2/dataset/importers/convert_devign.py"),
            ("primevul","v2/dataset/importers/convert_primevul.py"),
            ("securityeval", "v2/dataset/importers/convert_securityeval.py"),
            ("cvefixes","v2/dataset/importers/convert_cvefixes.py"),
            ("crossvul","v2/dataset/importers/convert_crossvul.py"),
            # Phase B expansion
            ("morefixes","v2/dataset/importers/convert_morefixes.py"),
            ("purplellama","v2/dataset/importers/convert_purplellama.py"),
            ("securityeval2","v2/dataset/importers/convert_securityeval2.py"),
            ("datadog", "v2/dataset/importers/convert_datadog.py"),
        ]
        for name, script in importers:
            print(f"\n>>> Importing {name} ({script})\n", flush=True)
            res = subprocess.run([PY, script], cwd=str(REPO))
            if res.returncode != 0:
                print(f"[orchestrate] WARNING: {name} importer returned {res.returncode}")

    if "clean" in stages:
        run([PY, "v2/dataset/clean.py"])

    if "dedup" in stages:
        run([PY, "-m", "pip", "install", "--quiet", "datasketch"])
        run([PY, "v2/dataset/dedup.py"])

    if "instruct" in stages:
        run([PY, "v2/dataset/to_instruct.py"])

    if "pack" in stages and not args.skip_pack:
        run([PY, "v2/dataset/pack.py"])

    if "validate" in stages:
        run([PY, "v2/dataset/validate.py"])

    print("\n[orchestrate] all stages done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

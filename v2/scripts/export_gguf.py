"""
RakshakAI v2 — Export merged model to GGUF (Q5_K_M) for llama.cpp / Ollama.

This wraps the official `convert.py` from llama.cpp.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="merged hf model dir")
    ap.add_argument("--out", required=True, help="output .gguf file path")
    ap.add_argument("--outtype", default="q5_K_M")
    ap.add_argument("--llama-cpp", default="v2/inputs/llama.cpp")
    args = ap.parse_args()

    repo = Path(args.model).resolve()
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    if not (Path(args.llama_cpp) / "convert.py").exists():
        print(f"[gguf] cloning llama.cpp into {args.llama_cpp}")
        subprocess.run([
            "git", "clone", "--depth=1", "https://github.com/ggerganov/llama.cpp",
            args.llama_cpp,
        ], check=True)

    convert = Path(args.llama_cpp) / "convert.py"
    cmd = [
        sys.executable, str(convert),
        str(repo),
        "--outfile", str(out),
        "--outtype", args.outtype,
        "--ctx", "8192",
    ]
    print(f"[gguf] running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    (out.parent / "rakshakai-v2.gguf.manifest.json").write_text(json.dumps({
        "source": str(repo),
        "outtype": args.outtype,
        "outfile": str(out),
    }, indent=2))
    print(f"[gguf] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

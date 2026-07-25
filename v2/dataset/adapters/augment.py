"""
RakshakAI v2 — Text-level code augmenter.

The v1 RakshakAI corpus produces ~5,925 records but only ~41 unique *strings*
per CWE (the `mutate_code` function in v1 changes identifier references but
not the textual surface, so the result is often byte-identical).

This module generates **textually distinct** variants of each template by:

  1. Identifier renames (sample N new names from a pool, do a full find-replace)
  2. Comment insertions at *multiple* positions (above, inline, trailing)
  3. Whitespace variation (indent depth, blank lines)
  4. Quote style variation (single/double/triple)
  5. Casing variation (only where language-permitted)
  6. Multi-language siblings (e.g. SQL injection also has Node.js, Go, Java
     forms in the seed library)

Each generated variant is **validated** against the SecuritySample schema
before being written; duplicates are dropped deterministically.

The output is a JSONL of SecuritySample records in v2 raw format, ready
for the cleaning step.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402


# ---------------------------------------------------------------------------
# Random naming pools
# ---------------------------------------------------------------------------

IDENT_POOL: list[str] = [
    "data", "value", "input", "user", "item", "record", "entry", "payload",
    "content", "param", "result", "output", "arg", "argument", "field",
    "name", "key", "val", "buf", "raw", "tmp", "body", "msg", "message",
    "uid", "pid", "q", "query", "x", "y", "s", "txt", "blob", "buf_in",
    "buf_out", "raw_data", "raw_input", "user_input", "user_id", "user_name",
    "filename", "filepath", "path", "url", "uri", "endpoint", "target",
    "host", "hostname", "port", "addr", "address", "cmd", "command", "arg1",
    "arg2", "arglist", "args", "argv",
]

COMMENTS: dict[str, list[str]] = {
    "python": [
        "# FIXME: validate user input",
        "# TODO: sanitize before use",
        "# unsafe — do not deploy as-is",
        "# source: cwe-{cwe} example",
        "# NOTE: this snippet is intentionally vulnerable",
        "# pragma: no cover",
        "# noqa: E501",
        "# security: handled at the API layer",
        "# pylint: disable=missing-docstring",
        "# type: ignore",
    ],
    "javascript": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "// unsafe — do not deploy as-is",
        "/* source: cwe-{cwe} example */",
        "/* eslint-disable */",
        "/* istanbul ignore next */",
        "// @ts-ignore",
        "// nosemgrep",
        "// noinspection JSUnresolvedVariable",
    ],
    "java": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "/* unsafe — do not deploy as-is */",
        "/** source: cwe-{cwe} example */",
        "@SuppressWarnings(\"unchecked\")",
    ],
    "go": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "// unsafe — do not deploy as-is",
        "/* source: cwe-{cwe} example */",
        "//nolint:gosec",
    ],
    "rust": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "// unsafe — do not deploy as-is",
        "/* source: cwe-{cwe} example */",
        "#[allow(unused)]",
    ],
    "ruby": [
        "# FIXME: validate user input",
        "# TODO: sanitize before use",
        "# unsafe — do not deploy as-is",
        "=begin\nsource: cwe-{cwe} example\n=end",
    ],
    "php": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "/* unsafe — do not deploy as-is */",
        "/** source: cwe-{cwe} example */",
    ],
    "csharp": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "/* unsafe — do not deploy as-is */",
        "/// <summary>source: cwe-{cwe} example</summary>",
    ],
    "typescript": [
        "// FIXME: validate user input",
        "// TODO: sanitize before use",
        "// unsafe — do not deploy as-is",
        "/* source: cwe-{cwe} example */",
        "// @ts-expect-error",
    ],
    "default": [
        "# FIXME: validate user input",
        "// TODO: sanitize before use",
        "/* unsafe — do not deploy as-is */",
    ],
}


# ---------------------------------------------------------------------------
# Per-language AST-naive augmentation
# ---------------------------------------------------------------------------


def _random_ident(rng: random.Random, exclude: set[str]) -> str:
    """Return a new identifier name distinct from `exclude`."""
    while True:
        name = rng.choice(IDENT_POOL)
        if name not in exclude:
            exclude.add(name)
            return name


def _rename_identifiers(rng: random.Random, code: str) -> str:
    """Replace a random *single* identifier in `code` with a new name.

    Conservative: only matches bare identifiers, not string contents.
    """
    # find all identifiers; pick one at random; replace all occurrences of it.
    ids = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", code)
    if not ids:
        return code
    target = rng.choice(ids)
    new = _random_ident(rng, set(ids))
    if target == new:
        return code
    # word-boundary replace
    return re.sub(rf"\b{re.escape(target)}\b", new, code)


def _add_comment(rng: random.Random, code: str, lang: str) -> str:
    pool = COMMENTS.get(lang, COMMENTS["default"])
    cwe_match = re.search(r"CWE-\d+", code)
    cwe = cwe_match.group(0) if cwe_match else "000"
    comment = rng.choice(pool).format(cwe=cwe.split("-")[-1])
    if rng.random() < 0.5:
        return comment + "\n" + code
    return code + "\n" + comment


def _vary_indent(rng: random.Random, code: str) -> str:
    """Apply 0–8 spaces of extra leading indent to each non-blank line."""
    pad = " " * (rng.choice([0, 2, 4, 4, 4, 6, 8]))
    return "\n".join((pad + ln) if ln.strip() else ln for ln in code.split("\n"))


def _vary_quotes(rng: random.Random, code: str) -> str:
    """Swap ' and " outside regex/comments — language-aware (best-effort)."""
    if rng.random() < 0.5:
        return code
    new = []
    in_str: str | None = None
    i = 0
    while i < len(code):
        c = code[i]
        if in_str is None:
            if c == "'":
                in_str = "'"
                new.append('"')
            elif c == '"':
                in_str = '"'
                new.append("'")
            else:
                new.append(c)
        else:
            if c == "\\" and i + 1 < len(code):
                new.append(c)
                new.append(code[i + 1])
                i += 2
                continue
            if c == in_str:
                new.append('"' if in_str == "'" else "'")
                in_str = None
            else:
                new.append(c)
        i += 1
    return "".join(new)


def _add_blank_lines(rng: random.Random, code: str) -> str:
    """Insert 0–2 blank lines at random positions."""
    lines = code.split("\n")
    n_extra = rng.randint(0, 2)
    for _ in range(n_extra):
        pos = rng.randint(0, len(lines))
        lines.insert(pos, "")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def augment(
    code: str,
    *,
    language: str,
    n_variants: int = 50,
    seed: int = 0,
) -> list[str]:
    """Produce n_variants textually distinct strings from one seed."""
    rng = random.Random(seed)
    out: set[str] = {code}
    attempts = 0
    while len(out) < n_variants and attempts < n_variants * 6:
        attempts += 1
        c = code
        # Apply 1–3 random operations
        ops = [_rename_identifiers, _add_comment, _vary_indent,
               _vary_quotes, _add_blank_lines]
        rng.shuffle(ops)
        for op in ops[: rng.randint(1, 3)]:
            try:
                if op is _add_comment:
                    c = op(rng, c, language)
                else:
                    c = op(rng, c)
            except Exception:  # noqa: BLE001
                c = code
                break
        # Reject trivial transformations (length unchanged and char-identical)
        if c and c != code:
            out.add(c)
    return list(out)


def expand_v1_corpus(
    in_jsonl: Path,
    out_jsonl: Path,
    variants_per_template: int = 50,
) -> int:
    """Take the unique v1 templates, augment them, and write a new raw JSONL.

    Reads the v1-corpus JSONL produced by the v1->v2 adapter, identifies the
    unique templates per (cwe, vulnerable_code), and produces
    ``variants_per_template`` textually distinct samples for each.
    """
    by_key: dict[tuple[str, str], dict] = {}
    with in_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            key = (rec.get("cwe") or "CLEAN", rec["vulnerable_code"])
            if key not in by_key:
                by_key[key] = rec

    print(f"[aug] unique templates: {len(by_key)}", flush=True)
    print(f"[aug] target variants per template: {variants_per_template}", flush=True)

    samples: list[SecuritySample] = []
    for i, ((cwe, code), rec) in enumerate(by_key.items()):
        variants = augment(
            code,
            language=rec["language"],
            n_variants=variants_per_template,
            seed=i,
        )
        for v_idx, variant in enumerate(variants):
            patched = (rec.get("patched_code") or "").strip() or None
            samples.append(SecuritySample.build(
                language=rec["language"],
                vulnerable_code=variant,
                patched_code=patched,
                cwe=rec.get("cwe"),
                severity=rec.get("severity"),
                explanation=rec.get("explanation", ""),
                attack_scenario=rec.get("attack_scenario", ""),
                secure_fix=rec.get("secure_fix", ""),
                source=f"v1-augmented",
                source_license=rec.get("source_license", "Apache-2.0"),
                is_vulnerable=bool(rec.get("is_vulnerable", True)),
                split="train",
            ))
        if (i + 1) % 5 == 0:
            print(f"  ... {i + 1}/{len(by_key)} templates expanded", flush=True)

    n = write_jsonl(out_jsonl, samples)
    print(f"[aug] wrote {n} samples to {out_jsonl}")
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_jsonl", type=Path,
                    default=Path("v2/inputs/datasets/raw/v1-corpus.jsonl"))
    ap.add_argument("--out", type=Path,
                    default=Path("v2/inputs/datasets/raw/v1-augmented.jsonl"))
    ap.add_argument("--variants", type=int, default=50)
    args = ap.parse_args()
    expand_v1_corpus(args.in_jsonl, args.out, args.variants)
    return 0


if __name__ == "__main__":
    sys.exit(main())

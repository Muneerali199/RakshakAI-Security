"""Import additional security datasets to expand non-C vuln coverage."""
import json, hashlib, sys
from pathlib import Path
from collections import Counter

try:
    from datasets import load_dataset
except ImportError:
    print("pip install datasets")
    sys.exit(1)

OUT = Path("inputs/datasets/extra_vuln")
OUT.mkdir(parents=True, exist_ok=True)

CWE_MAP = {
    "cwe-89": "CWE-89", "cwe-79": "CWE-79", "cwe-78": "CWE-78",
    "cwe-77": "CWE-77", "cwe-22": "CWE-22", "cwe-502": "CWE-502",
    "cwe-798": "CWE-798", "cwe-287": "CWE-287", "cwe-20": "CWE-20",
    "cwe-200": "CWE-200", "cwe-264": "CWE-264", "cwe-310": "CWE-310",
    "cwe-119": "CWE-119", "cwe-120": "CWE-120", "cwe-125": "CWE-125",
    "cwe-190": "CWE-190", "cwe-416": "CWE-416", "cwe-476": "CWE-476",
    "cwe-787": "CWE-787", "cwe-918": "CWE-918", "cwe-611": "CWE-611",
    "cwe-611": "CWE-611", "cwe-276": "CWE-276", "cwe-732": "CWE-732",
    "cwe-862": "CWE-862", "cwe-863": "CWE-863", "cwe-319": "CWE-319",
}

LANG_MAP = {
    "py": "python", "python": "python", "js": "javascript",
    "javascript": "javascript", "java": "java", "go": "go",
    "rb": "ruby", "ruby": "ruby", "php": "php", "rs": "rust",
    "rust": "rust", "cs": "csharp", "csharp": "csharp",
    "kt": "kotlin", "kotlin": "kotlin", "swift": "swift",
    "ts": "typescript", "typescript": "typescript",
    "scala": "scala", "pl": "perl", "c": "c", "cpp": "cpp",
    "c++": "cpp", "cc": "cpp",
}

def normalize_lang(l):
    l = (l or "").lower().strip()
    return LANG_MAP.get(l, l)

def fp_of(code):
    return hashlib.md5((code or "").encode()).hexdigest()

def make_sample(vuln_code, fix_code, cwe, lang, source, explanation=""):
    lang = normalize_lang(lang)
    return {
        "vulnerable_code": (vuln_code or "").strip(),
        "patched_code": (fix_code or "").strip(),
        "cwe": CWE_MAP.get(cwe.lower(), cwe.upper() if "/" not in (cwe or "") else cwe),
        "language": lang,
        "source": source,
        "is_vulnerable": True,
        "explanation": explanation or f"Vulnerability detected in {lang} code.",
        "fingerprint": fp_of(vuln_code),
        "severity": "high",
    }

# ── CrossVul ──────────────────────────────────────────────
print("=== CrossVul ===")
try:
    ds_cv = load_dataset("hitoshura25/crossvul", split="train", trust_remote_code=True)
    cv_count = 0
    cv_langs = Counter()
    with open(OUT / "crossvul.jsonl", "w") as f:
        for row in ds_cv:
            code = row.get("vulnerable_code", "") or ""
            fix = row.get("fixed_code", "") or ""
            lang = normalize_lang(row.get("language", "") or row.get("language_dir", "") or "")
            cwe = row.get("cwe_id", "") or row.get("cwe", "") or ""
            if not code or not fix:
                continue
            if lang in ("c", "cpp", ""):
                continue
            s = make_sample(code, fix, cwe, lang, "crossvul")
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
            cv_count += 1
            cv_langs[lang] += 1
    print(f"  {cv_count} non-C vuln samples")
    for lang, n in sorted(cv_langs.items(), key=lambda x: -x[1]):
        print(f"    {lang}: {n}")
except Exception as e:
    print(f"  FAILED: {e}")

# ── SecureCode ────────────────────────────────────────────
print("\n=== SecureCode ===")
try:
    ds_sc = load_dataset("scthornton/securecode", split="train", trust_remote_code=True)
    sc_count = 0
    sc_langs = Counter()
    with open(OUT / "securecode.jsonl", "w") as f:
        for row in ds_sc:
            conv = row.get("conversation", [])
            if len(conv) < 2:
                continue
            vuln = conv[-2].get("content", "")
            fix = conv[-1].get("content", "")
            lang = normalize_lang(row.get("language", ""))
            cwe = row.get("cwe", "") or row.get("vulnerability_type", "")
            if not vuln or not fix:
                continue
            if lang in ("c", "cpp", ""):
                continue
            s = make_sample(vuln, fix, cwe, lang, "securecode")
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
            sc_count += 1
            sc_langs[lang] += 1
    print(f"  {sc_count} non-C vuln samples")
    for lang, n in sorted(sc_langs.items(), key=lambda x: -x[1]):
        print(f"    {lang}: {n}")
except Exception as e:
    print(f"  FAILED: {e}")

# ── PatchEval (Go/JS/Python) ─────────────────────────────
print("\n=== PatchEval ===")
try:
    ds_pe = load_dataset("ByteDance/PatchEval", split="train", trust_remote_code=True)
    pe_count = 0
    pe_langs = Counter()
    with open(OUT / "patcheval.jsonl", "w") as f:
        for row in ds_pe:
            vuln = row.get("vul_func", "") or row.get("vulnerable_code", "") or ""
            fix = row.get("fix_func", "") or row.get("patched_code", "") or ""
            lang = normalize_lang(row.get("language", "") or row.get("lang", ""))
            cwe = row.get("cwe", "") or row.get("vulnerability_type", "")
            if not vuln or not fix:
                continue
            if lang in ("c", "cpp", ""):
                continue
            s = make_sample(vuln, fix, cwe, lang, "patcheval")
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
            pe_count += 1
            pe_langs[lang] += 1
    print(f"  {pe_count} non-C vuln samples")
    for lang, n in sorted(pe_langs.items(), key=lambda x: -x[1]):
        print(f"    {lang}: {n}")
except Exception as e:
    print(f"  FAILED: {e}")

# ── Summary ───────────────────────────────────────────────
print("\n" + "=" * 50)
total = 0
for p in sorted(OUT.glob("*.jsonl")):
    n = sum(1 for _ in open(p))
    print(f"  {p.name}: {n:,}")
    total += n
print(f"  TOTAL: {total:,}")
print(f"  Location: {OUT}")

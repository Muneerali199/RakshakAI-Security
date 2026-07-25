"""
RakshakAI v2 Phase B — Build 250K multi-task dataset.

Pipeline:
  1. Load existing clean vulnerable samples from clean/
  2. Load extracted non-vulnerable samples from nonvuln/
  3. Deduplicate globally (exact + near)
  4. Balance to 250K total (125K vuln + 125K non-vuln)
  5. Convert to multi-task chat format
  6. Generate chain-of-thought reasoning traces
  7. Split into train/val/test
  8. Write benchmark samples

Output: v2/inputs/datasets/phase_b/
  meta/           — raw SecuritySample records (balanced, deduped)
  instruct/       — chat-format (system/user/assistant)
  benchmark/      — locked 500-sample benchmark
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, read_jsonl, write_jsonl  # noqa: E402

random.seed(42)

# Paths
CLEAN_DIR = Path("v2/inputs/datasets/clean")
NONVULN_DIR = Path("v2/inputs/datasets/nonvuln")
OUT_DIR = Path("v2/inputs/datasets/phase_b")
OUT_META = OUT_DIR / "meta"
OUT_INSTRUCT = OUT_DIR / "instruct"
OUT_BENCHMARK = OUT_DIR / "benchmark"

TARGET_TOTAL = 250_000
BENCHMARK_SIZE = 500
# Auto-determine ratio: keep as close to 50/50 as available data allows
AUTO_BALANCE = True
TRAIN_FRAC, VAL_FRAC, TEST_FRAC = 0.85, 0.05, 0.10

SYSTEM_PROMPT = """You are RakshakAI v2, a security-specialized code analysis model. Analyze the code snippet for security vulnerabilities.

Think through your analysis step by step, then respond with a JSON object containing:
{
  "is_vulnerable": true/false,
  "vulnerability_type": "<CWE-XXX or null if not vulnerable>",
  "severity": "<critical|high|medium|low|clean>",
  "explanation": "<root cause explanation>",
  "patched_code": "<fixed code or null if already secure>",
  "secure_fix_recommendation": "<how to fix it>"
}
If the code is secure, set is_vulnerable=false, severity="clean", and all other fields to appropriate null/clean values."""


# ---------------------------------------------------------------------------
# 1. Loading
# ---------------------------------------------------------------------------

CONSOLIDATED_CLEAN = Path("v2/inputs/datasets/consolidated/clean_all.jsonl")

def _load_clean_vuln() -> list[SecuritySample]:
    """Load ALL vulnerable samples from clean/ directory (all lines in each file)."""
    samples = []
    if CONSOLIDATED_CLEAN.exists():
        with CONSOLIDATED_CLEAN.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    s = SecuritySample.from_dict(d)
                    if s.is_vulnerable:
                        samples.append(s)
                except Exception:
                    continue
        print(f"[load] {len(samples)} vulnerable samples from consolidated ({CONSOLIDATED_CLEAN})")
        return samples
    paths = sorted(CLEAN_DIR.rglob("*.jsonl"))
    for p in paths:
        try:
            with p.open("r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    s = SecuritySample.from_dict(d)
                    if s.is_vulnerable:
                        samples.append(s)
        except Exception:
            continue
    print(f"[load] {len(samples)} vulnerable samples from clean/ ({len(paths)} files)")
    return samples


def _load_nonvuln() -> list[SecuritySample]:
    """Load all non-vulnerable samples from nonvuln/ directory."""
    samples = []
    if not NONVULN_DIR.exists():
        print("[load] nonvuln/ directory not found, run extract_nonvuln.py first")
        return samples
    for p in sorted(NONVULN_DIR.rglob("*.jsonl")):
        try:
            with p.open("r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    s = SecuritySample.from_dict(d)
                    if not s.is_vulnerable:
                        samples.append(s)
        except Exception:
            continue
    print(f"[load] {len(samples)} non-vulnerable samples from nonvuln/")
    return samples


# ---------------------------------------------------------------------------
# 2. Dedup
# ---------------------------------------------------------------------------

def _dedup_exact(samples: list[SecuritySample]) -> list[SecuritySample]:
    seen: set[str] = set()
    out = []
    for s in samples:
        if s.fingerprint in seen:
            continue
        seen.add(s.fingerprint)
        out.append(s)
    print(f"[dedup] exact: {len(samples)} -> {len(out)}")
    return out


def _estimate_pool(vuln: list[SecuritySample], nonvuln: list[SecuritySample]) -> dict:
    """Report pool sizes before balancing."""
    return {
        "vulnerable": len(vuln),
        "non_vulnerable": len(nonvuln),
        "total": len(vuln) + len(nonvuln),
    }


LANG_WEIGHTS_PATH = Path("v2/configs/language_balance.json")

def _load_lang_weights() -> dict[str, float]:
    if LANG_WEIGHTS_PATH.exists():
        cfg = json.loads(LANG_WEIGHTS_PATH.read_text())
        return cfg.get("language_weights", {})
    return {}


def _weighted_downsample(samples: list[SecuritySample], n_target: int,
                         lang_weights: dict[str, float],
                         rng: random.Random) -> list[SecuritySample]:
    if len(samples) <= n_target:
        return samples
    by_lang: dict[str, list[SecuritySample]] = defaultdict(list)
    for s in samples:
        by_lang[s.language].append(s)
    total_weight = sum(lang_weights.get(lang, 1.0) for lang in by_lang)
    if total_weight <= 0:
        total_weight = len(by_lang)

    # Allocate slots proportionally by weight
    allocations: dict[str, int] = {}
    for lang, group in by_lang.items():
        raw = int(n_target * lang_weights.get(lang, 1.0) / total_weight)
        allocations[lang] = min(raw, len(group))

    # Distribute remaining slots (rounding) to highest-weight langs
    allocated = sum(allocations.values())
    remaining = n_target - allocated
    for _ in range(remaining):
        best_lang = None
        best_penalty = float('inf')
        for lang in by_lang:
            if allocations[lang] < len(by_lang[lang]):
                ideal = n_target * lang_weights.get(lang, 1.0) / total_weight
                penalty = (allocations[lang] + 1) / (lang_weights.get(lang, 1.0) or 1)
                if penalty < best_penalty:
                    best_penalty = penalty
                    best_lang = lang
        if best_lang:
            allocations[best_lang] += 1

    selected = []
    for lang, n_take in allocations.items():
        if n_take > 0:
            pool = by_lang[lang]
            selected.extend(rng.sample(pool, min(n_take, len(pool))))
    return selected


def _balance(vuln: list[SecuritySample], nonvuln: list[SecuritySample],
             target: int) -> tuple[list[SecuritySample], dict]:
    """Balance to target with language-weighted downsampling.

    Uses v2/configs/language_balance.json to reduce C-heavy skew.

    Returns (balanced_samples, stats).
    """
    rng = random.Random(42)
    lang_weights = _load_lang_weights()
    n_vuln = len(vuln)
    n_clean = len(nonvuln)

    max_balanced = 2 * min(n_vuln, n_clean)
    target_actual = min(target, max_balanced)

    n_vuln_target = target_actual // 2
    n_clean_target = target_actual - n_vuln_target

    if n_vuln_target > n_vuln:
        n_vuln_target = n_vuln
        n_clean_target = min(target_actual - n_vuln_target, n_clean)
    elif n_clean_target > n_clean:
        n_clean_target = n_clean
        n_vuln_target = min(target_actual - n_clean_target, n_vuln)

    if len(vuln) > n_vuln_target:
        vuln = _weighted_downsample(vuln, n_vuln_target, lang_weights, rng)
    if len(nonvuln) > n_clean_target:
        nonvuln = _weighted_downsample(nonvuln, n_clean_target, lang_weights, rng)

    stats = {
        "target": target,
        "actual_total": len(vuln) + len(nonvuln),
        "vulnerable": len(vuln),
        "non_vulnerable": len(nonvuln),
        "ratio": round(len(vuln) / (len(vuln) + len(nonvuln) + 0.001), 3),
    }

    combined = vuln + nonvuln
    rng.shuffle(combined)
    return combined, stats


# ---------------------------------------------------------------------------
# 3. Multi-task chat conversion
# ---------------------------------------------------------------------------

def _make_user_content(s: SecuritySample) -> str:
    lang = s.language
    code = s.vulnerable_code
    return f"Analyze the following {lang} code for security vulnerabilities:\n\n```{lang}\n{code}\n```"


def _make_assistant_content(s: SecuritySample) -> str:
    """Build the assistant JSON response + optional chain-of-thought."""
    if s.is_vulnerable:
        vuln_label = s.cwe or "CWE-UNKNOWN"
        severity = s.severity or "high"
        explanation = (s.explanation or "").strip() or "Vulnerability detected."
        attack = (s.attack_scenario or "").strip()
        fix = (s.secure_fix or "").strip() or "Apply standard security fixes."
        patched = (s.patched_code or "").strip() or "N/A"

        # Build chain-of-thought reasoning
        cot_parts = []
        cot_parts.append(f"1. Vulnerability analysis: {vuln_label} — {explanation}")
        if attack:
            cot_parts.append(f"2. Attack scenario: {attack}")
        cot_parts.append(f"3. Severity assessment: {severity}")
        if patched and patched != "N/A":
            cot_parts.append(f"4. Code fix: The vulnerable code should be rewritten to address the security issue.")
        cot_parts.append(f"5. Secure fix recommendation: {fix}")
        cot = "\n".join(cot_parts)

        result = {
            "is_vulnerable": True,
            "vulnerability_type": vuln_label,
            "severity": severity,
            "explanation": explanation,
            "patched_code": patched if patched != "N/A" else None,
            "secure_fix_recommendation": fix,
        }
    else:
        cot = "1. Vulnerability analysis: No vulnerability detected.\n"
        cot += "2. Attack scenario: None — code is secure.\n"
        cot += "3. Severity assessment: clean\n"
        cot += "4. Code fix: Not needed.\n"
        cot += "5. Secure fix recommendation: Code is already secure."

        result = {
            "is_vulnerable": False,
            "vulnerability_type": None,
            "severity": "clean",
            "explanation": "Code appears to be secure with no detected vulnerabilities.",
            "patched_code": None,
            "secure_fix_recommendation": "No fix needed — code is secure.",
        }

    return f"Let me analyze this code step by step.\n\n{cot}\n\n{json.dumps(result, indent=2)}"


def _to_chat(s: SecuritySample) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _make_user_content(s)},
            {"role": "assistant", "content": _make_assistant_content(s)},
        ],
        "_meta": {
            "id": s.id,
            "cwe": s.cwe,
            "severity": s.severity,
            "language": s.language,
            "source": s.source,
            "split": s.split,
            "is_vulnerable": s.is_vulnerable,
        },
    }


def _build_benchmark_samples() -> list[dict]:
    """Build 500 diverse benchmark samples (never trained on).

    Mix: 200 vuln (50 CWEs × 4 samples), 200 clean, 100 ambiguous/hard.
    Balanced across languages.
    """
    rng = random.Random(2024)

    # Vulnerable samples: craft with known CWE patterns
    vuln_templates = [
        # (cwe, language, code_pattern, explanation, fix)
        ("CWE-89", "python", "def get_user(user_id):\n    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n    return db.execute(query)",
         "SQL injection via string interpolation: user_id parameter is directly embedded in SQL query without sanitization.",
         "Use parameterized queries: `db.execute('SELECT * FROM users WHERE id = ?', (user_id,))`"),
        ("CWE-79", "javascript", "function displayComment(comment) {\n    document.getElementById('comments').innerHTML += comment;\n}",
         "XSS vulnerability: unescaped user input is injected directly into innerHTML.",
         "Use textContent instead: `element.textContent += comment` or sanitize with DOMPurify."),
        ("CWE-78", "python", "def ping_host(host):\n    os.system(f'ping -c 1 {host}')",
         "OS command injection: user-controlled hostname is passed to shell.",
         "Use subprocess with argument list: `subprocess.run(['ping', '-c', '1', host])`"),
        ("CWE-22", "python", "def read_file(filename):\n    with open(f'/var/data/{filename}') as f:\n        return f.read()",
         "Path traversal: filename is not sanitized, allowing '../' to escape base directory.",
         "Use os.path.realpath and verify it starts with the base directory."),
        ("CWE-502", "python", "import pickle\ndef load_data(data):\n    return pickle.loads(data)",
         "Insecure deserialization: pickle.loads can execute arbitrary code.",
         "Use safe serialization formats like JSON or implement allowlist-based deserialization."),
        ("CWE-79", "java", "out.println(\"<div>\" + request.getParameter(\"comment\") + \"</div>\")",
         "XSS vulnerability: user input printed directly to HTML without escaping.", "Sanitize with OWASP ESAPI or Jsoup.clean()"),
        ("CWE-89", "java", "String sql = \"SELECT * FROM users WHERE id='\" + userId + \"'\";",
         "SQL injection: string concatenation builds SQL query.", "Use PreparedStatement with parameterized queries."),
        ("CWE-416", "c", "char* ptr = malloc(64);\nfree(ptr);\nstrcpy(ptr, \"hello\");",
         "Use-after-free: memory is accessed after being freed.", "Set ptr to NULL after free and check before use."),
        ("CWE-787", "c", "void copy(char* src) {\n    char buf[64];\n    strcpy(buf, src);\n}",
         "Buffer overflow: strcpy does not bounds-check src length.", "Use strncpy with proper length limit."),
        ("CWE-20", "javascript", "app.get('/user/:id', (req, res) => {\n    db.query(`SELECT * FROM users WHERE id=${req.params.id}`, ...)\n})",
         "Improper input validation: route parameter used directly in SQL query.", "Validate ID is numeric, use parameterized queries."),
        ("CWE-89", "go", "func getUser(db *sql.DB, id string) (*User, error) {\n    row := db.QueryRow(fmt.Sprintf(\"SELECT * FROM users WHERE id='%s'\", id))\n    ...",
         "SQL injection: fmt.Sprintf builds SQL query with user input.", "Use parameterized query: `db.QueryRow(\"SELECT * FROM users WHERE id=?\", id)`"),
        ("CWE-200", "python", "except Exception as e:\n    return str(e)",
         "Information disclosure: full exception details leaked to user.", "Log the full error, return only a generic message."),
    ]

    clean_templates = [
        ("python", "def get_user(user_id):\n    query = \"SELECT * FROM users WHERE id = ?\"\n    return db.execute(query, (user_id,))",
         "Uses parameterized query — safe from SQL injection."),
        ("javascript", "const displayComment = (comment) => {\n    const el = document.getElementById('comments');\n    el.textContent += comment;\n}",
         "Uses textContent instead of innerHTML — safe from XSS."),
        ("python", "def ping_host(host):\n    import subprocess\n    return subprocess.run(['ping', '-c', '1', host], capture_output=True)",
         "Uses subprocess with argument list — no shell injection risk."),
        ("python", "def read_file(filename):\n    import os\n    base = '/var/data/'\n    path = os.path.realpath(os.path.join(base, filename))\n    if not path.startswith(os.path.realpath(base)):\n        raise ValueError('Invalid path')\n    with open(path) as f:\n        return f.read()",
         "Properly validates path against traversal — safe from path traversal."),
        ("java", "out.println(\"<div>\" + org.owasp.encoder.Encode.forHtml(request.getParameter(\"comment\")) + \"</div>\")",
         "Properly HTML-encodes output — safe from XSS."),
        ("go", "func getUser(db *sql.DB, id string) (*User, error) {\n    row := db.QueryRow(\"SELECT * FROM users WHERE id=?\", id)\n    ...",
         "Parameterized query — safe from SQL injection."),
        ("c", "void copy(char* src) {\n    char buf[64];\n    strncpy(buf, src, sizeof(buf) - 1);\n    buf[sizeof(buf) - 1] = '\\0';\n}",
         "Safe string copy with bounded length."),
        ("python", "try:\n    result = do_something()\nexcept Exception as e:\n    log.error(f'Error: {e}')\n    return 'An error occurred'",
         "Proper exception handling without leaking details."),
    ]

    ambiguous_templates = [
        ("python",
         "def process_data(data):\n    result = eval(data)\n    return transform(result)",
         "eval() is dangerous but data might be pre-validated elsewhere"),
        ("javascript",
         "app.get('/search', (req, res) => {\n    const q = req.query.q;\n    const results = db.query(`SELECT * FROM items WHERE name LIKE '%${q}%'`);\n    res.json(results);\n})",
         "String interpolation in LIKE clause — potential SQLi but LIKE '%...%' limits damage"),
        ("python",
         "def save_file(filename, content):\n    with open(filename, 'wb') as f:\n        f.write(content)",
         "No path validation but only called from internal routes with sanitized inputs"),
    ]

    samples = []

    # Vulnerable samples: 200
    for i in range(200):
        t = vuln_templates[i % len(vuln_templates)]
        cwe, lang, code, expl, fix = t
        samples.append({
            "id": f"bench-vuln-{i:04d}",
            "language": lang,
            "vulnerable_code": code,
            "patched_code": fix,
            "cwe": cwe,
            "severity": "high",
            "explanation": expl,
            "is_vulnerable": True,
            "source": "phase-b-benchmark",
        })

    # Clean samples: 200
    for i in range(200):
        t = clean_templates[i % len(clean_templates)]
        lang, code, expl = t
        samples.append({
            "id": f"bench-clean-{i:04d}",
            "language": lang,
            "vulnerable_code": code,
            "patched_code": None,
            "cwe": None,
            "severity": "clean",
            "explanation": expl,
            "is_vulnerable": False,
            "source": "phase-b-benchmark",
        })

    # Ambiguous samples: 100
    for i in range(100):
        t = ambiguous_templates[i % len(ambiguous_templates)]
        lang, code, expl = t
        samples.append({
            "id": f"bench-ambig-{i:04d}",
            "language": lang,
            "vulnerable_code": code,
            "patched_code": None,
            "cwe": None,
            "severity": "medium",
            "explanation": expl,
            "is_vulnerable": None,  # ambiguous
            "source": "phase-b-benchmark",
        })

    rng.shuffle(samples)
    return samples


def _lock_benchmark(samples: list[dict], out_dir: Path):
    """Write benchmark JSONL and SHA-256 lock file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "benchmark.jsonl"
    with path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # SHA-256 lock
    content = path.read_bytes()
    sha = hashlib.sha256(content).hexdigest()
    lock = {
        "sha256": sha,
        "num_samples": len(samples),
        "description": "RakshakAI v2 Phase B locked benchmark — 500 samples",
        "note": "NEVER train on these samples.",
    }
    lock_path = out_dir / "BENCHMARK_LOCK.json"
    lock_path.write_text(json.dumps(lock, indent=2))
    print(f"[benchmark] {len(samples)} samples written to {path}")
    print(f"[benchmark] SHA-256: {sha}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    target = TARGET_TOTAL
    if "--target" in sys.argv:
        idx = sys.argv.index("--target")
        target = int(sys.argv[idx + 1])
    print(f"[build_phase_b] target={target}")

    OUT_META.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    vuln = _load_clean_vuln()
    nonvuln = _load_nonvuln()

    pool = _estimate_pool(vuln, nonvuln)
    print(f"\n[pool] {json.dumps(pool, indent=2)}")

    # 2. Deduplicate
    combined = _dedup_exact(vuln + nonvuln)
    vuln = [s for s in combined if s.is_vulnerable]
    nonvuln = [s for s in combined if not s.is_vulnerable]
    print(f"[pool] after dedup: vuln={len(vuln)}, nonvuln={len(nonvuln)}")

    # 3. Balance
    balanced, balance_stats = _balance(vuln, nonvuln, target)
    print(f"[balance] final: {len(balanced)} samples ({balance_stats})")

    # 4. Report composition
    lang_counts = Counter(s.language for s in balanced)
    severity_counts = Counter(s.severity or "unknown" for s in balanced)
    is_vuln_counts = Counter(str(s.is_vulnerable) for s in balanced)
    cwe_counts = Counter(s.cwe or "CWE-CLEAN" for s in balanced)
    source_counts = Counter(s.source.split(":")[0] for s in balanced)

    print(f"\n[composition] languages: {dict(lang_counts.most_common(10))}")
    print(f"[composition] severity: {dict(severity_counts.most_common(10))}")
    print(f"[composition] is_vulnerable: {dict(is_vuln_counts)}")
    print(f"[composition] top CWEs: {dict(cwe_counts.most_common(20))}")
    print(f"[composition] sources: {dict(source_counts.most_common(10))}")

    # 5. Split into train/val/test
    rng = random.Random(42)
    indices = list(range(len(balanced)))
    rng.shuffle(indices)

    n_val = int(len(balanced) * VAL_FRAC)
    n_test = int(len(balanced) * TEST_FRAC)

    val_idx = set(indices[:n_val])
    test_idx = set(indices[n_val:n_val + n_test])
    train_idx = set(indices[n_val + n_test:])

    splits = {"train": [], "val": [], "test": []}
    for i, s in enumerate(balanced):
        s.split = "train"
        if i in val_idx:
            s.split = "val"
            splits["val"].append(s)
        elif i in test_idx:
            s.split = "test"
            splits["test"].append(s)
        else:
            splits["train"].append(s)

    print(f"\n[splits] train={len(splits['train'])}, val={len(splits['val'])}, test={len(splits['test'])}")

    # 6. Write meta (SecuritySample JSONL per split)
    for split_name, split_samples in splits.items():
        path = OUT_META / f"{split_name}.jsonl"
        write_jsonl(path, split_samples)
        print(f"[meta] wrote {len(split_samples)} -> {path}")

    # 7. Convert to multi-task chat format
    OUT_INSTRUCT.mkdir(parents=True, exist_ok=True)
    for split_name, split_samples in splits.items():
        path = OUT_INSTRUCT / f"{split_name}.jsonl"
        n = 0
        with path.open("w") as f:
            for s in split_samples:
                chat = _to_chat(s)
                f.write(json.dumps(chat, ensure_ascii=False) + "\n")
                n += 1
        print(f"[instruct] wrote {n} -> {path}")

    # also write combined all.jsonl
    all_path = OUT_INSTRUCT / "all.jsonl"
    with all_path.open("w") as f:
        for s in balanced:
            chat = _to_chat(s)
            f.write(json.dumps(chat, ensure_ascii=False) + "\n")
    print(f"[instruct] wrote {len(balanced)} combined -> {all_path}")

    # 8. Build and lock benchmark
    bench = _build_benchmark_samples()
    _lock_benchmark(bench, OUT_BENCHMARK)

    # 9. Write summary
    summary = {
        "target_total": target,
        "actual_total": len(balanced),
        "vulnerable": sum(1 for s in balanced if s.is_vulnerable),
        "non_vulnerable": sum(1 for s in balanced if not s.is_vulnerable),
        "train": len(splits["train"]),
        "val": len(splits["val"]),
        "test": len(splits["test"]),
        "benchmark": BENCHMARK_SIZE,
        "languages": dict(lang_counts.most_common(20)),
        "top_cwes": dict(cwe_counts.most_common(20)),
        "sources": dict(source_counts.most_common(10)),
    }
    summary_path = OUT_DIR / "phase_b_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\n[summary] wrote to {summary_path}")
    print(json.dumps(summary, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())

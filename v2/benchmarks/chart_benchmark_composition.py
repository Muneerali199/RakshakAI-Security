#!/usr/bin/env python3
"""Generate benchmark composition charts from the comprehensive benchmark JSONL.

Usage:
    python v2/benchmarks/chart_benchmark_composition.py [--push]
"""
import argparse, json, sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib required")
    sys.exit(1)

BG = "#0a0a0f"
FG = "#aaaaaa"

def load(path: str) -> list:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples

def chart_cwe_coverage(samples: list, out_dir: Path):
    cwe_counts = Counter(s["cwe"] for s in samples if s["cwe"] != "CWE-000")
    sorted_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)

    fig, ax = plt.subplots(figsize=(16, 8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    names = [c[0] for c in sorted_cwe]
    vals = [c[1] for c in sorted_cwe]
    colors_bar = ["#00ff88" if "89" in n or "78" in n or "79" in n else
                  "#00ccff" if int(v) >= 2 else
                  "#ff8800" for n, v in sorted_cwe]
    bars = ax.barh(names, vals, color=colors_bar, edgecolor="white", linewidth=0.4, height=0.7)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(v), va="center", fontsize=9, color="white", fontweight="bold")
    ax.set_xlim(0, max(vals) + 2)
    ax.set_title("Comprehensive Benchmark: CWE Coverage (72 samples, 57 unique CWEs)",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=FG, labelsize=9)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_xlabel("Number of Samples", color=FG)
    ax.grid(axis="x", alpha=0.1, color="white")
    fig.text(0.5, 0.01,
             "Green: OWASP Top 10  |  Blue: Multiple samples  |  Orange: Single sample",
             ha="center", fontsize=9, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    path = out_dir / "benchmark_cwe_coverage.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")

def chart_language_distribution(samples: list, out_dir: Path):
    lang_counts = Counter(s["language"] for s in samples)
    total = sum(lang_counts.values())
    sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)

    lang_colors = {
        "python": "#3776AB", "javascript": "#F7DF1E", "c": "#555555",
        "go": "#00ADD8", "cpp": "#00599C", "java": "#ED8B00",
        "ruby": "#CC342D", "rust": "#DEA584", "php": "#777BB4",
        "solidity": "#363636", "html": "#E34F26",
    }
    colors_l = [lang_colors.get(l, "#888888") for l, _ in sorted_langs]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    labels = [f"{l} ({c})" for l, c in sorted_langs]
    vals_l = [c for _, c in sorted_langs]
    wedges, texts, autotexts = ax.pie(
        vals_l, labels=None, autopct="%1.0f%%",
        colors=colors_l, startangle=90,
        textprops={"color": "white", "fontsize": 10},
        pctdistance=0.75, wedgeprops={"edgecolor": BG, "linewidth": 2},
    )
    for t in autotexts:
        t.set_fontsize(9)
        t.set_fontweight("bold")
    ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(-0.1, 0.5),
              fontsize=9, frameon=False, labelcolor="white")
    ax.set_title(f"Comprehensive Benchmark: Language Distribution ({total} samples, {len(sorted_langs)} languages)",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    plt.tight_layout()
    path = out_dir / "benchmark_language_distribution.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")

def chart_severity_distribution(samples: list, out_dir: Path):
    sev_order = ["critical", "high", "medium", "low", "none"]
    sev_counts = Counter(s.get("severity", "unknown") for s in samples)
    vals = [sev_counts.get(s, 0) for s in sev_order]
    sev_colors = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#88ccff", "none": "#44aa44"}
    colors_sev = [sev_colors.get(s, "#888888") for s in sev_order]
    labels_sev = [f"{s.title()} ({c})" if c > 0 else "" for s, c in zip(sev_order, vals)]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    bars = ax.bar(sev_order, vals, color=colors_sev, edgecolor="white", linewidth=1, width=0.5)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                str(v), ha="center", fontsize=14, fontweight="bold", color="white")
    ax.set_ylim(0, max(vals) + 5)
    ax.set_title("Comprehensive Benchmark: Severity Distribution",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=FG, labelsize=11)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_ylabel("Number of Samples", color=FG)
    ax.grid(axis="y", alpha=0.1, color="white")
    plt.tight_layout()
    path = out_dir / "benchmark_severity_distribution.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")

def chart_owasp_top10_coverage(samples: list, out_dir: Path):
    owasp_mapping = {
        "CWE-89": "A1: SQL Injection", "CWE-78": "A1: Command Injection",
        "CWE-79": "A3: XSS", "CWE-22": "A5: Path Traversal",
        "CWE-918": "A10: SSRF", "CWE-502": "A8: Deserialization",
        "CWE-287": "A7: Auth Bypass", "CWE-352": "A1: CSRF",
        "CWE-611": "A5: XXE", "CWE-434": "A5: File Upload",
        "CWE-862": "A1: Missing Auth", "CWE-78": "A1: OS Injection",
        "CWE-94": "A1: Code Injection", "CWE-798": "A7: Hardcoded Secrets",
        "CWE-200": "A5: Info Exposure", "CWE-307": "A7: Brute Force",
        "CWE-284": "A1: Broken Access Control",
        "CWE-400": "A6: Resource Exhaustion",
        "CWE-522": "A2: Weak Credentials",
        "CWE-295": "A7: Improper Cert Validation",
    }
    cwe_set = set(s["cwe"] for s in samples)
    covered = {}
    for cwe_name, owasp_cat in owasp_mapping.items():
        if cwe_name in cwe_set:
            covered[cwe_name] = owasp_cat

    fig, ax = plt.subplots(figsize=(14, 7))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    row_labels = [f"{cwe} - {cat}" for cwe, cat in sorted(covered.items())]
    coverage = [[1] for _ in row_labels]
    ax.imshow([[1]], cmap="Greens", aspect="auto", vmin=0, vmax=1)

    ax.barh(range(len(row_labels)), [1]*len(row_labels), color="#00ff88",
            edgecolor="white", linewidth=0.5, height=0.7)
    ax.set_yticks(range(len(row_labels)))
    ax.set_yticklabels(row_labels, fontsize=9, color="white")
    ax.set_xlim(0, 1.5)
    ax.set_xticks([])
    for i in range(len(row_labels)):
        ax.text(1.05, i, "[COVERED]", va="center", fontsize=9, color="#00ff88", fontweight="bold")
    ax.set_title("OWASP Top 10 & Common CWE Coverage in Benchmark",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    for s in ["top", "right", "bottom", "left"]:
        ax.spines[s].set_visible(False)
    plt.tight_layout()
    path = out_dir / "benchmark_owasp_coverage.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")

def chart_vulnerable_vs_clean(samples: list, out_dir: Path):
    vuln = sum(1 for s in samples if s.get("is_vulnerable", True))
    clean = sum(1 for s in samples if not s.get("is_vulnerable", True))

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    bars = ax.bar(["Vulnerable", "Clean (Non-Vulnerable)"], [vuln, clean],
                  color=["#ff4444", "#44aa44"], edgecolor="white", linewidth=1, width=0.4)
    for bar, v in zip(bars, [vuln, clean]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                f"{v}\n({v/(vuln+clean)*100:.0f}%)", ha="center", fontsize=13,
                fontweight="bold", color="white")
    ax.set_ylim(0, max(vuln, clean) + 10)
    ax.set_title("Benchmark Composition: Vulnerable vs Clean",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=FG, labelsize=11)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_ylabel("Number of Samples", color=FG)
    ax.grid(axis="y", alpha=0.1, color="white")
    plt.tight_layout()
    path = out_dir / "benchmark_vuln_vs_clean.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")

def main():
    parser = argparse.ArgumentParser(description="Generate benchmark composition charts")
    parser.add_argument("--benchmark", default=None,
                        help="Path to benchmark JSONL")
    parser.add_argument("--output-dir", default="v2/benchmarks/results",
                        help="Output directory for charts")
    parser.add_argument("--push-to-hub", action="store_true",
                        help="Push charts to HuggingFace")
    parser.add_argument("--hf-repo", default="Muneerali199/rakshak-cwe-14b-sft-final")
    parser.add_argument("--hf-token", default=None)
    args = parser.parse_args()

    if args.benchmark is None:
        args.benchmark = str(Path(__file__).resolve().parent / "comprehensive_benchmark.jsonl")
    if not Path(args.benchmark).exists():
        print(f"ERROR: {args.benchmark} not found")
        sys.exit(1)

    samples = load(args.benchmark)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating composition charts from {len(samples)} samples...")
    chart_cwe_coverage(samples, out_dir)
    chart_language_distribution(samples, out_dir)
    chart_severity_distribution(samples, out_dir)
    chart_vulnerable_vs_clean(samples, out_dir)
    chart_owasp_top10_coverage(samples, out_dir)
    print(f"\nAll charts saved to {out_dir}/")

    if args.push_to_hub:
        token = args.hf_token or __import__("os").environ.get("HF_TOKEN")
        if not token:
            print("ERROR: HF_TOKEN required for push")
            return
        from huggingface_hub import HfApi
        api = HfApi(token=token)
        for png in out_dir.glob("benchmark_*.png"):
            api.upload_file(
                path_or_fileobj=str(png),
                path_in_repo=f"benchmarks/{png.name}",
                repo_id=args.hf_repo, repo_type="model",
            )
            print(f"  Pushed: benchmarks/{png.name}")

if __name__ == "__main__":
    main()

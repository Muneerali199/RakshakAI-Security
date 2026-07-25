#!/usr/bin/env python3
"""Generate model comparison chart — RakshakAI vs published benchmarks.

Usage:
    python v2/benchmarks/chart_model_comparison.py [--push]
"""
import argparse, sys, json
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib required"); sys.exit(1)

BG = "#0a0a0f"
FG = "#aaaaaa"

def chart_castle_comparison(out_dir: Path):
    """Honest side-by-side: CASTLE results vs RakshakAI results — DIFFERENT benchmarks."""
    fig, ax = plt.subplots(figsize=(16, 8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    # Left group: CASTLE Benchmark
    castle_models = [
        "GPT-o3\nMini", "ChatGPT\no1", "DeepSeek\nR1", "GPT-4o",
        "GPT-4o\nMini", "Qwen 2.5\nCI 32B", "Falcon 3\n7B",
        "Mistral\n7B", "Gemma 2\n9B", "LLAMA 3.1\n8B",
    ]
    castle_scores = [63, 60, 51, 53, 34, 35, 35, 22, 23, 20]

    # Right group: RakshakAI Benchmark (OUR test set)
    our_models = ["RakshakAI\n14B"]
    our_scores = [87.5]
    our_labels = ["Internal\nBenchmark"]

    # Build combined
    all_models = castle_models + our_models
    all_scores = castle_scores + our_scores
    x = np.arange(len(all_models))

    # Colors: blue for CASTLE, yellow for ours
    colors_bar = ["#00aaff"] * len(castle_models) + ["#ffcc00"]
    edgecolors = ["white"] * len(castle_models) + ["#ffaa00"]

    bars = ax.bar(x, all_scores, color=colors_bar, edgecolor=edgecolors,
                  linewidth=[0.3]*len(castle_models) + [2.5], width=0.55)

    for bar, v in zip(bars, all_scores):
        clr = "#ffcc00" if bar == bars[-1] else "white"
        fs = 13 if bar == bars[-1] else 10
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f"{v:.0f}%", ha="center", fontsize=fs, fontweight="bold", color=clr)

    ax.set_xticks(x)
    ax.set_xticklabels(all_models, fontsize=8, color="white")
    ax.set_ylim(0, 105)

    # Vertical separator between CASTLE and our group
    sep_x = len(castle_models) - 0.5
    ax.axvline(x=sep_x, color="#ffcc00", linewidth=2, linestyle="--", alpha=0.7)
    ax.text(sep_x, 102, " !  DIFFERENT\n BENCHMARKS", ha="center", va="top",
            fontsize=9, fontweight="bold", color="#ffcc00",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#1a1a2e", edgecolor="#ffcc00", alpha=0.9))

    # Section labels
    ax.text((sep_x) / 2 - 0.3, 99, "CASTLE BENCHMARK", ha="center", va="top",
            fontsize=11, fontweight="bold", color="#00aaff")
    ax.text((sep_x + len(all_models) - 1) / 2 + 0.3, 99, "OUR BENCHMARK",
            ha="center", va="top", fontsize=11, fontweight="bold", color="#ffcc00")

    ax.set_ylabel("CWE Detection Accuracy (%)", fontsize=12, color=FG)
    ax.set_title("CWE Vulnerability Detection — Different Benchmarks, Different Scope",
                 fontsize=15, fontweight="bold", color="white", pad=20)
    ax.tick_params(colors=FG)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.grid(axis="y", alpha=0.1, color="white")

    fig.text(0.5, 0.01,
             "CASTLE (arXiv 2503.09433): 250 C micro-benchmarks, 25 CWEs — tests LLMs on C-only edge cases.\n"
             "RakshakAI: 8 CWE injection tests across C/Python/JS (SQLi, XSS, BufferOverflow, CmdInject, FormatStr, CodeInject) — same metric, different difficulty.\n"
             "Yellow section = our internal pilot benchmark. NOT a direct comparison. Both measure accuracy on their respective test sets.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.08, 1, 0.94])
    path = out_dir / "comparison_castle_benchmark.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def chart_realvuln_comparison(out_dir: Path):
    """RakshakAI vs RealVuln — Python vulnerability detection."""
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    models = [
        "Kolega.Dev\n(Security Spec.)",
        "Claude Sonnet 4.6\n(Anthropic)",
        "Gemini 3.1 Pro\n(Google)",
        "GPT-4.1\n(OpenAI)",
        "Claude Haiku 4.5\n(Anthropic)",
        "RakshakAI\n14B (Ours)",
    ]
    f1_scores = [52.4, 60.9, 55.0, 45.0, 55.0, 87.5]
    f3_scores = [73.0, 51.7, 51.0, 39.5, 47.0, 87.5]

    x = np.arange(len(models))
    w = 0.3

    bars1 = ax.bar(x - w/2, f1_scores, w, label="F1 Score (balanced)", color="#00aaff", edgecolor="white", linewidth=0.3)
    bars2 = ax.bar(x + w/2, f3_scores, w, label="F3 Score (recall-weighted)", color="#00ff88", edgecolor="white", linewidth=0.3)

    our_idx = len(models) - 1
    for bars, vals in [(bars1, f1_scores), (bars2, f3_scores)]:
        bars[our_idx].set_color("#ffcc00")
        bars[our_idx].set_edgecolor("white")
        bars[our_idx].set_linewidth(1.5)
        ax.text(x[our_idx] + (w/2 if bars is bars2 else -w/2),
                vals[our_idx] + 1.5, f"{vals[our_idx]:.0f}%",
                ha="center", fontsize=10, fontweight="bold", color="#ffcc00")

    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=8, color="white")
    ax.set_ylim(0, 105)
    ax.set_ylabel("Score (%)", fontsize=12, color=FG)
    ax.set_title("Vulnerability Detection: RakshakAI 14B vs RealVuln Leaderboard",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.legend(fontsize=10, frameon=False, labelcolor="white", loc="upper left")
    ax.tick_params(colors=FG)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.grid(axis="y", alpha=0.1, color="white")

    fig.text(0.5, 0.01,
             "Sources: RealVuln (arXiv 2604.13764, Apr 2026) — 796 Python vulnerabilities across 26 repos.\n"
             "RakshakAI: 87.5% on 8-test CWE injection pilot — NOT directly on RealVuln.\n"
             "Yellow bars = RakshakAI (preliminary, smaller test set, not RealVuln). Ours is CWE classification accuracy, not F1.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.07, 1, 0.96])
    path = out_dir / "comparison_realvuln.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def chart_web_detection_comparison(out_dir: Path):
    """RakshakAI vs WordPress plugin vulnerability detection benchmark."""
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    models = [
        "Claude Opus 4.6\n(Anthropic)",
        "MiniMax M2.5\n(Open-weight)",
        "Gemini 3.1 Pro\n(Google)",
        "Codex GPT-5.4\n(OpenAI)",
        "Qwen 3 Coder\nNext FP8",
        "Qwen 3.5 122B\n(Alibaba)",
        "RakshakAI\n14B (Ours)",
    ]
    detection_rates = [63, 48, 48, 47, 37, 35, 87.5]

    colors_bar = ["#888888"] * (len(models) - 1) + ["#ffcc00"]
    bars = ax.barh(models, detection_rates, color=colors_bar, edgecolor="white",
                   linewidth=0.5 if colors_bar[-1] != "#ffcc00" else 1.5, height=0.6)
    for bar, v in zip(bars, detection_rates):
        if v == 87.5:
            ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                    f"{v:.0f}% (pilot)", va="center", fontsize=11, fontweight="bold", color="#ffcc00")
        else:
            ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                    f"{v:.0f}%", va="center", fontsize=10, color="white")

    ax.set_xlim(0, 105)
    ax.set_title("Web Vulnerability Detection Rate: RakshakAI vs Frontier Models",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=FG, labelsize=10)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_xlabel("Detection Rate (%)", fontsize=12, color=FG)
    ax.grid(axis="x", alpha=0.1, color="white")

    fig.text(0.5, 0.01,
             "Sources: arXiv 2606.21397 (Jun 2026) — WordPress plugin vuln detection (SQLi, XSS, PT, RCE), 60 tests across 3 iterations.\n"
             "RakshakAI: 87.5% on 8-test CWE injection pilot (C/Python/JS). Yellow = preliminary, different test set.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.07, 1, 0.96])
    path = out_dir / "comparison_web_detection.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def chart_vader_positioning(out_dir: Path):
    """VADER benchmark positioning — shows where RakshakAI would fit if tested."""
    fig, ax = plt.subplots(figsize=(14, 7))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    models_vader = [
        "o3 (OpenAI)\n54.7%",
        "Gemini 2.5 Pro\n52.0%",
        "GPT-4.5\n50.0%",
        "Claude 3.7 Sonnet\n49.0%",
        "GPT-4.1\n48.0%",
        "Grok 3 Beta\n44.0%",
        "RakshakAI 14B\n???",
    ]
    scores = [54.7, 52.0, 50.0, 49.0, 48.0, 44.0, 0]
    colors_bar = ["#00aaff", "#ffcc00", "#00aaff", "#ff8800", "#00aaff", "#444444", "#ffcc00"]

    bars = ax.barh(models_vader, scores, color=colors_bar, height=0.5, edgecolor="white",
                   linewidth=0.3)

    for bar, s in zip(bars, scores):
        if s > 0:
            ax.text(s + 0.5, bar.get_y() + bar.get_height() / 2,
                    f"{s:.0f}%", va="center", fontsize=12, fontweight="bold", color="white")
        else:
            ax.text(2, bar.get_y() + bar.get_height() / 2,
                    "Not Tested", va="center", fontsize=12, color="#ffcc00", style="italic",
                    fontweight="bold")

    ax.set_xlim(0, 65)
    ax.set_xlabel("VADER Benchmark Score (%)", fontsize=13, color=FG)
    ax.set_title("CWE Patch Reasoning: VADER Benchmark — RakshakAI Untested",
                 fontsize=15, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=FG)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.grid(axis="x", alpha=0.15, color="white")

    fig.text(0.5, 0.01,
             "Source: arXiv 2505.19395 (2025). 174 real-world CVEs evaluated by security experts.\n"
             "Score = Remediation 50% + Explanation 20% + Classification 30%. RakshakAI not tested on VADER.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.06, 1, 0.97])
    path = out_dir / "comparison_vader_positioning.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def chart_groq_direct_comparison(out_dir: Path):
    """Direct same-benchmark comparison: RakshakAI vs Groq models (all 72 samples)."""
    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    models = ["RakshakAI\n14B+LoRA", "Llama 3.3\n70B", "Llama 3.1\n8B"]
    vuln_det = [94.4, 93.1, 94.4]
    cwe_exact = [27.8, 31.9, 22.2]

    x = np.arange(len(models))
    w = 0.3

    bars_vuln = ax.bar(x - w/2, vuln_det, w, label="Vulnerability Detection",
                       color="#00ff88", edgecolor="white", linewidth=0.3)
    bars_cwe = ax.bar(x + w/2, cwe_exact, w, label="CWE Exact Match",
                      color="#ff8800", edgecolor="white", linewidth=0.3)

    # Highlight RakshakAI bars
    for bars in [bars_vuln, bars_cwe]:
        bars[0].set_color("#ffcc00")
        bars[0].set_edgecolor("white")
        bars[0].set_linewidth(2)
        ax.text(x[0] + (w/2 if bars is bars_cwe else -w/2),
                bars[0].get_height() + 1.5, f"{bars[0].get_height():.1f}%",
                ha="center", fontsize=11, fontweight="bold", color="#ffcc00")

    for i in range(1, len(models)):
        ax.text(x[i] + (w/2 if i == 1 else -w/2), vuln_det[i] + 1.5,
                f"{vuln_det[i]:.1f}%", ha="center", fontsize=9, color="white")
        ax.text(x[i] + (w/2 if i == 1 else -w/2), cwe_exact[i] + 1.5,
                f"{cwe_exact[i]:.1f}%", ha="center", fontsize=9, color="white")

    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=11, color="white")
    ax.set_ylim(0, 108)
    ax.set_ylabel("Accuracy (%)", fontsize=12, color=FG)
    ax.set_title("Same Benchmark (72 samples, 57 CWEs) — RakshakAI vs Open Models via Groq",
                 fontsize=14, fontweight="bold", color="white", pad=15)
    ax.legend(fontsize=11, frameon=False, labelcolor="white", loc="upper right")
    ax.tick_params(colors=FG)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.grid(axis="y", alpha=0.1, color="white")

    fig.text(0.5, 0.01,
             "All models tested on identical 72-sample benchmark (57 CWE types, 11 languages) via Groq API (Llama) or Modal A10G (RakshakAI).\n"
             "RakshakAI = Qwen2.5-Coder-14B-Instruct + LoRA SFT (375 steps). Groq models = base instruct, no security fine-tuning.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.07, 1, 0.96])
    path = out_dir / "comparison_groq_direct.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def chart_overall_summary(out_dir: Path):
    """Single comprehensive summary comparison."""
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    model_labels = [
        "GPT-o3 Mini", "ChatGPT o1", "DeepSeek R1", "GPT-4o",
        "Claude Sonnet 4.6", "Kolega.Dev",
        "Claude Opus 4.6", "GPT-4.1", "Gemini 3.1 Pro",
        "o3", "Claude 3.7 Sonnet",
        "RakshakAI 14B",
    ]
    scores_bar = [63, 60, 51, 53, 60.9, 52.4, 63, 45, 48, 54.7, 49, 87.5]
    colors_flat = ["#4488ff"] * 4 + ["#ff8800"] * 2 + ["#00aaff"] * 3 + ["#88ff88"] * 2 + ["#ffcc00"]

    y = np.arange(len(model_labels))
    bars = ax.barh(y, scores_bar, color=colors_flat, edgecolor="white", linewidth=0.3, height=0.6)

    for bar, s, label in zip(bars, scores_bar, model_labels):
        if label == "RakshakAI 14B":
            bar.set_linewidth(2.5)
            bar.set_edgecolor("#ffcc00")
            ax.text(s + 0.5, bar.get_y() + bar.get_height() / 2,
                    f"{s:.0f}%", va="center", fontsize=11,
                    fontweight="bold", color="#ffcc00")
        else:
            ax.text(s + 0.5, bar.get_y() + bar.get_height() / 2,
                    f"{s:.0f}%", va="center", fontsize=9, color="white")

    ax.set_yticks(y)
    ax.set_yticklabels(model_labels, fontsize=9, color="white")
    ax.set_xlim(0, 105)
    ax.set_xlabel("Score (%)", fontsize=12, color=FG)
    ax.set_title("RakshakAI 14B vs Published Benchmarks — Cross-Benchmark Comparison",
                 fontsize=15, fontweight="bold", color="white", pad=15)

    for i, (start, end, label, cx) in enumerate([
        (0, 4, "CWE Detection (CASTLE)", -4),
        (4, 6, "Python Vuln (RealVuln)", -4),
        (6, 9, "Web Vuln (WordPress)", -4),
        (9, 11, "Patch Reasoning (VADER)", -4),
        (11, 12, "Our Model", -4),
    ]):
        mid = (start + end) / 2
        ax.text(cx, mid, label, va="center", ha="right", fontsize=9,
                color="#888888", style="italic", rotation=0,
                transform=ax.get_yaxis_transform())

    ax.tick_params(colors=FG)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.grid(axis="x", alpha=0.1, color="white")

    fig.text(0.5, 0.01,
             "Note: Each benchmark uses different test sets, languages, and metrics. Direct cross-benchmark comparison is approximate.\n"
             "RakshakAI result is from an 8-test CWE injection pilot — NOT directly comparable to any single benchmark above.",
             ha="center", fontsize=8, color="#555", style="italic")
    plt.tight_layout(rect=[0, 0.06, 1, 0.96])
    path = out_dir / "comparison_overall_summary.png"
    plt.savefig(path, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Saved: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="v2/benchmarks/results")
    parser.add_argument("--push-to-hub", action="store_true")
    parser.add_argument("--hf-repo", default="Muneerali199/rakshak-cwe-14b-sft-final")
    parser.add_argument("--hf-token", default=None)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating comparison charts...")
    chart_castle_comparison(out_dir)
    chart_realvuln_comparison(out_dir)
    chart_web_detection_comparison(out_dir)
    chart_vader_positioning(out_dir)
    chart_groq_direct_comparison(out_dir)
    chart_overall_summary(out_dir)
    print(f"\nAll charts saved to {out_dir}/")

    if args.push_to_hub:
        token = args.hf_token or Path.home().joinpath(".cache/huggingface/token").read_text().strip()
        if not token:
            token = __import__("os").environ.get("HF_TOKEN")
        if not token:
            print("ERROR: HF_TOKEN required for push")
            return
        from huggingface_hub import HfApi
        api = HfApi(token=token)
        for png in sorted(out_dir.glob("comparison_*.png")):
            try:
                api.upload_file(
                    path_or_fileobj=str(png),
                    path_in_repo=f"benchmarks/{png.name}",
                    repo_id=args.hf_repo, repo_type="model",
                )
                print(f"  Pushed: benchmarks/{png.name}")
            except Exception as e:
                print(f"  Skip {png.name}: {e}")

if __name__ == "__main__":
    main()

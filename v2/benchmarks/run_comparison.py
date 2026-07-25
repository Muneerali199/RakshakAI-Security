#!/usr/bin/env python3
"""Run benchmark comparison: our fine-tuned model vs base Qwen model."""
import json
import sys
import os
import time
import subprocess
import warnings
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent
BENCHMARK_SCRIPT = BENCHMARK_DIR / "public_benchmark.py"
BENCHMARK_DATA = BENCHMARK_DIR / "security_benchmark.jsonl"
RESULTS_DIR = BENCHMARK_DIR / "results"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

MODELS = {
    "RakshakAI-v1 (LoRA)": {
        "base": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "adapter": "Muneerali199/RakshakAI-SecureCoder-7B-v1",
        "type": "lora",
    },
    "Qwen2.5-Coder-7B-Instruct (base)": {
        "base": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "type": "base",
    },
    "DeepSeek-Coder-7B-Instruct-v1.5": {
        "base": "deepseek-ai/deepseek-coder-7b-instruct-v1.5",
        "type": "base",
    },
}


def load_lora_model(base_model_name, adapter_name):
    """Load base model + LoRA adapter."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    import torch

    print(f"  Loading base model: {base_model_name}")
    tokenizer = AutoTokenizer.from_pretrained(
        base_model_name, trust_remote_code=True, padding_side="left"
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
    )

    print(f"  Loading LoRA adapter: {adapter_name}")
    model = PeftModel.from_pretrained(model, adapter_name)
    model.eval()
    return model, tokenizer


def load_base_model(model_name):
    """Load base model directly."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

    print(f"  Loading model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(
        model_name, trust_remote_code=True, padding_side="left"
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
    )
    model.eval()
    return model, tokenizer


def make_model_fn(model, tokenizer):
    """Create model_fn for benchmark."""
    import torch
    warnings.filterwarnings("ignore", message=".*do_sample.*temperature.*")
    warnings.filterwarnings("ignore", message=".*do_sample.*top_p.*")
    warnings.filterwarnings("ignore", message=".*do_sample.*top_k.*")

    def model_fn(prompt, sample):
        messages = [{"role": "user", "content": prompt}]
        input_ids = tokenizer.apply_chat_template(
            messages, return_tensors="pt", add_generation_prompt=True
        ).to(model.device)
        attention_mask = torch.ones_like(input_ids).to(model.device)
        with torch.no_grad():
            outputs = model.generate(
                input_ids,
                attention_mask=attention_mask,
                max_new_tokens=512,
                do_sample=False,
                temperature=None,
                top_p=None,
                pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
            )
        return tokenizer.decode(
            outputs[0][input_ids.shape[1]:], skip_special_tokens=True
        )

    return model_fn


def run_single_benchmark(name, config):
    """Run benchmark for one model and return results."""
    print(f"\n{'='*60}")
    print(f"Benchmarking: {name}")
    print(f"{'='*60}")

    if config["type"] == "lora":
        model, tokenizer = load_lora_model(
            config["base"], config["adapter"]
        )
    else:
        model, tokenizer = load_base_model(config["base"])

    model_fn = make_model_fn(model, tokenizer)

    from public_benchmark import run_benchmark

    results = run_benchmark(model_fn, str(BENCHMARK_DATA))

    # Save individual results
    safe_name = name.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    out_path = RESULTS_DIR / f"{safe_name}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved to {out_path}")

    return results


def print_comparison(results_dict):
    """Print side-by-side comparison of results."""
    print("\n\n" + "=" * 80)
    print("BENCHMARK COMPARISON")
    print("=" * 80)

    names = list(results_dict.keys())
    metrics = [
        ("vulnerability_detection", "precision", "Precision"),
        ("vulnerability_detection", "recall", "Recall"),
        ("vulnerability_detection", "f1", "F1 Score"),
        ("vulnerability_detection", "accuracy", "Accuracy"),
        ("vulnerability_detection", "false_positive_rate", "FPR"),
        ("cwe_classification", "accuracy", "CWE Accuracy"),
        ("cwe_classification", "f1_macro", "CWE F1 (macro)"),
        ("severity_prediction", "exact_match_accuracy", "Severity Acc"),
        ("severity_prediction", "ordinal_accuracy_within_1", "Severity Ordinal"),
        ("fix_quality", "mean_quality_score", "Fix Quality"),
        ("fix_quality", "pass_rate_at_0.6", "Fix Pass@0.6"),
    ]

    print(f"\n{'Metric':<25}", end="")
    for n in names:
        print(f"{n:<25}", end="")
    print()
    print("-" * 80)

    for section, key, label in metrics:
        vals = []
        for n in names:
            r = results_dict[n]
            v = r.get(section, {}).get(key)
            if v is not None:
                vals.append(f"{v:<25}")
            else:
                vals.append(f"{'N/A':<25}")

        if any(v != f"{'N/A':<25}" for v in vals):
            print(f"{label:<25}", end="")
            for v in vals:
                print(v, end="")
            print()

    # Overall score
    print("-" * 80)
    print(f"{'Overall Score':<25}", end="")
    for n in names:
        v = results_dict[n].get("overall_score")
        if v is not None:
            print(f"{v:<25}", end="")
        else:
            print(f"{'N/A':<25}", end="")
    print()

    # Inference time
    print(f"{'Avg Inference (s)':<25}", end="")
    for n in names:
        v = results_dict[n].get("metadata", {}).get("avg_inference_time_s")
        if v is not None:
            print(f"{v:<25}", end="")
        else:
            print(f"{'N/A':<25}", end="")
    print()

    print("=" * 80)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run model benchmark comparison")
    parser.add_argument("--models", nargs="+", default=None,
                        help="Models to benchmark (names from config)")
    parser.add_argument("--quick", action="store_true",
                        help="Run with max 5 samples for quick test")
    args = parser.parse_args()

    models_to_run = args.models or list(MODELS.keys())

    results = {}
    for name in models_to_run:
        if name not in MODELS:
            print(f"Unknown model: {name}. Available: {list(MODELS.keys())}")
            continue
        config = MODELS[name]
        if args.quick:
            # Override max_samples by directly modifying the benchmark
            import public_benchmark as pb
            original_load = pb.run_benchmark

            def quick_run(model_fn, benchmark_path, max_samples=None):
                return original_load(model_fn, benchmark_path, max_samples=5)

            pb.run_benchmark = quick_run

        results[name] = run_single_benchmark(name, config)
        # Clear GPU memory
        import torch
        torch.cuda.empty_cache()

    if len(results) > 1:
        print_comparison(results)
    else:
        name = list(results.keys())[0]
        print(f"\nResults for {name}:")
        print(json.dumps(results[name], indent=2))


if __name__ == "__main__":
    main()

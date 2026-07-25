import json, os, re, time
from pathlib import Path
from typing import Optional

import modal

volume = modal.Volume.from_name("rakshak-cache", create_if_missing=True)
MODEL_DIR = "/cache"

app = modal.App("rakshak-benchmark")

# Use an image with all the deps we need
image = (
    modal.Image.from_registry("pytorch/pytorch:2.2.0-cuda12.1-cudnn8-runtime")
    .run_commands(
        "pip install torch==2.2.0 torchvision==0.17.0 'transformers>=4.45.0,<5.0.0' 'peft>=0.14.0,<0.20.0' accelerate bitsandbytes 'huggingface_hub>=0.24.0' sentencepiece protobuf",
    )
    .env({"HF_HOME": f"{MODEL_DIR}/hf", "HF_HUB_ENABLE_HF_TRANSFER": "0"})
)


def build_prompt(code: str, lang: str) -> str:
    return (
        f"Analyze the following {lang} code for security vulnerabilities. "
        f"Identify the vulnerability type (CWE), severity, root cause, "
        f"attack scenario, and provide a secure fix with patched code.\n"
        f"```{lang}\n{code}\n```"
    )


def extract_cwe(text: str) -> str:
    m = re.search(r"CWE-(\d+)", text, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else ""


@app.cls(
    image=image,
    gpu="T4",
    timeout=5400,
    volumes={MODEL_DIR: volume},
    secrets=[modal.Secret.from_name("hf-token")],
    scaledown_window=300,
)
class BenchmarkRunner:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.samples = []

    @modal.enter()
    def load(self):
        import torch
        from huggingface_hub import snapshot_download
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        from peft import PeftModel

        os.makedirs(f"{MODEL_DIR}/hf", exist_ok=True)
        hf_token = os.environ["HF_TOKEN"]

        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(
            "Qwen/Qwen2.5-Coder-14B-Instruct",
            trust_remote_code=True,
        )
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

        print("Downloading base model...")
        base = AutoModelForCausalLM.from_pretrained(
            "Qwen/Qwen2.5-Coder-14B-Instruct",
            quantization_config=bnb,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            trust_remote_code=True,
        )

        print("Downloading LoRA adapter...")
        adapter_path = snapshot_download(
            repo_id="Muneerali199/rakshak-cwe-14b-sft-step375",
            token=hf_token,
        )

        self.model = PeftModel.from_pretrained(base, adapter_path)
        self.model.eval()
        print("Model loaded successfully")

    @modal.method()
    def run_sample(self, sample: dict) -> dict:
        import torch

        code = sample.get("vulnerable_code", "")
        lang = sample.get("language", "python")
        prompt = build_prompt(code, lang)

        messages = [{"role": "user", "content": prompt}]
        inputs = self.tokenizer.apply_chat_template(
            messages, return_tensors="pt", add_generation_prompt=True
        ).to(self.model.device)

        ts = time.time()
        try:
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_new_tokens=512,
                    temperature=0.1,
                    do_sample=False,
                    pad_token_id=self.tokenizer.pad_token_id,
                )
            raw = self.tokenizer.decode(
                outputs[0][inputs.shape[1] :], skip_special_tokens=True
            )
            dur = time.time() - ts
        except Exception as e:
            raw = f"ERROR: {e}"
            dur = time.time() - ts

        pred_cwe = extract_cwe(raw)

        return {
            "id": sample.get("id", ""),
            "language": lang,
            "true_cwe": sample.get("cwe", ""),
            "true_severity": sample.get("severity", "high"),
            "true_vuln": sample.get("is_vulnerable", True),
            "pred_cwe": pred_cwe,
            "pred_vuln": bool(pred_cwe),
            "duration_s": round(dur, 2),
            "raw_output": raw,
        }

    @modal.method()
    def run_all(self) -> list:
        from huggingface_hub import hf_hub_download

        hf_token = os.environ["HF_TOKEN"]

        bench_path = hf_hub_download(
            repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
            filename="benchmarks/comprehensive_benchmark.jsonl",
            repo_type="model",
            token=hf_token,
        )
        samples = []
        with open(bench_path) as f:
            for line in f:
                if line.strip():
                    samples.append(json.loads(line))

        print(f"Running {len(samples)} samples...")
        results = []
        t0 = time.time()
        for i, s in enumerate(samples):
            r = self.run_sample.local(s)
            results.append(r)
            elapsed = time.time() - t0
            eta = (elapsed / (i + 1)) * (len(samples) - i - 1)
            ok = "✓" if r["pred_cwe"].upper() == r["true_cwe"].upper() else "✗"
            print(
                f"[{i+1}/{len(samples)}] {eta/60:.0f}m ETA | {ok} "
                f"{r['id']:30s} pred={r['pred_cwe'] or '?':12s} "
                f"true={r['true_cwe']:12s} {r['duration_s']:.0f}s"
            )

        total_time = time.time() - t0
        return {
            "model": "Muneerali199/rakshak-cwe-14b-sft-step375",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_samples": len(results),
            "total_time_s": round(total_time, 2),
            "avg_time_per_sample_s": round(total_time / len(results), 2),
            "results": results,
        }

    @modal.method()
    def push_results(self, output: dict):
        from huggingface_hub import HfApi

        api = HfApi(token=os.environ["HF_TOKEN"])
        results_path = f"{MODEL_DIR}/benchmark_results.json"
        with open(results_path, "w") as f:
            json.dump(output, f, indent=2)

        api.upload_file(
            path_or_fileobj=results_path,
            path_in_repo="benchmarks/results/full_benchmark_results.json",
            repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
            repo_type="model",
        )
        print("Results uploaded to HF")

    @modal.method()
    def compute_metrics(self, output: dict):
        results = output["results"]
        n = len(results)

        cwe_exact = sum(
            1
            for r in results
            if r["pred_cwe"].strip().upper() == r["true_cwe"].strip().upper()
        )
        cwe_family = sum(
            1
            for r in results
            if r["pred_cwe"] and r["true_cwe"]
            and r["pred_cwe"].split("-")[-1] == r["true_cwe"].split("-")[-1]
        )
        vuln_detect = sum(
            1 for r in results if r["pred_vuln"] == r["true_vuln"]
        )

        avg_dur = sum(r["duration_s"] for r in results) / n if n else 0
        max_dur = max(r["duration_s"] for r in results) if results else 0

        print(f"\n{'='*50}")
        print(f"  RAKSHAKAI BENCHMARK RESULTS (checkpoint-375)")
        print(f"  Samples: {n}  |  CWEs: 57  |  Languages: 11")
        print(f"{'='*50}")
        print(f"  Vulnerability Detection: {vuln_detect}/{n} ({vuln_detect/n*100:.1f}%)")
        print(f"  CWE Exact Match:        {cwe_exact}/{n} ({cwe_exact/n*100:.1f}%)")
        print(f"  CWE Family Match:       {cwe_family}/{n} ({cwe_family/n*100:.1f}%)")
        print(f"  Avg time per sample:    {avg_dur:.1f}s")
        print(f"  Total time:             {output['total_time_s']/60:.1f}m")
        print(f"{'='*50}\n")

        # Per-language breakdown
        from collections import defaultdict

        lang_stats = defaultdict(lambda: {"total": 0, "ok": 0})
        for r in results:
            lang = r["language"]
            lang_stats[lang]["total"] += 1
            if r["pred_cwe"].strip().upper() == r["true_cwe"].strip().upper():
                lang_stats[lang]["ok"] += 1

        print(f"{'Language':12s} {'Total':6s} {'Correct':8s} {'Accuracy':8s}")
        print("-" * 34)
        for lang in sorted(lang_stats.keys()):
            st = lang_stats[lang]
            acc = st["ok"] / st["total"] * 100 if st["total"] else 0
            print(f"{lang:12s} {st['total']:6d} {st['ok']:8d} {acc:6.1f}%")

        output["metrics"] = {
            "vuln_detection_accuracy": round(vuln_detect / n * 100, 2),
            "cwe_exact_accuracy": round(cwe_exact / n * 100, 2),
            "cwe_family_accuracy": round(cwe_family / n * 100, 2),
        }
        return output


@app.function(
    image=image,
    gpu="T4",
    timeout=5400,
    volumes={MODEL_DIR: volume},
    secrets=[modal.Secret.from_name("hf-token")],
)
def full_benchmark():
    runner = BenchmarkRunner()
    result = runner.run_all.remote()
    result = runner.compute_metrics.remote(result)
    runner.push_results.remote(result)
    return result


@app.local_entrypoint()
def main():
    cwe_exact, cwe_family, vuln = 0, 0, 0
    output = full_benchmark.remote()
    r = output["results"]
    n = len(r)
    cwe_exact = sum(1 for x in r if x["pred_cwe"].strip().upper() == x["true_cwe"].strip().upper())
    cwe_family = sum(1 for x in r if x["pred_cwe"] and x["true_cwe"] and x["pred_cwe"].split("-")[-1] == x["true_cwe"].split("-")[-1])
    vuln = sum(1 for x in r if x["pred_vuln"] == x["true_vuln"])
    print(f"\nFinal: CWE={cwe_exact}/{n} ({cwe_exact/n*100:.1f}%) Family={cwe_family}/{n} ({cwe_family/n*100:.1f}%) Vuln={vuln}/{n} ({vuln/n*100:.1f}%)")

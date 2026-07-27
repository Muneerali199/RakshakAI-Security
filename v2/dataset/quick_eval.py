#!/usr/bin/env python3
"""Quick eval: our LoRA model vs DeepSeek-V4-Pro on 10 benchmark records."""
import json, os, re, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

NVIDIA_KEY = "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"
BENCHMARK_PATH = "v2/inputs/datasets/eval/benchmark_300.jsonl"
N_RECORDS = 3

# DeepSeek client (for judge + baseline)
nim = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)

JUDGE_SYSTEM = "You are a security evaluation judge. Score model responses on C/C++ vulnerability analysis."
JUDGE_TEMPLATE = """Evaluate this model's response to a C/C++ vulnerability analysis task.

[Expected CWE]: {expected_cwe}
[Code]:
```{language}
{code}
```

[Model Response]:
{response}

Score on these 3 dimensions (1-5):

1. **CWE Accuracy** — Does the response identify the correct CWE? Score based on exact or close match.
2. **Reasoning Quality** — Is the analysis step-by-step, technically correct, and thorough?
3. **PoC Quality** — If a PoC is provided, is it valid, targeted, and executable? (If no PoC, score 1.)

Return ONLY a JSON object:
{{"cwe_accuracy": <1-5>, "reasoning_quality": <1-5>, "poc_quality": <1-5>, "predicted_cwe": "<extracted or null>", "explanation": "<1 sentence>"}}"""

def judge_response(expected_cwe, code, language, response_text):
    prompt = JUDGE_TEMPLATE.format(expected_cwe=expected_cwe, code=code, language=language, response=response_text)
    try:
        resp = nim.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=[{"role": "system", "content": JUDGE_SYSTEM}, {"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=1024,
        )
        text = resp.choices[0].message.content
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m: return json.loads(m.group())
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": "Parse fail"}
    except Exception as e:
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": f"Error: {e}"}

def query_deepseek(system, user_msg):
    try:
        resp = nim.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
            temperature=0.3, max_tokens=4096,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[ERROR: {e}]"

# Load benchmark
with open(BENCHMARK_PATH) as f:
    records = [json.loads(line) for line in f if line.strip()]
records = records[:N_RECORDS]
print(f"Loaded {len(records)} records")

# ─── Our model ───
print("\nLoading Rakshak model...")
t0 = time.time()
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

base = AutoModelForCausalLM.from_pretrained(
    "Qwen/Qwen3.5-9B",
    torch_dtype=torch.bfloat16,
    device_map="auto",
)
model = PeftModel.from_pretrained(base, "/home/zeus/v2/model/rakshak_sft_fixed")
tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-9B")
print(f"Model loaded in {time.time()-t0:.1f}s")
print(f"GPU mem: {torch.cuda.memory_allocated()/1e9:.1f} GiB")

def query_rakshak(messages):
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=2048,
            temperature=0.3,
            do_sample=True,
        )
    response = tokenizer.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    return response.strip()

# ─── Run eval ───
results = {"rakshak": [], "deepseek": []}

for i, rec in enumerate(records):
    msgs = rec.get("messages", [])
    meta = rec.get("_meta", {})
    expected_cwe = meta.get("cwe", "UNKNOWN")
    language = {"c": "C", "cpp": "C++"}.get(meta.get("language", ""), meta.get("language", ""))
    code = ""
    for m in msgs:
        if m["role"] == "user":
            content = m["content"]
            cbs = re.findall(r'```(?:\w+)?\n(.*?)```', content, re.DOTALL)
            code = cbs[0] if cbs else content

    system_prompt = ""
    user_msg = ""
    for m in msgs:
        if m["role"] == "system":
            system_prompt = m["content"]
        elif m["role"] == "user":
            user_msg = m["content"]

    print(f"\n[{i+1}/{N_RECORDS}] CWE={expected_cwe} lang={language}")

    # Our model
    t1 = time.time()
    rakshak_resp = query_rakshak(msgs[:-1])  # without assistant
    rt = time.time() - t1
    print(f"  Rakshak ({rt:.1f}s): {rakshak_resp[:100]}...")

    # DeepSeek
    t2 = time.time()
    ds_resp = query_deepseek(system_prompt, user_msg)
    dt = time.time() - t2
    print(f"  DeepSeek ({dt:.1f}s): {ds_resp[:100]}...")

    # Judge both
    r_scores = judge_response(expected_cwe, code, language, rakshak_resp)
    d_scores = judge_response(expected_cwe, code, language, ds_resp)
    print(f"  Rakshak scores: {r_scores['cwe_accuracy']}/{r_scores['reasoning_quality']}/{r_scores['poc_quality']}")
    print(f"  DeepSeek scores: {d_scores['cwe_accuracy']}/{d_scores['reasoning_quality']}/{d_scores['poc_quality']}")

    results["rakshak"].append({"scores": r_scores, "response": rakshak_resp[:500], "time": rt})
    results["deepseek"].append({"scores": d_scores, "response": ds_resp[:500], "time": dt})

# ─── Leaderboard ───
print(f"\n{'='*60}")
print(f"{'LEADERBOARD (10 records)':^60}")
print(f"{'='*60}")
print(f"{'Model':<25} {'CWE Acc':>10} {'Reasoning':>10} {'PoC Qual':>10} {'Overall':>10}")
print(f"{'-'*65}")

for model_name in ["rakshak", "deepseek"]:
    scores = [r["scores"] for r in results[model_name]]
    cwe = sum(s["cwe_accuracy"] for s in scores) / len(scores)
    reas = sum(s["reasoning_quality"] for s in scores) / len(scores)
    poc = sum(s["poc_quality"] for s in scores) / len(scores)
    overall = (cwe + reas + poc) / 3
    label = {"rakshak": "RakshakAI v2 (ours)", "deepseek": "DeepSeek-V4-Pro"}[model_name]
    print(f"{label:<25} {cwe:>7.2f}/5  {reas:>7.2f}/5  {poc:>7.2f}/5  {overall:>7.2f}/5")

# Save
out = {"rakshak": results["rakshak"], "deepseek": results["deepseek"]}
with open("v2/inputs/datasets/eval/results/quick_eval.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\nResults saved to v2/inputs/datasets/eval/results/quick_eval.json")

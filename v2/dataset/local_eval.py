#!/usr/bin/env python3
"""Minimal local eval: tries our model (from HF), falls back to Ollama qwen, compares vs DeepSeek."""
import json, os, re, sys, time
from openai import OpenAI

NVIDIA_KEY = "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"
BENCHMARK = "v2/inputs/datasets/eval/benchmark_300.jsonl"
N_RECORDS = 3

nim = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)
ollama = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

def query_model(client, model, system, user_msg):
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
            temperature=0.3, max_tokens=2048,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[ERROR: {e}]"

def get_scores(expected_cwe, code, language, response_text):
    prompt = f"""Evaluate this model's response to a C/C++ vulnerability analysis task.

[Expected CWE]: {expected_cwe}
[Code]:
```{language}
{code}
```

[Model Response]:
{response_text}

Score on these 3 dimensions (1-5):
1. **CWE Accuracy** — Does the response identify the correct CWE?
2. **Reasoning Quality** — Is the analysis step-by-step, technically correct, and thorough?
3. **PoC Quality** — If a PoC is provided, is it valid, targeted, and executable? (If no PoC, score 1.)

Return ONLY a JSON object:
{{"cwe_accuracy": <1-5>, "reasoning_quality": <1-5>, "poc_quality": <1-5>, "predicted_cwe": "<extracted or null>", "explanation": "<1 sentence>"}}"""
    try:
        resp = nim.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=[{"role": "system", "content": "You are a security evaluation judge."}, {"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=1024,
        )
        text = resp.choices[0].message.content
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m: return json.loads(m.group())
    except:
        pass
    return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1}

# Try loading our model from HF
rakshak_model = None
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    print("Loading Rakshak model from HuggingFace (CPU)...")
    t0 = time.time()
    base = AutoModelForCausalLM.from_pretrained("Qwen/Qwen3.5-9B", torch_dtype=torch.float16, device_map="cpu", low_cpu_mem_usage=True)
    rakshak_model = PeftModel.from_pretrained(base, "Muneerali199/rakshak-cwe-v2")
    rakshak_tok = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-9B")
    print(f"Loaded in {time.time()-t0:.1f}s")
except Exception as e:
    print(f"Could not load Rakshak model: {e}")
    rakshak_model = None

def query_rakshak(messages):
    text = rakshak_tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = rakshak_tok(text, return_tensors="pt")
    with torch.no_grad():
        out = rakshak_model.generate(**inputs, max_new_tokens=1024, temperature=0.3, do_sample=True)
    return rakshak_tok.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()

# Load benchmark
with open(BENCHMARK) as f:
    records = [json.loads(line) for line in f if line.strip()][:N_RECORDS]

results = {}

for i, rec in enumerate(records):
    msgs = rec.get("messages", [])
    meta = rec.get("_meta", {})
    expected_cwe = meta.get("cwe", "UNKNOWN")
    lang = {"c": "C", "cpp": "C++"}.get(meta.get("language", ""), "")
    code = ""
    for m in msgs:
        if m["role"] == "user":
            cbs = re.findall(r'```(?:\w+)?\n(.*?)```', m["content"], re.DOTALL)
            code = cbs[0] if cbs else m["content"]
    system_prompt = next((m["content"] for m in msgs if m["role"] == "system"), "")
    user_msg = next((m["content"] for m in msgs if m["role"] == "user"), "")

    print(f"\n[{i+1}/{N_RECORDS}] {expected_cwe} / {lang}")

    # Rakshak
    if rakshak_model:
        t1 = time.time()
        r_resp = query_rakshak(msgs[:-1])
        print(f"  Rakshak ({time.time()-t1:.1f}s): {r_resp[:80]}...")
        r_scores = get_scores(expected_cwe, code, lang, r_resp)
        results.setdefault("rakshak", []).append(r_scores)
        print(f"    Scores: {r_scores['cwe_accuracy']}/{r_scores['reasoning_quality']}/{r_scores['poc_quality']}")

    # DeepSeek
    t2 = time.time()
    d_resp = query_model(nim, "deepseek-ai/deepseek-v4-pro", system_prompt, user_msg)
    print(f"  DeepSeek ({time.time()-t2:.1f}s): {d_resp[:80]}...")
    d_scores = get_scores(expected_cwe, code, lang, d_resp)
    results.setdefault("deepseek", []).append(d_scores)
    print(f"    Scores: {d_scores['cwe_accuracy']}/{d_scores['reasoning_quality']}/{d_scores['poc_quality']}")

    # Ollama qwen2.5-coder as baseline
    t3 = time.time()
    q_resp = query_model(ollama, "qwen2.5-coder:7b", system_prompt, user_msg)
    print(f"  Qwen2.5-Coder-7B ({time.time()-t3:.1f}s): {q_resp[:80]}...")
    q_scores = get_scores(expected_cwe, code, lang, q_resp)
    results.setdefault("qwen25", []).append(q_scores)
    print(f"    Scores: {q_scores['cwe_accuracy']}/{q_scores['reasoning_quality']}/{q_scores['poc_quality']}")

# Leaderboard
print(f"\n{'='*60}")
print(f"{'LEADERBOARD':^60}")
print(f"{'='*60}")
print(f"{'Model':<25} {'CWE Acc':>10} {'Reason':>10} {'PoC':>10} {'Overall':>10}")
print(f"{'-'*65}")

for name, label in [("rakshak", "RakshakAI v2 (ours)"), ("deepseek", "DeepSeek-V4-Pro"), ("qwen25", "Qwen2.5-Coder-7B")]:
    if name not in results:
        continue
    s = [r["cwe_accuracy"] for r in results[name]]
    r = [r["reasoning_quality"] for r in results[name]]
    p = [r["poc_quality"] for r in results[name]]
    if s:
        cwe = sum(s)/len(s)
        reas = sum(r)/len(r)
        poc = sum(p)/len(p)
        overall = (cwe+reas+poc)/3
        print(f"{label:<25} {cwe:>7.2f}/5  {reas:>7.2f}/5  {poc:>7.2f}/5  {overall:>7.2f}/5")

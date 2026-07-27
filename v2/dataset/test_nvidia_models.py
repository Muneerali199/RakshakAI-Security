#!/usr/bin/env python3
"""Test multiple NVIDIA NIM models for speed and output quality."""
import json, os, sys, time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from openai import OpenAI

API_KEY = "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"
BASE_URL = "https://integrate.api.nvidia.com/v1"

MODELS = [
    "meta/llama-3.3-70b-instruct",
    "mistralai/mistral-medium-3.5-128b",
    "minimaxai/minimax-m2.7",
    "qwen/qwen-3-235b-a55b",
    "stepfun-ai/step-3.7-flash",
    "deepseek-ai/deepseek-v4-flash",
]

CODE = """#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}"""

PROMPT = f"""Analyze this C code for CWE-119 buffer overflow. Return JSON with "reasoning" and "poc" keys.

```c
{CODE}
```"""

def test_model(model_name):
    try:
        client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=120)
        t0 = time.time()
        resp = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": PROMPT}],
            max_tokens=400,
        )
        elapsed = time.time() - t0
        m = resp.choices[0]
        content = m.message.content or ""
        return {
            "model": model_name,
            "time": round(elapsed, 1),
            "tokens_in": resp.usage.prompt_tokens,
            "tokens_out": resp.usage.completion_tokens,
            "finish": m.finish_reason,
            "content_len": len(content),
            "content_preview": content[:150],
            "status": "ok",
        }
    except Exception as e:
        return {"model": model_name, "status": "error", "error": str(e)[:100]}

print("Testing NVIDIA NIM models for speed and code analysis quality...\n")

# Run tests sequentially to avoid rate limiting
results = []
for m in MODELS:
    print(f"  Testing {m}...", flush=True)
    r = test_model(m)
    results.append(r)
    if r["status"] == "ok":
        print(f"    Time: {r['time']}s, Tokens: {r['tokens_in']}+{r['tokens_out']}, Content: {r['content_len']} chars")
    else:
        print(f"    ERROR: {r['error']}")
    print()

print("\n=== Summary ===")
for r in results:
    tag = "OK" if r["status"] == "ok" else "ERR"
    if tag == "OK":
        print(f"  {r['model']}: {r['time']}s, {r['tokens_in']}+{r['tokens_out']} tok, {r['content_len']} chars")
    else:
        print(f"  {r['model']}: FAILED - {r['error']}")

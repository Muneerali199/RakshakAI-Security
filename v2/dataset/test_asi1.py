#!/usr/bin/env python3
"""Test ASI:One models for vulnerability analysis."""
import json, time, os, re, sys
from openai import OpenAI

API_KEY = "sk_69751c96a9d245a9936db84dfb698b8f830efd6faa2940daa0259b15b4121d9d"
BASE_URL = "https://api.asi1.ai/v1"

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

PROMPT = "Analyze this C code for CWE-119 buffer overflow. Return JSON with reasoning and poc keys.\n```c\n" + CODE + "\n```"

for model in ["asi1-ultra", "asi1"]:
    print(f"\n=== Testing {model} ===", flush=True)
    client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=60)
    t0 = time.time()
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security analyst. Output only valid JSON."},
                {"role": "user", "content": PROMPT},
            ],
            max_tokens=2000,
            temperature=0.3,
        )
        t1 = time.time()
        m = resp.choices[0]
        content = m.message.content or ""
        print(f"  Time: {t1-t0:.1f}s")
        print(f"  Usage: {resp.usage}")
        print(f"  Finish: {m.finish_reason}")
        print(f"  Content length: {len(content)}")
        
        cleaned = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.DOTALL)
        jm = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if jm:
            try:
                result = json.loads(jm.group())
                print(f"  JSON OK: reasoning={len(result.get('reasoning',''))} chars, poc={len(result.get('poc',''))} chars")
            except:
                print(f"  JSON parse failed. Preview: {cleaned[:200]}")
        else:
            print(f"  No JSON. Preview: {content[:200]}")
    except Exception as e:
        print(f"  ERROR: {e}")

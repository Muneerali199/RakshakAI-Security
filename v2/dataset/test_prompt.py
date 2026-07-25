#!/usr/bin/env python3
"""Test with exact prompt template from generate_reasoning.py."""
import os, json, re, sys
from openai import OpenAI

client = OpenAI(
    base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
    api_key=os.environ.get("NEBIUS_API_KEY"),
    timeout=120,
)

code = """#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}"""

prompt = "Analyze the following C code for vulnerability CWE-119 (Buffer overflow) - report task.\n\n"
prompt += "Produce a JSON object with exactly two keys:\n"
prompt += '- "reasoning": step-by-step analysis (300-600 words). Walk through entry points, data flow to the vulnerable sink, why the check is insufficient, the trigger condition, and impact.\n'
prompt += '- "poc": short PoC (C code, input, or sequence) that triggers the vulnerability. If not applicable set to "N/A".\n\n'
prompt += "Code:\n```c\n" + code + "\n```"

print(f"Prompt: {len(prompt)} chars")
resp = client.chat.completions.create(
    model="moonshotai/Kimi-K2.7-Code",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2,
    max_tokens=800,
)
m = resp.choices[0]
content = m.message.content
print(f"Finish: {m.finish_reason}")
print(f"Usage: {resp.usage}")
print(f"Content: {repr(content[:300])}")

if content and content.strip():
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.DOTALL)
    jm = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if jm:
        try:
            result = json.loads(jm.group())
            rl = len(result.get("reasoning", ""))
            pl = len(result.get("poc", ""))
            print(f"JSON parsed OK: reasoning={rl} chars, poc={pl} chars")
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            print(f"First 200 chars: {cleaned[:200]}")
    else:
        print(f"No JSON found. First 500 chars: {content[:500]}")
else:
    print("EMPTY CONTENT")

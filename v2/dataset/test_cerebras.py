#!/usr/bin/env python3
"""Test Cerebras API with zai-glm-4.7 for vulnerability analysis."""
import json, time, os, re
from cerebras.cloud.sdk import Cerebras

client = Cerebras(api_key="csk-93f6epcpd895w4mnhm5y2c4h5pxjjyc8kwfvcnmv3nnfnem6")

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

print("Testing Cerebras zai-glm-4.7...", flush=True)
t0 = time.time()

resp = client.chat.completions.create(
    model="zai-glm-4.7",
    messages=[{"role": "system", "content": "You are a security analyst. Output only valid JSON."},
              {"role": "user", "content": PROMPT}],
    max_completion_tokens=2000,
    temperature=0.3,
)

t1 = time.time()
content = resp.choices[0].message.content or ""
print(f"Time: {t1-t0:.1f}s")
print(f"Content length: {len(content)} chars")
print(f"Tokens in: {resp.usage.prompt_tokens}, out: {resp.usage.completion_tokens}")
print(f"Finish: {resp.choices[0].finish_reason}")
print(f"Preview: {content[:200]}")

# Try to parse JSON
cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.DOTALL)
jm = re.search(r"\{.*\}", cleaned, re.DOTALL)
if jm:
    try:
        result = json.loads(jm.group())
        print(f"\nJSON OK - reasoning: {len(result.get('reasoning',''))} chars, poc: {len(result.get('poc',''))} chars")
    except json.JSONDecodeError as e:
        print(f"\nJSON parse error: {e}")
else:
    print(f"\nNo JSON found in response")

import json
import time
import os
from openai import OpenAI
from tqdm import tqdm

# Ensure NVIDIA_NIM_KEY is in env
api_key = os.getenv("NVIDIA_NIM_KEY")
if not api_key:
    # Fallback to key used in previous successful runs
    api_key = "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"

client = OpenAI(api_key=api_key, base_url="https://integrate.api.nvidia.com/v1")

SYSTEM_PROMPT = "You are a senior security researcher. Analyze the code snippet for security vulnerabilities."
USER_PROMPT = """Analyze the following {lang} code for security vulnerabilities. 
Identify: 
1. The vulnerability (and CWE ID)
2. The root cause analysis
3. A realistic attack scenario
4. The secure fix and the patched code.

Return the analysis as a single JSON object.

Code:
```{lang}
{code}
```"""

# Load silver samples - using first 3 for test
with open('v2/inputs/datasets/silver_samples_scanned.jsonl', 'r') as f:
    samples = [json.loads(line) for line in f][:3]

output_file = "v2/inputs/datasets/teacher_generated_data_test.jsonl"

print(f"Generating teacher data for {len(samples)} test samples using GLM-5.2...")

with open(output_file, 'w') as out_f:
    for s in tqdm(samples):
        code = s['messages'][1]['content']
        lang = s.get('_meta', {}).get('language', 'c')
        
        success = False
        retries = 3
        while not success and retries > 0:
            try:
                response = client.chat.completions.create(
                    model="z-ai/glm-5.2", 
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": USER_PROMPT.format(lang=lang, code=code)}
                    ],
                    temperature=0.2,
                    max_tokens=800
                )
                
                analysis = response.choices[0].message.content
                sft_entry = {
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": USER_PROMPT.format(lang=lang, code=code)},
                        {"role": "assistant", "content": analysis}
                    ]
                }
                out_f.write(json.dumps(sft_entry) + "\n")
                print(f"\nAnalysis sample generated.")
                success = True
            except Exception as e:
                print(f"\nError: {e}. Retrying... ({retries} left)")
                time.sleep(10)
                retries -= 1

print(f"\nGeneration complete. Test data saved to {output_file}")
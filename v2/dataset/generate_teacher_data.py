import json
import time
import os
from openai import OpenAI
from tqdm import tqdm

# NVIDIA NIM base URL
client = OpenAI(api_key=os.getenv("NVIDIA_NIM_KEY") or "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", base_url="https://integrate.api.nvidia.com/v1")

# Load silver samples
with open('v2/inputs/datasets/silver_samples_scanned.jsonl', 'r') as f:
    samples = [json.loads(line) for line in f]

output_file = "v2/inputs/datasets/teacher_generated_data.jsonl"
processed_ids = set()

if os.path.exists(output_file):
    with open(output_file, 'r') as f:
        for line in f:
            try: processed_ids.add(json.loads(line)['messages'][1]['content'][:50])
            except: pass

remaining = [s for s in samples if s['messages'][1]['content'][:50] not in processed_ids]
batch_size = 20
to_process = remaining[:batch_size]

print(f"Batch mode: {len(to_process)} samples. (Processed: {len(processed_ids)}/{len(samples)})")

with open(output_file, 'a') as out_f:
    for s in tqdm(to_process):
        code = s['messages'][1]['content']
        lang = s.get('_meta', {}).get('language', 'c')
        
        try:
            response = client.chat.completions.create(
                model="deepseek-ai/deepseek-v4-pro",
                messages=[
                    {"role": "system", "content": "You are a senior security researcher."},
                    {"role": "user", "content": f"Analyze the following {lang} code for security vulnerabilities. Return as JSON.\n```{lang}\n{code}\n```"}
                ],
                temperature=0.2, max_tokens=1000
            )
            
            sft_entry = {
                "messages": [
                    {"role": "system", "content": "You are a senior security researcher."},
                    {"role": "user", "content": f"Analyze the following {lang} code for security vulnerabilities. Return as JSON.\n```{lang}\n{code}\n```"},
                    {"role": "assistant", "content": response.choices[0].message.content}
                ]
            }
            out_f.write(json.dumps(sft_entry) + "\n")
            out_f.flush()
        except Exception as e:
            print(f"\nError: {e}")
            break

print(f"\nBatch complete. Samples left: {len(remaining) - batch_size}")
from transformers import AutoModelForCausalLM
import torch

model = AutoModelForCausalLM.from_pretrained(
    "Qwen/Qwen3.5-9B",
    torch_dtype=torch.bfloat16,
    device_map="auto",
    low_cpu_mem_usage=True,
)

for name, _ in model.named_parameters():
    if "layers.0" in name and "q_proj" in name:
        print("Base model key:", name)
        break

print("Model modules:", list(model.model._modules.keys())[:10])

import json
with open("/home/zeus/v2/model/rakshak_sft/adapter_config.json") as f:
    cfg = json.load(f)

import re
# Check if adapter expects language_model prefix
print("Adapter base model:", cfg.get("base_model_name_or_path"))
print("Target modules:", cfg.get("target_modules"))

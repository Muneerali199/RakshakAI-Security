"""Rename adapter keys: remove 'language_model.' prefix to match base model structure."""
import os, json, shutil
from safetensors.torch import load_file, save_file

src = "/home/zeus/v2/model/rakshak_sft/adapter_model.safetensors"
dst = "/home/zeus/v2/model/rakshak_sft_fixed/adapter_model.safetensors"

os.makedirs(os.path.dirname(dst), exist_ok=True)

print("Loading safetensors...")
state = load_file(src)
print(f"Loaded {len(state)} tensors")

# Check keys with language_model prefix
has_lm = any("language_model" in k for k in state)
print(f"Has language_model prefix: {has_lm}")

new_state = {}
for k, v in state.items():
    new_k = k.replace("language_model.", "")
    new_state[new_k] = v

print(f"Renamed: old_prefix={len(state)}, new_prefix={len(new_state)} tensors")

save_file(new_state, dst)
print(f"Saved fixed adapter to {dst} ({os.path.getsize(dst)/1e6:.1f} MB)")

# Copy other files
src_dir = os.path.dirname(src)
dst_dir = os.path.dirname(dst)
for f in ["adapter_config.json", "config.json", "tokenizer.json", "tokenizer_config.json", "chat_template.jinja"]:
    sp = os.path.join(src_dir, f)
    if os.path.exists(sp):
        shutil.copy2(sp, os.path.join(dst_dir, f))
        print(f"Copied {f}")

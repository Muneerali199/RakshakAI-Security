"""
RakshakAI v3 — Modal Inference Server
Serves the fine-tuned Qwen2.5-Coder-7B-Instruct + LoRA adapter
behind an OpenAI-compatible endpoint for drop-in CLI integration.

Usage:
    modal deploy v2/modal_infer.py        # deploy to production
    modal run v2/modal_infer.py           # run once for testing

When the adapter exists on HuggingFace, the endpoint loads it
automatically. Until then, it serves the base model (still useful
for benchmarking but with no security fine-tuning).
"""
from __future__ import annotations

import os
from pathlib import Path

import modal

HF_TOKEN = os.environ.get("HF_TOKEN", "")
BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
ADAPTER_REPO = "Muneerali199/rakshak-cwe-v3"  # LoRA adapter pushed by training

app = modal.App("rakshakai-v3-infer")

image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 accelerate==1.2.1 "
        "peft==0.14.0 bitsandbytes==0.45.0 "
        "huggingface-hub==0.27.1 hf_transfer sentencepiece==0.2.0 "
        "fastapi pydantic uvicorn",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HUB_DISABLE_SYMLINKS_WARNING": "1"})
)


@app.cls(
    image=image,
    gpu="T4",
    timeout=600,
    scaledown_window=600,
    secrets=[],
    allow_concurrent_inputs=2,
    container_idle_timeout=600,
)
class RakshakInference:
    def __init__(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel

        os.environ["HF_TOKEN"] = HF_TOKEN

        print("Loading base model (4-bit)...")
        from transformers import BitsAndBytesConfig
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL, trust_remote_code=True, padding_side="right",
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token

        self.model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )

        try:
            print(f"Loading adapter from {ADAPTER_REPO}...")
            from peft import PeftModel
            self.model = PeftModel.from_pretrained(self.model, ADAPTER_REPO)
            print(f"Adapter loaded — model is RakshakAI fine-tune")
        except Exception as e:
            print(f"Adapter not found ({e}) — serving base model")

        self.model.eval()
        print("Model ready")

    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        import torch

        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                pad_token_id=self.tokenizer.pad_token_id,
            )
        return self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)

    def _build_prompt(self, messages: list[dict]) -> str:
        """Build a chat-formatted prompt from OpenAI-style messages."""
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                parts.append(f"<|im_start|>system\n{content}<|im_end|>")
            elif role == "user":
                parts.append(f"<|im_start|>user\n{content}<|im_end|>")
            elif role == "assistant":
                parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")
        parts.append("<|im_start|>assistant\n")
        return "\n".join(parts)

    @modal.web_endpoint(method="POST", docs=True, label="chat-completions")
    async def chat_completions(self, body: dict):
        """OpenAI-compatible /v1/chat/completions endpoint."""
        import asyncio

        messages = body.get("messages", [])
        max_tokens = body.get("max_tokens", 4096)
        temperature = body.get("temperature", 0.3)
        stream = body.get("stream", False)

        prompt = self._build_prompt(messages)

        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(
            None, self.generate, prompt, max_tokens, temperature,
        )

        return {
            "id": "rak-1",
            "object": "chat.completion",
            "created": 0,
            "model": ADAPTER_REPO,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": -1, "completion_tokens": -1, "total_tokens": -1},
        }


@app.local_entrypoint()
def main():
    print("Deploy with: modal deploy v2/modal_infer.py")
    print("Test with:  modal run v2/modal_infer.py")
    print("Once deployed, update the endpoint URL in llm.py")

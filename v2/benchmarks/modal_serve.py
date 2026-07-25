import os, re
import modal
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

web_app = FastAPI()
volume = modal.Volume.from_name("rakshak-cache", create_if_missing=True)
MODEL_DIR = "/cache"

image = (
    modal.Image.from_registry("pytorch/pytorch:2.2.0-cuda12.1-cudnn8-runtime")
    .run_commands(
        "pip install torch==2.2.0 torchvision==0.17.0 'transformers>=4.45.0,<5.0.0' 'peft>=0.14.0,<0.20.0' 'accelerate>=0.33.0' 'bitsandbytes>=0.40.0' 'huggingface_hub>=0.24.0' sentencepiece protobuf 'fastapi>=0.115.0' 'pydantic>=2.0.0'",
    )
    .env({"HF_HOME": f"{MODEL_DIR}/hf", "HF_HUB_ENABLE_HF_TRANSFER": "0"})
)

app = modal.App("rakshak-api", image=image)

class AnalyzeRequest(BaseModel):
    code: str
    language: str = "python"
    max_tokens: int = 512

class AnalyzeResponse(BaseModel):
    cwe: str
    raw_output: str
    duration_s: float

@app.cls(
    gpu="A10G",
    timeout=300,
    scaledown_window=600,
    volumes={MODEL_DIR: volume},
    secrets=[modal.Secret.from_name("hf-token")],
    allow_concurrent_inputs=8,
    container_idle_timeout=300,
)
class RakshakModel:
    def __init__(self):
        self.model = None
        self.tokenizer = None

    @modal.enter()
    def load(self):
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel

        os.makedirs(f"{MODEL_DIR}/hf", exist_ok=True)
        hf_token = os.environ["HF_TOKEN"]

        bnb = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(
            "Qwen/Qwen2.5-Coder-14B-Instruct", trust_remote_code=True,
        )
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

        print("Loading base model...")
        base = AutoModelForCausalLM.from_pretrained(
            "Qwen/Qwen2.5-Coder-14B-Instruct",
            quantization_config=bnb, device_map="auto",
            torch_dtype=torch.bfloat16, trust_remote_code=True,
        )
        print("Loading LoRA adapter...")
        adapter_path = snapshot_download(
            "Muneerali199/rakshak-cwe-14b-sft-step375", token=hf_token,
        )
        self.model = PeftModel.from_pretrained(base, adapter_path)
        self.model.eval()
        print("Model ready!")

    def analyze(self, code: str, language: str, max_tokens: int = 512) -> dict:
        import torch, time
        prompt = (
            f"Analyze the following {language} code for security vulnerabilities. "
            f"Identify CWE, severity, root cause, attack scenario, and secure fix.\n"
            f"```{language}\n{code}\n```"
        )
        msgs = [{"role": "user", "content": prompt}]
        inputs = self.tokenizer.apply_chat_template(
            msgs, return_tensors="pt", add_generation_prompt=True
        ).to(self.model.device)
        ts = time.time()
        with torch.no_grad():
            outputs = self.model.generate(
                inputs, max_new_tokens=max_tokens,
                temperature=0.1, do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
            )
        raw = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
        dur = time.time() - ts
        m = re.search(r"CWE-(\d+)", raw, re.IGNORECASE)
        cwe = f"CWE-{m.group(1)}" if m else ""
        return {"cwe": cwe, "raw_output": raw, "duration_s": round(dur, 2)}

    @modal.web_endpoint(method="POST", docs=True)
    def analyze_endpoint(self, req: AnalyzeRequest) -> AnalyzeResponse:
        try:
            result = self.analyze(req.code, req.language, req.max_tokens)
            return AnalyzeResponse(**result)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @modal.web_endpoint(method="GET")
    def health(self) -> dict:
        return {"status": "ok", "model": "rakshak-cwe-14b-sft-step375"}

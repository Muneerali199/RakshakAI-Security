---
language:
- en
- code
license: apache-2.0
library_name: transformers
tags:
- cybersecurity
- vulnerability-detection
- code-security
- llama-cpp
- qwen2.5-coder
- security
- cwe
- static-analysis
- code-review
pipeline_tag: text-generation
base_model: Qwen/Qwen2.5-Coder-7B-Instruct
model-index:
- name: RakshakAI-v2
  results:
  - task:
      type: text-generation
      name: Vulnerability Detection & Remediation
    dataset:
      type: security_benchmark
      name: RakshakAI Security Benchmark v1
    metrics:
      - type: cwe-accuracy
        value: TBD
        name: CWE Classification Accuracy
      - type: detection-f1
        value: TBD
        name: Vulnerability Detection F1
      - type: fix-success-rate
        value: TBD
        name: Secure Fix Success Rate
---
<div align="center">
  <img src="https://raw.githubusercontent.com/Muneerali1995/RakshakAI/main/docs/logo.svg" width="120" alt="RakshakAI logo">
  <h1>RakshakAI v2 (रक्षक AI)</h1>
  <p><em>Security-Specialized Code LLM — Vulnerability Detection, Root Cause Analysis, and Secure Fix Generation</em></p>
  <p><strong>रक्षक</strong> (Rakshak) means "Protector" in Sanskrit. Your code's first line of defense.</p>
</div>

---

## Model Overview

RakshakAI v2 is a **security-specialized language model** fine-tuned from Qwen2.5-Coder-7B-Instruct. It detects software vulnerabilities, classifies them by CWE, explains the root cause, describes attack scenarios, and generates secure fixes — all in a single forward pass.

**Key differentiator:** RakshakAI v2 produces a structured 9-field security report per finding, unlike general-purpose code models that output free-form text. This makes it suitable for automated CI/CD pipelines, IDE integrations, and security auditing workflows.

| Property | Value |
|----------|-------|
| Base model | [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) |
| Fine-tuning method | QLoRA (NF4 double-quant, r=64, rsLoRA) |
| Parameters (base) | 7.6B |
| Parameters (trainable) | ~330M (LoRA adapters) |
| Sequence length | 4,096 tokens |
| Precision | bf16 (base), 4-bit NFQ (serving) |
| Hardware | 1× AMD MI300X (ROCm 6.2) |
| License | Apache 2.0 |

---

## Security Capabilities

RakshakAI v2 is trained on a curated corpus of real-world CVE-bearing code, vulnerability datasets, and security benchmarks:

| Capability | Supported |
|------------|-----------|
| Vulnerability detection | ✅ |
| CWE classification | ✅ (682 CWE classes) |
| Severity assessment | ✅ |
| Root cause explanation | ✅ |
| Attack scenario generation | ✅ |
| Secure fix suggestion | ✅ |
| Patched code generation | ✅ |
| Multi-language support | ✅ (13 languages) |
| PR / diff review | ✅ |
| Batch scanning | ✅ |

---

## Supported Languages

The training corpus covers 13 programming languages with real-world CVE samples:

| Language | Coverage in training |
|----------|---------------------|
| Python | High |
| C | High |
| C++ | High |
| Java | Medium |
| JavaScript | Medium |
| TypeScript | Medium |
| Go | Medium |
| Rust | Low–Medium |
| PHP | Medium |
| C# | Low–Medium |
| Ruby | Low |
| Swift | Low |
| Kotlin | Low |

---

## Intended Use Cases

| Use Case | Description |
|----------|-------------|
| **CI/CD security scanning** | Automatic PR review in GitHub Actions / GitLab CI |
| **IDE integration** | Real-time vulnerability detection in VS Code |
| **Security auditing** | Root cause analysis and fix recommendations for penetration testing reports |
| **Developer education** | Explanations of why code patterns are insecure and how to fix them |
| **Code review augmentation** | Automated first-pass security review before human review |
| **Vulnerability research** | CWE classification and severity assessment for CVE analysis pipelines |

---

## Limitations

1. **Not a formal verification tool.** RakshakAI v2 produces probabilistic outputs. It may miss vulnerabilities (false negatives) or flag benign code (false positives).
2. **Base model limitations.** As a fine-tune of Qwen2.5-Coder-7B-Instruct, it inherits the base model's knowledge cutoff, tokenizer biases, and reasoning constraints.
3. **Context window.** The 4,096-token limit means very large files or long codebases must be chunked.
4. **Language coverage.** Languages with fewer training samples (Ruby, Swift, Kotlin, C#) have lower accuracy than Python, C, and C++.
5. **No exploit generation.** The model is trained to describe attack scenarios at a conceptual level, not to generate working exploits.
6. **Adversarial robustness.** The model has not been adversarially hardened against prompt injection or evasion attacks.

---

## Training Dataset

| Dataset | Records | Source | CWEs |
|---------|---------|--------|------|
| OSV.dev (filtered, deduped) | 96,000+ | Open Source Vulnerabilities database | 600+ |
| NVD (filtered) | CVE-linked | National Vulnerability Database | 140+ |
| OWASP Benchmark | ~1,200 | OWASP Benchmark project | 11 |
| BigVul (converted) | 121,709 | C/C++ real-world CVEs | 140+ |
| Devign (converted) | 21,853 | C functions, vulnerable/benign | 140+ |
| PrimeVul (converted) | 218,296 | C/C++ expert-verified | 140+ |
| SecurityEval | 121 | Python/C/C++ security examples | 13 |

**Training pipeline:** Raw → Clean → MinHash Dedup → Per-CWE Balance (cap: 80) → Instruct format → Pack at 4096 tokens.

| Split | Records | Tokens (approximate) |
|-------|---------|---------------------|
| Train (SFT) | 58,312 | ~239M |
| Validation | 2,748 | ~11M |
| Test | 5,459 | ~22M |

---

## Training Methodology

### Phase A: Real-World CVE Fine-Tuning
- **Data:** BigVul + Devign + PrimeVul instruction pairs
- **Goal:** Teach the model to recognize real-world vulnerability patterns
- **Steps:** 4,000 | **LR:** 2.0e-4 | **Eff. batch:** 32

### Phase B: Multi-Language + Patch Learning
- **Data:** SecurityEval + expanded multi-language samples
- **Goal:** Generalize across languages and code styles
- **Steps:** 3,000 | **LR:** 1.0e-4 | **Eff. batch:** 36

### Phase C: Synthetic Instruction Augmentation
- **Data:** Synthetic vulnerability→fix instruction pairs
- **Goal:** Improve instruction following and structured output adherence
- **Steps:** 2,500 | **LR:** 1.0e-4 | **Eff. batch:** 32

### QLoRA Configuration
- Quantization: NF4 double-quant (4-bit base)
- LoRA rank: 64, alpha: 128, dropout: 0.05
- Target modules: `all-linear`
- Adapters also trained on: `lm_head`, `embed_tokens`
- Optimizer: paged AdamW 8-bit
- Flash attention: enabled
- Sample packing: enabled
- NEFTune noise: α=5

---

## Benchmark Results

*Results will be populated after the first training run. The benchmark suite includes:*

| Benchmark | Samples | Languages | CWEs | Status |
|-----------|---------|-----------|------|--------|
| SecurityEval | 121 | Python, C, C++ | 13 | ✅ Locked |
| RakshakAI Security Benchmark | 31 | 7 languages | 26 | ✅ Locked |
| OWASP Benchmark | 1,200+ | Java | 11 | 🔄 Integration planned |
| PrimeVul test split | 5,000+ | C, C++ | 140+ | 🔄 Integration planned |

---

## Quick Start

```bash
# Install
pip install transformers torch accelerate

# Load model
from transformers import AutoModelForCausalLM, AutoTokenizer

model = AutoModelForCausalLM.from_pretrained(
    "Muneerali1995/RakshakAI-v2",
    device_map="auto",
    torch_dtype=torch.bfloat16
)
tokenizer = AutoTokenizer.from_pretrained("Muneerali1995/RakshakAI-v2")

# Scan code
code = """
def get_user(uid):
    return db.execute(f'SELECT * FROM users WHERE id = {uid}').fetchone()
"""

messages = [
    {"role": "user", "content": f"Analyze this code for security vulnerabilities:\n```python\n{code}\n```"}
]
inputs = tokenizer.apply_chat_template(messages, return_tensors="pt").to(model.device)
outputs = model.generate(inputs, max_new_tokens=512)
print(tokenizer.decode(outputs[0], skip_special_tokens=True))
```

---

## Citation

```bibtex
@software{rakshakai_v2,
  author       = {Muneer Ali and RakshakAI Contributors},
  title        = {RakshakAI v2: Security-Specialized Code LLM},
  year         = {2026},
  publisher    = {GitHub},
  url          = {https://github.com/Muneerali1995/RakshakAI},
  note         = {Fine-tuned from Qwen2.5-Coder-7B-Instruct}
}
```

---

## Acknowledgements

- [Qwen Team](https://huggingface.co/Qwen) for the excellent Qwen2.5-Coder base model
- [Axolotl](https://github.com/OpenAccess-AI-Collective/axolotl) for the training framework
- AMD for the AMD Developer Cloud credits and ROCm support
- The open-source security community for the datasets (OSV.dev, NVD, BigVul, Devign, PrimeVul, SecurityEval)

<div align="center">
  <strong>रक्षक AI — Made in India 🇮🇳</strong>
  <br>
  <em>Your code's first line of defense.</em>
</div>

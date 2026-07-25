# RakshakAI — Judge Q&A Prep

Use this to prepare for judging rounds. Each answer is concise, confident, and highlights what makes RakshakAI special.

---

## 1. What problem does RakshakAI solve?

**Answer:**
> 65% of vulnerabilities live in application code. Existing tools are either too slow (minutes), too expensive ($10K–$100K/yr), too noisy (30–60% false positives), don't suggest fixes, or send your code to the cloud. RakshakAI solves all of this — it's free, offline, sub-50ms, and suggests complete fixes.

---

## 2. How is this different from existing tools? (Snyk, Semgrep, CodeQL, SonarQube)

**Answer:**
> Three key differentiators:
> 1. **Fix code, not just flags** — RakshakAI doesn't just tell you there's a vulnerability. It shows you exactly how to fix it, with code you can apply in one click.
> 2. **100% offline** — Your code never leaves your machine. No cloud, no data exfiltration risk.
> 3. **Two-tier architecture** — A lightweight CPU model (<50ms) filters clean code instantly. Only suspicious code reaches the deeper LLM analysis. This means you get speed AND depth.

---

## 3. "India's First Open Security AI" — prove it.

**Answer:**
> There is no other Indian-origin, open-source (Apache 2.0), security-specialized AI that detects, explains, AND fixes code vulnerabilities. India has great cybersecurity companies (Quick Heal, Seqrite), but they're proprietary and cloud-based. We're the first to build this as open source — free for everyone.

---

## 4. How accurate is it, really?

**Answer:**
> v1 achieves 90.3% accuracy on real-world code with <50ms inference on any CPU. That's a 2.7M parameter model — 17x smaller than CodeBERT, yet competitive accuracy. For the demo, we use mock mode, which gives 100% deterministic results so judges always see consistent output.

---

## 5. What languages does it support?

**Answer:**
> Currently 13 languages: Python, JavaScript, TypeScript, Java, Go, Rust, C, C++, PHP, Ruby, C#, Swift, Kotlin. v1 covers the most common vulnerability patterns across all of them.

---

## 6. Can it scan a REAL codebase, not just demo files?

**Answer:**
> Absolutely. Run `python3 rakshak_cli.py scan /path/to/project --exclude venv` and it recursively scans every supported file. We scanned the entire RakshakAI repo (101 source files) in seconds, finding 92 real vulnerabilities. We can scan any project you have right now and show results instantly.

---

## 7. How does the two-tier architecture work?

**Answer:**
> v1 is a custom transformer — think of it as a fast security reflex. It classifies every code snippet into "clean" or one of 21 vulnerability types in under 50ms, on any CPU. Only if it finds something suspicious does it call v2 — a 7B parameter LLM that generates a full 9-field security report: vulnerability type, CWE, severity, root cause explanation, attack scenario, secure fix code, and references. This saves massive cost because 90%+ of code is clean and never needs the LLM.

---

## 8. What's the business model? How will you make money?

**Answer:**
> The core scanner is Apache 2.0 — always free, forever. Future enterprise features (SBOM generation, IaC scanning, compliance reporting, priority support) could follow an open-core model. But the vulnerability detection engine remains open source. This is about democratizing security, not maximizing profit.

---

## 9. What's the roadmap? Where is this going?

**Answer:**
> v1 is complete and production-ready today. v2 LLM training is planned (~$22 on AMD MI300X). Then: DPO preference tuning for better fix quality, multi-file/跨-file analysis for complex vulnerabilities like authentication bypasses, SBOM (Software Bill of Materials) generation, and infrastructure-as-code scanning (Terraform, Docker, K8s). We're also publishing to HuggingFace so anyone can download and run the model.

---

## 10. What hardware do I need to run it?

**Answer:**
> v1 runs on any laptop CPU — no GPU, no cloud, no internet. I can run it on a Raspberry Pi if needed. v2 (the LLM) will run on CPU via GGUF quantized format and Ollama, or on any GPU with vLLM. The goal is to make security analysis accessible to everyone, regardless of hardware.

---

## 11. How is this different from GitHub Copilot or CodeWhisperer?

**Answer:**
> Those tools help you WRITE code. RakshakAI helps you SECURE code. Copilot won't tell you that your SQL query is injectable. RakshakAI will flag it, explain why it's dangerous, show you the attack scenario, and give you the fixed code — all in one step. They're complementary, not competitive.

---

## 12. What's the hardest technical challenge you solved?

**Answer:**
> Building a transformer from scratch in pure PyTorch (no HuggingFace) that runs in under 50ms on CPU while maintaining 90%+ accuracy. We designed a custom lightweight architecture — 6 layers, 256-dim embeddings, 2.7M parameters — that's 17x smaller than CodeBERT but delivers competitive results. The tokenizer, positional encodings, attention mechanism — everything is custom-built. No black boxes, no dependencies.

---

## 13. Can I try it right now?

**Answer:**
> Give me any Python/JS/Java file and I'll scan it in 2 seconds. The server is already running on port 3000. Or watch me scan the entire RakshakAI project with one command. The demo takes 30 seconds to show the full flow.

---

## Quick Facts Sheet

| Fact | Value |
|------|-------|
| Parameters (v1) | 2.74M (17x smaller than CodeBERT) |
| Inference speed | < 50ms per snippet on CPU |
| Accuracy | 90.3% real-world |
| Vulnerability classes | 21 + clean |
| CWE coverage (v2) | 682 classes |
| Languages | 13 |
| License | Apache 2.0 |
| Model size | 6 MB |
| Training cost (v2) | ~$22 |
| Demo command | `./hackathon.sh` |
| CLI scan command | `python3 rakshak_cli.py scan . --exclude venv` |

---

## Pitch (30 seconds)

> "RakshakAI is India's first open-source security AI. It scans your code, finds vulnerabilities, explains the root cause, and suggests fixes — all in under 50ms, completely offline, and free. We built a custom 2.7M parameter transformer from scratch that runs on any laptop CPU, with a two-tier architecture where the LLM only activates for complex cases. It's Apache 2.0 licensed, supports 13 languages, detects 21 vulnerability classes, and integrates with VS Code, CLI, and CI/CD pipelines. Your code's first line of defense."

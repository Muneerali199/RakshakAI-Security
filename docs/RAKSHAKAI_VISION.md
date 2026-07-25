# RakshakAI — Vision

> An open cybersecurity AI platform focused on **vulnerability detection, remediation, secure code generation, repository auditing, and developer education.**

---

## Why RakshakAI exists

Software vulnerabilities cost the global economy **trillions of dollars annually**. Yet most developers ship code without any security review. Existing tools are either:

- **Proprietary and expensive** (Snyk, GitHub Advanced Security) — out of reach for individual developers and small teams
- **Complex to configure** (CodeQL, Semgrep) — require dedicated security expertise
- **Limited in scope** (linters, formatters) — detect shallow patterns but miss logical flaws, business logic vulnerabilities, and insecure API usage

RakshakAI's mission is to **democratize security analysis** — make it free, open-source, and accessible to every developer regardless of team size, budget, or geography.

---

## What RakshakAI v2 is

RakshakAI v2 is a **security-specialized language model** — a fine-tuned version of Qwen2.5-Coder-7B-Instruct that produces structured security reports with vulnerability classification, root cause explanation, attack scenario description, and secure fix suggestions.

| Aspect | Detail |
|--------|--------|
| **What it is** | Fine-tuned instruction-following LLM for security code analysis |
| **What it is NOT** | A foundation model, a pre-trained-from-scratch model, or a frontier AI system |
| **Base technology** | Qwen2.5-Coder-7B-Instruct (open-source coding LLM) |
| **Fine-tuning method** | QLoRA (NF4 double-quant) — ~330M trainable parameters on top of 7.6B frozen base |
| **Output** | Structured 9-field JSON: vulnerability, CWE, severity, confidence, root cause, attack scenario, secure fix, patched code, references |
| **License** | Apache 2.0 — free to use, modify, and distribute |

---

## Platform components

RakshakAI is not just a model — it is a platform with multiple access points:

```
                 ┌──────────────────────┐
                 │   RakshakAI Model    │
                 │  (fine-tuned 7B LLM) │
                 └──────────┬───────────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                   │
     ┌────┴────┐      ┌────┴────┐       ┌──────┴──────┐
     │ VS Code │      │ GitHub  │       │  FastAPI    │
     │ Extension│     │ Action  │       │  Server     │
     └─────────┘      └─────────┘       └─────────────┘
                                            │
                               ┌────────────┼────────────┐
                               │            │            │
                          ┌────┴───┐  ┌────┴───┐  ┌─────┴─────┐
                          │ Ollama │  │  CLI   │  │  vLLM     │
                          │ (local)│  │        │  │ (prod)    │
                          └────────┘  └────────┘  └───────────┘
```

### Access points

| Component | Description | Status |
|-----------|-------------|--------|
| **VS Code extension** | Real-time vulnerability detection in editor | 📝 Planned |
| **GitHub Action** | Automated PR security review | 📝 Planned |
| **FastAPI server** | REST API for programmatic access | 🛠️ Built (pre-training) |
| **CLI tool** | Command-line scanning, review, generation | 🛠️ Built (pre-training) |
| **Ollama integration** | Local inference on laptop/desktop | 📝 Planned |
| **vLLM deployment** | Production-scale serving | 📝 Planned |

---

## Vision and roadmap

### Near term (v2, 2026 H2)

- [x] Dataset pipeline (96K+ curated CVE samples)
- [x] Training config (Axolotl, QLoRA, Phase A/B/C)
- [x] Benchmark (31 locked samples, 26 CWEs)
- [ ] First training run (blocked: GPU availability)
- [ ] Model release (HuggingFace, Apache 2.0)
- [ ] VS Code extension MVP
- [ ] GitHub Action MVP
- [ ] Public demo / API

### Medium term (v2.x, 2027 H1)

- [ ] 14B ablation study
- [ ] Preference tuning (DPO) for fix quality
- [ ] Extended benchmark (100+ samples, 50+ CWEs)
- [ ] Adversarial robustness evaluation
- [ ] Multi-repo scanning (org-level audit)
- [ ] CI/CD plugin for GitLab, Jenkins
- [ ] Security dashboard (web UI)

### Long term (v3, 2027+)

- [ ] Multi-file / cross-function vulnerability analysis
- [ ] Context-aware scanning (whole-repo understanding)
- [ ] Automated exploitability assessment
- [ ] Integration with SBOM and dependency analysis
- [ ] Native support for infrastructure-as-code (Terraform, Kubernetes)
- [ ] Security education: interactive fix explanations for developers
- [ ] Community-driven CWE coverage expansion

---

## Design principles

1. **Open source first.** All model weights, code, and documentation are Apache 2.0. No paywalls, no proprietary tiers.
2. **Local-first.** The model runs on your hardware — no data leaves your machine. The VS Code extension and CLI operate fully offline.
3. **Practical over perfect.** A simple 9-field structured finding that every developer can understand is better than a complex report that requires a security expert to interpret.
4. **Complement, don't replace.** RakshakAI augments human reviewers and existing SAST tools. It does not replace security audits or responsible disclosure processes.
5. **India-built, global reach.** Developed with AMD MI300X hardware and open ROCm ecosystem, demonstrating that world-class security AI can be built outside the major cloud AI platforms.

---

## Competitive landscape

RakshakAI v2 occupies a specific niche: **open-source, security-specialized, structured-output LLMs for code analysis.**

| Tool | Type | Open source | Generates fixes | Structured output | Runs offline |
|------|------|-------------|-----------------|-------------------|-------------|
| **RakshakAI v2** | Fine-tuned LLM | ✅ Apache 2.0 | ✅ Patched code | ✅ 9 fields | ✅ GGUF / Ollama |
| **RakshakAI v1** | Custom transformer | ✅ Apache 2.0 | ❌ | ❌ 21-class | ✅ CPU |
| **Semgrep** | AST pattern matcher | ✅ LGPL | ❌ | ✅ Rule-based | ✅ |
| **Bandit** | Python AST analyzer | ✅ Apache 2.0 | ❌ | ❌ Report | ✅ |
| **CodeQL** | QL query engine | ❌ (semantic code analysis engine is proprietary) | ❌ | ✅ SARIF | ✅ (CLI) |
| **Snyk Code** | Proprietary LLM | ❌ | ❌ | ✅ | ❌ |
| **GitHub Copilot** | General code LLM | ❌ | ✅ (generic) | ❌ Free text | ❌ |
| **GPT-4 / Claude** | Frontier LLM | ❌ | ✅ | ❌ Free text | ❌ |

---

## Call to action

RakshakAI is built for the community, by the community. If you believe that security analysis should be free and open for every developer:

- **Use it** — run the model locally with Ollama, integrate the CLI into your workflow
- **Contribute** — add CWE coverage, improve the benchmark, fix bugs, write documentation
- **Share** — tell your team, post about it, write a blog, give a talk at your local OWASP chapter
- **Build** — create integrations, extensions, plugins for your favorite tools

The code is at **[github.com/Muneerali1995/RakshakAI](https://github.com/Muneerali1995/RakshakAI)**. Licensed under Apache 2.0.

---

> **रक्षक** — *Protector.* Your code's first line of defense.
>
> Made in India 🇮🇳

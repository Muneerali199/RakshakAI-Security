# RakshakAI v2 — Open Source Launch Strategy

**Target launch date:** TBD (after first training run completes)
**Product:** RakshakAI v2 — Security-specialized coding LLM (Apache 2.0)

---

## Launch channels

### 1. GitHub Launch

**Action:** Create v2.0.0 release on [github.com/Muneerali1995/RakshakAI](https://github.com/Muneerali1995/RakshakAI)

**Release assets:**
- Source code (tagged)
- Pre-built AWQ 4-bit model (via HuggingFace)
- Pre-built GGUF Q5_K_M (via HuggingFace)
- Docker image (GHCR)
- CLI binary (optional)

**Release notes structure:**
```markdown
## RakshakAI v2.0.0 — Security-Specialized Code LLM

### What's new
- v2 LLM: fine-tuned Qwen2.5-Coder-7B-Instruct with QLoRA
- Structured 9-field security reports (vulnerability, CWE, severity, root cause, fix, patch)
- 682 CWE classes, 13 languages
- 96,000+ real-world CVE samples in training

### Quick start
...

### Changelog
...
```

**GitHub optimizations:**
- Update repository description and topics (`cybersecurity`, `vulnerability-detection`, `code-security`, `llm`, `rag`, `ai-security`)
- Enable GitHub Discussions for community Q&A
- Configure issue templates (bug report, feature request, model submission)
- Add `CONTRIBUTING.md` with setup instructions
- Add GitHub Action badges (CI, license, version)

### 2. Hugging Face Launch

**Action:** Upload model to [huggingface.co/Muneerali1995/RakshakAI-v2](https://huggingface.co/Muneerali1995/RakshakAI-v2)

**Uploads:**
- `pytorch_model.bin` (bf16 merged weights)
- `config.json` with RakshakAI-specific configuration
- AWQ quantized version (`Muneerali1995/RakshakAI-v2-AWQ`)
- GGUF quantized version (`Muneerali1995/RakshakAI-v2-GGUF`)
- Complete model card (see `v2/release/HUGGINGFACE_MODEL_CARD.md`)
- Inference widget configured

**HuggingFace optimizations:**
- Add to `text-generation` pipeline
- Add security-related tags
- Enable community tab for discussions
- Link GitHub repository and paper/technical report
- Enable inference API (if resources permit)

### 3. Reddit

**Subreddits (ranked by relevance):**

| Subreddit | Audience | Content angle |
|-----------|----------|---------------|
| r/MachineLearning | ML practitioners, researchers | Technical deep-dive: QLoRA fine-tuning process, dataset curation, benchmark results |
| r/LocalLLaMA | Self-hosted LLM enthusiasts | "Run a security AI on your laptop with Ollama" — GGUF deployment, performance |
| r/netsec | Security professionals | "Open-source vulnerability detection LLM" — benchmark comparison against SAST tools |
| r/cybersecurity | General security audience | "India's first open security AI" — broader impact story |
| r/programming | General developers | "AI that reviews your code for vulnerabilities" — practical usage, VS Code extension |

**Posting strategy:**
- Do NOT post to all subreddits simultaneously (1 post per 2–3 days)
- Adapt content to each audience (technical depth, framing)
- Respond to comments promptly (first 24 hours are critical)
- Coordinate with mods for any subreddit-specific rules
- Consider an AMA on r/MachineLearning or r/LocalLLaMA

### 4. Hacker News

**Action:** Submit Show HN post

**Title suggestions:**
- "Show HN: RakshakAI – Open-source security code LLM (Apache 2.0)"
- "Show HN: AI that reviews your code for vulnerabilities, runs locally on Ollama"
- "Show HN: RakshakAI v2 — Security-specialized 7B model, 682 CWEs"

**Content:**
- Direct, honest, no hype
- Include benchmark numbers (or state TBD with caveats)
- Link to GitHub, HuggingFace, demo
- Highlight what makes it different (structured output, Apache 2.0, MI300X, India-built)

**Timing:** Tuesday–Thursday, 9–11 AM ET (peak HN engagement)

### 5. Dev.to Article

**Title:** "Building RakshakAI v2: A Security-Specialized Code LLM from Data to Deployment"

**Structure:**
1. Why we built it (the gap in open-source security AI)
2. Dataset journey (OSV, NVD, BigVul, Devign, PrimeVul → 96K clean samples)
3. Training methodology (QLoRA, NF4, Phase A/B/C)
4. Benchmark & evaluation
5. Deployment (Ollama, vLLM, VS Code, GitHub Actions)
6. Lessons learned
7. Future roadmap

**Publishing:** Technical / tutorial style, ~15 min read, cross-post to Medium and LinkedIn

### 6. LinkedIn Launch

**Action:** Founders / core contributors post on their personal and company pages

**Content structure:**
- Part 1 (launch day): The story — why open-source cybersecurity AI matters
- Part 2 (day 3): Technical deep-dive — datasets, training, benchmarks
- Part 3 (day 7): Community — how to contribute, future plans

**Tags:** `#Cybersecurity` `#OpenSource` `#AI` `#LLM` `#DevSecOps` `#India` `#CodeSecurity`

### 7. Security Communities

| Community | Format | Contact |
|-----------|--------|---------|
| OWASP local chapters | Talk / demo | Contact Mumbai/Bangalore chapter leads |
| null (Open Security Community) | Slack post + meetup | Post in #projects channel |
| BSides events | Call for papers (CFP) | Submit to BSides Bangalore/Mumbai/Delhi |
| CyberLabs | Workshop | Partner for hands-on security AI workshop |
| DEF CON groups | Demo / lightning talk | Contact DC91xx India groups |

---

## Launch timeline

| Phase | Week | Activities |
|-------|------|------------|
| **Pre‑launch** | W-2 | Finalize model, run full benchmark, complete release checklist |
| | W-1 | Upload to HuggingFace, prepare release artifacts, draft all posts |
| **Launch week** | W0 | GitHub release → HN → Reddit (r/MachineLearning) → Dev.to → LinkedIn |
| **Post‑launch** | W+1 | Reddit (r/netsec, r/cybersecurity) → Security communities → OWASP talks |
| | W+2 | Community Q&A, iterate on issues, publish benchmark results |
| **Sustain** | W+3–6 | VS Code extension launch, GitHub Action marketplace, blog posts |

---

## Success metrics

| Metric | Target (30 days) |
|--------|------------------|
| GitHub stars | 500+ |
| HuggingFace downloads | 5,000+ |
| Reddit/HN upvotes | 200+ combined |
| Dev.to / Medium views | 10,000+ |
| Community contributors | 5+ external PRs |
| GitHub issues filed | 20+ (signals interest) |

---

## Risk mitigation

| Risk | Mitigation |
|------|------------|
| GPU shortage (ongoing blocker) | Publish weights, code, and docs now; training step in release checklist is "deferred" |
| Low engagement | Targeted posts per community (not spray-and-pray). Follow up with comments and DM community leads |
| Negative comparisons to GPT-4 / Claude | Set expectations: 7B open-source model, not frontier. Compare to equivalently sized models and SAST tools |
| Licensing questions | Apache 2.0 + documented data provenance in repo. Pre-emptively address in FAQ |

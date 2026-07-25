# RakshakAI — AI Security, Powered by ASI:One

---

## Slide 1: The Problem

**Every developer ships vulnerable code.**

- 84% of codebases have at least one open-source vulnerability
- Average time to fix a bug: **200 days**
- Most developers only find out AFTER a breach

*Why?* Existing tools are slow, noisy, and don't understand the code.

---

## Slide 2: The Vision

**What if security scanned itself — automatically, instantly, invisibly?**

Not a button you click.
Not a CI check you wait for.

A guardian that watches your code as you type, finds vulnerabilities instantly, and fixes them before you commit.

---

## Slide 3: What RakshakAI Does

| Feature | What it does |
|---------|-------------|
| **Real-time scanning** | Detects vulnerabilities as you type in VSCode |
| **Auto-fix** | One click to replace vulnerable code with secure version |
| **Background indexer** | Scans your entire project silently when you're idle |
| **Git hook** | Blocks commits with vulnerabilities — no action needed |
| **Solidity audit** | Smart contract security for Web3/DeFi projects |

All invisible. Zero context switches.

---

## Slide 4: Powered by ASI:One

RakshakAI uses **ASI:One** as its core intelligence engine.

**Why ASI:One?**
- **Agentic reasoning** — understands code context, not just pattern matching
- **200K context window** — can analyze entire files in one pass
- **Web3 native** — natively understands Solidity, smart contracts, DeFi patterns
- **OpenAI compatible** — drop-in integration with the developer ecosystem

**What changed:**
Before: custom ML model → slow, limited, 21 CWE classes
After: **ASI:One LLM** → finds any vulnerability, explains root cause, suggests fixes

We swapped a black-box model for an intelligent agent.

---

## Slide 5: Web3 Security — Solidity Support

Smart contracts hold **billions** in value. A single reentrancy bug can drain an entire protocol.

RakshakAI detects **Web3-specific vulnerabilities**:

| Vulnerability | Example |
|--------------|---------|
| Reentrancy | Unchecked external calls in withdrawal functions |
| Flash loan attacks | Manipulated oracle prices in DeFi |
| Access control | Missing `onlyOwner` modifiers |
| Integer overflow | Unchecked arithmetic in token math |
| tx.origin auth | Phishing via identity spoofing |
| Front-running | Predictable transaction ordering |

*Every Solidity file opened in VSCode is scanned automatically.*

---

## Slide 6: The Invisible Experience (Demo)

**This is RakshakAI in action:**

1. Open `app.py` in VSCode — **instant results**
   - Cache check → 0ms (already scanned before)
   - No loading, no waiting

2. Type `password = "secret123"` — **real-time detection**
   - ASI:One analyzes the change
   - Red squiggly underline appears
   - Left sidebar updates with finding
   - Hover shows: *"Hardcoded secret detected — use environment variables"*
   - One click to auto-fix

3. `git commit` — **blocked**
   - Pre-commit hook scans staged files
   - "Commit blocked: vulnerabilities found"
   - `git commit --no-verify` to override

*No user action. No extra tooling. Just works.*

---

## Slide 7: Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  VSCode     │────▶│  ASI:One API     │────▶│  Returns JSON    │
│  Extension  │     │  asi1-ultra      │     │  { issues: [] }  │
│  (JS)       │     │  https://asi1.ai │     │                  │
└──────┬──────┘     └─────────────────┘     └──────────────────┘
       │
       ▼
┌──────────────┐
│  ~/.rakshak  │
│  cache.json  │ ← Persistent disk cache (8,000+ files)
└──────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Detection modes:                    │
│  • asi1 — Balanced (daily scanning) │
│  • asi1-ultra — Deep audit (Web3)   │
│  • asi1-mini — Free tier (testing)  │
└─────────────────────────────────────┘
```

No local server needed. The extension calls ASI:One directly.

---

## Slide 8: Why This Matters for ASI:One

We're not just using ASI:One — we're proving what it can do:

1. **Security is a perfect agentic use case**
   - Multi-step reasoning: read code → find vuln → explain → suggest fix
   - Autonomous: background indexer scans while you work
   - Goal-oriented: "Is this code secure?"

2. **Web3-native validation**
   - ASI:One understands Solidity at a deep level
   - Catches reentrancy, flash loan attacks, smart contract bugs
   - Real proof that Web3-native LLMs matter

3. **Real product, real users**
   - VSCode extension + CLI + GitHub Action
   - 8,000+ files already cached in background indexing
   - Works today with just an API key

---

## Slide 9: Demo Script (3 minutes)

**What to show:**

| Time | Action | What happens |
|------|--------|-------------|
| 0:00 | Open VSCode with a Python file | Results appear instantly from cache |
| 0:30 | Open a Solidity contract | ASI:One scans for Web3 vulns |
| 1:00 | Type vulnerable code | Real-time underline + sidebar update |
| 1:30 | Hover over the squiggly | CWE, OWASP ref, fix suggestion |
| 2:00 | Click "Apply Fix" | Code replaced, re-scanned |
| 2:30 | Run `git commit` | Pre-commit hook blocks it |
| 3:00 | `rakshak cache` | Shows cache stats |

**One-sentence closer:**

> *"RakshakAI brings autonomous security to every developer — powered by the intelligence of ASI:One."*

---

## Slide 10: What's Next

- **Agentverse integration** — Deploy Rakshak as an agent on Fetch.ai's marketplace
- **Autonomous repo guardian** — Watch GitHub repos, auto-file PRs with fixes
- **Multi-agent** — Rakshak agent coordinates with other agents for dependency scanning

---

## Closing

> *"We built a security agent that works like one — invisible, intelligent, and autonomous."*

**Rakshak × ASI:One**

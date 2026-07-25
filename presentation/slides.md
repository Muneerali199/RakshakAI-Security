---
# try also 'default' to start simple
theme: seriph
# random image from a curated Unsplash collection by Anthony
# like them? see https://unsplash.com/collections/94734566/slidev
background: https://cover.sli.dev
title: RakshakAI
titleTemplate: India's First Open Security AI
info: |
  ## RakshakAI
  India's First Open Security AI — CPU vulnerability classifier AND a security-specialized coding LLM
drawing:
  persist: false
transition: slide-left
mdc: true
lineNumbers: false
colorSchema: dark
fonts:
  sans: DM Sans
  serif: DM Serif Display
  mono: Fira Code
css: unocss
layout: cover
class: text-center
---

<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&family=DM+Serif+Display:ital@0;1&family=Fira+Code:wght@400;500&display=swap');

:root {
  --primary: #00f0ff;
  --secondary: #7c3aed;
  --accent: #f59e0b;
  --bg-dark: #0a0a1a;
  --bg-card: rgba(255,255,255,0.05);
  --text-primary: #f0f0ff;
  --text-secondary: #9494b8;
}

.slidev-layout {
  background: linear-gradient(135deg, #0a0a1a 0%, #1a0a2e 50%, #0a1a2e 100%);
}

h1, h2, h3, h4 {
  font-family: 'DM Serif Display', serif !important;
  letter-spacing: -0.02em;
}

h1 {
  background: linear-gradient(135deg, #00f0ff 0%, #7c3aed 50%, #f59e0b 100%);
  -webkit-background-clip: text;
  -moz-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  -moz-text-fill-color: transparent;
}

.slidev-page {
  background: linear-gradient(135deg, #0a0a1a 0%, #1a0a2e 50%, #0a1a2e 100%);
}

.gradient-text {
  background: linear-gradient(135deg, #00f0ff 0%, #7c3aed 50%, #f59e0b 100%);
  -webkit-background-clip: text;
  -moz-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  -moz-text-fill-color: transparent;
}

.glow-card {
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px;
  backdrop-filter: blur(20px);
  transition: all 0.3s ease;
}

.glow-card:hover {
  border-color: rgba(0,240,255,0.3);
  box-shadow: 0 0 30px rgba(0,240,255,0.1);
}

.stat-number {
  font-size: 3.5rem;
  font-weight: 800;
  line-height: 1;
  background: linear-gradient(135deg, #00f0ff, #7c3aed);
  -webkit-background-clip: text;
  -moz-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  -moz-text-fill-color: transparent;
}

.tag {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.tag-v1 {
  background: rgba(0,240,255,0.15);
  color: #00f0ff;
  border: 1px solid rgba(0,240,255,0.3);
}

.tag-v2 {
  background: rgba(124,58,237,0.15);
  color: #c084fc;
  border: 1px solid rgba(124,58,237,0.3);
}

.feature-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.feature-item {
  padding: 1rem;
  border-radius: 12px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
}

.arrow-gradient {
  font-size: 2rem;
  margin: 0 1rem;
}
</style>

<br>
<br>

<div class="absolute top-4 left-8 text-xs text-gray-500 font-mono">v1 + v2</div>

<div class="flex justify-center mb-6">
  <div class="text-7xl">🛡️</div>
</div>

# RakshakAI

### <span class="gradient-text">रक्षक — India's First Open Security AI</span>

<div class="mt-4 text-gray-400 text-sm">
  CPU Vulnerability Classifier <span class="text-cyan-400 mx-2">✦</span> Security-Specialized Coding LLM
</div>

<div class="mt-6 flex justify-center gap-4 text-xs">
  <span class="tag tag-v1">v1 CPU — 50ms</span>
  <span class="tag tag-v2">v2 LLM — 682 CWEs</span>
  <span class="tag" style="background:rgba(245,158,11,0.15);color:#fbbf24;border-color:rgba(245,158,11,0.3);">Apache 2.0</span>
</div>

<div class="absolute bottom-8 left-1/2 -translate-x-1/2 text-gray-600 text-xs">
  Made in India 🇮🇳
</div>

---
transition: fade
layout: default
---

<style>
.problem-stat {
  text-align: center;
  padding: 2rem;
  border-radius: 16px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
}
.problem-stat .number {
  font-size: 4rem;
  font-weight: 800;
  background: linear-gradient(135deg, #ef4444, #f59e0b);
  -webkit-background-clip: text;
  -moz-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  -moz-text-fill-color: transparent;
  line-height: 1;
}
</style>

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">⚠️</div>
  <div>
    <div class="text-xs text-red-400 font-semibold tracking-widest uppercase">The Problem</div>
    <h2 class="!text-4xl !m-0">The Vulnerability Crisis</h2>
  </div>
</div>

<div class="grid grid-cols-3 gap-6 mt-8">
  <div class="problem-stat">
    <div class="number">65%</div>
    <div class="mt-2 text-sm text-gray-400">of vulnerabilities found in <strong class="text-white">application code</strong>, not infrastructure</div>
  </div>
  <div class="problem-stat">
    <div class="number">28B</div>
    <div class="mt-2 text-sm text-gray-400">lines of vulnerable code <strong class="text-white">added yearly</strong> by developers</div>
  </div>
  <div class="problem-stat">
    <div class="number">$4.45M</div>
    <div class="mt-2 text-sm text-gray-400">average cost of a <strong class="text-white">data breach</strong> in 2025</div>
  </div>
</div>

<div class="grid grid-cols-2 gap-6 mt-6">
  <div class="problem-stat">
    <div class="number">82%</div>
    <div class="mt-2 text-sm text-gray-400">of developers <strong class="text-white">know about security</strong> — but ship vulnerable code anyway</div>
  </div>
  <div class="problem-stat">
    <div class="number">200+</div>
    <div class="mt-2 text-sm text-gray-400">days average time to <strong class="text-white">discover & fix</strong> a critical vulnerability</div>
  </div>
</div>

<div class="mt-8 p-4 rounded-xl bg-red-950/30 border border-red-900/30 text-center">
  <span class="text-red-400 text-sm">Existing tools are either too slow, too expensive, or don't understand code context.</span>
</div>

---
transition: slide-left
layout: default
---

<style>
.cost-item {
  padding: 1.2rem;
  border-radius: 12px;
  background: rgba(255,255,255,0.02);
  border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.3s ease;
}
.cost-item:hover {
  border-color: rgba(239,68,68,0.3);
  background: rgba(239,68,68,0.05);
}
</style>

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">💸</div>
  <div>
    <div class="text-xs text-red-400 font-semibold tracking-widest uppercase">The Pain</div>
    <h2 class="!text-4xl !m-0">Why Existing Tools Fail</h2>
  </div>
</div>

<div class="grid grid-cols-2 gap-4 mt-8">
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">🐌</span>
      <h3 class="!text-lg !m-0">Too Slow</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2">SAST tools take <strong>minutes to hours</strong> per scan. Developers can't wait.</p>
  </div>
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">💰</span>
      <h3 class="!text-lg !m-0">Too Expensive</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2">Enterprise tools cost <strong>$10K–$100K+</strong>/year. Freelancers & startups get locked out.</p>
  </div>
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">🔇</span>
      <h3 class="!text-lg !m-0">Too Noisy</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2"><strong>30–60% false positive</strong> rates cause alert fatigue. Real issues get buried.</p>
  </div>
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">🔒</span>
      <h3 class="!text-lg !m-0">Not Private</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2">Cloud-based scanners <strong>upload your code</strong> to third-party servers.</p>
  </div>
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">📋</span>
      <h3 class="!text-lg !m-0">No Fix Suggestions</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2">Most tools <strong>just flag the issue</strong> — no patched code, no root cause analysis.</p>
  </div>
  <div class="cost-item">
    <div class="flex items-center gap-2">
      <span class="text-xl">🌐</span>
      <h3 class="!text-lg !m-0">Limited Language Support</h3>
    </div>
    <p class="text-sm text-gray-400 mt-2">Most tools support <strong>only 2–3 languages</strong>. Modern polyglot codebases get partial coverage.</p>
  </div>
</div>

---
transition: fade
layout: two-cols
---

<style>
.pillar {
  padding: 1.5rem;
  border-radius: 16px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.08);
  height: 100%;
}
.pillar-icon {
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
}
.pillar h3 {
  margin-bottom: 0.75rem;
}
.pillar ul {
  padding-left: 1rem;
}
.pillar li {
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
  color: #c0c0d0;
}
</style>

::left::

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">💡</div>
  <div>
    <div class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">Our Answer</div>
    <h2 class="!text-4xl !m-0">Introducing RakshakAI</h2>
  </div>
</div>

<div class="mt-4 text-gray-400 text-sm leading-relaxed">
  A <strong class="text-white">two-tier security AI</strong> that combines a lightning-fast CPU classifier with a deep-reasoning security LLM — all <strong class="text-white">offline, open-source, and free.</strong>
</div>

<div class="mt-6 flex justify-center">
  <div class="text-6xl opacity-30">🛡️</div>
</div>

<div class="mt-6 text-xs text-gray-500">
  <span class="text-cyan-400">रक्षक</span> (Rakshak) — "Protector" in Sanskrit. Your code's first line of defense.
</div>

::right::

<div class="pillar mt-16">
  <div class="pillar-icon">⚡</div>
  <h3 class="gradient-text !text-xl">Two-Tier Architecture</h3>
  
  <div class="space-y-4">
    <div class="p-3 rounded-xl bg-cyan-950/30 border border-cyan-900/30">
      <div class="flex items-center gap-2">
        <span class="tag tag-v1 text-xs">v1</span>
        <span class="text-sm font-semibold text-white">CPU Classifier — The Reflex</span>
      </div>
      <p class="text-xs text-gray-400 mt-1">1.5M–18M params, 21 classes, <strong class="text-cyan-400">< 50ms</strong></p>
    </div>
    
    <div class="flex justify-center text-gray-600 text-lg">▼</div>
    
    <div class="p-3 rounded-xl bg-purple-950/30 border border-purple-900/30">
      <div class="flex items-center gap-2">
        <span class="tag tag-v2 text-xs">v2</span>
        <span class="text-sm font-semibold text-white">Security LLM — The Brain</span>
      </div>
      <p class="text-xs text-gray-400 mt-1">7B Qwen fine-tune, 682 CWEs, <strong class="text-purple-400">9-field structured report</strong></p>
    </div>
  </div>

  <div class="mt-4 p-3 rounded-xl bg-amber-950/30 border border-amber-900/30 text-center">
    <span class="text-xs text-amber-400">v1 pre-filters clean code — v2 only runs when needed</span>
  </div>
</div>

---
transition: slide-up
layout: default
---

<style>
.arch-step {
  padding: 1.2rem;
  border-radius: 12px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
  text-align: center;
}
.arch-arrow {
  font-size: 1.5rem;
  color: #7c3aed;
  text-align: center;
}
</style>

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">⚡</div>
  <div>
    <div class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">How It Works</div>
    <h2 class="!text-4xl !m-0">The Two-Tier Pipeline</h2>
  </div>
</div>

<div class="grid grid-cols-5 gap-3 mt-8 items-center">
  <div class="arch-step col-span-1">
    <div class="text-3xl mb-2">📝</div>
    <div class="text-xs text-gray-400">Your Code</div>
    <div class="text-[10px] text-gray-600 mt-1">Any file, any language</div>
  </div>

  <div class="arch-arrow">→</div>

  <div class="arch-step col-span-1 !border-cyan-500/40 !bg-cyan-950/20">
    <div class="text-3xl mb-2">🧠</div>
    <div class="text-xs text-cyan-400 font-semibold">v1 CPU Classifier</div>
    <div class="text-[10px] text-gray-500 mt-1">1.5M–18M params</div>
    <div class="text-[10px] text-gray-500">< 50ms inference</div>
    <div class="text-[10px] text-gray-400 mt-1">21 vulnerability classes</div>
  </div>

  <div class="arch-arrow">→</div>

  <div class="arch-step col-span-1">
    <div class="text-3xl mb-2">✅</div>
    <div class="text-xs text-green-400 font-semibold">Clean?</div>
    <div class="text-[10px] text-gray-500 mt-1">97% of real-world code</div>
    <div class="text-xs text-green-400 mt-2">✓ Pass — Skip LLM</div>
  </div>

  <div class="arch-arrow">→</div>

  <div class="arch-step col-span-1 !border-purple-500/40 !bg-purple-950/20">
    <div class="text-3xl mb-2">🤖</div>
    <div class="text-xs text-purple-400 font-semibold">v2 Security LLM</div>
    <div class="text-[10px] text-gray-500 mt-1">Qwen2.5-Coder-7B</div>
    <div class="text-[10px] text-gray-500">682 CWE classes</div>
    <div class="text-[10px] text-gray-400 mt-1">9-field structured report</div>
  </div>
</div>

<div class="grid grid-cols-2 gap-4 mt-8">
  <div class="p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/30">
    <div class="flex items-center justify-between">
      <span class="text-sm font-semibold text-white">v1 Specs</span>
      <span class="tag tag-v1 text-[10px]">CPU Only</span>
    </div>
    <div class="grid grid-cols-2 gap-2 mt-2 text-xs text-gray-400">
      <div><span class="text-cyan-400">Architecture:</span> Custom Transformer</div>
      <div><span class="text-cyan-400">Layers:</span> 4–6 Encoder Blocks</div>
      <div><span class="text-cyan-400">Model Size:</span> 6 MB</div>
      <div><span class="text-cyan-400">Cost:</span> $0 — runs on laptop</div>
    </div>
  </div>
  <div class="p-4 rounded-xl bg-purple-950/20 border border-purple-900/30">
    <div class="flex items-center justify-between">
      <span class="text-sm font-semibold text-white">v2 Specs</span>
      <span class="tag tag-v2 text-[10px]">GPU</span>
    </div>
    <div class="grid grid-cols-2 gap-2 mt-2 text-xs text-gray-400">
      <div><span class="text-purple-400">Base:</span> Qwen2.5-Coder-7B</div>
      <div><span class="text-purple-400">Method:</span> QLoRA (NF4, r=64)</div>
      <div><span class="text-purple-400">Training Cost:</span> ~$22</div>
      <div><span class="text-purple-400">Output:</span> 9-field JSON report</div>
    </div>
  </div>
</div>

---
transition: slide-left
layout: default
---

<style>
.metric-card {
  text-align: center;
  padding: 1.5rem;
  border-radius: 16px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.3s ease;
}
.metric-card:hover {
  transform: translateY(-2px);
  border-color: rgba(0,240,255,0.3);
  box-shadow: 0 8px 30px rgba(0,240,255,0.08);
}
.metric-value {
  font-size: 2.8rem;
  font-weight: 800;
  line-height: 1;
}
.v1-value { background: linear-gradient(135deg, #00f0ff, #06b6d4); -webkit-background-clip: text; -moz-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; -moz-text-fill-color: transparent; }
.v2-value { background: linear-gradient(135deg, #a855f7, #7c3aed); -webkit-background-clip: text; -moz-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; -moz-text-fill-color: transparent; }
</style>

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">📊</div>
  <div>
    <div class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">Technical Deep Dive</div>
    <h2 class="!text-4xl !m-0">Performance By The Numbers</h2>
  </div>
</div>

<div class="grid grid-cols-4 gap-4 mt-8">
  <div class="metric-card">
    <div class="metric-value v1-value">90.3%</div>
    <div class="text-xs text-gray-400 mt-2">Real-world accuracy <span class="tag tag-v1 text-[10px] block mt-1 inline-block">v1</span></div>
  </div>
  <div class="metric-card">
    <div class="metric-value v1-value">< 50ms</div>
    <div class="text-xs text-gray-400 mt-2">Inference per snippet <span class="tag tag-v1 text-[10px] block mt-1 inline-block">v1</span></div>
  </div>
  <div class="metric-card">
    <div class="metric-value v2-value">682</div>
    <div class="text-xs text-gray-400 mt-2">CWE classes covered <span class="tag tag-v2 text-[10px] block mt-1 inline-block">v2</span></div>
  </div>
  <div class="metric-card">
    <div class="metric-value v2-value">13</div>
    <div class="text-xs text-gray-400 mt-2">Programming languages <span class="tag tag-v2 text-[10px] block mt-1 inline-block">v2</span></div>
  </div>
</div>

<div class="grid grid-cols-3 gap-4 mt-4">
  <div class="metric-card">
    <div class="metric-value v2-value">78%</div>
    <div class="text-xs text-gray-400 mt-2">CWE Top-1 Accuracy <span class="tag tag-v2 text-[10px] block mt-1 inline-block">v2</span></div>
  </div>
  <div class="metric-card">
    <div class="metric-value v2-value">≤ 2.5s</div>
    <div class="text-xs text-gray-400 mt-2">p95 latency (vLLM) <span class="tag tag-v2 text-[10px] block mt-1 inline-block">v2</span></div>
  </div>
  <div class="metric-card">
    <div class="metric-value v2-value">65%</div>
    <div class="text-xs text-gray-400 mt-2">Fix Success Rate <span class="tag tag-v2 text-[10px] block mt-1 inline-block">v2</span></div>
  </div>
</div>

<div class="mt-6 p-4 rounded-xl bg-gray-950/40 border border-gray-800 text-center">
  <div class="text-xs text-gray-500">
    Training dataset: <strong class="text-white">96,000+ curated CVE samples</strong> • 
    Trained on <strong class="text-white">1× AMD MI300X</strong> (192 GB HBM3) • 
    Total training cost: <strong class="text-amber-400">~$22</strong>
  </div>
</div>

---
transition: slide-up
layout: default
---

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">🖥️</div>
  <div>
    <div class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">Demo</div>
    <h2 class="!text-4xl !m-0">VS Code Extension — In Action</h2>
  </div>
</div>

<div class="grid grid-cols-2 gap-6 mt-6">
  <div class="glow-card p-4">
    <div class="flex items-center gap-2 mb-3">
      <span class="text-xl">📋</span>
      <h3 class="!text-base !m-0">Inline Diagnostics</h3>
    </div>
    <div class="text-xs text-gray-400 space-y-1">
      <p>• Real-time vulnerability highlighting in the editor</p>
      <p>• Severity-coded (Critical / High / Medium / Low)</p>
      <p>• CWE and OWASP classification shown inline</p>
      <p>• Click-to-navigate issue list in Problems panel</p>
    </div>
  </div>
  <div class="glow-card p-4">
    <div class="flex items-center gap-2 mb-3">
      <span class="text-xl">🩺</span>
      <h3 class="!text-base !m-0">Rich Hover Information</h3>
    </div>
    <div class="text-xs text-gray-400 space-y-1">
      <p>• Hover over highlighted code for full security report</p>
      <p>• Shows vulnerability description & root cause</p>
      <p>• Links to CWE & OWASP references</p>
      <p>• Recommended fix with "Apply Fix" button</p>
    </div>
  </div>
  <div class="glow-card p-4">
    <div class="flex items-center gap-2 mb-3">
      <span class="text-xl">⚡</span>
      <h3 class="!text-base !m-0">One-Click Fix</h3>
    </div>
    <div class="text-xs text-gray-400 space-y-1">
      <p>• Quick-fix lightbulb action on every finding</p>
      <p>• Applies the model's patched code automatically</p>
      <p>• Rescans after fix to verify</p>
      <p>• Works inline — no context switching</p>
    </div>
  </div>
  <div class="glow-card p-4">
    <div class="flex items-center gap-2 mb-3">
      <span class="text-xl">🌳</span>
      <h3 class="!text-base !m-0">Security Tree View</h3>
    </div>
    <div class="text-xs text-gray-400 space-y-1">
      <p>• Dedicated Rakshak tab in Activity Bar</p>
      <p>• File-level security overview with issue counts</p>
      <p>• Expand to see individual findings per file</p>
      <p>• Click any issue to jump directly to the code</p>
    </div>
  </div>
</div>

<div class="mt-6 p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/30 text-center">
  <div class="text-sm text-cyan-400 font-semibold">🔄 Real-time scanning — on type, on save, on file switch</div>
  <div class="text-xs text-gray-500 mt-1">8 languages supported: Python, JavaScript, TypeScript, Java, PHP, Go, C#, Ruby</div>
</div>

---
transition: slide-left
layout: default
---

<style>
.usp-card {
  padding: 1.5rem;
  border-radius: 16px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.3s ease;
}
.usp-card:hover {
  border-color: rgba(245,158,11,0.3);
  box-shadow: 0 0 30px rgba(245,158,11,0.08);
  transform: translateY(-2px);
}
.usp-icon {
  font-size: 2rem;
  margin-bottom: 0.5rem;
}
.comparison-row {
  display: flex;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  font-size: 0.8rem;
  border-bottom: 1px solid rgba(255,255,255,0.04);
}
.comparison-row:last-child { border-bottom: none; }
.comparison-row .feature { color: #c0c0d0; width: 35%; }
.comparison-row .others { color: #ef4444; width: 30%; text-align: center; }
.comparison-row .rakshak { color: #00f0ff; width: 35%; text-align: right; font-weight: 600; }
</style>

<div class="flex items-center gap-3 mb-6">
  <div class="text-3xl">🏆</div>
  <div>
    <div class="text-xs text-amber-400 font-semibold tracking-widest uppercase">Why Us</div>
    <h2 class="!text-4xl !m-0">Our Unique Edge</h2>
  </div>
</div>

<div class="grid grid-cols-3 gap-4 mt-4">
  <div class="usp-card">
    <div class="usp-icon">🆓</div>
    <h3 class="!text-base !m-0 text-white">100% Free & Open Source</h3>
    <p class="text-xs text-gray-400 mt-2">Apache 2.0 license. No paywalls, no credit card, no usage limits. <strong class="text-white">Security shouldn't be a premium feature.</strong></p>
  </div>
  <div class="usp-card">
    <div class="usp-icon">🔒</div>
    <h3 class="!text-base !m-0 text-white">Fully Offline</h3>
    <p class="text-xs text-gray-400 mt-2">Your code never leaves your machine. v1 runs on any CPU. v2 runs locally via Ollama. <strong class="text-white">Privacy by design.</strong></p>
  </div>
  <div class="usp-card">
    <div class="usp-icon">⚡</div>
    <h3 class="!text-base !m-0 text-white">Blazing Fast</h3>
    <p class="text-xs text-gray-400 mt-2">v1 classifies in < 50ms. v2 generates a full 9-field report in < 2.5s. <strong class="text-white">No more waiting minutes for scans.</strong></p>
  </div>
  <div class="usp-card">
    <div class="usp-icon">🔧</div>
    <h3 class="!text-base !m-0 text-white">Fix Generator</h3>
    <p class="text-xs text-gray-400 mt-2">We don't just find bugs — we <strong class="text-white">provide patched code</strong>. One-click apply in the editor. Zero context switching.</p>
  </div>
  <div class="usp-card">
    <div class="usp-icon">🌍</div>
    <h3 class="!text-base !m-0 text-white">13 Languages</h3>
    <p class="text-xs text-gray-400 mt-2">From Python to Rust, C++ to Go — <strong class="text-white">unmatched language coverage</strong> for polyglot codebases.</p>
  </div>
  <div class="usp-card">
    <div class="usp-icon">🎯</div>
    <h3 class="!text-base !m-0 text-white">Low False Positives</h3>
    <p class="text-xs text-gray-400 mt-2">Two-tier validation means <strong class="text-white">accurate results</strong>. v1 pre-filter + v2 deep analysis dramatically reduces noise.</p>
  </div>
</div>

<div class="mt-6">
  <div class="p-4 rounded-xl bg-gray-950/40 border border-gray-800">
    <div class="text-xs text-gray-500 mb-2 font-semibold tracking-wider text-center">VS COMPETITION</div>
    <div class="comparison-row">
      <span class="feature">Feature</span>
      <span class="others">Others (Snyk, Semgrep, etc.)</span>
      <span class="rakshak">RakshakAI</span>
    </div>
    <div class="comparison-row">
      <span class="feature">Price</span>
      <span class="others">$10K–$100K+/year</span>
      <span class="rakshak">Free (Apache 2.0)</span>
    </div>
    <div class="comparison-row">
      <span class="feature">Privacy</span>
      <span class="others">Cloud-based, code uploaded</span>
      <span class="rakshak">100% offline</span>
    </div>
    <div class="comparison-row">
      <span class="feature">Fix Suggestions</span>
      <span class="others">Basic or none</span>
      <span class="rakshak">Patched code + apply</span>
    </div>
    <div class="comparison-row">
      <span class="feature">Scan Speed</span>
      <span class="others">Minutes to hours</span>
      <span class="rakshak">Milliseconds to seconds</span>
    </div>
    <div class="comparison-row">
      <span class="feature">Languages</span>
      <span class="others">2–5 typically</span>
      <span class="rakshak">13 languages</span>
    </div>
  </div>
</div>

---
transition: fade
layout: default
---

<style>
.milestone {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  padding: 1rem;
  border-radius: 12px;
  background: rgba(255,255,255,0.02);
  border-left: 3px solid;
}
.milestone-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
  margin-top: 4px;
}
</style>

<div class="flex items-center gap-3 mb-8">
  <div class="text-3xl">🚀</div>
  <div>
    <div class="text-xs text-cyan-400 font-semibold tracking-widest uppercase">The Vision</div>
    <h2 class="!text-4xl !m-0">Roadmap & Future Impact</h2>
  </div>
</div>

<div class="grid grid-cols-2 gap-6 mt-6">
  <div>
    <h3 class="!text-sm text-gray-500 uppercase tracking-widest mb-4">Now — v2.0.0</h3>
    <div class="space-y-3">
      <div class="milestone" style="border-color: #00f0ff;">
        <div class="milestone-dot" style="background:#00f0ff;"></div>
        <div>
          <div class="text-sm text-white font-semibold">✅ v1 CPU Classifier</div>
          <div class="text-xs text-gray-400">Production-ready, 90.3% accuracy, < 50ms</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #a855f7;">
        <div class="milestone-dot" style="background:#a855f7;"></div>
        <div>
          <div class="text-sm text-white font-semibold">🔄 v2 LLM Training</div>
          <div class="text-xs text-gray-400">Qwen2.5-Coder-7B QLoRA, 682 CWEs, 13 languages</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #f59e0b;">
        <div class="milestone-dot" style="background:#f59e0b;"></div>
        <div>
          <div class="text-sm text-white font-semibold">🖥️ VS Code Extension</div>
          <div class="text-xs text-gray-400">Real-time scanning, inline fixes, tree view</div>
        </div>
      </div>
    </div>

    <h3 class="!text-sm text-gray-500 uppercase tracking-widest mb-4 mt-6">Next — v2.1.x (H1 2027)</h3>
    <div class="space-y-3">
      <div class="milestone" style="border-color: #f59e0b; opacity: 0.7;">
        <div class="milestone-dot" style="background:#f59e0b;"></div>
        <div>
          <div class="text-sm text-white">DPO Preference Tuning</div>
          <div class="text-xs text-gray-400">Better fix quality, fewer hallucinations</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #f59e0b; opacity: 0.7;">
        <div class="milestone-dot" style="background:#f59e0b;"></div>
        <div>
          <div class="text-sm text-white">14B Model Ablation</div>
          <div class="text-xs text-gray-400">Scaling laws for security LLMs</div>
        </div>
      </div>
    </div>
  </div>

  <div>
    <h3 class="!text-sm text-gray-500 uppercase tracking-widest mb-4">Future — v3.x (2027+)</h3>
    <div class="space-y-3">
      <div class="milestone" style="border-color: #6366f1; opacity: 0.5;">
        <div class="milestone-dot" style="background:#6366f1;"></div>
        <div>
          <div class="text-sm text-white">Multi-File Analysis</div>
          <div class="text-xs text-gray-400">Cross-file vulnerability chains & data flow</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #6366f1; opacity: 0.5;">
        <div class="milestone-dot" style="background:#6366f1;"></div>
        <div>
          <div class="text-sm text-white">SBOM Integration</div>
          <div class="text-xs text-gray-400">Software Bill of Materials + dependency scanning</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #6366f1; opacity: 0.5;">
        <div class="milestone-dot" style="background:#6366f1;"></div>
        <div>
          <div class="text-sm text-white">IaC Security</div>
          <div class="text-xs text-gray-400">Terraform, CloudFormation, Kubernetes manifests</div>
        </div>
      </div>
      <div class="milestone" style="border-color: #6366f1; opacity: 0.5;">
        <div class="milestone-dot" style="background:#6366f1;"></div>
        <div>
          <div class="text-sm text-white">Security Education Platform</div>
          <div class="text-xs text-gray-400">Learn-by-fixing with guided remediation</div>
        </div>
      </div>
    </div>

    <div class="mt-6 p-4 rounded-xl bg-amber-950/20 border border-amber-900/30">
      <div class="text-xs text-amber-400 font-semibold text-center">🌎 The Big Picture</div>
      <p class="text-xs text-gray-400 mt-2 text-center">
        Making enterprise-grade security analysis <strong class="text-white">free, private, and accessible to every developer on the planet</strong> — from solo freelancers to Fortune 500 teams.
      </p>
    </div>
  </div>
</div>

---
transition: fade
layout: center
class: text-center
---

<style>
.cta-button {
  display: inline-block;
  padding: 1rem 3rem;
  border-radius: 50px;
  font-weight: 700;
  font-size: 1.1rem;
  transition: all 0.3s ease;
  cursor: pointer;
  text-decoration: none;
}
.cta-primary {
  background: linear-gradient(135deg, #00f0ff, #7c3aed);
  color: white;
  box-shadow: 0 4px 20px rgba(0,240,255,0.3);
}
.cta-primary:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 40px rgba(0,240,255,0.4);
}
.social-link {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 1.2rem;
  border-radius: 8px;
  background: rgba(255,255,255,0.05);
  border: 1px solid rgba(255,255,255,0.1);
  color: #9494b8;
  text-decoration: none;
  font-size: 0.85rem;
  transition: all 0.3s ease;
}
.social-link:hover {
  background: rgba(255,255,255,0.1);
  color: white;
}
</style>

<div class="text-6xl mb-6">🛡️</div>

# Let's Build the Future of <span class="gradient-text">Open Security</span>

<br>

<div class="text-gray-400 max-w-xl mx-auto text-sm leading-relaxed">
  RakshakAI is just getting started. We're building the first truly open, private, and intelligent security layer for the world's code.
</div>

<br>
<br>

<div class="flex justify-center gap-4">
  <a href="https://github.com/Muneerali1995/RakshakAI" class="cta-button cta-primary" target="_blank">
    ⭐ Star on GitHub
  </a>
</div>

<br>

<div class="flex justify-center gap-3 text-xs">
  <span class="social-link">📦 <span>PyPI: rakshakai</span></span>
  <span class="social-link">🖥️ <span>VS Code Marketplace</span></span>
  <span class="social-link">🤗 <span>HuggingFace (Coming Soon)</span></span>
</div>

<br>

<div class="text-gray-600 text-xs">
  Apache 2.0 • Made in India 🇮🇳 • रक्षक — "Protector" in Sanskrit
</div>

<div class="absolute bottom-6 left-1/2 -translate-x-1/2 text-gray-700 text-[10px]">
  © 2026 RakshakAI — Open Source Security for Everyone
</div>

---
layout: end
---

# Thank You 🙏

<div class="text-gray-400">Let's make the digital world safer — together.</div>

<div class="mt-6 text-xs text-gray-500">
  <span class="gradient-text font-semibold">RakshakAI</span> • India's First Open Security AI
</div>

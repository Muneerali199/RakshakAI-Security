# RakshakAI v2 — VS Code Extension Roadmap

> **Vision:** Real-time security vulnerability detection and fix suggestions directly in the editor.

---

## Feature overview

| Feature | Priority | Status |
|---------|----------|--------|
| Inline vulnerability diagnostics | P0 | 📝 Planned |
| Quick-fix code action (apply patch) | P0 | 📝 Planned |
| CWE lookup hover | P1 | 📝 Planned |
| On-save scan | P1 | 📝 Planned |
| Repository-wide scan | P2 | 📝 Planned |
| Security score gutter | P2 | 📝 Planned |
| Code lens: "Show explanation" | P2 | 📝 Planned |

---

## Architecture

```
VS Code Extension (TypeScript)
│
├── Client (webview + activation)
│   ├── Diagnostics provider
│   ├── Code actions provider
│   ├── Hover provider
│   └── Status bar widget
│
├── Language server (LSP)
│   └── v2/deploy/cli.py scan --format lsp
│
└── Backend (local or remote)
    ├── Local: GGUF via llama.cpp / Ollama
    ├── Local: Transformers (Python)
    └── Remote: RakshakAI API (Phase 3)
```

### Communication

```
User types code → Extension detects change
  → Debounce (1s idle)
  → Send to language server or CLI
  → Parse structured output
  → Add diagnostics to current file
  → Register code actions (quick-fix)
```

Two modes:

| Mode | Backend | Latency | Requirements |
|------|---------|---------|-------------|
| **Local (Ollama)** | `ollama run rakshakai-v2` | 8–15s | 8 GB RAM, 4.5 GB disk |
| **Local (Python)** | `v2/deploy/cli.py` | 3–8s | Python + torch, GPU preferred |
| **Remote API** | `POST /v2/scan` | 1–3s | Internet + API key |

---

## Feature details

### P0: Inline diagnostics

When the user opens or edits a file:
1. Debounce 1s after last edit
2. Send file content to the backend
3. Parse the 9-field security finding
4. Add VS Code `Diagnostic` at the vulnerability line
5. Color: red (critical/high), yellow (medium), blue (low)

![Diagnostic mockup](docs/assets/vscode-diagnostic-mockup.png)

### P0: Quick-fix code action

When a diagnostic exists:
1. Register a `CodeAction` with kind `quickfix`
2. Action label: "Apply RakshakAI secure fix"
3. Insert patch from `patched_code` field
4. Replace the vulnerable range

### P1: CWE lookup hover

When hovering over a CWE reference (e.g., `CWE-89`):
1. Fetch CWE description from bundled JSON database
2. Show: CWE ID, name, description, typical severity
3. Link to `https://cwe.mitre.org/data/definitions/{id}.html`

### P1: On-save scan

When the user saves a file:
1. Run full security scan
2. Show results as diagnostics + problems panel
3. Non-blocking (fire-and-forget with progress notification)

### P2: Repository-wide scan

```bash
Command Palette → "RakshakAI: Scan entire workspace"
```

1. Walk all supported files in the workspace
2. Scan each file (or batch via `POST /v2/batch`)
3. Show results in problems panel + custom results view

### P2: Security score gutter

Color-coded gutter decorations per file:
- Green: no vulnerabilities found
- Yellow: 1–2 low/medium issues
- Red: high/critical issues

### P2: Code lens explanation

Above each detected vulnerability:
```
🚨 CWE-89: SQL Injection — [Show explanation]
```

Clicking shows the full 9-field finding in a hover panel.

---

## Implementation plan

### Phase 1: MVP (2 weeks)

**Deliverable:** Extension that sends active file to CLI and shows diagnostics.

```bash
# File: v2/integrations/vscode/package.json
{
  "name": "rakshakai-vscode",
  "displayName": "RakshakAI Security",
  "activationEvents": ["onLanguage:python", "onLanguage:javascript", ...],
  "contributes": {
    "commands": [
      { "command": "rakshakai.scanFile", "title": "RakshakAI: Scan this file" }
    ],
    "configuration": {
      "properties": {
        "rakshakai.backend": {
          "enum": ["cli", "ollama", "api"],
          "default": "cli"
        },
        "rakshakai.apiUrl": { "type": "string", "default": "" },
        "rakshakai.apiKey": { "type": "string" }
      }
    }
  }
}
```

### Phase 2: Enhanced (1 week)

- Quick-fix code actions
- CWE lookup hover
- On-save scan (can be toggled)

### Phase 3: Advanced (2 weeks)

- Repository-wide scan
- Security score gutter
- Code lens explanations
- Results panel (custom tree view)

### Phase 4: Polish (ongoing)

- Configuration UI
- Status bar indicator
- Error handling (model not loaded, timeout, quota exceeded)
- Telemetry (optional)

---

## Technical decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | TypeScript | Native VS Code extension API support |
| Backend comms | STDIO JSON-RPC (for CLI), HTTP (for API) | Simple, works with existing `cli.py` |
| Packaging | VSIX + GitHub Releases | Standard VS Code distribution |
| Publishing | VS Code Marketplace | Largest reach |
| Model format | GGUF (Ollama) | Smallest download, CPU-inference capable |
| Open source | Yes (Apache 2.0) | Align with RakshakAI project license |

---

## Dependencies

| Dependency | License | Purpose |
|------------|---------|---------|
| VS Code Extension API | Proprietary (free) | Extension framework |
| Ollama (optional) | MIT | Local model serving |
| `v2/deploy/cli.py` | Apache 2.0 | CLI backend |

---

## Market positioning

- **Competition:** Snyk Code (proprietary, expensive), GitHub Copilot (proprietary, code completion), Semgrep (SAST, no LLM)
- **Differentiator:** RakshakAI runs fully offline, outputs structured security reports, generates patches, Apache 2.0
- **Target users:** Security-conscious individual developers, small teams without Snyk budget, open-source maintainers

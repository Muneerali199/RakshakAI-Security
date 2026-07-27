# RakshakAI v2 — VS Code Extension

Adds inline security diagnostics, a quick-fix to apply the model's
patched code, and a workspace-wide scan command.

## Prereqs

1. The RakshakAI v2 server is running:

   ```bash
   uvicorn v2.deploy.server:app --host 0.0.0.0 --port 8080
   ```

2. Node 20+ and TypeScript 5+.

## Build

```bash
cd v2/integrations/vscode
npm install
npm run build
```

## Run (development)

In VS Code, "Run Extension" from the Run and Debug view, or:

```bash
code --extensionDevelopmentPath=v2/integrations/vscode .
```

## Package

```bash
npm run package
# → rakshakai-v2-2.0.0.vsix
code --install-extension rakshakai-v2-2.0.0.vsix
```

## Settings

| Setting | Default | Description |
|---|---|---|
| `rakshakai.serverUrl` | `http://localhost:8080` | URL of the RakshakAI v2 server |
| `rakshakai.scanOnSave` | `true` | Scan active editor on save |
| `rakshakai.severityFilter` | `["critical","high","medium"]` | Only show diagnostics at these severities |
| `rakshakai.minConfidence` | `0.6` | Hide findings below this confidence |

## Commands

| Command | Action |
|---|---|
| `RakshakAI: Scan Current File` | Scans the active editor and surfaces findings as diagnostics |
| `RakshakAI: Scan Workspace` | Scans all open files |
| `RakshakAI: Show Last Finding` | Opens a side panel with the structured review |
| `RakshakAI: Apply Suggested Patch` | Replaces the file with `patched_code` (quick-fix on a diagnostic) |

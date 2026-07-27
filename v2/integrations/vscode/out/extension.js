"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const axios_1 = __importDefault(require("axios"));
const RAKSHAK_DIAG = 'rakshakai-v2';
const abortControllers = new Map();
const findingsCache = new Map();
let totalScans = 0;
let totalFindings = 0;
function getConfig() {
    const cfg = vscode.workspace.getConfiguration('rakshakai');
    return {
        serverUrl: cfg.get('serverUrl', 'http://localhost:8080'),
        scanOnSave: cfg.get('scanOnSave', true),
        severityFilter: cfg.get('severityFilter', ['critical', 'high', 'medium']),
        minConfidence: cfg.get('minConfidence', 0.6),
        provider: cfg.get('provider', 'ollama'),
        model: cfg.get('model', ''),
    };
}
function langIdFor(doc) {
    const map = {
        python: 'python', javascript: 'javascript', typescript: 'typescript',
        java: 'java', go: 'go', rust: 'rust', c: 'c', cpp: 'cpp',
        php: 'php', csharp: 'csharp', ruby: 'ruby',
    };
    return map[doc.languageId] || 'text';
}
// ─── Dashboard Webview ───
function getDashboardHtml(findings, provider) {
    const critical = findings.filter(f => f.finding.severity === 'critical').length;
    const high = findings.filter(f => f.finding.severity === 'high').length;
    const medium = findings.filter(f => f.finding.severity === 'medium').length;
    const low = findings.filter(f => f.finding.severity === 'low').length;
    const total = findings.length;
    const findingCards = findings.map((f, idx) => {
        const sevColor = {
            critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280'
        };
        const sevBg = {
            critical: 'rgba(239,68,68,0.08)', high: 'rgba(249,115,22,0.08)', medium: 'rgba(234,179,8,0.08)',
            low: 'rgba(59,130,246,0.08)', info: 'rgba(107,114,128,0.08)'
        };
        const sev = f.finding.severity || 'info';
        const fileShort = f.file.split('/').pop() || f.file;
        const filePath = f.file.split('/').slice(-3).join('/');
        return `
      <div class="finding-card" style="animation-delay: ${idx * 0.05}s">
        <div class="finding-header">
          <div class="severity-badge ${sev}">${sev}</div>
          <div class="cwe-badge">${escapeHtml(f.finding.cwe || '')}</div>
        </div>
        <div class="finding-title">${escapeHtml(f.finding.vulnerability || 'Unknown')}</div>
        <div class="finding-file">
          <span class="file-icon">📄</span>
          <span>${escapeHtml(filePath)}</span>
        </div>
        ${f.finding.confidence ? `
          <div class="confidence-meter">
            <div class="confidence-label">Confidence: ${(f.finding.confidence * 100).toFixed(0)}%</div>
            <div class="confidence-bar">
              <div class="confidence-fill" style="width: ${(f.finding.confidence * 100)}%"></div>
            </div>
          </div>
        ` : ''}
        ${f.finding.root_cause ? `
          <div class="finding-detail">
            <strong>Root Cause:</strong> ${escapeHtml(f.finding.root_cause.slice(0, 150))}${f.finding.root_cause.length > 150 ? '...' : ''}
          </div>
        ` : ''}
        ${f.finding.secure_fix ? `
          <div class="finding-fix">
            <span class="fix-icon">💡</span>
            <span>${escapeHtml(f.finding.secure_fix.slice(0, 120))}${f.finding.secure_fix.length > 120 ? '...' : ''}</span>
          </div>
        ` : ''}
      </div>`;
    }).join('');
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { 
      margin: 0; 
      padding: 0; 
      box-sizing: border-box; 
    }
    
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; 
      background: #0d1117; 
      color: #e5e5e5; 
      padding: 32px;
      line-height: 1.6;
    }

    @media (max-width: 768px) {
      body { padding: 16px; }
    }
    
    .header { 
      text-align: center; 
      margin-bottom: 40px;
      animation: fadeInDown 0.6s ease;
    }
    
    @keyframes fadeInDown {
      from {
        opacity: 0;
        transform: translateY(-20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateX(-20px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }
    
    .logo { 
      font-size: 64px; 
      margin-bottom: 12px;
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.08); }
    }
    
    h1 { 
      font-size: 32px; 
      font-weight: 900; 
      background: linear-gradient(135deg, #4ade80, #22d3ee, #a78bfa); 
      -webkit-background-clip: text; 
      -webkit-text-fill-color: transparent;
      background-size: 200% auto;
      animation: gradient 3s ease infinite;
      margin-bottom: 8px;
    }

    @keyframes gradient {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    
    .subtitle { 
      color: #8b949e; 
      font-size: 14px; 
      letter-spacing: 0.5px;
    }
    
    .meta-bar {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 24px;
      margin-bottom: 36px;
      flex-wrap: wrap;
      animation: fadeInUp 0.6s ease 0.2s both;
    }

    .provider-badge, .scan-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #161b22; 
      border: 1px solid #30363d; 
      border-radius: 20px; 
      padding: 8px 18px; 
      font-size: 13px; 
      color: #8b949e;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #4ade80;
      animation: blink 1.5s ease-in-out infinite;
    }

    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }

    .provider-badge .value, .scan-badge .value { 
      color: #4ade80; 
      font-weight: 700; 
    }
    
    .stats { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); 
      gap: 16px; 
      margin-bottom: 40px;
      animation: fadeInUp 0.6s ease 0.3s both;
    }

    @media (max-width: 600px) {
      .stats {
        grid-template-columns: repeat(2, 1fr);
        gap: 12px;
      }
    }
    
    .stat { 
      background: #161b22; 
      border: 1px solid #30363d; 
      border-radius: 12px; 
      padding: 24px 20px; 
      text-align: center;
      transition: all 0.3s ease;
      cursor: pointer;
      position: relative;
      overflow: hidden;
    }

    .stat::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--stat-color);
      transform: scaleX(0);
      transition: transform 0.3s ease;
    }

    .stat:hover::before {
      transform: scaleX(1);
    }
    
    .stat:hover { 
      border-color: var(--stat-color);
      transform: translateY(-4px);
      box-shadow: 0 8px 24px rgba(0,0,0,0.3);
    }
    
    .stat-num { 
      font-size: 42px; 
      font-weight: 900; 
      line-height: 1;
      color: var(--stat-color);
      margin-bottom: 8px;
    }
    
    .stat-label { 
      font-size: 12px; 
      color: #8b949e; 
      text-transform: uppercase; 
      letter-spacing: 1px; 
      font-weight: 600; 
    }
    
    .stat-critical { --stat-color: #ef4444; }
    .stat-high { --stat-color: #f97316; }
    .stat-medium { --stat-color: #eab308; }
    .stat-total { --stat-color: #4ade80; }
    
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      animation: fadeInUp 0.6s ease 0.4s both;
    }

    .section-title { 
      color: #c9d1d9; 
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .findings-count {
      background: #21262d;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      color: #4ade80;
    }

    .findings-grid {
      display: grid;
      gap: 16px;
      animation: fadeInUp 0.6s ease 0.5s both;
    }

    .finding-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s ease;
      animation: slideIn 0.5s ease both;
    }

    .finding-card:hover {
      border-color: #4ade80;
      transform: translateX(4px);
      box-shadow: 0 4px 16px rgba(74,222,128,0.1);
    }

    .finding-header {
      display: flex;
      gap: 10px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }

    .severity-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .severity-badge.critical {
      background: rgba(239,68,68,0.15);
      color: #ef4444;
      border: 1px solid #ef444440;
    }

    .severity-badge.high {
      background: rgba(249,115,22,0.15);
      color: #f97316;
      border: 1px solid #f9731640;
    }

    .severity-badge.medium {
      background: rgba(234,179,8,0.15);
      color: #eab308;
      border: 1px solid #eab30840;
    }

    .severity-badge.low {
      background: rgba(59,130,246,0.15);
      color: #3b82f6;
      border: 1px solid #3b82f640;
    }

    .cwe-badge {
      background: #21262d;
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 11px;
      color: #8b949e;
      font-family: 'SF Mono', monospace;
    }

    .finding-title {
      color: #e5e5e5;
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 10px;
      line-height: 1.4;
    }

    .finding-file {
      display: flex;
      align-items: center;
      gap: 6px;
      color: #8b949e;
      font-size: 12px;
      margin-bottom: 12px;
      font-family: 'SF Mono', monospace;
    }

    .file-icon {
      font-size: 14px;
    }

    .confidence-meter {
      margin-bottom: 12px;
    }

    .confidence-label {
      font-size: 11px;
      color: #8b949e;
      margin-bottom: 4px;
    }

    .confidence-bar {
      height: 4px;
      background: #21262d;
      border-radius: 2px;
      overflow: hidden;
    }

    .confidence-fill {
      height: 100%;
      background: linear-gradient(90deg, #4ade80, #22d3ee);
      border-radius: 2px;
      transition: width 0.8s ease;
    }

    .finding-detail {
      background: #0d111780;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 12px;
      color: #c9d1d9;
      margin-bottom: 10px;
      line-height: 1.5;
      border-left: 2px solid #30363d;
    }

    .finding-detail strong {
      color: #f97316;
    }

    .finding-fix {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      background: rgba(74,222,128,0.08);
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 12px;
      color: #4ade80;
      border-left: 2px solid #4ade80;
      line-height: 1.5;
    }

    .fix-icon {
      font-size: 16px;
      flex-shrink: 0;
    }
    
    .empty { 
      text-align: center; 
      padding: 80px 24px; 
      color: #8b949e;
      animation: fadeInUp 0.6s ease both;
    }
    
    .empty-icon { 
      font-size: 72px; 
      margin-bottom: 20px;
      animation: bounce 2s ease-in-out infinite;
    }

    @keyframes bounce {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-10px); }
    }

    .empty-title {
      font-size: 24px;
      font-weight: 700;
      color: #4ade80;
      margin-bottom: 8px;
    }

    .empty-text {
      font-size: 14px;
      color: #8b949e;
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️</div>
    <h1>RakshakAI Dashboard</h1>
    <div class="subtitle">Security Code Analysis Report</div>
  </div>

  <div class="meta-bar">
    <div class="provider-badge">
      <span class="status-dot"></span>
      <span>Provider:</span>
      <span class="value">${provider}</span>
    </div>
    <div class="scan-badge">
      <span>Total Scans:</span>
      <span class="value">${totalScans}</span>
    </div>
  </div>

  <div class="stats">
    <div class="stat stat-critical">
      <div class="stat-num">${critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat stat-high">
      <div class="stat-num">${high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat stat-medium">
      <div class="stat-num">${medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat stat-total">
      <div class="stat-num">${total}</div>
      <div class="stat-label">Total Findings</div>
    </div>
  </div>

  ${total > 0 ? `
    <div class="section-header">
      <div class="section-title">
        <span>🔍</span>
        <span>Vulnerability Findings</span>
      </div>
      <div class="findings-count">${total} ${total === 1 ? 'issue' : 'issues'}</div>
    </div>
    <div class="findings-grid">
      ${findingCards}
    </div>
  ` : `
    <div class="empty">
      <div class="empty-icon">✅</div>
      <div class="empty-title">No Vulnerabilities Detected</div>
      <div class="empty-text">Your codebase is secure and looking great!</div>
    </div>
  `}
</body>
</html>`;
}
function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
// ─── Scan ───
async function scanDocument(doc) {
    const cfg = getConfig();
    const code = doc.getText();
    if (!code.trim())
        return;
    const docId = doc.uri.toString();
    const existing = abortControllers.get(docId);
    if (existing)
        existing.abort();
    const controller = new AbortController();
    abortControllers.set(docId, controller);
    const payload = { code, language: langIdFor(doc), filename: doc.fileName };
    if (cfg.provider)
        payload.provider = cfg.provider;
    if (cfg.model)
        payload.model = cfg.model;
    let resp;
    try {
        const r = await axios_1.default.post(`${cfg.serverUrl}/v2/scan`, payload, { timeout: 30_000, signal: controller.signal });
        resp = r.data;
    }
    catch (e) {
        if (e?.code === 'ERR_CANCELED' || e?.name === 'CanceledError')
            return;
        return;
    }
    finally {
        abortControllers.delete(docId);
    }
    totalScans++;
    const f = resp.finding;
    if (!f || !f.cwe)
        return;
    if (cfg.severityFilter.indexOf(f.severity ?? 'info') < 0)
        return;
    if ((f.confidence ?? 0) < cfg.minConfidence)
        return;
    findingsCache.set(docId, f);
    totalFindings++;
    const range = new vscode.Range(0, 0, 0, Math.max(1, code.split('\n')[0].length));
    const severityMap = {
        critical: vscode.DiagnosticSeverity.Error,
        high: vscode.DiagnosticSeverity.Error,
        medium: vscode.DiagnosticSeverity.Warning,
        low: vscode.DiagnosticSeverity.Information,
        info: vscode.DiagnosticSeverity.Information,
    };
    const sev = severityMap[f.severity || 'info'] ?? vscode.DiagnosticSeverity.Warning;
    const msg = [
        `${f.severity?.toUpperCase()} | ${f.cwe} | ${f.vulnerability}`,
        f.root_cause ? `Root: ${f.root_cause}` : '',
        f.secure_fix ? `Fix: ${f.secure_fix}` : '',
    ].filter(Boolean).join('\n');
    const diag = new vscode.Diagnostic(range, msg, sev);
    diag.code = f.cwe ?? 'RAKSHAK';
    diag.source = RAKSHAK_DIAG;
    diag.patched_code = f.patched_code;
    diag.vulnerability = f.vulnerability;
    diag.cwe = f.cwe;
    diag.root_cause = f.root_cause;
    const collection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
    collection.set(doc.uri, [diag]);
}
// ─── Diff Preview ───
function showDiffPreview(oldCode, newCode, explanation, fileName) {
    const panel = vscode.window.createWebviewPanel('rakshakai-diff', `RakshakAI Fix — ${fileName}`, vscode.ViewColumn.Beside, { enableScripts: false });
    const oldLines = oldCode.split('\n');
    const newLines = newCode.split('\n');
    let diffHtml = '';
    let adds = 0, dels = 0;
    const maxLen = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLen; i++) {
        const oldLine = oldLines[i] || '';
        const newLine = newLines[i] || '';
        const lineNum = String(i + 1).padStart(3);
        if (oldLine !== newLine) {
            if (oldLine) {
                diffHtml += `<div class="del"><span class="ln">${lineNum}</span> - ${escapeHtml(oldLine)}</div>`;
                dels++;
            }
            if (newLine) {
                diffHtml += `<div class="add"><span class="ln">${lineNum}</span> + ${escapeHtml(newLine)}</div>`;
                adds++;
            }
        }
        else {
            diffHtml += `<div class="ctx"><span class="ln">${lineNum}</span>   ${escapeHtml(oldLine)}</div>`;
        }
    }
    panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; font-size: 13px; }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
    .header h3 { font-size: 16px; font-weight: 700; color: #4ade80; }
    .badge { display: inline-block; background: #1f2937; border-radius: 12px; padding: 3px 10px; font-size: 11px; color: #9ca3af; }
    .badge.green { border: 1px solid #22c55e40; color: #4ade80; }
    .badge.red { border: 1px solid #ef444440; color: #f87171; }
    .explanation { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #4ade80; padding: 14px; border-radius: 8px; margin-bottom: 16px; font-family: -apple-system, sans-serif; font-size: 13px; color: #e5e5e5; line-height: 1.5; }
    .explanation strong { color: #4ade80; }
    .diff { border: 1px solid #30363d; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }
    .diff-header { background: #161b22; padding: 8px 12px; border-bottom: 1px solid #30363d; font-size: 11px; color: #888; display: flex; justify-content: space-between; }
    .add { background: #0d2818; padding: 2px 12px; border-left: 3px solid #22c55e; color: #4ade80; white-space: pre; }
    .del { background: #2d0f0f; padding: 2px 12px; border-left: 3px solid #ef4444; color: #f87171; white-space: pre; }
    .ctx { padding: 2px 12px; color: #555; white-space: pre; }
    .ln { color: #444; display: inline-block; width: 32px; text-align: right; margin-right: 12px; user-select: none; }
    .buttons { display: flex; gap: 10px; }
    button { padding: 10px 24px; border: none; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.15s; }
    button:hover { transform: translateY(-1px); }
    .accept { background: linear-gradient(135deg, #22c55e, #16a34a); color: white; box-shadow: 0 2px 8px rgba(34,197,94,0.3); }
    .reject { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
    .reject:hover { border-color: #ef4444; color: #f87171; }
  </style>
</head>
<body>
  <div class="header">
    <h3>🛡️ Security Fix</h3>
    <span class="badge green">+${adds} lines</span>
    <span class="badge red">-${dels} lines</span>
  </div>
  <div class="explanation"><strong>Fix:</strong> ${escapeHtml(explanation)}</div>
  <div class="diff">
    <div class="diff-header"><span>patched code</span><span>${escapeHtml(fileName)}</span></div>
    ${diffHtml}
  </div>
  <div class="buttons">
    <button class="accept">✅ Apply Fix</button>
    <button class="reject">❌ Cancel</button>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    document.querySelector('.accept').addEventListener('click', () => vscode.postMessage({ action: 'accept' }));
    document.querySelector('.reject').addEventListener('click', () => vscode.postMessage({ action: 'reject' }));
  </script>
</body>
</html>`;
    return new Promise((resolve) => {
        panel.webview.onDidReceiveMessage((msg) => { panel.dispose(); resolve(msg.action === 'accept'); });
        panel.onDidDispose(() => resolve(false));
    });
}
// ─── Fix with LLM ───
async function fixWithLLM(doc, diag) {
    const cfg = getConfig();
    const code = doc.getText();
    const f = findingsCache.get(doc.uri.toString()) || diag;
    const vuln = f.vulnerability || 'Unknown vulnerability';
    const cwe = f.cwe || diag.code || '';
    const rootCause = f.root_cause || '';
    vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `🛡️ Generating fix via ${cfg.provider}...` }, async () => {
        const payload = {
            code, language: langIdFor(doc),
            vulnerability: vuln, cwe: String(cwe), root_cause: rootCause,
            filename: doc.fileName,
        };
        if (cfg.provider)
            payload.provider = cfg.provider;
        if (cfg.model)
            payload.model = cfg.model;
        let fixResp;
        try {
            const r = await axios_1.default.post(`${cfg.serverUrl}/v2/fix`, payload, { timeout: 30_000 });
            fixResp = r.data;
        }
        catch (e) {
            vscode.window.showErrorMessage(`Fix failed: ${e?.message || 'server error'}`);
            return;
        }
        if (!fixResp.patched_code) {
            vscode.window.showWarningMessage('LLM did not return patched code.');
            return;
        }
        const accepted = await showDiffPreview(code, fixResp.patched_code, fixResp.explanation || 'Security fix applied', doc.fileName.split('/').pop() || doc.fileName);
        if (accepted) {
            const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(code.length));
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await editor.edit((eb) => eb.replace(fullRange, fixResp.patched_code));
            }
            vscode.window.showInformationMessage(`✅ Fix applied via ${fixResp.provider || cfg.provider}`);
        }
    });
}
// ─── Code Action ───
function applyPatchCommand(diag) {
    const fix = new vscode.CodeAction('🛡️ Fix with RakshakAI', vscode.CodeActionKind.QuickFix);
    fix.diagnostics = [diag];
    fix.isPreferred = true;
    fix.command = { title: 'Fix', command: 'rakshakai.fixIssue', arguments: [diag] };
    return fix;
}
function createNotionReportCommand(diag) {
    const action = new vscode.CodeAction('📋 Create Notion Report', vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diag];
    action.command = { title: 'Notion Report', command: 'rakshakai.notionReport', arguments: [diag] };
    return action;
}
// ─── Tree View ───
class FindingTreeItem extends vscode.TreeItem {
    label;
    collapsibleState;
    severity;
    uri;
    diagnostic;
    constructor(label, collapsibleState, severity, uri, diagnostic) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.severity = severity;
        this.uri = uri;
        this.diagnostic = diagnostic;
    }
}
class RakshakTreeProvider {
    _onDidChangeTreeData = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChangeTreeData.event;
    refresh() { this._onDidChangeTreeData.fire(undefined); }
    getTreeItem(el) { return el; }
    getChildren(element) {
        if (!element) {
            // Root level: show severity groups
            return this.getSeverityGroups();
        }
        else if (element.severity) {
            // Severity group: show files
            return this.getFilesForSeverity(element.severity);
        }
        else if (element.uri) {
            // File: show individual findings
            return this.getFindingsForFile(element.uri);
        }
        return [];
    }
    getSeverityGroups() {
        const allDiags = vscode.languages.getDiagnostics();
        const severityCounts = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0
        };
        for (const [_, diagList] of allDiags) {
            for (const d of diagList.filter(d => d.source === RAKSHAK_DIAG)) {
                const f = findingsCache.get(_.toString());
                const sev = f?.severity || 'info';
                severityCounts[sev]++;
            }
        }
        const groups = [];
        const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
        if (total === 0) {
            const welcome = new FindingTreeItem('✅ No vulnerabilities found', vscode.TreeItemCollapsibleState.None);
            welcome.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
            return [welcome];
        }
        const severityConfig = [
            { key: 'critical', label: 'Critical', icon: 'error', color: 'errorForeground' },
            { key: 'high', label: 'High', icon: 'warning', color: 'editorWarning.foreground' },
            { key: 'medium', label: 'Medium', icon: 'info', color: 'editorInfo.foreground' },
            { key: 'low', label: 'Low', icon: 'issue-opened', color: 'foreground' }
        ];
        for (const cfg of severityConfig) {
            const count = severityCounts[cfg.key];
            if (count > 0) {
                const item = new FindingTreeItem(`${cfg.label} (${count})`, vscode.TreeItemCollapsibleState.Expanded, cfg.key);
                item.iconPath = new vscode.ThemeIcon(cfg.icon, new vscode.ThemeColor(cfg.color));
                item.contextValue = 'severityGroup';
                groups.push(item);
            }
        }
        return groups;
    }
    getFilesForSeverity(severity) {
        const allDiags = vscode.languages.getDiagnostics();
        const items = [];
        for (const [uri, diagList] of allDiags) {
            const matchingDiags = diagList.filter(d => {
                if (d.source !== RAKSHAK_DIAG)
                    return false;
                const f = findingsCache.get(uri.toString());
                return f?.severity === severity;
            });
            if (matchingDiags.length > 0) {
                const fileName = uri.fsPath.split('/').pop() || uri.fsPath;
                const item = new FindingTreeItem(fileName, vscode.TreeItemCollapsibleState.Collapsed, severity, uri);
                item.iconPath = new vscode.ThemeIcon('file-code');
                item.description = `${matchingDiags.length} issue${matchingDiags.length > 1 ? 's' : ''}`;
                item.resourceUri = uri;
                item.command = { command: 'vscode.open', title: 'Open', arguments: [uri] };
                item.contextValue = 'findingFile';
                items.push(item);
            }
        }
        return items;
    }
    getFindingsForFile(uri) {
        const diagList = vscode.languages.getDiagnostics(uri);
        const items = [];
        for (const d of diagList.filter(d => d.source === RAKSHAK_DIAG)) {
            const f = findingsCache.get(uri.toString());
            const label = f?.vulnerability || d.message.split('|')[2]?.trim() || 'Unknown';
            const cwe = f?.cwe || d.code || '';
            const item = new FindingTreeItem(label, vscode.TreeItemCollapsibleState.None, f?.severity || undefined, uri, d);
            item.iconPath = new vscode.ThemeIcon('bug');
            item.description = String(cwe);
            item.tooltip = d.message;
            item.command = {
                command: 'rakshakai.showFindingDetails',
                title: 'Show Details',
                arguments: [uri, d]
            };
            item.contextValue = 'finding';
            items.push(item);
        }
        return items;
    }
}
// ─── Sidebar Webview Panel ───
class RakshakSidebarProvider {
    _extensionUri;
    constructor(_extensionUri) {
        this._extensionUri = _extensionUri;
    }
    resolveWebviewView(webviewView, _context, _token) {
        webviewView.webview.options = { enableScripts: true };
        webviewView.webview.html = this.getHtmlContent();
        // Handle messages from webview
        webviewView.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'scanFile':
                    vscode.commands.executeCommand('rakshakai.scanFile');
                    break;
                case 'scanWorkspace':
                    vscode.commands.executeCommand('rakshakai.scanWorkspace');
                    break;
                case 'dashboard':
                    vscode.commands.executeCommand('rakshakai.dashboard');
                    break;
                case 'chooseProvider':
                    vscode.commands.executeCommand('rakshakai.chooseProvider');
                    break;
            }
        });
    }
    getHtmlContent() {
        const allDiags = vscode.languages.getDiagnostics();
        let critical = 0, high = 0, medium = 0, low = 0;
        for (const [_, diagList] of allDiags) {
            for (const d of diagList.filter(d => d.source === RAKSHAK_DIAG)) {
                const f = findingsCache.get(_.toString());
                const sev = f?.severity || 'info';
                if (sev === 'critical')
                    critical++;
                else if (sev === 'high')
                    high++;
                else if (sev === 'medium')
                    medium++;
                else if (sev === 'low')
                    low++;
            }
        }
        const total = critical + high + medium + low;
        const cfg = getConfig();
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
      padding: 16px 12px;
      line-height: 1.5;
    }

    .header {
      text-align: center;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
    }

    .logo {
      font-size: 48px;
      margin-bottom: 8px;
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }

    .title {
      font-size: 18px;
      font-weight: 700;
      background: linear-gradient(135deg, #4ade80, #22d3ee);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 4px;
    }

    .subtitle {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      opacity: 0.8;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-bottom: 20px;
    }

    .stat-card {
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 8px;
      padding: 12px;
      text-align: center;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .stat-card:hover {
      border-color: var(--vscode-focusBorder);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }

    .stat-number {
      font-size: 28px;
      font-weight: 800;
      line-height: 1;
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      opacity: 0.7;
      font-weight: 600;
    }

    .stat-critical .stat-number { color: #ef4444; }
    .stat-high .stat-number { color: #f97316; }
    .stat-medium .stat-number { color: #eab308; }
    .stat-total .stat-number { color: #4ade80; }

    .progress-bar {
      height: 6px;
      background: var(--vscode-editor-background);
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 20px;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #4ade80, #22d3ee);
      transition: width 0.3s ease;
      animation: shimmer 2s infinite;
    }

    @keyframes shimmer {
      0% { background-position: -100% 0; }
      100% { background-position: 100% 0; }
    }

    .action-section {
      margin-bottom: 20px;
    }

    .section-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--vscode-descriptionForeground);
      margin-bottom: 10px;
      font-weight: 600;
    }

    .action-btn {
      width: 100%;
      padding: 12px 16px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-bottom: 8px;
    }

    .action-btn:hover {
      background: var(--vscode-button-hoverBackground);
      transform: translateY(-1px);
      box-shadow: 0 2px 6px rgba(0,0,0,0.2);
    }

    .action-btn:active {
      transform: translateY(0);
    }

    .action-btn.secondary {
      background: var(--vscode-editor-background);
      color: var(--vscode-foreground);
      border: 1px solid var(--vscode-panel-border);
    }

    .action-btn.secondary:hover {
      background: var(--vscode-list-hoverBackground);
    }

    .provider-info {
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 11px;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .provider-label {
      color: var(--vscode-descriptionForeground);
    }

    .provider-value {
      color: #4ade80;
      font-weight: 600;
    }

    .status-indicator {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #4ade80;
      margin-right: 6px;
      animation: blink 1.5s ease-in-out infinite;
    }

    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }

    .empty-state {
      text-align: center;
      padding: 32px 16px;
      color: var(--vscode-descriptionForeground);
    }

    .empty-icon {
      font-size: 48px;
      margin-bottom: 12px;
      opacity: 0.5;
    }

    @media (max-width: 300px) {
      .stats-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🛡️</div>
    <div class="title">RakshakAI</div>
    <div class="subtitle">Security Code Scanner</div>
  </div>

  <div class="provider-info">
    <span class="provider-label">
      <span class="status-indicator"></span>Provider
    </span>
    <span class="provider-value">${cfg.provider}</span>
  </div>

  ${total > 0 ? `
    <div class="stats-grid">
      <div class="stat-card stat-critical">
        <div class="stat-number">${critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-number">${high}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="stat-number">${medium}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card stat-total">
        <div class="stat-number">${total}</div>
        <div class="stat-label">Total</div>
      </div>
    </div>

    <div class="progress-bar">
      <div class="progress-fill" style="width: ${Math.min(100, (critical + high) * 10)}%"></div>
    </div>
  ` : `
    <div class="empty-state">
      <div class="empty-icon">✅</div>
      <div>No vulnerabilities detected</div>
      <div style="font-size: 10px; margin-top: 4px; opacity: 0.6;">Your code is secure!</div>
    </div>
  `}

  <div class="action-section">
    <div class="section-title">Quick Actions</div>
    <button class="action-btn" onclick="scanFile()">
      <span>🔍</span>
      <span>Scan Current File</span>
    </button>
    <button class="action-btn secondary" onclick="scanWorkspace()">
      <span>📂</span>
      <span>Scan Workspace</span>
    </button>
    <button class="action-btn secondary" onclick="openDashboard()">
      <span>📊</span>
      <span>Open Dashboard</span>
    </button>
  </div>

  <div class="action-section">
    <div class="section-title">Settings</div>
    <button class="action-btn secondary" onclick="chooseProvider()">
      <span>⚙️</span>
      <span>Change Provider</span>
    </button>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    function scanFile() { vscode.postMessage({ command: 'scanFile' }); }
    function scanWorkspace() { vscode.postMessage({ command: 'scanWorkspace' }); }
    function openDashboard() { vscode.postMessage({ command: 'dashboard' }); }
    function chooseProvider() { vscode.postMessage({ command: 'chooseProvider' }); }
  </script>
</body>
</html>`;
    }
}
// ─── Activate ───
function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection(RAKSHAK_DIAG);
    const treeProvider = new RakshakTreeProvider();
    vscode.window.registerTreeDataProvider('rakshak-files', treeProvider);
    // Register sidebar webview provider
    const sidebarProvider = new RakshakSidebarProvider(context.extensionUri);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider('rakshak-sidebar', sidebarProvider));
    const cfg = getConfig();
    // ─── Commands ───
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanFile', async () => {
        const ed = vscode.window.activeTextEditor;
        if (ed) {
            await scanDocument(ed.document);
            treeProvider.refresh();
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.scanWorkspace', async () => {
        const docs = vscode.workspace.textDocuments;
        vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: '🛡️ Scanning workspace...' }, async () => {
            for (const d of docs)
                await scanDocument(d);
            treeProvider.refresh();
        });
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.showFindingDetails', (uri, diag) => {
        const f = findingsCache.get(uri.toString());
        if (!f) {
            vscode.window.showInformationMessage('No detailed information available.');
            return;
        }
        const panel = vscode.window.createWebviewPanel('rakshakai-details', `🛡️ ${f.vulnerability}`, vscode.ViewColumn.Beside, { enableScripts: false });
        panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
      background: #0d1117; 
      color: #e5e5e5; 
      padding: 24px;
      line-height: 1.6;
    }
    .header {
      background: linear-gradient(135deg, #ef444420, #f9731620);
      border: 1px solid ${f.severity === 'critical' ? '#ef4444' : '#f97316'}40;
      border-left: 4px solid ${f.severity === 'critical' ? '#ef4444' : '#f97316'};
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 24px;
    }
    .severity {
      display: inline-block;
      background: ${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#eab308'};
      color: white;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    h1 {
      font-size: 24px;
      color: #e5e5e5;
      margin-bottom: 8px;
    }
    .cwe {
      color: #888;
      font-size: 13px;
    }
    .section {
      background: #161b22;
      border: 1px solid #30363d;
      padding: 18px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    .section-title {
      color: #4ade80;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 10px;
    }
    .content {
      color: #c9d1d9;
      font-size: 14px;
    }
    .code {
      background: #0d1117;
      border: 1px solid #30363d;
      padding: 14px;
      border-radius: 6px;
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 13px;
      color: #4ade80;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .confidence {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 12px;
    }
    .confidence-bar {
      flex: 1;
      height: 8px;
      background: #21262d;
      border-radius: 4px;
      overflow: hidden;
    }
    .confidence-fill {
      height: 100%;
      background: linear-gradient(90deg, #4ade80, #22d3ee);
      width: ${(f.confidence * 100).toFixed(0)}%;
    }
    .confidence-value {
      font-weight: 700;
      color: #4ade80;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="severity">${f.severity}</div>
    <h1>${escapeHtml(f.vulnerability || 'Security Issue')}</h1>
    <div class="cwe">${escapeHtml(f.cwe || 'Unknown CWE')}</div>
    <div class="confidence">
      <span style="font-size: 12px; color: #888;">Confidence:</span>
      <div class="confidence-bar">
        <div class="confidence-fill"></div>
      </div>
      <span class="confidence-value">${(f.confidence * 100).toFixed(0)}%</span>
    </div>
  </div>

  ${f.root_cause ? `
    <div class="section">
      <div class="section-title">🔍 Root Cause</div>
      <div class="content">${escapeHtml(f.root_cause)}</div>
    </div>
  ` : ''}

  ${f.attack_scenario ? `
    <div class="section">
      <div class="section-title">⚔️ Attack Scenario</div>
      <div class="content">${escapeHtml(f.attack_scenario)}</div>
    </div>
  ` : ''}

  ${f.secure_fix ? `
    <div class="section">
      <div class="section-title">✅ Recommended Fix</div>
      <div class="content">${escapeHtml(f.secure_fix)}</div>
    </div>
  ` : ''}

  ${f.patched_code ? `
    <div class="section">
      <div class="section-title">💻 Patched Code</div>
      <div class="code">${escapeHtml(f.patched_code.slice(0, 500))}${f.patched_code.length > 500 ? '...' : ''}</div>
    </div>
  ` : ''}

  ${f.references && f.references.length > 0 ? `
    <div class="section">
      <div class="section-title">📚 References</div>
      <div class="content">
        ${f.references.map(ref => `<div style="margin-bottom: 4px;">• <a href="${ref}" style="color: #22d3ee;">${ref}</a></div>`).join('')}
      </div>
    </div>
  ` : ''}
</body>
</html>`;
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.showLastFinding', () => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const diags = vscode.languages.getDiagnostics(ed.document.uri);
        const mine = diags.filter(d => d.source === RAKSHAK_DIAG);
        if (!mine.length) {
            vscode.window.showInformationMessage('No findings for this file.');
            return;
        }
        const panel = vscode.window.createWebviewPanel('rakshakai', 'RakshakAI Findings', vscode.ViewColumn.Beside, { enableScripts: false });
        panel.webview.html = `<pre style="white-space:pre-wrap;font-family:monospace">${mine.map(d => d.message).join('\n\n---\n\n')}</pre>`;
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.fixIssue', async (diag) => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        await fixWithLLM(ed.document, diag);
        treeProvider.refresh();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.applyPatch', async (diag) => {
        const ed = vscode.window.activeTextEditor;
        if (!ed)
            return;
        const patched = diag.patched_code;
        if (!patched) {
            vscode.window.showInformationMessage('No patch available. Use "Fix with RakshakAI" for AI fix.');
            return;
        }
        const fullRange = new vscode.Range(ed.document.positionAt(0), ed.document.positionAt(ed.document.getText().length));
        await ed.edit(b => b.replace(fullRange, patched));
        treeProvider.refresh();
    }));
    // ─── Provider Picker ───
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.chooseProvider', async () => {
        const providers = ['ollama', 'groq', 'fireworks', 'nebius', 'huggingface'];
        const labels = {
            ollama: '🦙 Ollama — Local, Free, Private',
            groq: '⚡ Groq — Fast, Free Tier',
            fireworks: '🔥 Fireworks AI — Paid, Fast',
            nebius: '🌐 Nebius — Kimi K2.7, Qwen 3.5',
            huggingface: '🤗 HuggingFace — Free Tier',
        };
        const chosen = await vscode.window.showQuickPick(providers.map(p => ({ label: labels[p], description: p })), { placeHolder: 'Select LLM provider', title: '🛡️ Choose Provider' });
        if (!chosen)
            return;
        const provider = chosen.description;
        let models = [];
        try {
            const r = await axios_1.default.get(`${cfg.serverUrl}/v2/providers`, { timeout: 5_000 });
            models = r.data[provider]?.models || [];
        }
        catch {
            models = [{ id: 'default', name: 'Default', speed: 'fast' }];
        }
        const picked = await vscode.window.showQuickPick(models.map(m => ({
            label: `$(rocket) ${m.name}`,
            description: m.id,
            detail: `Speed: ${m.speed}`,
        })), { placeHolder: `Select model for ${provider}`, title: '🛡️ Choose Model' });
        const model = picked?.description || '';
        await vscode.workspace.getConfiguration('rakshakai').update('provider', provider, vscode.ConfigurationTarget.Global);
        await vscode.workspace.getConfiguration('rakshakai').update('model', model, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`🛡️ Provider: ${provider} | Model: ${model || 'default'}`);
        treeProvider.refresh();
    }));
    // ─── Dashboard ───
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.dashboard', () => {
        const panel = vscode.window.createWebviewPanel('rakshakai-dashboard', '🛡️ RakshakAI Dashboard', vscode.ViewColumn.One, { enableScripts: false });
        const findings = [];
        for (const [uri, diagList] of vscode.languages.getDiagnostics()) {
            for (const d of diagList) {
                if (d.source === RAKSHAK_DIAG) {
                    const f = findingsCache.get(uri.toString());
                    if (f)
                        findings.push({ file: uri.fsPath, finding: f });
                }
            }
        }
        panel.webview.html = getDashboardHtml(findings, cfg.provider);
    }));
    // ─── Code Actions ───
    const langs = ['python', 'javascript', 'typescript', 'java', 'go', 'rust', 'c', 'cpp', 'php', 'csharp', 'ruby'];
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider(langs, {
        provideCodeActions: (_doc, _range, ctx) => ctx.diagnostics
            .filter(d => d.source === RAKSHAK_DIAG)
            .flatMap(d => [applyPatchCommand(d), createNotionReportCommand(d)]),
    }));
    // ─── Notion Integration ───
    context.subscriptions.push(vscode.commands.registerCommand('rakshakai.notionReport', async (diag) => {
        const cfg = getConfig();
        const ed = vscode.window.activeTextEditor;
        const docUri = ed?.document.uri.toString() || '';
        const f = findingsCache.get(docUri) || diag;
        const payload = {
            title: f.vulnerability || diag.message.split('\n')[0] || 'Security Finding',
            severity: (f.severity || 'medium').charAt(0).toUpperCase() + (f.severity || 'medium').slice(1),
            confidence: f.confidence || 0.8,
            cwe_id: f.cwe || diag.code || '',
            vulnerability_type: f.vulnerability || '',
            repository: ed ? ed.document.uri.fsPath.split('/').slice(-3, -1).join('/') : '',
            file_path: ed ? ed.document.fileName : '',
            line_number: diag.range.start.line + 1,
            language: ed ? ed.document.languageId : '',
            root_cause: f.root_cause || '',
            attack_scenario: f.attack_scenario || '',
            secure_fix: f.secure_fix || '',
            patched_code: f.patched_code || '',
            original_code: ed ? ed.document.getText(diag.range) : '',
            references: f.references || [],
            tags: [ed?.document.languageId || 'unknown'],
        };
        try {
            const r = await axios_1.default.post(`${cfg.serverUrl}/v2/notion/report`, payload, { timeout: 15_000 });
            const url = r.data.url;
            vscode.window.showInformationMessage(`📋 Notion Report Created`, 'Open in Notion').then(choice => {
                if (choice && url)
                    vscode.env.openExternal(url);
            });
        }
        catch (e) {
            vscode.window.showErrorMessage(`Notion: ${e?.response?.data?.detail || e?.message || 'failed'}`);
        }
    }));
    // ─── Events ───
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (getConfig().scanOnSave) {
            await scanDocument(doc);
            treeProvider.refresh();
        }
    }));
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument(doc => {
        findingsCache.delete(doc.uri.toString());
        abortControllers.delete(doc.uri.toString());
        diagnosticCollection.delete(doc.uri);
        treeProvider.refresh();
    }));
    // ─── Status Bar ───
    const sb = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    sb.text = '$(shield) Rakshak';
    sb.tooltip = `Provider: ${cfg.provider} | Click to scan`;
    sb.command = 'rakshakai.scanFile';
    sb.show();
    context.subscriptions.push(sb);
}
function deactivate() {
    for (const c of abortControllers.values())
        c.abort();
    abortControllers.clear();
    findingsCache.clear();
}

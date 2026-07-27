#!/usr/bin/env node
/**
 * RakshakAI — full-stack server with web UI + AI API endpoints.
 * Serves modern chat UI, Groq-powered AI, Modal model endpoint, and code scanning.
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { scanProject } = require("./scanner");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const GROQ_API_KEY = process.env.GROQ_API_KEY || "";
const MODAL_API_URL = "https://alimuneerali245--rakshak-api-rakshakmodel-analyze-endpoint.modal.run";

const MIME = {
  ".html": "text/html", ".css": "text/css", ".js": "application/javascript",
  ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function serveStatic(req, res) {
  let filePath = path.join(PUBLIC_DIR, req.url === "/" ? "index.html" : req.url);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end("Forbidden");
  }
  const ext = path.extname(filePath);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404); return res.end("Not found");
    }
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try { resolve(JSON.parse(body)); }
      catch (e) { reject(new Error("Invalid JSON")); }
    });
  });
}

// ── Groq API call ──
async function callGroq(messages, model = "llama-3.3-70b-versatile") {
  const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${GROQ_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: "system",
          content: `You are RakshakAI, a security-specialized code analysis model.
Analyze code for vulnerabilities. Think step by step, then respond with JSON:
{
  "is_vulnerable": true/false,
  "vulnerability_type": "CWE-XXX or null",
  "severity": "critical|high|medium|low|clean",
  "explanation": "root cause",
  "attack_scenario": "how to exploit",
  "secure_fix": "how to fix"
}`
        },
        ...messages,
      ],
      temperature: 0.1,
      max_tokens: 2048,
    }),
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Groq ${resp.status}: ${err.slice(0, 200)}`);
  }
  return resp.json();
}

// ── Modal API call ──
async function callModal(code, lang) {
  const resp = await fetch(MODAL_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: code.slice(0, 4000), language: lang, max_tokens: 1024 }),
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) throw new Error(`Modal ${resp.status}`);
  return resp.json();
}

function startServer() {
  const server = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204); return res.end();
    }

    // ── API Routes ──

    // Chat with AI (Groq)
    if (req.url === "/api/chat" && req.method === "POST") {
      parseBody(req).then(async body => {
        try {
          const model = body.model || "llama-3.3-70b-versatile";
          const messages = body.messages || [];
          const data = await callGroq(messages, model);
          const content = data.choices?.[0]?.message?.content || "";

          // Extract thinking blocks
          const thinkMatch = content.match(/<think>([\s\S]*?)<\/think>/);
          const thinking = thinkMatch ? [thinkMatch[1].trim()] : [];
          const cleanContent = content.replace(/<think>[\s\S]*?<\/think>/g, "").trim();

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            content: cleanContent || content,
            thinking,
            model: data.model,
            usage: data.usage,
          }));
        } catch (e) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: e.message }));
        }
      }).catch(e => {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      });
      return;
    }

    // Scan with RakshakAI 14B (Modal)
    if (req.url === "/api/scan-ai" && req.method === "POST") {
      parseBody(req).then(async body => {
        try {
          const code = (body.code || body.content || "").slice(0, 4000);
          const lang = body.language || "python";
          const data = await callModal(code, lang);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(data));
        } catch (e) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: e.message }));
        }
      }).catch(e => {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      });
      return;
    }

    // Local regex scan
    if (req.url === "/api/scan" && req.method === "POST") {
      parseBody(req).then(body => {
        try {
          const scanPath = body.path || ".";
          const result = scanProject(scanPath);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: e.message }));
        }
      }).catch(e => {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      });
      return;
    }

    // Models list
    if (req.url === "/api/models") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        models: [
          { id: "groq-llama-70b", name: "Llama 3.3 70B (Groq)", provider: "groq" },
          { id: "groq-llama-8b", name: "Llama 3.1 8B (Groq)", provider: "groq" },
          { id: "rakshak-14b", name: "RakshakAI 14B (Modal)", provider: "modal" },
        ]
      }));
      return;
    }

    // Health
    if (req.url === "/api/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok", version: "2.0.0",
        groq: !!GROQ_API_KEY,
        modal: true,
      }));
      return;
    }

    // Static files
    serveStatic(req, res);
  });

  server.listen(PORT, () => {
    const url = `http://localhost:${PORT}`;
    console.log(`\n  ▲ RakshakAI Server v2`);
    console.log(`  ─────────────────────`);
    console.log(`  Web UI:  ${url}`);
    console.log(`  Health:  ${url}/api/health`);
    console.log(`  Groq:    ${GROQ_API_KEY ? "✓ connected" : "✗ no key"}`);
    console.log(`  Modal:   ${MODAL_API_URL ? "✓ configured" : "✗ no endpoint"}`);
    console.log();
  });
}

module.exports = { startServer };

if (require.main === module) {
  startServer();
}

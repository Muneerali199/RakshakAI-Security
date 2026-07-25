#!/usr/bin/env node
const { execSync } = require("child_process");
try {
  execSync("pip3 --version", { stdio: "ignore" });
  console.log("  \x1b[36m\u25b6 Installing Python AI dependencies...\x1b[0m");
  execSync("pip3 install --upgrade pip 2>/dev/null", { stdio: "ignore" });
  execSync("pip3 install rich openai pygments watchdog GitPython httpx requests", { stdio: "inherit" });
  console.log("  \x1b[32m\u2713 AI dependencies ready\x1b[0m");
  console.log("  \x1b[90m  Run 'rakshak chat' for AI chat, 'rakshak scan <file>' for scanning\x1b[0m");
} catch (_) {}

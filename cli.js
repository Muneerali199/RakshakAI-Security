#!/usr/bin/env node
/**
 * RakshakAI — Unified CLI.
 * npm install -g rakshakai installs everything automatically.
 *
 * Commands:
 *   rakshak scan <file|dir>    Scan for vulnerabilities
 *   rakshak chat               AI chat with 65+ models
 *   rakshak server             Web UI at localhost:3000
 *   rakshak models             Browse models
 *   rakshak --help             Show help
 */
const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const PKG_DIR = __dirname;
const PY_MODULE = path.join(PKG_DIR, "v2", "cli", "main.py");
const SCANNER = path.join(PKG_DIR, "scanner.js");

function hasPython() {
  try { execSync("python3 --version", { stdio: "ignore" }); return true; }
  catch { return false; }
}

function hasPyModule() {
  if (!fs.existsSync(PY_MODULE)) return false;
  try {
    execSync('python3 -c "import v2.cli.main"', { stdio: "ignore", cwd: PKG_DIR,
      env: { ...process.env, PYTHONPATH: PKG_DIR + ":" + (process.env.PYTHONPATH || "") } });
    return true;
  } catch { return false; }
}

function ensurePyModule() {
  if (hasPyModule()) return true;
  if (!hasPython()) {
    console.log("  \x1b[33m⚠ Python 3.9+ not found. Chat requires Python.\x1b[0m");
    console.log("  \x1b[90m  Install: https://python.org or: brew install python\x1b[0m");
    console.log("  \x1b[90m  Scanner still works: rakshak scan <file>\x1b[0m\n");
    return false;
  }
  console.log("  \x1b[36m▶ Auto-installing Python AI dependencies...\x1b[0m\n");
  try {
    execSync("pip3 install --upgrade pip 2>/dev/null", { stdio: "ignore" });
    execSync("pip3 install rich openai pygments watchdog GitPython httpx requests", { stdio: "inherit" });
    if (fs.existsSync(PY_MODULE)) {
      execSync("pip3 install -e " + PKG_DIR + " 2>/dev/null", { stdio: "ignore" });
    }
    console.log("\n  \x1b[32m✓ AI dependencies installed. Enjoy!\x1b[0m\n");
    return true;
  } catch (e) {
    console.log("  \x1b[33m⚠ Auto-install failed. Run 'rakshak install' manually.\x1b[0m");
    console.log("  \x1b[90m  pip3 install rich openai pygments watchdog GitPython httpx requests\x1b[0m\n");
    return false;
  }
}

function runPython(args) {
  const child = spawn("python3", [PY_MODULE, ...args], {
    stdio: "inherit", cwd: PKG_DIR,
    env: { ...process.env, PYTHONPATH: PKG_DIR + ":" + (process.env.PYTHONPATH || "") },
  });
  child.on("exit", (code) => process.exit(code));
}

function runScanner(target, opts) {
  if (!fs.existsSync(SCANNER)) {
    console.error("Scanner module not found. Reinstall rakshakai.");
    process.exit(1);
  }
  const args = [SCANNER, target];
  if (opts.format) args.push("--format", opts.format);
  const child = spawn("node", args, { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code));
}

function startServer() {
  try {
    const { startServer } = require("./server");
    startServer().then((url) => {
      console.log(`\n  🔒 RakshakAI running at ${url}\n  Press Ctrl+C to stop\n`);
      try { require("open")(url); } catch {}
    });
  } catch (e) {
    console.error("Failed to start server:", e.message);
    process.exit(1);
  }
}

function listModels() {
  if (ensurePyModule()) { runPython(["--models"]); return; }
  const sample = [
    ["Claude 3.5 Sonnet", "Anthropic"], ["GPT-4o", "OpenAI"],
    ["Gemini 1.5 Pro", "Google"], ["DeepSeek V3", "DeepSeek"],
  ];
  console.log("\n  \x1b[1mRakshakAI — 65+ Models, 9 Providers\x1b[0m");
  console.log("  \x1b[90mInstall Python deps for full list: rakshak install\x1b[0m\n");
  for (const [n, p] of sample) console.log(`  \x1b[36m•\x1b[0m ${n}  \x1b[90m(${p})\x1b[0m`);
  console.log("");
}

function installDeps() {
  ensurePyModule();
}

function printHelp() {
  const help = `
  \x1b[1mRakshakAI\x1b[0m — AI Security Scanner & Chat

  \x1b[1mUsage:\x1b[0m
    rakshak scan <file|dir>    \x1b[90mScan for vulnerabilities\x1b[0m
    rakshak chat               \x1b[90mAI chat with 65+ models\x1b[0m
    rakshak server             \x1b[90mWeb UI at localhost:3000\x1b[0m
    rakshak models             \x1b[90mBrowse available models\x1b[0m
    rakshak install            \x1b[90m(Re)install Python AI deps\x1b[0m
    rakshak --help             \x1b[90mThis help\x1b[0m

  \x1b[1mScan Options:\x1b[0m
    --json     \x1b[90mJSON output\x1b[0m
    --model    \x1b[90mUse specific AI model\x1b[0m

  \x1b[1mExamples:\x1b[0m
    rakshak scan app.py           \x1b[90mScan file\x1b[0m
    rakshak scan src/ --json      \x1b[90mScan dir as JSON\x1b[0m
    rakshak chat                  \x1b[90mAI chat REPL\x1b[0m
    npm install -g rakshakai      \x1b[90mEverything above in one command\x1b[0m

  \x1b[90mhttps://github.com/Muneerali199/RakshakAI\x1b[0m
`;
  console.log(help);
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (!cmd || cmd === "--help" || cmd === "-h") { printHelp(); return; }

  switch (cmd) {
    case "scan": {
      const target = args[1];
      if (!target) { console.error("Usage: rakshak scan <file|dir>"); process.exit(1); }
      const useJson = args.includes("--json");
      const useAI = args.includes("--model");
      if (useAI && hasPyModule()) {
        const pyArgs = ["--no-interactive", "scan", target];
        if (useJson) pyArgs.push("--json");
        runPython(pyArgs);
      } else {
        runScanner(target, { format: useJson ? "json" : "table" });
      }
      break;
    }
    case "chat":
      if (ensurePyModule()) runPython([]);
      break;
    case "server":
      startServer();
      break;
    case "models":
      listModels();
      break;
    case "install":
      ensurePyModule();
      break;
    default:
      if (hasPyModule()) { runPython(args); }
      else { console.error(`\x1b[31m✖ Unknown: ${cmd}\x1b[0m`); printHelp(); process.exit(1); }
  }
}

main().catch((e) => { console.error(e.message); process.exit(1); });

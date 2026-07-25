#!/usr/bin/env bash
#
# RakshakAI — Hackathon Demo Launcher
# Starts the backend server + VS Code extension with one command.
#
# Usage:
#   ./hackathon.sh          Launch everything
#   ./hackathon.sh --stop   Stop the server
#
set -e

# ── Handle --stop flag ──────────────────────────────────────
if [ "$1" = "--stop" ]; then
    if [ -f /tmp/rakshakai_server.pid ]; then
        PID=$(cat /tmp/rakshakai_server.pid)
        kill $PID 2>/dev/null && echo "✅ Server stopped" || echo "⚠ Server not running"
        rm -f /tmp/rakshakai_server.pid
    else
        echo "⚠ No running server found"
    fi
    exit 0
fi

GREEN='\033[0;32m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

cd "$(dirname "$0")"

# ── Banner ──────────────────────────────────────────────────
echo ""
echo -e "${CYAN}  ██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗${NC}"
echo -e "${CYAN}  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║ ██╔╝██╔══██╗██║${NC}"
echo -e "${PURPLE}  ██████╔╝███████║█████╔╝ ███████╗█████╔╝ ███████║██║${NC}"
echo -e "${PURPLE}  ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔═██╗ ██╔══██║██║${NC}"
echo -e "${YELLOW}  ██║  ██║██║  ██║██║  ██╗███████║██║  ██╗██║  ██║███████╗${NC}"
echo -e "${YELLOW}  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝${NC}"
echo ""
echo -e "  ${BOLD}India's First Open Security AI${NC}"
echo -e "  ${GREEN}रक्षक${NC} — \"Protector\" in Sanskrit"
echo ""

# ── Check Dependencies ──────────────────────────────────────
echo -e "${CYAN}▶${NC} Checking dependencies..."

command -v python3 >/dev/null 2>&1 || { echo "❌ python3 not found"; exit 1; }
command -v code >/dev/null 2>&1 || { echo "❌ 'code' CLI not found. Install VS Code and run 'Shell Command: Install code command in PATH'"; exit 1; }

echo -e "  ${GREEN}✓${NC} python3 $(python3 --version | cut -d' ' -f2)"
echo -e "  ${GREEN}✓${NC} code CLI available"

# ── Install Python Dependencies ──────────────────────────────
echo ""
echo -e "${CYAN}▶${NC} Checking Python dependencies..."
if [ ! -f "requirements.txt" ]; then
    echo -e "  ${YELLOW}⚠${NC} requirements.txt not found, skipping"
else
    pip3 install -q -r requirements.txt 2>&1 | tail -1
    echo -e "  ${GREEN}✓${NC} Python dependencies ready"
fi

# ── Kill any existing server on port 3000 ────────────────────
EXISTING_PID=$(lsof -ti:3000 2>/dev/null || true)
if [ -n "$EXISTING_PID" ]; then
    echo ""
    echo -e "${YELLOW}⚠${NC} Port 3000 in use (PID $EXISTING_PID) — killing..."
    kill -9 $EXISTING_PID 2>/dev/null || true
    sleep 1
fi

# ── Start Backend Server ─────────────────────────────────────
echo ""
echo -e "${CYAN}▶${NC} Starting RakshakAI inference server on ${BOLD}http://127.0.0.1:3000${NC}..."
RAKSHAK_MOCK=1 python3 -m uvicorn server:app --port 3000 --host 0.0.0.0 &
SERVER_PID=$!
echo -e "  ${GREEN}✓${NC} Server PID: $SERVER_PID"

# ── Wait for Server ──────────────────────────────────────────
echo ""
echo -ne "${CYAN}▶${NC} Waiting for server to be ready..."
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:3000/ml/health >/dev/null 2>&1; then
        echo -e " ${GREEN}ready!${NC}"
        break
    fi
    echo -n "."
    sleep 0.5
done
echo ""

# ── Check if server started ─────────────────────────────────
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo ""
    echo -e "  ${YELLOW}⚠${NC} Server may have failed to start. Check server.py for errors."
    echo -e "  ${YELLOW}⚠${NC} The extension will use mock mode (no ML model loaded)."
fi

# ── Health Check ─────────────────────────────────────────────
ENGINE=$(curl -s http://127.0.0.1:3000/ml/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('engine','unknown'))" 2>/dev/null || echo "unknown")
echo -e "  ${GREEN}✓${NC} Engine mode: ${BOLD}$ENGINE${NC}"

# ── Launch VS Code ───────────────────────────────────────────
echo ""
echo -e "${CYAN}▶${NC} Opening VS Code with Rakshak extension + demo files..."
echo ""

code --extensionDevelopmentPath=/Users/macbook/Desktop/Rakshak \
     --new-window \
     /Users/macbook/Desktop/RakshakAI

# ── Info ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  ✅ ${BOLD}RakshakAI is LIVE!${NC}                                      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                         ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}Server:${NC}    http://127.0.0.1:3000                           ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}Health:${NC}    http://127.0.0.1:3000/ml/health                  ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${CYAN}Scan API:${NC}  POST http://127.0.0.1:3000/api/scan              ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                         ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${YELLOW}In VS Code:${NC}                                                  ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  1. Open ${BOLD}demo_vulnerable.py${NC} from the file tree            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  2. See issues highlighted in real-time                    ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  3. Hover over issues for details + fix                    ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  4. Click the lightbulb (💡) to auto-apply fixes            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  5. Check the Rakshak tab in Activity Bar (left side)      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}                                                         ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  ${PURPLE}To stop:${NC}   ./hackathon.sh --stop                            ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Save PID for cleanup ────────────────────────────────────
echo "$SERVER_PID" > /tmp/rakshakai_server.pid

# ── Trap exit to clean up ────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}▶${NC} Shutting down RakshakAI server..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    echo -e "${GREEN}✓${NC} Server stopped. Goodbye! 👋"
    rm -f /tmp/rakshakai_server.pid
}
trap cleanup EXIT INT TERM

# ── Wait for VS Code to close (optional) ────────────────────
echo -e "${CYAN}▶${NC} VS Code is open. Close it or press Ctrl+C to stop the server."
echo ""
wait $SERVER_PID 2>/dev/null || true

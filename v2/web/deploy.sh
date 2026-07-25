#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# RakshakAI Auth Server — Deploy Script
# ──────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${CYAN}  RakshakAI Auth Server — Deploy${RESET}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Detect project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── 1. Dependencies ───────────────────────────

echo -e "${BOLD}${YELLOW}[1/5] Checking dependencies...${RESET}"
cd "$PROJECT_ROOT"

# Check Python3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}✗ python3 not found. Install Python 3.9+${RESET}"
    exit 1
fi

# Install requirements
if [ ! -f "requirements.txt" ] || ! grep -q "fastapi" requirements.txt 2>/dev/null; then
    echo "fastapi>=0.104.0" >> requirements.txt
    echo "uvicorn>=0.24.0" >> requirements.txt
fi

pip3 install -q fastapi uvicorn bcrypt 2>/dev/null || pip3 install fastapi uvicorn bcrypt
echo -e "${GREEN}✓ Dependencies installed${RESET}"

# ── 2. Default Config ─────────────────────────

echo -e "${BOLD}${YELLOW}[2/5] Checking configuration...${RESET}"

if [ -z "${RAKSHAK_JWT_SECRET:-}" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo -e "${YELLOW}  ⚠ RAKSHAK_JWT_SECRET not set — generating random one${RESET}"
    echo -e "  ${BOLD}Add to ~/.zshrc or ~/.bashrc:${RESET}"
    echo -e "  ${CYAN}export RAKSHAK_JWT_SECRET=\"$SECRET\"${RESET}"
fi

# ── 3. Bcrypt Check ───────────────────────────

echo -e "${BOLD}${YELLOW}[3/5] Verifying bcrypt...${RESET}"
if python3 -c "import bcrypt" 2>/dev/null; then
    echo -e "${GREEN}✓ bcrypt available — passwords will be hashed securely${RESET}"
else
    echo -e "${RED}✗ bcrypt not installed! Run: pip3 install bcrypt${RESET}"
    echo -e "${RED}  Without bcrypt, the auth server will refuse to start.${RESET}"
    exit 1
fi

# ── 4. Firewall / Port ────────────────────────

PORT="${RAKSHAK_AUTH_PORT:-8888}"
echo -e "${BOLD}${YELLOW}[4/5] Checking port ${PORT}...${RESET}"

if lsof -i:$PORT &>/dev/null 2>&1; then
    echo -e "${YELLOW}  ⚠ Port ${PORT} is in use. Set RAKSHAK_AUTH_PORT to a different value.${RESET}"
else
    echo -e "${GREEN}✓ Port ${PORT} is available${RESET}"
fi

echo -e ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN}  Ready to deploy!${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e ""
echo -e "  ${BOLD}Start the server:${RESET}"
echo -e "  ${CYAN}python3 -m v2.web.server${RESET}"
echo -e ""
echo -e "  ${BOLD}Or with gunicorn (recommended for production):${RESET}"
echo -e "  ${CYAN}pip3 install gunicorn${RESET}"
echo -e "  ${CYAN}gunicorn v2.web.server:app \\"
echo -e "    --worker-class uvicorn.workers.UvicornWorker \\"
echo -e "    --bind 0.0.0.0:${PORT} \\"
echo -e "    --workers 2 \\"
echo -e "    --timeout 30 \\"
echo -e "    --forwarded-allow-ips='*' \\"
echo -e "    --access-logfile -${RESET}"
echo -e ""
echo -e "  ${BOLD}Access:${RESET}"
echo -e "  ${CYAN}  http://localhost:${PORT}/login${RESET}"
echo -e "  ${CYAN}  http://localhost:${PORT}/register${RESET}"
echo -e ""

# ── 5. Systemd Service (optional) ─────────────

echo -e "${BOLD}${YELLOW}[5/5] Systemd service (optional)?${RESET}"
if command -v systemctl &>/dev/null; then
    echo -e ""
    echo -e "  ${BOLD}To install as systemd service:${RESET}"
    echo -e "  ${CYAN}sudo cat > /etc/systemd/system/rakshak-auth.service << 'EOF'${RESET}"
    echo -e "${CYAN}[Unit]${RESET}"
    echo -e "${CYAN}Description=RakshakAI Auth Server${RESET}"
    echo -e "${CYAN}After=network.target${RESET}"
    echo -e "${CYAN}${RESET}"
    echo -e "${CYAN}[Service]${RESET}"
    echo -e "${CYAN}Type=simple${RESET}"
    echo -e "${CYAN}User=$USER${RESET}"
    echo -e "${CYAN}WorkingDirectory=$PROJECT_ROOT${RESET}"
    echo -e "${CYAN}ExecStart=$(which python3) -m v2.web.server${RESET}"
    echo -e "${CYAN}Restart=always${RESET}"
    echo -e "${CYAN}Environment=RAKSHAK_AUTH_PORT=${PORT}${RESET}"
    echo -e "${CYAN}EOF${RESET}"
    echo -e "${CYAN}sudo systemctl daemon-reload${RESET}"
    echo -e "${CYAN}sudo systemctl enable --now rakshak-auth${RESET}"
fi

echo -e ""
echo -e "${BOLD}${GREEN}✓ Deploy script complete${RESET}"

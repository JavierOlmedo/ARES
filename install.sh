#!/usr/bin/env bash
# ARES — Install, Update & Dependency Checker
# Usage:
#   bash install.sh            → install / verify dependencies
#   bash install.sh --update   → git pull + update deps
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; ERRORS=$((ERRORS + 1)); }
info() { echo -e "  ${CYAN}ℹ${RESET}  $1"; }

ERRORS=0
UPDATE_MODE=0
[[ "${1:-}" == "--update" ]] && UPDATE_MODE=1

echo -e "\n${BOLD}${RED}    ___    ____  ___________"
echo -e "   /   |  / __ \/ ____/ ___/"
echo -e "  / /| | / /_/ / __/  \__ \\ "
echo -e " / ___ |/ _, _/ /___ ___/ / "
echo -e "/_/  |_/_/ |_/_____//____/  ${RESET}"
echo -e "${CYAN}  Advanced Reconnaissance & Enumeration Scanner${RESET}"
echo -e "${CYAN}  Install & Dependency Checker — hackpuntes.com${RESET}\n"

# ── Update mode ────────────────────────────────────────────────────────────────
if [[ "$UPDATE_MODE" -eq 1 ]]; then
    echo -e "${BOLD}[Update]${RESET}"
    if ! command -v git &>/dev/null; then
        fail "git not found — cannot update"
        exit 1
    fi
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    info "Branch: $BRANCH"
    info "Pulling latest changes..."
    if git pull origin "$BRANCH"; then
        ok "Repository updated"
    else
        fail "git pull failed"
        ((ERRORS++))
    fi
    echo ""
fi

# Resolve installation directory (wherever install.sh lives)
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

# ── Root check ─────────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    warn "Not running as root — apt installs will be skipped if they fail"
fi

# ── Python ──────────────────────────────────────────────────────────────────────
echo -e "${BOLD}[Python]${RESET}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
        ok "Python $PY_VER"
    else
        fail "Python $PY_VER found — requires 3.10+"
    fi
else
    fail "python3 not found — install Python 3.10+"
fi

# ── Python dependencies ─────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Python dependencies]${RESET}"
if pip3 install -r requirements.txt -q 2>/dev/null; then
    ok "rich, python-nmap, jinja2 installed"
else
    fail "pip install failed — check requirements.txt and try manually"
fi

# ── System tools ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[System tools]${RESET}"

try_install() {
    local tool=$1
    local pkg=${2:-$1}
    if command -v "$tool" &>/dev/null; then
        ok "$tool"
        return 0
    fi
    warn "$tool not found — trying: sudo apt-get install -y $pkg"
    if sudo apt-get install -y "$pkg" -qq 2>/dev/null; then
        ok "$tool installed"
    else
        fail "$tool — install failed. Run: sudo apt install $pkg"
    fi
}

try_install nmap
try_install patator
try_install nuclei

# Fuzzing: at least one required
FUZZER_FOUND=""
for fuzzer in gobuster ffuf feroxbuster; do
    if command -v "$fuzzer" &>/dev/null; then
        FUZZER_FOUND="$fuzzer"
        break
    fi
done

if [[ -n "$FUZZER_FOUND" ]]; then
    ok "$FUZZER_FOUND (fuzzer)"
else
    warn "No fuzzer found (gobuster/ffuf/feroxbuster) — trying gobuster..."
    if sudo apt-get install -y gobuster -qq 2>/dev/null; then
        ok "gobuster installed"
    else
        fail "No fuzzer available — install gobuster, ffuf, or feroxbuster"
    fi
fi

# ── ares command ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[ares command]${RESET}"

WRAPPER=/usr/local/bin/ares
cat > /tmp/ares_wrapper << WRAPPER_EOF
#!/usr/bin/env bash
if [[ \$EUID -ne 0 ]]; then
    exec sudo python3 ${INSTALL_DIR}/ares.py "\$@"
else
    exec python3 ${INSTALL_DIR}/ares.py "\$@"
fi
WRAPPER_EOF

if sudo mv /tmp/ares_wrapper "$WRAPPER" && sudo chmod +x "$WRAPPER"; then
    ok "ares → $WRAPPER (installed from $INSTALL_DIR)"
    chmod +x "$INSTALL_DIR/ares.py" 2>/dev/null || true
    info "You can now run: ares -t <TARGET_IP>"
else
    fail "Could not install wrapper at $WRAPPER — try: sudo bash install.sh"
fi

# ── ~/.ares workspace ────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Workspace]${RESET}"
ARES_HOME="$HOME/.ares"
if mkdir -p "$ARES_HOME" 2>/dev/null; then
    ok "~/.ares workspace ready ($ARES_HOME)"
else
    warn "Could not create ~/.ares — projects will fall back to current directory"
fi

# ── Wordlists ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Wordlists]${RESET}"

if [[ -d /usr/share/seclists ]]; then
    ok "seclists (/usr/share/seclists)"
else
    warn "seclists not found — trying: sudo apt-get install seclists"
    if sudo apt-get install -y seclists -qq 2>/dev/null; then
        ok "seclists installed"
    else
        warn "seclists — install manually: sudo apt install seclists"
    fi
fi

if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    ok "rockyou.txt (/usr/share/wordlists/rockyou.txt)"
elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    warn "rockyou.txt is compressed — run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
else
    warn "rockyou.txt not found at /usr/share/wordlists/rockyou.txt"
fi

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
if [[ "$ERRORS" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  ✓  ARES is ready!${RESET}"
    echo -e "     ${CYAN}ares -t <TARGET_IP>${RESET}\n"
else
    echo -e "${RED}${BOLD}  ✗  $ERRORS error(s) — fix them before running ARES${RESET}"
    echo -e "     Run ${CYAN}ares --check${RESET} anytime to re-verify\n"
fi

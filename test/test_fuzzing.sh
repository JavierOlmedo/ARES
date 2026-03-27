#!/usr/bin/env bash
# ARES — Fuzzing smoke test
# Starts a local HTTP server with known paths and verifies gobuster finds them.
#
# Usage: bash test/test_fuzzing.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; ERRORS=$((ERRORS+1)); }
info() { echo -e "  ${CYAN}ℹ${RESET}  $1"; }

ERRORS=0
PORT=18080
SERVE_DIR=$(mktemp -d)
WORDLIST="$(dirname "$0")/../wordlists/web/raft-large-directories-lowercase-56136.txt"
OUTFILE=$(mktemp)

echo -e "\n${BOLD}ARES — Fuzzing smoke test${RESET}\n"

# ── Setup fake web root ──────────────────────────────────────────────────────
info "Creating test web root: $SERVE_DIR"
mkdir -p "$SERVE_DIR/zm"
mkdir -p "$SERVE_DIR/admin"
mkdir -p "$SERVE_DIR/api"
echo "ZoneMinder" > "$SERVE_DIR/zm/index.html"
echo "Admin panel" > "$SERVE_DIR/admin/index.html"
echo "API"        > "$SERVE_DIR/api/index.html"
echo "Root"       > "$SERVE_DIR/index.html"
info "Directories: /zm  /admin  /api"

# ── Start HTTP server ────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    python3 -m http.server "$PORT" --directory "$SERVE_DIR" &>/dev/null &
    SERVER_PID=$!
elif command -v python &>/dev/null; then
    python -m SimpleHTTPServer "$PORT" &>/dev/null &
    SERVER_PID=$!
else
    fail "python3 not found — cannot start test server"
    exit 1
fi

sleep 1  # wait for server to start

info "Test server: http://127.0.0.1:$PORT (pid $SERVER_PID)"
echo ""

cleanup() { kill "$SERVER_PID" 2>/dev/null; rm -rf "$SERVE_DIR" "$OUTFILE"; }
trap cleanup EXIT

# ── Check wordlist ───────────────────────────────────────────────────────────
echo -e "${BOLD}[Wordlist]${RESET}"
if [[ -f "$WORDLIST" ]]; then
    ok "Found: $WORDLIST"
    WL_LINES=$(wc -l < "$WORDLIST")
    info "Entries: $WL_LINES"
    if grep -q "^zm$" "$WORDLIST"; then
        ok "'zm' is in the wordlist"
    else
        fail "'zm' NOT found in wordlist — this is why it won't be detected!"
    fi
else
    fail "Wordlist not found: $WORDLIST"
fi
echo ""

# ── Check fuzzer ─────────────────────────────────────────────────────────────
echo -e "${BOLD}[Fuzzer]${RESET}"
FUZZER=""
for f in gobuster ffuf feroxbuster; do
    if command -v "$f" &>/dev/null; then
        FUZZER="$f"
        ok "Using: $f"
        break
    fi
done
if [[ -z "$FUZZER" ]]; then
    fail "No fuzzer found (gobuster/ffuf/feroxbuster)"
    exit 1
fi
echo ""

# ── Run fuzzer ───────────────────────────────────────────────────────────────
echo -e "${BOLD}[Fuzzing http://127.0.0.1:$PORT]${RESET}"
info "Running $FUZZER — looking for /zm /admin /api ..."
echo ""

TARGET="http://127.0.0.1:$PORT"

if [[ "$FUZZER" == "gobuster" ]]; then
    gobuster dir -u "$TARGET" -w "$WORDLIST" -t 10 --no-error -q -k \
        --timeout 5s -o "$OUTFILE" 2>/dev/null || true

elif [[ "$FUZZER" == "ffuf" ]]; then
    ffuf -u "$TARGET/FUZZ" -w "$WORDLIST" -t 10 \
        -o "$OUTFILE" -of json -mc all -fc 404 -s 2>/dev/null || true

elif [[ "$FUZZER" == "feroxbuster" ]]; then
    feroxbuster -u "$TARGET" -w "$WORDLIST" -t 10 \
        -o "$OUTFILE" -k --quiet --depth 1 2>/dev/null || true
fi

echo ""

# ── Verify expected directories were found ───────────────────────────────────
echo -e "${BOLD}[Results]${RESET}"
OUTPUT=$(cat "$OUTFILE" 2>/dev/null || echo "")
info "Raw output:"
echo "$OUTPUT" | head -30 | sed 's/^/    /'
echo ""

for expected in zm admin api; do
    if echo "$OUTPUT" | grep -qi "/$expected"; then
        ok "/$expected found"
    else
        fail "/$expected NOT found"
    fi
done

echo ""
if [[ "$ERRORS" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  All tests passed — fuzzing is working correctly${RESET}\n"
else
    echo -e "${RED}${BOLD}  $ERRORS test(s) failed${RESET}"
    echo -e "  Check the raw output above for clues\n"
fi

exit "$ERRORS"

#!/usr/bin/env bash
# Installs the intrupt approval extension into Pi (coding agent).
#
# One-line install (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/Aegmis/pi-intrupt-hook/main/install.sh | bash
#
# Or, after cloning:
#   bash install.sh

set -euo pipefail

REPO_RAW="${AEGMIS_REPO_RAW:-https://raw.githubusercontent.com/Aegmis/pi-intrupt-hook/main}"

# Pi auto-discovers extensions in this directory (global scope).
EXT_DIR="$HOME/.pi/agent/extensions"
EXT_DEST="$EXT_DIR/intrupt.ts"
ENV_FILE="$HOME/.pi/agent/.env.intrupt"

if [ -n "${BASH_SOURCE:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR=""
fi

fetch() {
  local rel="$1" dest="$2"
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$rel" ]; then
    cp "$SCRIPT_DIR/$rel" "$dest"
  elif command -v curl &>/dev/null; then
    curl -fsSL "$REPO_RAW/$rel" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -qO "$dest" "$REPO_RAW/$rel"
  else
    echo "✗ Need curl or wget to download $rel" >&2
    exit 1
  fi
}

echo "→ Creating extensions directory: $EXT_DIR"
mkdir -p "$EXT_DIR"

echo "→ Installing extension"
fetch "intrupt.ts" "$EXT_DEST"

if [ ! -f "$ENV_FILE" ]; then
  echo "→ Creating env file at $ENV_FILE"
  cat > "$ENV_FILE" <<'EOF'
# intrupt extension configuration — sourced by your shell profile
export AEGMIS_BASE_URL=https://api.aegmis.com
export AEGMIS_API_KEY=sk_org_xxxx_yyyy      # replace with your API key
export AEGMIS_APPROVAL=true          # set false to disable the gate entirely
export AEGMIS_FORWARD_ALL=true
export AEGMIS_TIMEOUT=600
export AEGMIS_POLL_INTERVAL=5
# AEGMIS_PROTECTED_PATHS=/Users/you/work,/data   # extra dirs to gate rm on
EOF
  echo ""
  echo "   Edit $ENV_FILE and fill in your AEGMIS_API_KEY."
  echo "   Then add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc)."
  echo ""
fi

echo ""
echo "✓ Installation complete."
echo ""
echo "  Extension: $EXT_DEST"
echo "  Env file:  $ENV_FILE"
echo ""
echo "  Next steps:"
echo "  1. Edit $ENV_FILE with your API key"
echo "  2. Add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc) so Pi inherits it"
echo "  3. Verify it loads:  pi -e $EXT_DEST"
echo "  4. Restart Pi and try a gated command (e.g. git push)"
echo ""

#!/usr/bin/env bash
set -euo pipefail

# CookieJar Lab  - Cleanup Script
# Removes mkcert root CA and generated certificates

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
DOMAIN="cookiejar.test"

echo ""
echo "============================================"
echo "  CookieJar Lab  - Cleanup"
echo "============================================"
echo ""

# --- Remove mkcert root CA ---
if command -v mkcert &>/dev/null; then
  echo "Removing mkcert root CA from system trust store..."
  mkcert -uninstall
  echo "Root CA removed."
else
  echo "mkcert not found  - skipping CA removal."
fi

# --- Remove certificates ---
if [ -d "$CERT_DIR" ]; then
  echo "Removing generated certificates ($CERT_DIR)..."
  rm -rf "$CERT_DIR"
  echo "Certificates removed."
else
  echo "No certs/ directory found  - nothing to remove."
fi

# --- /etc/hosts reminder ---
echo ""
if grep -q "$DOMAIN" /etc/hosts 2>/dev/null; then
  echo "NOTE: /etc/hosts still contains an entry for $DOMAIN."
  echo "To remove it, edit /etc/hosts with sudo and delete this line:"
  echo "  127.0.0.1  $DOMAIN"
  echo ""
  echo "  sudo sed -i '' '/cookiejar\\.test/d' /etc/hosts   # macOS"
  echo "  sudo sed -i '/cookiejar\\.test/d' /etc/hosts      # Linux"
else
  echo "/etc/hosts is clean  - no $DOMAIN entry found."
fi

echo ""
echo "============================================"
echo "  Cleanup complete!"
echo "============================================"
echo ""
echo "  The mkcert root CA has been removed from your trust store."
echo "  The lab will still work in HTTP mode (docker compose up --build)."
echo ""

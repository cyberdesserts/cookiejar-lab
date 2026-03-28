#!/usr/bin/env bash
set -euo pipefail

# CookieJar Lab  - HTTPS Setup Script
# Generates TLS certificates using mkcert and configures /etc/hosts

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
DOMAIN="cookiejar.test"

echo ""
echo "============================================"
echo "  CookieJar Lab  - Setup"
echo "============================================"
echo ""
echo "This lab can run in two modes:"
echo ""
echo "  [HTTP]   No setup needed  - just run: docker compose up --build"
echo "           Open http://localhost:3001 and http://localhost:3002"
echo ""
echo "  [HTTPS]  Requires mkcert to generate trusted TLS certificates."
echo "           Open https://cookiejar.test:3001 and https://cookiejar.test:3002"
echo ""

read -rp "Set up HTTPS mode? (y/N): " choice
if [[ ! "$choice" =~ ^[Yy]$ ]]; then
  echo ""
  echo "No changes made. To start the lab in HTTP mode:"
  echo "  docker compose up --build"
  echo ""
  exit 0
fi

# --- Check for mkcert ---
echo ""
if ! command -v mkcert &>/dev/null; then
  echo "ERROR: mkcert is not installed."
  echo ""
  echo "Install it first:"
  echo "  macOS:   brew install mkcert"
  echo "  Linux:   https://github.com/FiloSottile/mkcert#installation"
  echo "  Windows: choco install mkcert"
  echo ""
  exit 1
fi

echo "Found mkcert: $(command -v mkcert)"

# --- Warn about root CA ---
echo ""
echo "============================================"
echo "  IMPORTANT: What mkcert does"
echo "============================================"
echo ""
echo "  mkcert installs a local Certificate Authority (CA) into your"
echo "  operating system and browser trust stores. This CA can generate"
echo "  trusted certificates for any domain on this machine."
echo ""
echo "  This is safe for local development, but:"
echo "    - The CA private key is stored on your disk"
echo "    - If compromised, an attacker could MITM any HTTPS site"
echo "    - Always run ./cleanup.sh when you're done with the lab"
echo ""
echo "  See docs/security-notes.md for full details."
echo ""

read -rp "Continue and install the mkcert root CA? (yes/N): " confirm
if [[ "$confirm" != "yes" ]]; then
  echo "Aborted. No changes made."
  exit 0
fi

# --- Install mkcert CA ---
echo ""
echo "Installing mkcert root CA..."
mkcert -install
echo "Root CA installed."

# --- Generate certificates ---
echo ""
echo "Generating certificates for $DOMAIN..."
mkdir -p "$CERT_DIR"
mkcert -cert-file "$CERT_DIR/cert.pem" -key-file "$CERT_DIR/key.pem" \
  "$DOMAIN" "localhost" "127.0.0.1" "::1"
echo "Certificates saved to $CERT_DIR/"

# --- /etc/hosts entry ---
echo ""
if grep -q "$DOMAIN" /etc/hosts 2>/dev/null; then
  echo "/etc/hosts already contains $DOMAIN  - no changes needed."
else
  echo "To use https://$DOMAIN, we need to add it to /etc/hosts:"
  echo "  127.0.0.1  $DOMAIN"
  echo ""
  read -rp "Add this entry now? Requires sudo. (y/N): " hosts_choice
  if [[ "$hosts_choice" =~ ^[Yy]$ ]]; then
    echo "127.0.0.1  $DOMAIN" | sudo tee -a /etc/hosts >/dev/null
    echo "Added $DOMAIN to /etc/hosts."
  else
    echo "Skipped. You can add it manually later:"
    echo "  echo '127.0.0.1  $DOMAIN' | sudo tee -a /etc/hosts"
  fi
fi

# --- Done ---
echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "  Start the lab:"
echo "    docker compose up --build"
echo ""
echo "  Then open:"
echo "    https://cookiejar.test:3001  (vulnerable app)"
echo "    https://cookiejar.test:3002  (hardened app)"
echo ""
echo "  When you're done, run:"
echo "    ./cleanup.sh"
echo ""

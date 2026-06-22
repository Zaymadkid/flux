#!/usr/bin/env bash
set -euo pipefail

echo "[*] MPC - Mobile Pentesting Companion Setup"
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt
pip3 install -r requirements-mcp.txt 2>/dev/null || true

echo "[*] Checking external tools..."
command -v adb >/dev/null && echo "  [OK] adb" || echo "  [WARN] adb not found"
command -v jadx >/dev/null && echo "  [OK] jadx" || echo "  [WARN] jadx not found"

echo ""
echo "[+] Setup complete. Run: python mpc.py --help"

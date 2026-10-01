#!/bin/bash
# Launch Agentic Blockchain Forensics Electron UI from WSL2 (window via WSLg).
# Prerequisite: npm install in ui/; AI :8000 and Node :3000 should already be up.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT/ui"
if ! command -v electron >/dev/null 2>&1 && [ ! -x node_modules/.bin/electron ]; then
  echo "Installing Electron deps..."
  npm install
fi
exec npm start

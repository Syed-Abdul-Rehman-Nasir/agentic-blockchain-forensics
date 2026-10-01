#!/bin/bash
# Start the Node.js Express orchestrator on port 3000
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load backend .env then Fabric port-fix endpoints (written by start-fabric.sh)
ENV_FILE="$PROJECT_ROOT/backend-node/.env"
FABRIC_EP="$PROJECT_ROOT/backend-node/.fabric-endpoints.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi
if [ -f "$FABRIC_EP" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$FABRIC_EP"
  set +a
fi

cd "$PROJECT_ROOT/backend-node"
exec npm start

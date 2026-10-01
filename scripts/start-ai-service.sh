#!/bin/bash
# Start the Python FastAPI AI service on port 8000
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load environment variables from backend-node/.env if it exists
ENV_FILE="$PROJECT_ROOT/backend-node/.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

cd "$PROJECT_ROOT"
source .venv/bin/activate
export OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
exec uvicorn ai_service.main:app --host 0.0.0.0 --port 8000

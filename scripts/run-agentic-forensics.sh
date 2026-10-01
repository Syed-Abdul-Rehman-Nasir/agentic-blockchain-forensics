#!/bin/bash
# Agentic Blockchain Forensics — Master Startup Script
# Launches AI Service, Node Backend, and (optionally) Fabric network
# in a single tmux session with named panes.
#
# Usage:
#   ./scripts/run-agentic-forensics.sh          # start everything
#   ./scripts/run-agentic-forensics.sh stop     # stop everything
#   ./scripts/run-agentic-forensics.sh status   # check health
#   ./scripts/run-agentic-forensics.sh attach   # reattach to running session

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="agentic-forensics"
LOG_DIR="/tmp/agentic-forensics-logs"
mkdir -p "$LOG_DIR"

# ---------- Colors ----------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[run]${NC} $1"; }
ok()   { echo -e "${GREEN}[ok]${NC}  $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
err()  { echo -e "${RED}[error]${NC} $1"; }

# ---------- Commands ----------

cmd_stop() {
    log "Stopping Agentic Blockchain Forensics services..."
    tmux kill-session -t "$SESSION" 2>/dev/null && ok "tmux session killed" || warn "No tmux session running"
    pkill -f "uvicorn ai_service.main:app" 2>/dev/null && ok "AI service stopped" || true
    pkill -f "node server.js" 2>/dev/null && ok "Node backend stopped" || true
    ok "All services stopped. Fabric network left running (use 'fabric-down' to stop it)."
}

cmd_fabric_down() {
    log "Stopping Fabric network (clean)..."
    bash "$PROJECT_ROOT/scripts/stop-fabric.sh"
    ok "Fabric network stopped"
}

cmd_status() {
    echo ""
    log "Service Health Check"
    echo "----------------------------------------"

    AI_HEALTH=$(curl -s -m 3 http://localhost:8000/health 2>/dev/null)
    if echo "$AI_HEALTH" | grep -q "ok"; then
        ok "AI Service (:8000)      — UP"
    else
        err "AI Service (:8000)      — DOWN"
    fi

    NODE_HEALTH=$(curl -s -m 3 http://localhost:3000/health 2>/dev/null)
    if echo "$NODE_HEALTH" | grep -q "ok"; then
        ok "Node Backend (:3000)    — UP"
    else
        err "Node Backend (:3000)    — DOWN"
    fi

    if command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "peer0.org1"; then
        ok "Fabric Network          — UP"
    else
        warn "Fabric Network          — DOWN (optional — mockChain fallback active)"
    fi

    if [ -n "$OLLAMA_HOST" ]; then
        OLLAMA_OK=$(curl -s -m 3 "$OLLAMA_HOST/api/tags" 2>/dev/null | grep -c "qwen2.5")
        if [ "$OLLAMA_OK" != "0" ]; then
            ok "Ollama (qwen2.5:3b)     — UP"
        else
            err "Ollama (qwen2.5:3b)     — DOWN or model missing"
        fi
    else
        warn "OLLAMA_HOST not set — run: export OLLAMA_HOST=http://\$(cat /etc/resolv.conf | grep nameserver | awk '{print \$2}'):11434"
    fi

    echo "----------------------------------------"
    echo ""
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        ok "tmux session '$SESSION' is running — attach with: tmux attach -t $SESSION"
    else
        warn "tmux session not running — start with: ./scripts/run-agentic-forensics.sh"
    fi
    echo ""
}

cmd_attach() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux attach -t "$SESSION"
    else
        err "No session running. Start with: ./scripts/run-agentic-forensics.sh"
        exit 1
    fi
}

cmd_start() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    pkill -f "uvicorn ai_service.main:app" 2>/dev/null || true
    pkill -f "node server.js" 2>/dev/null || true
    sleep 1

    log "Starting Agentic Blockchain Forensics in tmux session '$SESSION'..."
    log "Logs: $LOG_DIR"

    export OLLAMA_HOST=http://$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):11434

    tmux new-session -d -s "$SESSION" -n "ai-service" -c "$PROJECT_ROOT"
    tmux send-keys -t "$SESSION:ai-service" \
        "source .venv/bin/activate && uvicorn ai_service.main:app --host 0.0.0.0 --port 8000 2>&1 | tee $LOG_DIR/ai-service.log" C-m

    tmux new-window -t "$SESSION" -n "backend" -c "$PROJECT_ROOT/backend-node"
    tmux send-keys -t "$SESSION:backend" \
        "node server.js 2>&1 | tee $LOG_DIR/backend.log" C-m

    tmux new-window -t "$SESSION" -n "control" -c "$PROJECT_ROOT"
    tmux send-keys -t "$SESSION:control" \
        "echo 'Control pane — run: ./scripts/run-agentic-forensics.sh status'" C-m

    log "Waiting for services to come up..."
    sleep 8

    AI_OK=$(curl -s -m 3 http://localhost:8000/health 2>/dev/null | grep -c "ok")
    NODE_OK=$(curl -s -m 3 http://localhost:3000/health 2>/dev/null | grep -c "ok")

    echo ""
    if [ "$AI_OK" != "0" ]; then ok "AI Service is UP"; else err "AI Service FAILED — check: tmux attach -t $SESSION (window: ai-service)"; fi
    if [ "$NODE_OK" != "0" ]; then ok "Node Backend is UP"; else err "Node Backend FAILED — check: tmux attach -t $SESSION (window: backend)"; fi

    OLLAMA_OK=$(curl -s -m 3 "$OLLAMA_HOST/api/tags" 2>/dev/null | grep -c "qwen2.5")
    if [ "$OLLAMA_OK" != "0" ]; then
        ok "Ollama reachable (qwen2.5:3b found)"
    else
        warn "Ollama not reachable — make sure Ollama is running on Windows"
    fi

    echo ""
    log "All backend services are running inside tmux session '$SESSION'"
    echo ""
    echo "  View live logs / switch windows : tmux attach -t $SESSION"
    echo "    (inside tmux: Ctrl+b then 0/1/2 to switch windows, Ctrl+b d to detach)"
    echo "  Check status any time            : ./scripts/run-agentic-forensics.sh status"
    echo "  Stop everything                  : ./scripts/run-agentic-forensics.sh stop"
    echo ""
    echo "  Now launch the UI from WSL:"
    echo "    bash scripts/start-ui.sh"
    echo "    # or: cd ui && npm start"
    echo ""
}

cmd_fabric_up() {
    log "Starting Hyperledger Fabric network (clean reset + CCAAS)..."
    bash "$PROJECT_ROOT/scripts/start-fabric.sh"
    ok "Fabric network up and chaincode deployed"
}

case "${1:-start}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    status)  cmd_status ;;
    attach)  cmd_attach ;;
    fabric-up)   cmd_fabric_up ;;
    fabric-down) cmd_fabric_down ;;
    *)
        echo "Usage: $0 {start|stop|status|attach|fabric-up|fabric-down}"
        exit 1
        ;;
esac

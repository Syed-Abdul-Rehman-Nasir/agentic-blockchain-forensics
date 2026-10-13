#!/bin/bash
# Tear down Fabric test-network + leftover CCAAS / port-fix containers cleanly.
# Safe to run when the network is already partially down.
set -euo pipefail

FABRIC_SAMPLES="${FABRIC_SAMPLES:-$HOME/fabric-samples}"
TEST_NETWORK="$FABRIC_SAMPLES/test-network"

export PATH="${HOME}/bin:${FABRIC_SAMPLES}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_SAMPLES}/config"

# Undo temporary proxy patches left by start-fabric.sh (including interrupted runs).
restore_env_patches() {
  local env_var="$TEST_NETWORK/scripts/envVar.sh"
  local orderer_sh="$TEST_NETWORK/scripts/orderer.sh"
  if [ ! -d "$TEST_NETWORK/scripts" ]; then
    return 0
  fi
  if [ -f "$env_var.abf.bak" ]; then
    mv -f "$env_var.abf.bak" "$env_var"
    echo "[fabric] Restored scripts/envVar.sh from .abf.bak"
  fi
  if [ -f "$orderer_sh.abf.bak" ]; then
    mv -f "$orderer_sh.abf.bak" "$orderer_sh"
    echo "[fabric] Restored scripts/orderer.sh from .abf.bak"
  fi
  find "$TEST_NETWORK/scripts" -type f -name '*.abf.bak' 2>/dev/null \
    | while read -r bak; do
        mv -f "$bak" "${bak%.abf.bak}"
        echo "[fabric] Restored ${bak%.abf.bak} from .abf.bak"
      done
}

echo "[fabric] Stopping Fabric test-network (if present)..."

if [ -d "$TEST_NETWORK" ]; then
  (
    cd "$TEST_NETWORK"
    ./network.sh down || true
  )
else
  echo "[fabric] WARN: $TEST_NETWORK not found - skipping network.sh down"
fi

restore_env_patches

echo "[fabric] Removing leftover Fabric / CCAAS / port-fix containers..."
docker ps -aq --format '{{.ID}} {{.Names}}' 2>/dev/null \
  | awk 'BEGIN{IGNORECASE=1}
      /forensiccc|_ccaas|peer0\.org|peer0org|orderer\.example|ca_org|ca_orderer|dev-peer|couchdb|fabric-peer-proxy|fabric-orderer-proxy|fabric-org2-proxy|fabric-orderer-listen/ {
        print $1
      }' \
  | sort -u \
  | while read -r id; do
      [ -n "$id" ] && docker rm -f "$id" >/dev/null 2>&1 || true
    done

# Named helpers from start-fabric.sh
docker rm -f fabric-peer-proxy fabric-org2-proxy fabric-orderer-proxy fabric-orderer-listen-proxy >/dev/null 2>&1 || true

echo "[fabric] Removing stuck fabric_test Docker network and peer/orderer volumes..."
docker network rm fabric_test >/dev/null 2>&1 || true

docker volume ls --format '{{.Name}}' 2>/dev/null \
  | awk '/peer0\.org|orderer\.example|compose_peer|compose_orderer|fabric/ {print}' \
  | while read -r vol; do
      [ -n "$vol" ] && docker volume rm -f "$vol" >/dev/null 2>&1 || true
    done

# Best-effort: clear zombie docker-proxy entries inside Docker Desktop VM
if command -v wsl.exe >/dev/null 2>&1; then
  echo "[fabric] Clearing stale docker-proxy processes in docker-desktop VM (best effort)..."
  wsl.exe -d docker-desktop -u root -- sh -c \
    'ps -ef 2>/dev/null | grep docker-proxy | grep -E "705[0-9]|9051|944[0-9]" | grep -v grep | awk "{print \$2}" | xargs -r kill -9' \
    >/dev/null 2>&1 || true
fi

echo "[fabric] Stop complete."

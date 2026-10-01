#!/bin/bash
# Bring up Fabric test-network (LevelDB) and deploy forensiccc via CCAAS.
# Always performs a clean reset first so missing crypto / half-down state
# (DEADLINE_EXCEEDED on :7051, missing orderer TLS certs) cannot recur.
#
# Uses cryptogen by default (reliable regenerate). Set FABRIC_CA=1 to use CAs.
# CCAAS is required: peer-side docker builds fail on Docker Engine 29.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$HOME/fabric-samples}"
TEST_NETWORK="$FABRIC_SAMPLES/test-network"
CHANNEL="${CHANNEL_NAME:-forensicchannel}"
CC_NAME="${CHAINCODE_NAME:-forensiccc}"
USE_CA="${FABRIC_CA:-0}"
ORDERER_TLS="$TEST_NETWORK/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"
PEER_TLS_CA="$TEST_NETWORK/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
REGISTER_ENROLL="$TEST_NETWORK/organizations/fabric-ca/registerEnroll.sh"

export PATH="${HOME}/bin:${FABRIC_SAMPLES}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_SAMPLES}/config"
export DOCKER_SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"

die() { echo "[fabric] ERROR: $*" >&2; exit 1; }
log() { echo "[fabric] $*"; }

require_prereqs() {
  command -v docker >/dev/null 2>&1 || die "docker not found"
  docker info >/dev/null 2>&1 || die "Docker daemon not reachable"
  [ -d "$TEST_NETWORK" ] || die "Fabric test-network not found at $TEST_NETWORK
Install fabric-samples under \$HOME/fabric-samples, or set FABRIC_SAMPLES."
  [ -x "$TEST_NETWORK/network.sh" ] || die "network.sh missing/not executable in $TEST_NETWORK"
  command -v configtxgen >/dev/null 2>&1 || die "configtxgen not on PATH (expected under $FABRIC_SAMPLES/bin or \$HOME/bin)"
  command -v cryptogen >/dev/null 2>&1 || die "cryptogen not on PATH"
}

# Docker often writes org crypto as root; reclaim ownership so we can purge/regenerate.
fix_org_ownership() {
  local orgs="$TEST_NETWORK/organizations"
  [ -d "$orgs" ] || return 0
  log "Reclaiming ownership of organizations/ (Docker may have left root-owned files)..."
  docker run --rm \
    -v "$orgs:/orgs" \
    alpine \
    chown -R "$(id -u):$(id -g)" /orgs >/dev/null
}

# Restore sample CA helper scripts if a previous broken purge deleted them.
restore_fabric_ca_scripts() {
  if [ -f "$REGISTER_ENROLL" ]; then
    return 0
  fi
  if [ -d "$FABRIC_SAMPLES/.git" ]; then
    log "Restoring missing fabric-ca/registerEnroll.sh from fabric-samples git..."
    (
      cd "$FABRIC_SAMPLES"
      git checkout -- test-network/organizations/fabric-ca/registerEnroll.sh \
        test-network/organizations/fabric-ca/org1/fabric-ca-server-config.yaml \
        test-network/organizations/fabric-ca/org2/fabric-ca-server-config.yaml \
        test-network/organizations/fabric-ca/ordererOrg/fabric-ca-server-config.yaml \
        2>/dev/null || true
    )
  fi
  if [ ! -f "$REGISTER_ENROLL" ] && [ "$USE_CA" = "1" ]; then
    die "organizations/fabric-ca/registerEnroll.sh is missing and could not be restored.
Re-clone fabric-samples, or run without CA: FABRIC_CA=0 bash scripts/start-fabric.sh"
  fi
}

# Remove generated MSP/TLS only - never delete fabric-ca/*.sh sample sources.
purge_generated_crypto() {
  fix_org_ownership
  restore_fabric_ca_scripts

  log "Purging generated peer/orderer crypto and channel artifacts..."
  rm -rf \
    "$TEST_NETWORK/organizations/peerOrganizations" \
    "$TEST_NETWORK/organizations/ordererOrganizations" \
    "$TEST_NETWORK/channel-artifacts" \
    "$TEST_NETWORK/system-genesis-block" \
    2>/dev/null || true

  # Clear CA runtime state dirs but keep YAML/scripts under fabric-ca/
  if [ -d "$TEST_NETWORK/organizations/fabric-ca" ]; then
    find "$TEST_NETWORK/organizations/fabric-ca" -mindepth 2 -maxdepth 2 \
      \( -name 'msp' -o -name 'tls-cert.pem' -o -name 'ca-cert.pem' -o -name 'fabric-ca-server.db' \
         -o -name 'Issuer*' -o -name '*.pem' \) \
      -exec rm -rf {} + 2>/dev/null || true
  fi
}

PEER_PROXY_PORT="${FABRIC_PEER_PROXY_PORT:-17051}"
ORG2_PROXY_PORT="${FABRIC_ORG2_PROXY_PORT:-19051}"
ORDERER_ADMIN_PROXY_PORT="${FABRIC_ORDERER_ADMIN_PROXY_PORT:-17053}"
ORDERER_PROXY_PORT="${FABRIC_ORDERER_PROXY_PORT:-17050}"
ENDPOINT_FILE="$PROJECT_ROOT/backend-node/.fabric-endpoints.env"

tls_fingerprint() {
  local target="$1"
  echo | openssl s_client -connect "$target" -servername peer0.org1.example.com 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2 || true
}

file_fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2
}

wait_for_peer() {
  local host="${1:-127.0.0.1}"
  local port="${2:-7051}"
  local tries="${3:-90}"
  log "Waiting for peer ${host}:${port} (up to ${tries}s)..."
  for ((i = 1; i <= tries; i++)); do
    if (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      log "Port ${host}:${port} is accepting connections."
      return 0
    fi
    sleep 1
  done
  die "Nothing listening on ${host}:${port}."
}

# Docker Desktop on WSL2 sometimes leaves zombie host ports (7051/7053/9051)
# pointing at dead container IPs with old CA certs. Sidecar proxies on alternate
# ports always reach the live containers via the fabric_test network.
ensure_port_fixies() {
  log "Installing localhost port-fix sidecars (bypass stale Docker :7050/:7051/:7053/:9051)..."
  docker rm -f fabric-peer-proxy fabric-org2-proxy fabric-orderer-proxy fabric-orderer-listen-proxy >/dev/null 2>&1 || true
  docker pull alpine/socat >/dev/null 2>&1 || true

  docker run -d --restart unless-stopped --name fabric-peer-proxy \
    --network fabric_test -p "${PEER_PROXY_PORT}:7051" \
    alpine/socat TCP-LISTEN:7051,fork,reuseaddr TCP:peer0.org1.example.com:7051 >/dev/null

  docker run -d --restart unless-stopped --name fabric-org2-proxy \
    --network fabric_test -p "${ORG2_PROXY_PORT}:9051" \
    alpine/socat TCP-LISTEN:9051,fork,reuseaddr TCP:peer0.org2.example.com:9051 >/dev/null

  docker run -d --restart unless-stopped --name fabric-orderer-proxy \
    --network fabric_test -p "${ORDERER_ADMIN_PROXY_PORT}:7053" \
    alpine/socat TCP-LISTEN:7053,fork,reuseaddr TCP:orderer.example.com:7053 >/dev/null

  docker run -d --restart unless-stopped --name fabric-orderer-listen-proxy \
    --network fabric_test -p "${ORDERER_PROXY_PORT}:7050" \
    alpine/socat TCP-LISTEN:7050,fork,reuseaddr TCP:orderer.example.com:7050 >/dev/null

  sleep 2
  wait_for_peer 127.0.0.1 "$PEER_PROXY_PORT" 30

  local server_cert="$TEST_NETWORK/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt"
  local host_fp live_fp
  host_fp="$(file_fingerprint "$server_cert")"
  live_fp="$(tls_fingerprint "127.0.0.1:${PEER_PROXY_PORT}")"
  if [ -z "$live_fp" ] || [ "$live_fp" != "$host_fp" ]; then
    die "Port-fix TLS mismatch on :${PEER_PROXY_PORT}
Host: $host_fp
Live: $live_fp
Restart Docker Desktop from Windows, then re-run bash scripts/start-fabric.sh"
  fi
  log "Port-fix OK - peer TLS on localhost:${PEER_PROXY_PORT} matches crypto."

  cat > "$ENDPOINT_FILE" <<EOF
# Generated by scripts/start-fabric.sh — do not edit by hand.
# Stale Docker Desktop proxies poison :7051/:7053; use these instead.
PEER_ENDPOINT=localhost:${PEER_PROXY_PORT}
PEER_HOST_ALIAS=peer0.org1.example.com
EOF
  log "Wrote $ENDPOINT_FILE (PEER_ENDPOINT=localhost:${PEER_PROXY_PORT})"
}

patch_env_for_proxies() {
  local env_var="$TEST_NETWORK/scripts/envVar.sh"
  local orderer_sh="$TEST_NETWORK/scripts/orderer.sh"
  cp -f "$env_var" "$env_var.abf.bak"
  cp -f "$orderer_sh" "$orderer_sh.abf.bak"
  sed -i \
    -e "s/localhost:7051/localhost:${PEER_PROXY_PORT}/g" \
    -e "s/localhost:9051/localhost:${ORG2_PROXY_PORT}/g" \
    -e "s/localhost:7050/localhost:${ORDERER_PROXY_PORT}/g" \
    "$env_var"
  sed -i "s/localhost:7053/localhost:${ORDERER_ADMIN_PROXY_PORT}/g" "$orderer_sh"
  # Anchor peer / setAnchorPeer scripts also talk to the orderer on :7050
  find "$TEST_NETWORK/scripts" -type f -name '*.sh' ! -name 'envVar.sh' ! -name 'orderer.sh' \
    -exec grep -l 'localhost:7050' {} \; 2>/dev/null \
    | while read -r f; do
        cp -f "$f" "$f.abf.bak"
        sed -i "s/localhost:7050/localhost:${ORDERER_PROXY_PORT}/g" "$f"
      done
}

restore_env_patches() {
  local env_var="$TEST_NETWORK/scripts/envVar.sh"
  local orderer_sh="$TEST_NETWORK/scripts/orderer.sh"
  if [ -f "$env_var.abf.bak" ]; then
    mv -f "$env_var.abf.bak" "$env_var"
  fi
  if [ -f "$orderer_sh.abf.bak" ]; then
    mv -f "$orderer_sh.abf.bak" "$orderer_sh"
  fi
  find "$TEST_NETWORK/scripts" -type f -name '*.abf.bak' 2>/dev/null \
    | while read -r bak; do
        mv -f "$bak" "${bak%.abf.bak}"
      done
}

wait_for_tls_match() {
  local server_cert="$TEST_NETWORK/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt"
  [ -f "$server_cert" ] || die "Missing peer server.crt after network up"

  log "Restarting peers/orderer so they load freshly generated TLS..."
  docker restart peer0.org1.example.com peer0.org2.example.com orderer.example.com >/dev/null
  sleep 4

  # Prefer docker-network path (not poisoned host :7051)
  local host_fp live_fp
  host_fp="$(file_fingerprint "$server_cert")"
  for ((i = 1; i <= 40; i++)); do
    live_fp="$(docker run --rm --network fabric_test alpine/openssl \
      s_client -connect peer0.org1.example.com:7051 </dev/null 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2 || true)"
    if [ -n "$live_fp" ] && [ "$live_fp" = "$host_fp" ]; then
      log "In-network peer TLS matches host crypto ($live_fp)."
      return 0
    fi
    sleep 1
  done
  die "In-network peer TLS still mismatches host crypto.
Host: $host_fp
Live: $live_fp"
}

bring_up_network() {
  cd "$TEST_NETWORK"
  if [ "$USE_CA" = "1" ]; then
    log "Starting nodes with Fabric CA (-ca)..."
    restore_fabric_ca_scripts
    [ -f "$REGISTER_ENROLL" ] || die "registerEnroll.sh required for FABRIC_CA=1"
    ./network.sh up -ca
  else
    log "Starting nodes with cryptogen (recommended)..."
    ./network.sh up
  fi

  [ -f "$ORDERER_TLS" ] || die "Orderer TLS cert missing after './network.sh up'"
  wait_for_tls_match
  ensure_port_fixies

  log "Creating channel '${CHANNEL}' via port-fix endpoints..."
  patch_env_for_proxies
  trap restore_env_patches EXIT
  ./network.sh createChannel -c "$CHANNEL"
  restore_env_patches
  trap - EXIT
}

verify_ready() {
  [ -f "$ORDERER_TLS" ] || die "Orderer TLS cert still missing after up: $ORDERER_TLS"
  [ -f "$PEER_TLS_CA" ] || die "Peer TLS CA still missing after up: $PEER_TLS_CA"
  wait_for_peer 127.0.0.1 "$PEER_PROXY_PORT" 30

  if ! docker ps --format '{{.Names}}' | grep -q 'peer0.org1.example.com'; then
    die "peer0.org1.example.com container is not running."
  fi
  if ! docker ps --format '{{.Names}}' | grep -q 'fabric-peer-proxy'; then
    die "fabric-peer-proxy sidecar missing - re-run start-fabric.sh"
  fi
  log "Fabric peer + port-fix :${PEER_PROXY_PORT} + crypto OK."
}

# ---------- main ----------
require_prereqs

log "Clean reset before bring-up..."
bash "$PROJECT_ROOT/scripts/stop-fabric.sh"
purge_generated_crypto

bring_up_network

[ -f "$ORDERER_TLS" ] || die "Channel up finished but orderer TLS cert is still missing.
Crypto generation failed - check cryptogen/CA output above."

log "Deploying chaincode '${CC_NAME}' via CCAAS..."
(
  cd "$TEST_NETWORK"
  patch_env_for_proxies
  trap 'cd "$TEST_NETWORK"; restore_env_patches' EXIT
  ./network.sh deployCCAAS \
    -c "$CHANNEL" \
    -ccn "$CC_NAME" \
    -ccp "$PROJECT_ROOT/chaincode"
  restore_env_patches
  trap - EXIT
)

verify_ready

# Merge peer endpoint into .env if present
if [ -f "$PROJECT_ROOT/backend-node/.env" ]; then
  if grep -q '^PEER_ENDPOINT=' "$PROJECT_ROOT/backend-node/.env"; then
    sed -i "s|^PEER_ENDPOINT=.*|PEER_ENDPOINT=localhost:${PEER_PROXY_PORT}|" "$PROJECT_ROOT/backend-node/.env"
  else
    printf '\nPEER_ENDPOINT=localhost:%s\n' "$PEER_PROXY_PORT" >> "$PROJECT_ROOT/backend-node/.env"
  fi
  log "Updated backend-node/.env PEER_ENDPOINT=localhost:${PEER_PROXY_PORT}"
fi

cat <<EOF

[fabric] Ready.
  Channel:     ${CHANNEL}
  Chaincode:   ${CC_NAME} (CCAAS)
  Peer (app):  localhost:${PEER_PROXY_PORT}  (use this - NOT :7051 if Docker ports are stale)
  Peer alias:  peer0.org1.example.com
  Identity:    $([ "$USE_CA" = "1" ] && echo "Fabric CA" || echo "cryptogen")

Next:
  1. Ensure USE_REAL_FABRIC=true in backend-node/.env
  2. Restart Node backend: bash scripts/start-backend.sh
     (start-backend loads PEER_ENDPOINT from .env / .fabric-endpoints.env)
  3. Verify a sealed case from the Blockchain panel

To stop cleanly later:
  bash scripts/stop-fabric.sh

EOF

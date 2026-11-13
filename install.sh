#!/usr/bin/env bash
set -euo pipefail
umask 077

VERSION=v0.2.0-beta.1
INSTALL_ROOT=/opt/openvpnpa
INPUT_CONFIG=
CHECK_ONLY=0
PUBLIC_UI=0
usage() {
  cat <<'EOF'
OpenVPNPA isolated node + management UI installer (Ubuntu 24.04)
  sudo bash install.sh [--config /absolute/private-input.json] [--public-ui] [--check]
  --check  Read-only preflight; install nothing and contact no panel.
  --public-ui  Expose the authenticated HTTPS management UI on all IPv4 addresses.
The installer does not register a node or modify the active PasarGuard panel.
Existing Docker services, containers, host firewall rules and user files are preserved.
EOF
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --check) CHECK_ONLY=1; shift ;;
    --public-ui) PUBLIC_UI=1; shift ;;
    --config) [[ $# -ge 2 ]] || { usage; exit 2; }; INPUT_CONFIG=$2; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -r /etc/os-release ]] || { echo 'Cannot identify the OS.' >&2; exit 1; }
# OS-supplied file, never a user config or downloaded shell fragment.
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'Ubuntu 24.04 is required.' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This beta installer is validated for amd64 only.' >&2; exit 1; }
[[ -c /dev/net/tun ]] || {
  echo 'TUN device missing. Enable /dev/net/tun on this VPS before installing; nothing was changed.' >&2
  exit 1
}
if ((CHECK_ONLY)); then
  echo 'OS, architecture and TUN device preflight passed.'
  if command -v docker >/dev/null; then docker info --format 'Docker: {{.ServerVersion}}'; fi
  exit 0
fi
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
if [[ -n "$INPUT_CONFIG" ]]; then
  [[ "$INPUT_CONFIG" == /* && -f "$INPUT_CONFIG" ]] || { echo '--config must be an absolute regular file.' >&2; exit 1; }
  [[ $(stat -c '%a' "$INPUT_CONFIG") == 600 ]] || { echo 'Input config must have mode 0600.' >&2; exit 1; }
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv
if ! command -v docker >/dev/null; then
  apt-get install -y --no-install-recommends docker.io docker-compose-v2
  systemctl enable --now docker
elif ! docker compose version >/dev/null 2>&1; then
  echo 'Docker exists but Compose v2 is missing. Install the matching Compose plugin and rerun.' >&2
  exit 1
fi
docker info >/dev/null
# Never restart an existing Docker daemon, enable a VPN, or flush a firewall.
mkdir -p "$INSTALL_ROOT/releases" "$INSTALL_ROOT/config" "$INSTALL_ROOT/state"
chmod 700 "$INSTALL_ROOT/config" "$INSTALL_ROOT/state"
RELEASE_DIR="$INSTALL_ROOT/releases/$VERSION"
if [[ ! -e "$RELEASE_DIR" ]]; then
  STAGING=$(mktemp -d "$INSTALL_ROOT/releases/.download-XXXXXX")
  trap '[[ -z "${STAGING:-}" ]] || rm -rf -- "$STAGING"' EXIT
  git clone --depth 1 --branch "$VERSION" https://github.com/zhilvanzhinos/openvpnpa.git "$STAGING/source"
  mv "$STAGING/source" "$RELEASE_DIR"
  rmdir "$STAGING"
  STAGING=
else
  git -C "$RELEASE_DIR" diff --quiet
  git -C "$RELEASE_DIR" diff --cached --quiet
  [[ $(git -C "$RELEASE_DIR" describe --tags --exact-match HEAD) == "$VERSION" ]] || { echo 'Existing release does not match the requested tag.' >&2; exit 1; }
fi
SETUP_ARGS=(--output "$INSTALL_ROOT/config/config.json")
[[ -z "$INPUT_CONFIG" ]] || SETUP_ARGS+=(--from-file "$INPUT_CONFIG")
(cd "$RELEASE_DIR" && python3 -m openvpnpa.setup "${SETUP_ARGS[@]}")
# Write only validated, non-secret port values to the Compose env file.
python3 - "$INSTALL_ROOT" "$PUBLIC_UI" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
data=json.loads((root/'config/config.json').read_text())
text=''.join(f'{key}={int(data.get(field,default))}\n' for key,field,default in
    [('UI_PORT','ui_port',8443),('NODE_PORT','node_port',62050),('VPN_PORT','vpn_port',1194)])
target=root/'config/compose.env'
if not target.exists():
    with target.open('x') as stream:
        stream.write(text+'UI_BIND='+('0.0.0.0' if sys.argv[2]=='1' else '127.0.0.1')+'\n')
elif sys.argv[2]=='1':
    rows=target.read_text().splitlines()
    target.write_text('\n'.join(line for line in rows if not line.startswith('UI_BIND='))+'\nUI_BIND=0.0.0.0\n')
PY
COMPOSE=(docker compose --project-name openvpnpa --env-file "$INSTALL_ROOT/config/compose.env" -f "$RELEASE_DIR/deploy/compose.yaml")
# Managed cloud builds may need their injected CA; keep it out of image layers.
if [[ -n "${CODEX_PROXY_CERT:-}" ]]; then
  export OPENVPNPA_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  COMPOSE+=(-f "$RELEASE_DIR/deploy/compose.cloud.yaml")
fi
"${COMPOSE[@]}" build
"${COMPOSE[@]}" run --rm --no-deps node --init
"${COMPOSE[@]}" up -d --wait --wait-timeout 60
# Only publish the local helper after successful startup. Use an argv array.
HELPER="$INSTALL_ROOT/manage"
if [[ ! -e "$HELPER" ]]; then
  cat > "$HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/openvpnpa
exec docker compose --project-name openvpnpa --env-file "$ROOT/config/compose.env" -f "$ROOT/releases/v0.2.0-beta.1/deploy/compose.yaml" "$@"
EOF
  chmod 700 "$HELPER"
fi
echo "Installed $VERSION. Public UI was requested: $PUBLIC_UI (otherwise loopback only)."
echo "Use HTTPS on the configured UI port; use SSH forwarding for a loopback-only UI."
echo "Public CA certificate: $INSTALL_ROOT/state/pki/ca.crt"
echo "In the UI open /setup to register a NEW PasarGuard core, group and REST node."
echo "After setting group_ids in $INSTALL_ROOT/config/config.json: $HELPER restart node"
echo "Logs: $HELPER logs --tail=100 node"

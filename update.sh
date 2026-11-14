#!/usr/bin/env bash
set -euo pipefail
umask 077
# Managed by OpenVPNPA updater
OPENVPNPA_BOOTSTRAP_RELEASE=v0.2.0-beta.9

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  echo 'OpenVPNPA update: sudo bash update.sh'
  echo 'Akharin code az main gerefte mishavad; config va state hefz mishavand.'
  exit 0
fi
[[ $# -eq 0 ]] || { echo 'Argument ezafi mojaz nist.' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Ba sudo ejra konid.' >&2; exit 1; }
# sudo/non-interactive shells may omit standard system or Snap CLI paths.
export PATH="${PATH:-/usr/bin:/bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
UPDATE_TMP=$(mktemp -d /tmp/openvpnpa-update.XXXXXXXX)
trap 'rm -rf -- "$UPDATE_TMP"' EXIT
fetch_installer() {
  if [[ ! -f "$UPDATE_TMP/install.sh" ]]; then
    curl -fsSL "https://raw.githubusercontent.com/zhilvanzhinos/openvpnpa/$OPENVPNPA_BOOTSTRAP_RELEASE/install.sh" -o "$UPDATE_TMP/install.sh"
  fi
}
if [[ ! -f /opt/openvpnpa/config/config.json || ! -f /opt/openvpnpa/config/compose.env ]]; then
  echo 'Nasb avaliye kamel nist; nasb-konande edame midahad. Config ghabli hefz mishavad.'
  fetch_installer
  bash "$UPDATE_TMP/install.sh"
  exit 0
fi
NEEDS_PREPARE=0
for tool in git python3 docker flock; do
  command -v "$tool" >/dev/null || NEEDS_PREPARE=1
done
if (( ! NEEDS_PREPARE )); then
  if ! docker compose version >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    NEEDS_PREPARE=1
  fi
fi
if ((NEEDS_PREPARE)); then
  echo 'Pishniaz kam ast; Docker va tool-haye lazem barresi va nasb mishavand...'
  fetch_installer
  bash "$UPDATE_TMP/install.sh" --prepare-only
fi
for tool in git python3 docker flock; do
  command -v "$tool" >/dev/null || { echo "Tool $tool hanooz dar dastres nist." >&2; exit 1; }
done
# Serialize the download as well as deployment. No process or daemon restart.
exec 9>/opt/openvpnpa/.update.lock
flock -n 9 || { echo 'Yek update digar dar hale ejra ast.' >&2; exit 1; }
docker compose version >/dev/null
docker info >/dev/null
if [[ -z $(docker ps -aq --filter label=com.docker.compose.project=openvpnpa --filter label=com.docker.compose.service=node) ]]; then
  echo 'Container node vojood nadarad; nasb nimetamam edame midahad.'
  fetch_installer
  bash "$UPDATE_TMP/install.sh"
  exit 0
fi
echo 'Daryaft akharin taghirat az GitHub...'
git -c advice.detachedHead=false clone --depth 1 --branch main https://github.com/zhilvanzhinos/openvpnpa.git "$UPDATE_TMP/source"
(cd "$UPDATE_TMP/source" && python3 -m openvpnpa.update --root /opt/openvpnpa --source "$UPDATE_TMP/source")

#!/usr/bin/env bash
set -euo pipefail
umask 077
# Managed by OpenVPNPA updater

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  echo 'OpenVPNPA update: sudo bash update.sh'
  echo 'Akharin code az main gerefte mishavad; config va state hefz mishavand.'
  exit 0
fi
[[ $# -eq 0 ]] || { echo 'Argument ezafi mojaz nist.' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Ba sudo ejra konid.' >&2; exit 1; }
for tool in git python3 docker flock; do
  command -v "$tool" >/dev/null || { echo "Tool $tool nasb nist." >&2; exit 1; }
done
[[ -f /opt/openvpnpa/config/config.json && -f /opt/openvpnpa/config/compose.env ]] || {
  echo 'Nasb ghabli OpenVPNPA dar /opt/openvpnpa peyda nashod.' >&2
  exit 1
}
# Serialize the download as well as deployment. No process or daemon restart.
exec 9>/opt/openvpnpa/.update.lock
flock -n 9 || { echo 'Yek update digar dar hale ejra ast.' >&2; exit 1; }
docker compose version >/dev/null
docker info >/dev/null
UPDATE_TMP=$(mktemp -d /tmp/openvpnpa-update.XXXXXXXX)
trap 'rm -rf -- "$UPDATE_TMP"' EXIT
echo 'Daryaft akharin taghirat az GitHub...'
git -c advice.detachedHead=false clone --depth 1 --branch main https://github.com/zhilvanzhinos/openvpnpa.git "$UPDATE_TMP/source"
(cd "$UPDATE_TMP/source" && python3 -m openvpnpa.update --root /opt/openvpnpa --source "$UPDATE_TMP/source")

#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -- "$0" "$@"
fi

systemctl disable --now awus-surveyor.service 2>/dev/null || true
rm -f /etc/systemd/system/awus-surveyor.service
rm -f /usr/local/bin/awus-survey
rm -f /usr/local/sbin/awus-surveyor
rm -rf /usr/local/share/doc/awus-surveyor
systemctl daemon-reload 2>/dev/null || true

echo "AWUS1900 Surveyor executables and service unit removed. Survey output was left intact."

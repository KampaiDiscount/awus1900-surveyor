#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -- "$0" "$@"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

missing_packages=()
command -v python3 >/dev/null 2>&1 || missing_packages+=(python3)
command -v iw >/dev/null 2>&1 || missing_packages+=(iw)
command -v ip >/dev/null 2>&1 || missing_packages+=(iproute2)

if (( ${#missing_packages[@]} )); then
  echo "Installing required packages: ${missing_packages[*]}"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}"
fi

# Optional local OUI database for vendor names.
if ! dpkg-query -W -f='${Status}' ieee-data 2>/dev/null | grep -q 'install ok installed'; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y ieee-data || true
fi

install -m 0755 "$SCRIPT_DIR/awus_surveyor.py" /usr/local/sbin/awus-surveyor
install -d -m 0755 /usr/local/share/doc/awus-surveyor
install -m 0644 "$SCRIPT_DIR/README.md" /usr/local/share/doc/awus-surveyor/README.md
install -m 0644 "$SCRIPT_DIR/CHANGELOG.md" /usr/local/share/doc/awus-surveyor/CHANGELOG.md
install -m 0644 "$SCRIPT_DIR/LICENSE" /usr/local/share/doc/awus-surveyor/LICENSE
install -m 0644 "$SCRIPT_DIR/RELEASE_NOTES_v1.0.1.md" /usr/local/share/doc/awus-surveyor/RELEASE_NOTES_v1.0.1.md
install -d -m 0755 /usr/local/share/doc/awus-surveyor/docs
install -m 0644 "$SCRIPT_DIR/docs/rssi.md" /usr/local/share/doc/awus-surveyor/docs/rssi.md
install -m 0644 "$SCRIPT_DIR/docs/companion-deployment.md" /usr/local/share/doc/awus-surveyor/docs/companion-deployment.md
cat > /usr/local/bin/awus-survey <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec sudo -- /usr/local/sbin/awus-surveyor --country ZA "$@"
EOF
chmod 0755 /usr/local/bin/awus-survey

if [[ -f "$SCRIPT_DIR/systemd/awus-surveyor.service" ]]; then
  install -m 0644 "$SCRIPT_DIR/systemd/awus-surveyor.service" /etc/systemd/system/awus-surveyor.service
  systemctl daemon-reload || true
fi

echo
echo "Installed successfully."
echo "Run interactively:  awus-survey"
echo "One validation sweep: awus-survey --once"
echo "Adapter check only:  sudo awus-surveyor --self-test"
echo
echo "The optional systemd unit was installed but NOT enabled."
echo "Enable it only when you want the dedicated AWUS1900 surveyed at boot:"
echo "  sudo systemctl enable --now awus-surveyor.service"

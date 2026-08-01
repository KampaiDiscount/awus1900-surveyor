#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The supplied launcher uses South Africa's regulatory domain. The Python
# program restores the previous regulatory setting when it exits.
exec sudo -- "$SCRIPT_DIR/awus_surveyor.py" --country ZA "$@"

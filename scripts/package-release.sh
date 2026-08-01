#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(python3 - <<'PY' "$ROOT/awus_surveyor.py"
from pathlib import Path
import re
import sys
text = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r'^VERSION = "([^"]+)"$', text, re.M)
if not match:
    raise SystemExit("VERSION not found")
print(match.group(1))
PY
)"
NAME="awus1900-surveyor-v${VERSION}"
DIST="$ROOT/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$DIST" "$STAGE/$NAME"
cp -a "$ROOT/." "$STAGE/$NAME/"
rm -rf \
  "$STAGE/$NAME/.git" \
  "$STAGE/$NAME/dist" \
  "$STAGE/$NAME/awus-surveys"
find "$STAGE/$NAME" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$STAGE/$NAME" -type f -name '*.pyc' -delete

(
  cd "$STAGE/$NAME"
  find . -type f ! -name MANIFEST.txt -print0 | sort -z | xargs -0 sha256sum > MANIFEST.txt
)
(
  cd "$STAGE"
  python3 -m zipfile -c "$DIST/$NAME.zip" "$NAME"
  tar -czf "$DIST/$NAME.tar.gz" "$NAME"
)
(
  cd "$DIST"
  sha256sum "$NAME.zip" "$NAME.tar.gz" > "$NAME.sha256"
)

printf 'Created:\n  %s\n  %s\n  %s\n' \
  "$DIST/$NAME.zip" \
  "$DIST/$NAME.tar.gz" \
  "$DIST/$NAME.sha256"

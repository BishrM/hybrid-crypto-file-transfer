#!/usr/bin/env bash
# Launch CipherLink: ./run.sh [--home DIR]
# Creates .venv (Python 3.12+) on first use and reinstalls requirements.txt only when it
# changes. Arguments go to main.py. CIPHERLINK_HOME and existing app data are left alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
VENV_PY="$VENV/bin/python"
REQS="$ROOT/requirements.txt"
STAMP="$VENV/.cipherlink-requirements.sha256"

die() { printf 'run.sh: error: %s\n' "$*" >&2; exit 1; }
is_compatible() { "$1" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; }

[[ -f "$ROOT/main.py" && -f "$REQS" ]] || die "main.py or requirements.txt missing in $ROOT"

if [[ -x "$VENV_PY" ]]; then
    is_compatible "$VENV_PY" || die "$VENV uses $("$VENV_PY" --version 2>&1); CipherLink needs Python 3.12+.
Move or delete that folder yourself, then run ./run.sh again to recreate it."
else
    PY=""
    for cand in ${PYTHON:-} python3.14 python3.13 python3.12 python3; do
        if command -v "$cand" >/dev/null 2>&1 && is_compatible "$cand"; then PY="$cand"; break; fi
    done
    [[ -n "$PY" ]] || die "Python 3.12 or newer not found.
Install it from https://www.python.org/downloads/ (or your package manager),
or point to one with: PYTHON=/path/to/python3.12 ./run.sh"
    echo "Creating virtual environment in $VENV with $("$PY" --version 2>&1) ..."
    "$PY" -m venv "$VENV" || die "could not create $VENV.
On Debian/Ubuntu install the venv module first: sudo apt install python3-venv"
fi

want="$("$VENV_PY" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$REQS")"
have="$(cat "$STAMP" 2>/dev/null || true)"
if [[ "$want" != "$have" ]] || ! "$VENV_PY" -c 'import cryptography, PyQt6.QtWidgets' 2>/dev/null; then
    echo "Installing dependencies from requirements.txt ..."
    "$VENV_PY" -m pip install --disable-pip-version-check -r "$REQS" \
        || die "dependency installation failed; see the pip output above (network access is needed on first install)."
    printf '%s\n' "$want" > "$STAMP"
fi

exec "$VENV_PY" "$ROOT/main.py" "$@"

#!/usr/bin/env bash
# Wrapper for this Nix-based host: wheels from PyPI need libstdc++ on LD_LIBRARY_PATH.
set -euo pipefail
cd "$(dirname "$0")"
if ! python3 -c 'import numpy' >/dev/null 2>&1; then
  libstdcxx="$(dirname "$(find /nix/store -name 'libstdc++.so.6' 2>/dev/null | head -n 1)")"
  if [ -n "$libstdcxx" ]; then
    export LD_LIBRARY_PATH="${libstdcxx}:${LD_LIBRARY_PATH:-}"
  fi
fi
exec .venv/bin/python -m src.cli "$@"

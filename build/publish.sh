#!/usr/bin/env bash
# Publishes every shipped executable, self-contained for win-x64, into one folder (shared runtime files).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/artifacts/publish}"
rm -rf "$OUT"; mkdir -p "$OUT"
for p in SAMP.Service SAMP.Monitor SAMP.App SAMP.UninstallGuard; do
  echo "== publish $p"
  dotnet publish "$ROOT/src/$p/$p.csproj" -c Release -r win-x64 --self-contained true \
    -p:EnableWindowsTargeting=true -p:DebugType=none -p:DebugSymbols=false -o "$OUT"
done
echo "Published to $OUT"

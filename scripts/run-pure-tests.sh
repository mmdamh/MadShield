#!/usr/bin/env bash
# Compiles every pure-Kotlin source (no android/androidx/coroutines/okhttp imports) together with
# tests/pure/Tests.kt and runs it. Needs `kotlinc` on PATH (or KOTLINC=/path/to/kotlinc) and a JRE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/app/src/main/java/com/aethershield/app"
KOTLINC="${KOTLINC:-kotlinc}"
OUT="$(mktemp -d)"
export MADSHIELD_ROOT="$ROOT"   # the golden files are looked up under it
files=()
for f in "$SRC"/core/*.kt "$SRC"/util/*.kt; do
  if ! grep -qE "^import (android|androidx|kotlinx\.coroutines|okhttp3)" "$f"; then files+=("$f"); fi
done
"$KOTLINC" "${files[@]}" "$ROOT/tests/pure/Tests.kt" -include-runtime -d "$OUT/t.jar" 2>&1 | grep -v "^warning" || true
java -cp "$OUT/t.jar" TestsKt | tee "$OUT/result.txt"
grep -q "^ALL PASSED" "$OUT/result.txt"

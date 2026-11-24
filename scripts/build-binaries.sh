#!/usr/bin/env bash
# Build standalone `gap` binaries.
#
#   ./scripts/build-binaries.sh                 # every platform
#   ./scripts/build-binaries.sh darwin-arm64    # one target, for local smoke tests
#
# Requires Bun >= 1.3 and network access for cross-compilation: Bun downloads
# the runtime for each non-host target on first use. The CLI embeds the
# inspector UI and compiles a user's action registry at runtime, so the
# resulting binary has no Node.js dependency.
set -euo pipefail

cd "$(dirname "$0")/.."

BUN="${BUN:-$(command -v bun || true)}"
if [ -z "$BUN" ] && [ -x "$HOME/.bun/bin/bun" ]; then
  BUN="$HOME/.bun/bin/bun"
fi
if [ -z "$BUN" ]; then
  echo "error: bun is required (https://bun.sh)" >&2
  exit 1
fi

VERSION="$(node -p "require('./packages/cli/package.json').version")"
OUT="dist-bin"

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=(darwin-arm64 darwin-x64 linux-x64 linux-arm64 windows-x64)
fi

rm -rf "$OUT"
mkdir -p "$OUT"

build() {
  local name="$1" target="$2" outfile="$3"
  echo "building $name ($target)"
  "$BUN" build --compile --minify --target="$target" \
    packages/cli/src/index.ts --outfile "$OUT/$outfile"
}

for target in "${TARGETS[@]}"; do
  case "$target" in
    darwin-arm64) build "$target" bun-darwin-arm64 gap-darwin-arm64 ;;
    darwin-x64) build "$target" bun-darwin-x64 gap-darwin-x64 ;;
    linux-x64) build "$target" bun-linux-x64 gap-linux-x64 ;;
    linux-arm64) build "$target" bun-linux-arm64 gap-linux-arm64 ;;
    windows-x64) build "$target" bun-windows-x64 gap-windows-x64.exe ;;
    *)
      echo "error: unknown target '$target' (expected darwin-arm64, darwin-x64, linux-x64, linux-arm64, windows-x64)" >&2
      exit 1
      ;;
  esac
done

# Unix archives contain a single `gap` executable.
for name in gap-darwin-arm64 gap-darwin-x64 gap-linux-x64 gap-linux-arm64; do
  [ -f "$OUT/$name" ] || continue
  chmod +x "$OUT/$name"
  stage="$(mktemp -d)"
  cp "$OUT/$name" "$stage/gap"
  tar -czf "$OUT/$name.tar.gz" -C "$stage" gap
  rm -rf "$stage" "$OUT/$name"
done

# Windows: a zip containing `gap.exe` for Scoop and winget.
if [ -f "$OUT/gap-windows-x64.exe" ]; then
  stage="$(mktemp -d)"
  cp "$OUT/gap-windows-x64.exe" "$stage/gap.exe"
  zip -q -j "$OUT/gap-windows-x64.zip" "$stage/gap.exe"
  rm -rf "$stage" "$OUT/gap-windows-x64.exe"
fi

(
  cd "$OUT"
  shasum -a 256 ./*.tar.gz ./*.zip > SHA256SUMS
  # Per-asset checksums let Scoop's autoupdate verify a download without
  # parsing the combined checksum file.
  for file in ./*.tar.gz ./*.zip; do
    shasum -a 256 "$file" | cut -d' ' -f1 > "$file.sha256"
  done
)

echo
echo "Built $VERSION artifacts in $OUT:"
ls -lh "$OUT"

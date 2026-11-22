#!/usr/bin/env bash
# Build standalone `gap` binaries for every supported platform.
#
# Requires Bun >= 1.3. The CLI embeds the inspector UI and bundles a user's
# action registry at runtime with Bun's transpiler, so the resulting binary has
# no Node.js dependency.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(node -p "require('./packages/cli/package.json').version")"
OUT="dist-bin"
rm -rf "$OUT"
mkdir -p "$OUT"

build() {
  local target="$1" name="$2"
  echo "building $name ($target)"
  bun build --compile --minify --target="$target" \
    packages/cli/src/index.ts --outfile "$OUT/$name"
}

build bun-darwin-arm64 gap-darwin-arm64
build bun-darwin-x64 gap-darwin-x64
build bun-linux-x64 gap-linux-x64
build bun-linux-arm64 gap-linux-arm64
build bun-windows-x64 gap-windows-x64.exe

# Unix archives keep the executable bit and a predictable top-level name.
for name in gap-darwin-arm64 gap-darwin-x64 gap-linux-x64 gap-linux-arm64; do
  chmod +x "$OUT/$name"
  tar -czf "$OUT/$name.tar.gz" -C "$OUT" "$name"
  rm "$OUT/$name"
done

# Windows: a zip for Scoop, plus the bare exe for winget.
zip -q -j "$OUT/gap-windows-x64.zip" "$OUT/gap-windows-x64.exe"

(
  cd "$OUT"
  shasum -a 256 ./*.tar.gz ./*.zip ./*.exe > SHA256SUMS
)

echo
echo "Built $VERSION artifacts in $OUT:"
ls -lh "$OUT"

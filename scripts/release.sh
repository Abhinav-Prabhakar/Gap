#!/usr/bin/env bash
# Publish a Gap release end to end, locally.
#
#   ./scripts/release.sh --help
#   NPM_CONFIG_OTP=123456 ./scripts/release.sh
#
# There is deliberately no CI. This script is the release pipeline: it verifies
# the tree, publishes the npm packages, builds standalone binaries, creates the
# GitHub release, and updates the Homebrew tap, Scoop bucket and winget fork.
#
# Every remote step can be skipped, which is useful when re-running after a
# network failure:
#
#   SKIP_NPM=1 SKIP_CHECKS=1 ./scripts/release.sh
#
# Environment:
#   NPM_CONFIG_OTP   one-time password for npm (or use a bypass-2FA token)
#   GH_TOKEN         token for gh; defaults to the gh session
#   PUBLISH_PYTHON=1 also build and publish the Python package with uv
#   UV_PUBLISH_TOKEN PyPI token for uv publish
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(node -p "require('./packages/cli/package.json').version")"
TAG="v$VERSION"
OWNER="${GAP_OWNER:-Abhinav-Prabhakar}"
REPO="$OWNER/Gap"
OUT="dist-bin"
MANIFESTS="dist-manifests"
RELEASE_DIR=".release"

SKIP_CHECKS="${SKIP_CHECKS:-0}"
SKIP_NPM="${SKIP_NPM:-0}"
SKIP_BINARIES="${SKIP_BINARIES:-0}"
SKIP_GITHUB_RELEASE="${SKIP_GITHUB_RELEASE:-0}"
SKIP_BREW="${SKIP_BREW:-0}"
SKIP_SCOOP="${SKIP_SCOOP:-0}"
SKIP_WINGET="${SKIP_WINGET:-0}"
SKIP_GO_TAG="${SKIP_GO_TAG:-0}"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Publish a Gap release end to end, locally.

  ./scripts/release.sh --help
  NPM_CONFIG_OTP=123456 ./scripts/release.sh

There is deliberately no CI. This script verifies the tree, publishes the npm
packages, builds standalone binaries, creates the GitHub release, and updates
the Homebrew tap, Scoop bucket and winget fork.

Options:
  --skip-checks          skip tests, typecheck and builds
  --skip-npm             skip npm publishing
  --skip-binaries        reuse dist-bin and its SHA256SUMS
  --skip-github-release  skip the tag and GitHub release
  --skip-brew            skip the Homebrew tap
  --skip-scoop           skip the Scoop bucket
  --skip-winget          skip the winget fork and PR
  --help                 show this help

The version comes from packages/cli/package.json. Every publishable package
must share it; the script refuses to run otherwise.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --skip-checks) SKIP_CHECKS=1 ;;
    --skip-npm) SKIP_NPM=1 ;;
    --skip-binaries) SKIP_BINARIES=1 ;;
    --skip-github-release) SKIP_GITHUB_RELEASE=1 ;;
    --skip-brew) SKIP_BREW=1 ;;
    --skip-scoop) SKIP_SCOOP=1 ;;
    --skip-winget) SKIP_WINGET=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $arg (try --help)" ;;
  esac
done

step "Preflight"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git repository"

node - "$VERSION" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const expected = process.argv[2];
const root = process.cwd();
const packages = fs
  .readdirSync(path.join(root, "packages"))
  .map((dir) => path.join(root, "packages", dir, "package.json"))
  .filter((file) => fs.existsSync(file))
  .map((file) => JSON.parse(fs.readFileSync(file, "utf8")))
  .filter((pkg) => !pkg.private);
const mismatched = packages.filter((pkg) => pkg.version !== expected);
if (mismatched.length > 0) {
  console.error(
    `Version mismatch: CLI is ${expected}, but ${mismatched
      .map((pkg) => `${pkg.name}@${pkg.version}`)
      .join(", ")}`,
  );
  process.exit(1);
}
console.log(`   ${packages.length} publishable packages at ${expected}`);
NODE

[ -z "$(git status --porcelain)" ] || fail "working tree is dirty; commit or stash first"
branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = "main" ] || fail "release from main, not $branch"
command -v gh >/dev/null 2>&1 || fail "gh is required"
command -v node >/dev/null 2>&1 || fail "node is required"

if [ "$SKIP_NPM" != "1" ]; then
  npm_user="$(npm whoami 2>/dev/null || true)"
  [ -n "$npm_user" ] || fail "npm is not authenticated (run npm login, or set NODE_AUTH_TOKEN)"
  info "npm user: $npm_user"
fi

if [ "$SKIP_CHECKS" != "1" ]; then
  step "Verify TypeScript"
  pnpm test
  pnpm typecheck
  pnpm build

  step "Verify Python"
  pnpm test:python

  step "Verify Go"
  pnpm test:go
fi

if [ "$SKIP_NPM" != "1" ]; then
  step "Publish npm packages"
  args=(--access public --no-git-checks)
  if [ -n "${NPM_CONFIG_OTP:-}" ]; then
    args+=(--otp "$NPM_CONFIG_OTP")
  fi
  pnpm -r publish "${args[@]}"

  step "Verify npm"
  short=(core server auth policy observability evals importers dom testing cli)
  for name in "${short[@]}"; do
    package="gapmcp-$name"
    for attempt in 1 2 3 4 5; do
      published="$(npm view "$package@$VERSION" version 2>/dev/null || true)"
      [ "$published" = "$VERSION" ] && break
      [ "$attempt" = 5 ] && fail "$package@$VERSION is not visible on npm"
      sleep 3
    done
    info "$package@$VERSION"
  done
  published="$(npm view "gapmcp@$VERSION" version 2>/dev/null || true)"
  [ "$published" = "$VERSION" ] || fail "gapmcp@$VERSION is not visible on npm"
  info "gapmcp@$VERSION"
fi

if [ "$SKIP_BINARIES" != "1" ]; then
  step "Build standalone binaries"
  ./scripts/build-binaries.sh
  [ "$(grep -c . "$OUT/SHA256SUMS")" = "5" ] ||
    fail "expected 5 release assets; cross-compilation may have failed. See $OUT."
fi
[ -f "$OUT/SHA256SUMS" ] || fail "missing $OUT/SHA256SUMS"

step "Generate packaging manifests"
rm -rf "$MANIFESTS"
[ -f packages/cli/dist/index.js ] || pnpm --filter gapmcp-cli build
node packages/cli/dist/index.js release manifests \
  --release-version "$VERSION" \
  --checksums "$OUT/SHA256SUMS" \
  --repository "$REPO" \
  --out "$MANIFESTS"

if [ "$SKIP_GITHUB_RELEASE" != "1" ]; then
  step "Tag and release"
  if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    info "tag $TAG already exists"
  else
    git tag -a "$TAG" -m "Gap $VERSION"
  fi
  git push origin main
  git push origin "$TAG"

  if [ "$SKIP_GO_TAG" != "1" ]; then
    # The Go module lives in go/, so its version tag is prefixed.
    GO_TAG="go/$TAG"
    if git rev-parse -q --verify "refs/tags/$GO_TAG" >/dev/null; then
      info "tag $GO_TAG already exists"
    else
      git tag -a "$GO_TAG" -m "Go module $VERSION"
      git push origin "$GO_TAG"
    fi
  fi

  if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release upload "$TAG" "$OUT"/*.tar.gz "$OUT"/*.zip "$OUT"/*.sha256 "$OUT/SHA256SUMS" --repo "$REPO" --clobber
    info "uploaded assets to existing release $TAG"
  else
    gh release create "$TAG" "$OUT"/*.tar.gz "$OUT"/*.zip "$OUT"/*.sha256 "$OUT/SHA256SUMS" \
      --repo "$REPO" \
      --title "Gap $VERSION" \
      --generate-notes
  fi
fi

if [ "$SKIP_BREW" != "1" ]; then
  step "Update Homebrew tap"
  rm -rf "$RELEASE_DIR/homebrew-tap"
  mkdir -p "$RELEASE_DIR"
  git clone --depth 1 "https://github.com/$OWNER/homebrew-tap" "$RELEASE_DIR/homebrew-tap"
  tap="$RELEASE_DIR/homebrew-tap"
  if [ -d "$tap/Formula" ]; then formula_dir="$tap/Formula"; else formula_dir="$tap"; fi
  cp "$MANIFESTS/homebrew/Formula/gap.rb" "$formula_dir/gap.rb"
  if [ -z "$(git -C "$tap" status --porcelain)" ]; then
    info "formula already up to date"
  else
    git -C "$tap" add -A
    git -C "$tap" commit -m "gap $VERSION"
    git -C "$tap" push
    info "pushed $formula_dir/gap.rb"
  fi
  info "verify: brew install $OWNER/tap/gap"
fi

if [ "$SKIP_SCOOP" != "1" ]; then
  step "Update Scoop bucket"
  rm -rf "$RELEASE_DIR/ScoopBucket"
  git clone --depth 1 "https://github.com/$OWNER/ScoopBucket" "$RELEASE_DIR/ScoopBucket"
  bucket="$RELEASE_DIR/ScoopBucket"
  if [ -d "$bucket/bucket" ]; then bucket_dir="$bucket/bucket"; else bucket_dir="$bucket"; fi
  cp "$MANIFESTS/scoop/bucket/gap.json" "$bucket_dir/gap.json"
  if [ -z "$(git -C "$bucket" status --porcelain)" ]; then
    info "manifest already up to date"
  else
    git -C "$bucket" add -A
    git -C "$bucket" commit -m "gap $VERSION"
    git -C "$bucket" push
    info "pushed $(basename "$bucket_dir")/gap.json"
  fi
  info "verify: scoop bucket add $OWNER https://github.com/$OWNER/ScoopBucket && scoop install gap"
fi

if [ "$SKIP_WINGET" != "1" ]; then
  step "Submit winget manifest"
  rm -rf "$RELEASE_DIR/winget-pkgs"
  mkdir -p "$RELEASE_DIR"
  git clone --depth 1 --filter=blob:none --sparse \
    "https://github.com/$OWNER/winget-pkgs" "$RELEASE_DIR/winget-pkgs"
  winget="$RELEASE_DIR/winget-pkgs"
  git -C "$winget" sparse-checkout set manifests/a/AbhinavPrabhakar/Gap
  branch="gap-$VERSION"
  git -C "$winget" checkout -b "$branch"
  mkdir -p "$winget/manifests/a/AbhinavPrabhakar/Gap/$VERSION"
  cp "$MANIFESTS/winget/manifests/a/AbhinavPrabhakar/Gap/$VERSION/"*.yaml \
    "$winget/manifests/a/AbhinavPrabhakar/Gap/$VERSION/"
  git -C "$winget" add "manifests/a/AbhinavPrabhakar/Gap"
  git -C "$winget" commit -m "Add AbhinavPrabhakar.Gap version $VERSION"
  git -C "$winget" push -u origin "$branch"
  gh pr create \
    --repo microsoft/winget-pkgs \
    --base master \
    --head "$OWNER:$branch" \
    --title "Add AbhinavPrabhakar.Gap version $VERSION" \
    --body "Adds Gap $VERSION, a standalone CLI for typed agent actions.

- Release: https://github.com/$REPO/releases/tag/$TAG
- Installer: portable \`gap.exe\` from $OUT/gap-windows-x64.zip
- Sha256: $(grep 'gap-windows-x64.zip' "$OUT/SHA256SUMS" | cut -d' ' -f1)" ||
    info "PR may already exist; check https://github.com/microsoft/winget-pkgs/pulls?q=AbhinavPrabhakar.Gap"
fi

if [ "${PUBLISH_PYTHON:-0}" = "1" ]; then
  step "Publish Python package"
  (cd python && uv build)
  if [ -n "${UV_PUBLISH_TOKEN:-}" ]; then
    (cd python && uv publish --token "$UV_PUBLISH_TOKEN")
  else
    (cd python && uv publish)
  fi
fi

step "Done"
info "version  $VERSION"
info "tag      $TAG"
info "release  https://github.com/$REPO/releases/tag/$TAG"
info "npm      https://www.npmjs.com/package/gapmcp-cli"
info "brew     brew install $OWNER/tap/gap"
info "scoop    scoop install gap"
info "winget   winget install AbhinavPrabhakar.Gap"
info ""
info "Post-release smoke test:"
info "  brew install $OWNER/tap/gap && gap --version"
info "  npx gapmcp-cli@$VERSION --version"

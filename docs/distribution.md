# Distribution

Gap ships as libraries and as a standalone `gap` binary. TypeScript and Python
are the supported SDKs; Go runs the same server contract.

## npm

| Package | Use |
| --- | --- |
| `gapmcp` | Umbrella: core plus `gapmcp/server`, `gapmcp/auth`, `gapmcp/policy`, `gapmcp/observability`, `gapmcp/dom` |
| `gapmcp-core` | Action contract, registry, schemas |
| `gapmcp-server` | MCP transports and the call pipeline |
| `gapmcp-auth` | API keys, JWT/OAuth 2.1, approvals, audit sinks |
| `gapmcp-policy` | Policy DSL |
| `gapmcp-observability` | Tracers and replay |
| `gapmcp-importers` | OpenAPI and Next.js importers |
| `gapmcp-dom` | DOM manifest, runtime, signed handoff |
| `gapmcp-evals` | Tool-selection evals and lint |
| `gapmcp-testing` | Test harness |
| `gapmcp-cli` | `gap` CLI and inspector |

```bash
npm install gapmcp
npm install -D gapmcp-cli
```

## Standalone binary

The CLI is also compiled with Bun, so `gap` runs without Node.js:

```bash
# macOS (Apple silicon)
curl -fsSL https://github.com/Abhinav-Prabhakar/Gap/releases/download/v0.1.0/gap-darwin-arm64.tar.gz \
  | tar -xz
sudo mv gap /usr/local/bin/gap
gap --version
```

Release assets: `gap-darwin-arm64`, `gap-darwin-x64`, `gap-linux-x64`,
`gap-linux-arm64`, `gap-windows-x64.exe`, plus `.tar.gz`/`.zip` archives and
`SHA256SUMS`. The binary loads a project's `gap.actions.ts` with Bun's
transpiler, so project dependencies still need to be installed.

## Homebrew

```bash
brew install Abhinav-Prabhakar/tap/gap
```

## Scoop

```powershell
scoop bucket add abhinav https://github.com/Abhinav-Prabhakar/ScoopBucket
scoop install gap
```

## winget

```powershell
winget install AbhinavPrabhakar.Gap
```

Manifests live in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
under `manifests/a/Abhinav-Prabhakar/Gap`.

## Python

```bash
pip install gapmcp
# or
uv add gapmcp
```

```python
from gapmcp import define_action, ActionRegistry
```

The Python package mirrors the action contract and server pipeline. It lives in
[`python/`](../python) and ships `py.typed`.

## Go

```bash
go get github.com/Abhinav-Prabhakar/Gap/go
```

```go
import gap "github.com/Abhinav-Prabhakar/Gap/go"
```

The Go module implements the core contract, auth, policy, approvals, receipts,
tasks and an MCP server. See [`go/README.md`](../go/README.md).

## Verifying a release

```bash
shasum -a 256 -c SHA256SUMS
gh attestation verify gap-darwin-arm64 --repo Abhinav-Prabhakar/Gap
```

Binaries are built locally from the tagged commit; there is no CI. The release
notes record the Bun version and the commands used.

## Cutting a release

There is no CI by design. One script performs the whole release:

```bash
NPM_CONFIG_OTP=123456 ./scripts/release.sh
```

It verifies TypeScript, Python and Go, publishes every workspace package, builds
the five standalone binaries, generates the packaging manifests, tags
`v<version>` (and `go/v<version>` for the nested Go module), creates the GitHub
release, updates the tap and bucket, and opens the winget PR. Failed network
steps can be retried in isolation:

```bash
SKIP_NPM=1 SKIP_CHECKS=1 ./scripts/release.sh
```

The manifests alone can be regenerated from a checksum file:

```bash
node packages/cli/dist/index.js release manifests \
  --release-version 0.1.0 \
  --checksums dist-bin/SHA256SUMS \
  --out dist-manifests
```

This writes `homebrew/Formula/gap.rb`, `scoop/bucket/gap.json` and the three
winget YAML files. They are committed to
[`homebrew-tap`](https://github.com/Abhinav-Prabhakar/homebrew-tap),
[`ScoopBucket`](https://github.com/Abhinav-Prabhakar/ScoopBucket) and a
`winget-pkgs` fork respectively.

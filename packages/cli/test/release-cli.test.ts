import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildProgram } from "../src/program";

const tempDirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "gap-release-cli-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("gap release manifests", () => {
  it("writes manifests from a checksum file", async () => {
    const dir = tempDir();
    const checksums = path.join(dir, "SHA256SUMS");
    writeFileSync(
      checksums,
      [
        `${"1".repeat(64)}  gap-darwin-arm64.tar.gz`,
        `${"2".repeat(64)}  gap-darwin-x64.tar.gz`,
        `${"3".repeat(64)}  gap-linux-arm64.tar.gz`,
        `${"4".repeat(64)}  gap-linux-x64.tar.gz`,
        `${"5".repeat(64)}  gap-windows-x64.zip`,
      ].join("\n"),
    );
    const out = path.join(dir, "out");
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.join(" "));
    });

    await buildProgram().parseAsync(
      ["node", "gap", "release", "manifests", "--release-version", "9.9.9", "--checksums", checksums, "--out", out],
      { from: "node" },
    );

    expect(logs.join("\n")).toContain("Gap 9.9.9 manifests");
    expect(readFileSync(path.join(out, "homebrew/Formula/gap.rb"), "utf8")).toContain('version "9.9.9"');
    expect(JSON.parse(readFileSync(path.join(out, "scoop/bucket/gap.json"), "utf8")).version).toBe("9.9.9");
    expect(
      readFileSync(
        path.join(
          out,
          "winget/manifests/a/AbhinavPrabhakar/Gap/9.9.9/AbhinavPrabhakar.Gap.installer.yaml",
        ),
        "utf8",
      ),
    ).toContain(`InstallerSha256: ${"5".repeat(64).toUpperCase()}`);
  });

  it("fails when the checksum file has no assets", async () => {
    const dir = tempDir();
    const checksums = path.join(dir, "SHA256SUMS");
    writeFileSync(checksums, "nothing here\n");
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    await expect(
      buildProgram().parseAsync(
        ["node", "gap", "release", "manifests", "--checksums", checksums, "--out", path.join(dir, "out")],
        { from: "node" },
      ),
    ).rejects.toThrow(/No SHA-256 entries/);
  });
});

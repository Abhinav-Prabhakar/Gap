import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseChecksums,
  renderHomebrewFormula,
  renderManifests,
  renderScoopManifest,
  renderWingetManifests,
  writeManifests,
  type ReleaseAsset,
} from "../src/manifests";

const assets: ReleaseAsset[] = [
  { name: "gap-darwin-arm64.tar.gz", sha256: "a".repeat(64) },
  { name: "gap-darwin-x64.tar.gz", sha256: "b".repeat(64) },
  { name: "gap-linux-arm64.tar.gz", sha256: "c".repeat(64) },
  { name: "gap-linux-x64.tar.gz", sha256: "d".repeat(64) },
  { name: "gap-windows-x64.zip", sha256: "e".repeat(64) },
];

const options = {
  version: "1.2.3",
  repository: "Abhinav-Prabhakar/Gap",
  assets,
  releaseDate: "2026-11-22",
};

describe("release manifests", () => {
  it("parses shasum output, including binary-mode markers", () => {
    const parsed = parseChecksums(
      [
        `${"1".repeat(64)}  gap-darwin-arm64.tar.gz`,
        `${"2".repeat(64)} *gap-windows-x64.zip`,
        "",
        "not a checksum line",
        `${"3".repeat(64)}  dist/gap-linux-x64.tar.gz`,
      ].join("\n"),
    );
    expect(parsed).toEqual([
      { sha256: "1".repeat(64), name: "gap-darwin-arm64.tar.gz" },
      { sha256: "2".repeat(64), name: "gap-windows-x64.zip" },
      { sha256: "3".repeat(64), name: "dist/gap-linux-x64.tar.gz" },
    ]);
  });

  it("renders a multi-platform Homebrew formula", () => {
    const formula = renderHomebrewFormula(options);
    expect(formula).toContain("class Gap < Formula");
    expect(formula).toContain('version "1.2.3"');
    expect(formula).toContain('license "MIT"');
    expect(formula).toContain("bin.install \"gap\"");
    expect(formula).toContain(
      "https://github.com/Abhinav-Prabhakar/Gap/releases/download/v1.2.3/gap-darwin-arm64.tar.gz",
    );
    expect(formula).toContain(`sha256 "${"a".repeat(64)}"`);
    expect(formula).toContain(`sha256 "${"b".repeat(64)}"`);
    expect(formula).toContain(`sha256 "${"c".repeat(64)}"`);
    expect(formula).toContain(`sha256 "${"d".repeat(64)}"`);
    expect(formula.match(/on_macos do/g)).toHaveLength(1);
    expect(formula.match(/on_linux do/g)).toHaveLength(1);
    expect(formula.match(/on_arm do/g)).toHaveLength(2);
    expect(formula.match(/on_intel do/g)).toHaveLength(2);
  });

  it("renders a valid Scoop manifest with autoupdate", () => {
    const manifest = JSON.parse(renderScoopManifest(options)) as Record<string, any>;
    expect(manifest.version).toBe("1.2.3");
    expect(manifest.license).toBe("MIT");
    expect(manifest.bin).toBe("gap.exe");
    expect(manifest.architecture["64bit"].hash).toBe("e".repeat(64));
    expect(manifest.architecture["64bit"].url).toContain("/v1.2.3/gap-windows-x64.zip");
    expect(manifest.checkver.github).toBe("https://github.com/Abhinav-Prabhakar/Gap");
    expect(manifest.autoupdate.architecture["64bit"].url).toContain("/v$version/gap-windows-x64.zip");
    expect(manifest.autoupdate.architecture["64bit"].hash).toEqual({ url: "$url.sha256" });
  });

  it("renders three winget manifests with an uppercase hash", () => {
    const { version, installer, locale } = renderWingetManifests(options);
    expect(version).toContain("PackageIdentifier: AbhinavPrabhakar.Gap");
    expect(version).toContain("PackageVersion: 1.2.3");
    expect(version).toContain("ManifestType: version");
    expect(installer).toContain("InstallerType: zip");
    expect(installer).toContain("NestedInstallerType: portable");
    expect(installer).toContain("RelativeFilePath: gap.exe");
    expect(installer).toContain("PortableCommandAlias: gap");
    expect(installer).toContain(`InstallerSha256: ${"E".repeat(64)}`);
    expect(installer).toContain("ReleaseDate: 2026-11-22");
    expect(locale).toContain("PackageLocale: en-US");
    expect(locale).toContain("License: MIT");
    expect(locale).toContain("ManifestType: defaultLocale");
  });

  it("normalizes a v-prefixed version and a full repository URL", () => {
    const rendered = renderManifests({
      ...options,
      version: "v2.0.0",
      repository: "https://github.com/example/gap/",
    });
    expect(rendered.homebrew).toContain('version "2.0.0"');
    expect(rendered.homebrew).toContain("https://github.com/example/gap/releases/download/v2.0.0/");
  });

  it("fails clearly when a platform asset is missing", () => {
    expect(() =>
      renderManifests({ ...options, assets: assets.filter((asset) => !asset.name.includes("linux")) }),
    ).toThrow(/Missing release assets: gap-linux-arm64\.tar\.gz, gap-linux-x64\.tar\.gz/);
  });

  it("rejects malformed versions, repositories and hashes", () => {
    expect(() => renderManifests({ ...options, version: "latest" })).toThrow(/semantic version/);
    expect(() => renderManifests({ ...options, repository: "not-a-repo" })).toThrow(/owner\/name/);
    expect(() =>
      renderManifests({ ...options, assets: [{ name: "gap-windows-x64.zip", sha256: "nope" }] }),
    ).toThrow(/Invalid SHA-256/);
  });

  it("writes the tap, bucket and winget layouts", () => {
    const out = mkdtempSync(path.join(tmpdir(), "gap-manifests-"));
    try {
      const files = writeManifests(
        options,
        out,
        (file, content) => {
          mkdirSync(path.dirname(file), { recursive: true });
          writeFileSync(file, content);
        },
        (dir) => mkdirSync(dir, { recursive: true }),
      );
      expect(files).toHaveLength(5);
      expect(readFileSync(path.join(out, "homebrew/Formula/gap.rb"), "utf8")).toContain("class Gap");
      expect(JSON.parse(readFileSync(path.join(out, "scoop/bucket/gap.json"), "utf8")).version).toBe("1.2.3");
      const wingetDir = path.join(out, "winget/manifests/a/AbhinavPrabhakar/Gap/1.2.3");
      expect(readFileSync(path.join(wingetDir, "AbhinavPrabhakar.Gap.installer.yaml"), "utf8")).toContain(
        "PackageVersion: 1.2.3",
      );
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });
});

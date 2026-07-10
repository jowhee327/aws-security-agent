import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseApkInstalled,
  parseDpkgStatus,
  parseOsRelease,
} from "../../../src/scanners/ecr-image-cve/parsers.js";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures", "ecr-image-cve");

describe("parseApkInstalled", () => {
  const content = readFileSync(join(fixturesDir, "apk-installed.txt"), "utf8");

  it("parses all package stanzas with name, version, and origin", () => {
    const packages = parseApkInstalled(content);
    expect(packages).toHaveLength(4);

    const nginx = packages.find((p) => p.name === "nginx");
    expect(nginx).toBeDefined();
    expect(nginx!.version).toBe("1.26.3-r0");
    expect(nginx!.sourcePackage).toBe("nginx");
    expect(nginx!.manager).toBe("apk");
  });

  it("records origin package for subpackages (libssl3 → openssl)", () => {
    const packages = parseApkInstalled(content);
    const libssl = packages.find((p) => p.name === "libssl3");
    expect(libssl!.sourcePackage).toBe("openssl");
    expect(libssl!.version).toBe("3.3.2-r4");
  });

  it("returns empty array for empty content", () => {
    expect(parseApkInstalled("")).toEqual([]);
  });
});

describe("parseDpkgStatus", () => {
  const content = readFileSync(join(fixturesDir, "dpkg-status.txt"), "utf8");

  it("parses installed packages with source mapping", () => {
    const packages = parseDpkgStatus(content);
    const names = packages.map((p) => p.name);
    expect(names).toContain("curl");
    expect(names).toContain("libssl3");
    expect(names).toContain("nginx-core");

    const libssl = packages.find((p) => p.name === "libssl3");
    expect(libssl!.version).toBe("3.0.2-0ubuntu1.18");
    expect(libssl!.sourcePackage).toBe("openssl");
    expect(libssl!.manager).toBe("dpkg");
  });

  it("skips packages that are not in 'install ok installed' state", () => {
    const packages = parseDpkgStatus(content);
    expect(packages.find((p) => p.name === "removed-package")).toBeUndefined();
  });
});

describe("parseOsRelease", () => {
  it("parses Alpine os-release with quoted values", () => {
    const os = parseOsRelease(
      'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.21.0\nPRETTY_NAME="Alpine Linux v3.21"\n',
    );
    expect(os.id).toBe("alpine");
    expect(os.versionId).toBe("3.21.0");
    expect(os.prettyName).toBe("Alpine Linux v3.21");
  });

  it("parses Ubuntu os-release", () => {
    const os = parseOsRelease('ID=ubuntu\nVERSION_ID="22.04"\n');
    expect(os.id).toBe("ubuntu");
    expect(os.versionId).toBe("22.04");
  });
});

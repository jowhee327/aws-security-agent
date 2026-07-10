import { describe, it, expect } from "vitest";
import {
  buildComponentRecords,
  matchCves,
  classifyGapReason,
  diffWithOfficial,
  applySuppressions,
  normalizeComponentName,
} from "../../../src/scanners/ecr-image-cve/engine.js";
import { OFFLINE_ADVISORIES } from "../../../src/scanners/ecr-image-cve/advisories.js";
import type {
  ImageInventory,
  OfficialFinding,
  GapFinding,
} from "../../../src/scanners/ecr-image-cve/types.js";

/** Alpine 3.21 image with an unmanaged nginx 1.27.4 binary — the CVE-2026-42945 Lilly reference scenario. */
function lillyInventory(): ImageInventory {
  return {
    packages: [
      { name: "musl", version: "1.2.5-r8", sourcePackage: "musl", manager: "apk" },
      { name: "busybox", version: "1.37.0-r12", sourcePackage: "busybox", manager: "apk" },
    ],
    binaries: [
      {
        component: "nginx",
        version: "1.27.4",
        filePath: "usr/sbin/nginx",
        signatureId: "nginx-version-string",
        layerDigest: "sha256:layer2",
      },
    ],
    os: { id: "alpine", versionId: "3.21.0", prettyName: "Alpine Linux v3.21", alpineRelease: "3.21.0" },
    rpmDbPresent: false,
  };
}

/** Same image but nginx 1.26.3-r0 installed from the Alpine 3.21 repo (package-managed variant). */
function packageManagedInventory(): ImageInventory {
  return {
    packages: [
      { name: "nginx", version: "1.26.3-r0", sourcePackage: "nginx", manager: "apk" },
    ],
    binaries: [
      {
        component: "nginx",
        version: "1.26.3",
        filePath: "usr/sbin/nginx",
        signatureId: "nginx-version-string",
        layerDigest: "sha256:layer2",
      },
    ],
    os: { id: "alpine", versionId: "3.21.0", alpineRelease: "3.21.0" },
    rpmDbPresent: false,
  };
}

describe("normalizeComponentName", () => {
  it("maps package names to canonical components", () => {
    expect(normalizeComponentName("nginx")).toBe("nginx");
    expect(normalizeComponentName("nginx-core")).toBe("nginx");
    expect(normalizeComponentName("libssl3")).toBe("openssl");
    expect(normalizeComponentName("libcurl4")).toBe("curl");
    expect(normalizeComponentName("redis-server")).toBe("redis");
    expect(normalizeComponentName("apache2")).toBe("httpd");
    expect(normalizeComponentName("musl")).toBeUndefined();
  });
});

describe("buildComponentRecords provenance", () => {
  it("flags a binary with no matching package as unmanaged-binary", () => {
    const records = buildComponentRecords(lillyInventory());
    const nginx = records.find((r) => r.component === "nginx");
    expect(nginx).toBeDefined();
    expect(nginx!.channel).toBe("binary");
    expect(nginx!.provenance).toBe("unmanaged-binary");
    expect(nginx!.evidence).toBe("usr/sbin/nginx");
  });

  it("marks a binary matching an installed package version as package-managed", () => {
    const records = buildComponentRecords(packageManagedInventory());
    const binaryRec = records.find((r) => r.channel === "binary" && r.component === "nginx");
    expect(binaryRec!.provenance).toBe("package-managed");
  });

  it("treats version mismatch between binary and package as unmanaged", () => {
    const inv = packageManagedInventory();
    inv.binaries[0].version = "1.27.4"; // binary newer than the installed 1.26.3-r0 package
    const records = buildComponentRecords(inv);
    const binaryRec = records.find((r) => r.channel === "binary" && r.component === "nginx");
    expect(binaryRec!.provenance).toBe("unmanaged-binary");
  });
});

describe("CVE-2026-42945 reference scenario (spec R8)", () => {
  it("unmanaged nginx 1.27.4 on Alpine 3.21 yields a CRITICAL/HIGH gap with reason unmanaged-binary", () => {
    const inventory = lillyInventory();
    const components = buildComponentRecords(inventory);
    const matches = matchCves(components, OFFLINE_ADVISORIES, "HIGH");

    const ref = matches.find((m) => m.cveId === "CVE-2026-42945");
    expect(ref).toBeDefined();
    expect(["CRITICAL", "HIGH"]).toContain(ref!.severity);
    expect(ref!.provenance).toBe("unmanaged-binary");

    const diff = diffWithOfficial({
      imageDigest: "sha256:abc123",
      repository: "prod-nginx",
      ourMatches: matches,
      officialFindings: [], // ECR + Inspector both report nothing — the Lilly case
      inventory,
      minSeverity: "HIGH",
    });

    const gap = diff.gaps.find((g) => g.cveId === "CVE-2026-42945");
    expect(gap).toBeDefined();
    expect(gap!.reason).toBe("unmanaged-binary");
    expect(gap!.imageDigest).toBe("sha256:abc123");
  });

  it("package-managed nginx 1.26.x on supported Alpine yields reason distro-secdb-no-entry", () => {
    const inventory = packageManagedInventory();
    const components = buildComponentRecords(inventory);
    const matches = matchCves(components, OFFLINE_ADVISORIES, "HIGH");

    const ref = matches.find((m) => m.cveId === "CVE-2026-42945");
    expect(ref).toBeDefined();
    expect(ref!.provenance).toBe("package-managed");

    const reason = classifyGapReason(ref!, inventory);
    expect(reason).toBe("distro-secdb-no-entry");
  });

  it("classifies EOL alpine as eol-os for package-managed matches", () => {
    const inventory = packageManagedInventory();
    inventory.os = { id: "alpine", versionId: "3.16.0" };
    const components = buildComponentRecords(inventory);
    const matches = matchCves(components, OFFLINE_ADVISORIES, "HIGH");
    expect(classifyGapReason(matches[0], inventory)).toBe("eol-os");
  });
});

describe("matchCves severity filtering", () => {
  it("filters below minSeverity", () => {
    const components = buildComponentRecords(lillyInventory());
    const critOnly = matchCves(components, OFFLINE_ADVISORIES, "CRITICAL");
    expect(critOnly.every((m) => m.severity === "CRITICAL")).toBe(true);
  });

  it("does not match fixed versions", () => {
    const inv = lillyInventory();
    inv.binaries[0].version = "1.31.0";
    const matches = matchCves(buildComponentRecords(inv), OFFLINE_ADVISORIES, "HIGH");
    expect(matches.find((m) => m.cveId === "CVE-2026-42945")).toBeUndefined();
  });
});

describe("diffWithOfficial classification", () => {
  const inventory = lillyInventory();
  const components = buildComponentRecords(inventory);
  const matches = matchCves(components, OFFLINE_ADVISORIES, "HIGH");

  it("classifies both-found as confirmed and dedups by cveId + component", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2026-42945", component: "nginx", severity: "CRITICAL", source: "enhanced" },
      { cveId: "CVE-2026-42945", component: "nginx", severity: "CRITICAL", source: "basic" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: matches,
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    const confirmed = diff.confirmed.find((c) => c.cveId === "CVE-2026-42945");
    expect(confirmed).toBeDefined();
    expect(confirmed!.confirmedBy.sort()).toEqual(["basic", "enhanced"]);
    expect(diff.gaps.find((g) => g.cveId === "CVE-2026-42945")).toBeUndefined();
    expect(diff.reverseGaps).toEqual([]);
  });

  it("classifies official-only findings as reverse-gap", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2024-99999", component: "zlib", severity: "HIGH", source: "basic" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: [],
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    expect(diff.reverseGaps).toHaveLength(1);
    expect(diff.reverseGaps[0].cveId).toBe("CVE-2024-99999");
    expect(diff.reverseGaps[0].source).toBe("basic");
  });

  it("filters reverse-gaps below minSeverity", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2024-11111", component: "zlib", severity: "MEDIUM", source: "basic" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: [],
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    expect(diff.reverseGaps).toEqual([]);
  });

  it("does not confirm when the official finding has no component (cveId alone is not enough)", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2026-42945", severity: "CRITICAL", source: "basic" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: matches,
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    expect(diff.confirmed).toEqual([]);
    expect(diff.gaps.find((g) => g.cveId === "CVE-2026-42945")).toBeDefined();
    // The component-less official finding stays visible as a self-audit row
    expect(diff.reverseGaps.find((r) => r.cveId === "CVE-2026-42945")).toBeDefined();
  });

  it("does not confirm when the official component is unrecognized", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2026-42945", component: "some-vendor-pkg", severity: "CRITICAL", source: "enhanced" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: matches,
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    expect(diff.confirmed).toEqual([]);
    expect(diff.gaps.find((g) => g.cveId === "CVE-2026-42945")).toBeDefined();
    expect(diff.reverseGaps.find((r) => r.cveId === "CVE-2026-42945" && r.component === "some-vendor-pkg")).toBeDefined();
  });

  it("does not let unknown/non-standard severities bypass minSeverity and flood reverse-gaps (finding 5)", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2024-70001", component: "zlib", severity: "UNTRIAGED", source: "enhanced" },
      { cveId: "CVE-2024-70002", component: "zlib", severity: "INFORMATIONAL", source: "enhanced" },
      { cveId: "CVE-2024-70003", component: "zlib", severity: "CRITICAL", source: "enhanced" },
    ];
    const highOnly = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: [],
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    // Only the CRITICAL finding survives; UNTRIAGED/INFORMATIONAL are filtered.
    expect(highOnly.reverseGaps.map((r) => r.cveId)).toEqual(["CVE-2024-70003"]);
  });

  it("surfaces UNTRIAGED in report-everything mode (minSeverity LOW) but never INFORMATIONAL", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2024-70001", component: "zlib", severity: "UNTRIAGED", source: "enhanced" },
      { cveId: "CVE-2024-70002", component: "zlib", severity: "INFORMATIONAL", source: "enhanced" },
    ];
    const all = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: [],
      officialFindings: official,
      inventory,
      minSeverity: "LOW",
    });
    expect(all.reverseGaps.map((r) => r.cveId)).toEqual(["CVE-2024-70001"]);
  });

  it("does not confirm on cveId match with a conflicting component", () => {
    const official: OfficialFinding[] = [
      { cveId: "CVE-2026-42945", component: "curl", severity: "HIGH", source: "basic" },
    ];
    const diff = diffWithOfficial({
      imageDigest: "sha256:abc",
      repository: "repo",
      ourMatches: matches,
      officialFindings: official,
      inventory,
      minSeverity: "HIGH",
    });
    expect(diff.gaps.find((g) => g.cveId === "CVE-2026-42945")).toBeDefined();
    expect(diff.reverseGaps.find((r) => r.cveId === "CVE-2026-42945")).toBeDefined();
  });
});

describe("applySuppressions", () => {
  const gap: GapFinding = {
    cveId: "CVE-2026-42945",
    component: "nginx",
    version: "1.27.4",
    severity: "CRITICAL",
    cvss: 9.2,
    fixedIn: ["1.30.1"],
    provenance: "unmanaged-binary",
    channel: "binary",
    evidence: "usr/sbin/nginx",
    advisorySource: "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
    summary: "test",
    imageDigest: "sha256:abc123def",
    repository: "prod-nginx",
    reason: "unmanaged-binary",
  };

  it("moves matching gaps to suppressed with the rule's reason, never dropping them", () => {
    const { kept, suppressed } = applySuppressions([gap], [
      { cveId: "CVE-2026-42945", reason: "accepted risk until Q3 rebuild" },
    ]);
    expect(kept).toEqual([]);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].suppressionReason).toBe("accepted risk until Q3 rebuild");
  });

  it("respects imageDigestPrefix and component constraints", () => {
    const noMatchDigest = applySuppressions([gap], [
      { cveId: "CVE-2026-42945", imageDigestPrefix: "sha256:zzz", reason: "x" },
    ]);
    expect(noMatchDigest.kept).toHaveLength(1);

    const matchPrefix = applySuppressions([gap], [
      { cveId: "CVE-2026-42945", imageDigestPrefix: "sha256:abc", component: "nginx", reason: "x" },
    ]);
    expect(matchPrefix.suppressed).toHaveLength(1);

    const wrongComponent = applySuppressions([gap], [
      { cveId: "CVE-2026-42945", component: "curl", reason: "x" },
    ]);
    expect(wrongComponent.kept).toHaveLength(1);
  });
});

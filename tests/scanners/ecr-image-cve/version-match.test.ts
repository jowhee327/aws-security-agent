import { describe, it, expect } from "vitest";
import {
  compareVersions,
  versionInRange,
  advisoryMatches,
} from "../../../src/scanners/ecr-image-cve/version-match.js";
import { OFFLINE_ADVISORIES } from "../../../src/scanners/ecr-image-cve/advisories.js";

describe("compareVersions", () => {
  it("compares plain semver", () => {
    expect(compareVersions("1.27.4", "1.30.0")).toBeLessThan(0);
    expect(compareVersions("1.30.1", "1.30.0")).toBeGreaterThan(0);
    expect(compareVersions("1.27.4", "1.27.4")).toBe(0);
  });

  it("handles differing segment counts", () => {
    expect(compareVersions("1.27", "1.27.0")).toBe(0);
    expect(compareVersions("1.27.0.1", "1.27")).toBeGreaterThan(0);
  });

  it("handles Alpine -rN package revisions", () => {
    expect(compareVersions("1.26.3-r0", "1.26.3-r1")).toBeLessThan(0);
    expect(compareVersions("1.26.3-r1", "1.26.3-r0")).toBeGreaterThan(0);
    expect(compareVersions("1.26.3-r0", "1.26.3-r0")).toBe(0);
    // Upstream version dominates the revision
    expect(compareVersions("1.26.3-r5", "1.27.0-r0")).toBeLessThan(0);
  });

  it("handles openssl letter suffixes", () => {
    expect(compareVersions("1.0.2k", "1.0.2l")).toBeLessThan(0);
    expect(compareVersions("1.0.2k", "1.0.2")).toBeGreaterThan(0);
    expect(compareVersions("1.0.2k", "1.0.2k")).toBe(0);
    expect(compareVersions("1.0.2a", "1.1.0")).toBeLessThan(0);
  });

  it("strips dpkg epochs and distro suffixes", () => {
    expect(compareVersions("1:1.26.3-1", "1.26.3")).toBe(0);
    expect(compareVersions("1.18.0-6ubuntu14.4", "1.18.0")).toBe(0);
    expect(compareVersions("3.0.2-0ubuntu1.18", "3.0.7")).toBeLessThan(0);
  });
});

describe("versionInRange", () => {
  it("respects inclusive bounds", () => {
    const range = { min: "0.6.27", max: "1.30.0", minInclusive: true, maxInclusive: true };
    expect(versionInRange("0.6.27", range)).toBe(true);
    expect(versionInRange("1.30.0", range)).toBe(true);
    expect(versionInRange("1.27.4", range)).toBe(true);
    expect(versionInRange("1.30.1", range)).toBe(false);
    expect(versionInRange("0.6.26", range)).toBe(false);
  });

  it("respects exclusive bounds", () => {
    const range = { min: "3.0.0", max: "3.0.7", minInclusive: true, maxInclusive: false };
    expect(versionInRange("3.0.7", range)).toBe(false);
    expect(versionInRange("3.0.6", range)).toBe(true);
    expect(versionInRange("3.0.0", range)).toBe(true);
  });

  it("handles unbounded ranges", () => {
    expect(versionInRange("1.0.0", { max: "6.2.7", maxInclusive: false })).toBe(true);
    expect(versionInRange("7.0.1", { max: "6.2.7", maxInclusive: false })).toBe(false);
  });

  it("matches Alpine package versions against upstream ranges", () => {
    const range = { min: "0.6.27", max: "1.30.0", minInclusive: true, maxInclusive: true };
    expect(versionInRange("1.26.3-r0", range)).toBe(true);
  });

  it("ignores the Alpine -rN revision when the advisory bound has none (inclusive max edge)", () => {
    // CVE-2026-42945-style range: upstream max 1.30.0 inclusive must cover 1.30.0-r0/-r5
    const range = { min: "0.6.27", max: "1.30.0", minInclusive: true, maxInclusive: true };
    expect(versionInRange("1.30.0-r0", range)).toBe(true);
    expect(versionInRange("1.30.0-r5", range)).toBe(true);
    expect(versionInRange("1.30.1-r0", range)).toBe(false);
  });

  it("ignores the revision on exclusive upstream bounds too", () => {
    // Upstream fixed in 1.27.4 ⇒ the distro build 1.27.4-r0 is fixed as well
    const range = { min: "1.25.0", max: "1.27.4", minInclusive: true, maxInclusive: false };
    expect(versionInRange("1.27.4-r0", range)).toBe(false);
    expect(versionInRange("1.27.3-r2", range)).toBe(true);
    expect(versionInRange("1.25.0-r0", range)).toBe(true);
  });

  it("honors the revision when the advisory bound itself carries one", () => {
    const range = { max: "1.30.0-r2", maxInclusive: true };
    expect(versionInRange("1.30.0-r1", range)).toBe(true);
    expect(versionInRange("1.30.0-r2", range)).toBe(true);
    expect(versionInRange("1.30.0-r3", range)).toBe(false);
  });
});

describe("advisoryMatches with the CVE-2026-42945 reference entry", () => {
  const ref = OFFLINE_ADVISORIES.find((a) => a.cveId === "CVE-2026-42945")!;

  it("exists in the offline table with the specced metadata", () => {
    expect(ref).toBeDefined();
    expect(ref.component).toBe("nginx");
    expect(ref.cvss).toBe(9.2);
    expect(["HIGH", "CRITICAL"]).toContain(ref.severity);
    expect(ref.fixedIn).toContain("1.30.1");
    expect(ref.fixedIn).toContain("1.31.0");
  });

  it("matches nginx 1.27.4 (the Lilly case) and the range edges", () => {
    expect(advisoryMatches(ref, "nginx", "1.27.4")).toBe(true);
    expect(advisoryMatches(ref, "nginx", "0.6.27")).toBe(true);
    expect(advisoryMatches(ref, "nginx", "1.30.0")).toBe(true);
  });

  it("does not match fixed versions or other components", () => {
    expect(advisoryMatches(ref, "nginx", "1.30.1")).toBe(false);
    expect(advisoryMatches(ref, "nginx", "1.31.0")).toBe(false);
    expect(advisoryMatches(ref, "openssl", "1.27.4")).toBe(false);
  });
});

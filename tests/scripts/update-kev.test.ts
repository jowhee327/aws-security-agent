import { describe, it, expect } from "vitest";
import {
  parseArgs,
  serializeKevSnapshot,
  slimKevFeed,
  validateKevFeed,
  KEV_FEED_URL,
  DEFAULT_OUT,
} from "../../scripts/update-kev.js";

const FEED = {
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  catalogVersion: "2026.11.03",
  dateReleased: "2026-11-03T20:00:24.8741Z",
  count: 4,
  vulnerabilities: [
    {
      cveID: "CVE-2024-10000",
      vendorProject: "B",
      product: "b",
      vulnerabilityName: "drop me",
      dateAdded: "2024-12-01",
      shortDescription: "drop me",
      requiredAction: "drop me",
      dueDate: "2024-12-22",
      knownRansomwareCampaignUse: "Known",
      notes: "drop me",
      cwes: ["CWE-79"],
    },
    { cveID: "CVE-2024-9999", vendorProject: "A", product: "a", dateAdded: "2024-11-01", knownRansomwareCampaignUse: "Unknown" },
    { cveID: "CVE-2002-0367", vendorProject: "C", product: "c", dateAdded: "2022-03-03", knownRansomwareCampaignUse: "Unknown" },
    // duplicate — first occurrence wins
    { cveID: "CVE-2024-9999", vendorProject: "dup", product: "dup", dateAdded: "2024-11-02", knownRansomwareCampaignUse: "Known" },
  ],
};

describe("validateKevFeed", () => {
  it("accepts a well-formed feed", () => {
    expect(validateKevFeed(FEED)).toEqual([]);
  });

  it("rejects non-objects, missing or empty vulnerabilities", () => {
    expect(validateKevFeed(null)).toHaveLength(1);
    expect(validateKevFeed("x")).toHaveLength(1);
    expect(validateKevFeed({})[0]).toMatch(/not an array/);
    expect(validateKevFeed({ vulnerabilities: [] })[0]).toMatch(/empty/);
  });

  it("rejects malformed cveIDs", () => {
    const errs = validateKevFeed({
      vulnerabilities: [{ cveID: "CVE-2024-1" }, { cveID: 42 }, {}, { cveID: "CVE-2024-1234" }],
    });
    expect(errs).toHaveLength(3);
    expect(errs[0]).toContain("vulnerabilities[0]");
  });
});

describe("slimKevFeed", () => {
  it("keeps only snapshot fields, de-duplicates and sorts numerically", () => {
    const snap = slimKevFeed(FEED);
    expect(snap).toMatchObject({
      source: KEV_FEED_URL,
      license: "Public domain (U.S. Government work, CISA KEV catalog)",
      catalogVersion: "2026.11.03",
      dateReleased: "2026-11-03T20:00:24.8741Z",
      snapshotDate: "2026-11-03",
      count: 3,
    });
    expect(snap.vulnerabilities.map((v) => v.cveID)).toEqual(["CVE-2002-0367", "CVE-2024-9999", "CVE-2024-10000"]);
    expect(snap.vulnerabilities[1].vendorProject).toBe("A");
    expect(Object.keys(snap.vulnerabilities[2]).sort()).toEqual(
      ["cveID", "dateAdded", "knownRansomwareCampaignUse", "product", "vendorProject"],
    );
  });

  it("throws on invalid feeds", () => {
    expect(() => slimKevFeed({ vulnerabilities: [] })).toThrow(/Invalid KEV feed/);
  });
});

describe("serializeKevSnapshot", () => {
  it("round-trips as compact JSON with one entry per line", () => {
    const snap = slimKevFeed(FEED);
    const text = serializeKevSnapshot(snap);
    expect(JSON.parse(text)).toEqual(snap);
    expect(text.split("\n").filter(Boolean)).toHaveLength(1 + snap.count + 1);
    expect(text).not.toContain("  ");
  });
});

describe("parseArgs", () => {
  it("defaults to src/data/kev.json and online fetch", () => {
    const a = parseArgs([]);
    expect(a.from).toBeUndefined();
    expect(a.out).toBe(DEFAULT_OUT);
    expect(DEFAULT_OUT.replace(/\\/g, "/")).toMatch(/src\/data\/kev\.json$/);
  });

  it("parses --from / --out and rejects unknown flags", () => {
    const a = parseArgs(["--from", "/tmp/feed.json", "--out", "/tmp/out.json"]);
    expect(a).toEqual({ from: "/tmp/feed.json", out: "/tmp/out.json" });
    expect(() => parseArgs(["--from"])).toThrow(/requires a path/);
    expect(() => parseArgs(["--bogus"])).toThrow(/Unknown argument/);
  });
});

describe("committed snapshot src/data/kev.json", () => {
  it("is valid, sorted and matches its declared count", async () => {
    const { readFileSync } = await import("node:fs");
    const snap = JSON.parse(readFileSync(DEFAULT_OUT, "utf8"));
    expect(validateKevFeed(snap)).toEqual([]);
    expect(snap.count).toBe(snap.vulnerabilities.length);
    // Re-slimming the snapshot is a no-op (already slim, de-duplicated, sorted).
    expect(slimKevFeed(snap, snap.source)).toEqual(snap);
  });
});

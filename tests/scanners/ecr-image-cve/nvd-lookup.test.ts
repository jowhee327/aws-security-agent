import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  fetchNvdAdvisories,
  fetchNvdAdvisoriesResult,
} from "../../../src/scanners/ecr-image-cve/nvd-lookup.js";

// Redirect the on-disk NVD cache to a throwaway temp dir so tests never touch
// (or depend on) the real ~/.aws-security cache. cacheDir() joins against
// os.homedir(), which on Linux resolves HOME — so overriding HOME is enough.
const originalHome = process.env.HOME;
const tmpHome = mkdtempSync(join(tmpdir(), "nvd-cache-test-"));
beforeAll(() => {
  process.env.HOME = tmpHome;
});
afterAll(() => {
  process.env.HOME = originalHome;
});

function nvdPage(vulns: unknown[], totalResults: number): Response {
  return new Response(JSON.stringify({ totalResults, vulnerabilities: vulns }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/** A minimal NVD 2.0 vulnerability item with a HIGH+ CVSS and one version range. */
function nvdItem(id: string, baseScore = 9.1) {
  return {
    cve: {
      id,
      metrics: { cvssMetricV31: [{ cvssData: { baseScore } }] },
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: true, versionStartIncluding: "1.0.0", versionEndExcluding: "2.0.0" },
              ],
            },
          ],
        },
      ],
      descriptions: [{ lang: "en", value: `desc for ${id}` }],
    },
  };
}

describe("fetchNvdAdvisoriesResult", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("degrades silently to an empty list on a network error (never throws)", async () => {
    const failing = vi.fn(async () => {
      throw new Error("ENETUNREACH");
    }) as unknown as typeof fetch;
    const res = await fetchNvdAdvisoriesResult("nginx", { ttlMs: 0, fetchImpl: failing, pageDelayMs: 0 });
    expect(res.advisories).toEqual([]);
    expect(res.truncated).toBe(false);
  });

  it("degrades silently on a non-OK HTTP response", async () => {
    const notOk = vi.fn(async () => new Response("rate limited", { status: 403 })) as unknown as typeof fetch;
    const res = await fetchNvdAdvisoriesResult("php", { ttlMs: 0, fetchImpl: notOk, pageDelayMs: 0 });
    expect(res.advisories).toEqual([]);
  });

  it("does not report truncation or a 'fetched 0 of Infinity' warning when the first page is an HTTP error (finding N1)", async () => {
    const notOk = vi.fn(async () => new Response("rate limited", { status: 403 })) as unknown as typeof fetch;
    const res = await fetchNvdAdvisoriesResult("php", { ttlMs: 0, fetchImpl: notOk, pageDelayMs: 0 });
    // An error is not a truncation: NVD never reported a total, so there is
    // nothing to be truncated relative to.
    expect(res.truncated).toBe(false);
    expect(res.warning).toBeUndefined();
  });

  it("still reports truncation when an HTTP error interrupts pagination after a successful page", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(nvdPage([nvdItem("CVE-2024-0001")], 5))
      .mockResolvedValueOnce(new Response("rate limited", { status: 403 })) as unknown as typeof fetch;
    const res = await fetchNvdAdvisoriesResult("php", { ttlMs: 0, fetchImpl, pageDelayMs: 0 });
    expect(res.advisories.map((a) => a.cveId)).toEqual(["CVE-2024-0001"]);
    // Here NVD did report a real total (5) and we fetched 1 — that IS truncation.
    expect(res.truncated).toBe(true);
    expect(res.warning).toContain("fetched 1 of 5");
  });

  it("paginates via startIndex until totalResults is exhausted", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(nvdPage([nvdItem("CVE-2024-0001")], 3))
      .mockResolvedValueOnce(nvdPage([nvdItem("CVE-2024-0002")], 3))
      .mockResolvedValueOnce(nvdPage([nvdItem("CVE-2024-0003")], 3)) as unknown as typeof fetch;

    const res = await fetchNvdAdvisoriesResult("openssl", { ttlMs: 0, fetchImpl, pageDelayMs: 0 });
    expect((fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(3);
    expect(res.advisories.map((a) => a.cveId)).toEqual(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]);
    expect(res.truncated).toBe(false);

    // The second call must advance startIndex past the first page.
    const secondUrl = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[1][0] as string;
    expect(secondUrl).toContain("startIndex=1");
  });

  it("reports truncation and a warning when the page cap is hit before totalResults", async () => {
    const fetchImpl = vi.fn(async () => nvdPage([nvdItem("CVE-2024-9999")], 10_000)) as unknown as typeof fetch;
    const res = await fetchNvdAdvisoriesResult("openssl", {
      ttlMs: 0,
      fetchImpl,
      pageDelayMs: 0,
      maxPages: 2,
    });
    expect((fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2);
    expect(res.truncated).toBe(true);
    expect(res.warning).toContain("truncated");
  });

  it("preserves the real total in the warning served from a cached truncated result (finding N1)", async () => {
    // First call: 10 fetched (page cap 1 × 10-item page) of 40 total → truncated.
    const items = Array.from({ length: 10 }, (_, i) => nvdItem(`CVE-2024-${1000 + i}`));
    const fetchImpl = vi.fn(async () => nvdPage(items, 40)) as unknown as typeof fetch;
    const first = await fetchNvdAdvisoriesResult("curl", { fetchImpl, pageDelayMs: 0, maxPages: 1 });
    expect(first.truncated).toBe(true);
    expect(first.warning).toContain("fetched 10 of 40");
    const callsAfterFirst = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length;

    // Second call hits the disk cache; the warning must still show the real
    // total (10 of 40), not the degenerate "fetched N of N".
    const second = await fetchNvdAdvisoriesResult("curl", { fetchImpl, pageDelayMs: 0, maxPages: 1 });
    expect((fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsAfterFirst);
    expect(second.truncated).toBe(true);
    expect(second.warning).toContain("fetched 10 of 40");
  });

  it("caches results and reuses them without a second fetch", async () => {
    const fetchImpl = vi.fn(async () => nvdPage([nvdItem("CVE-2024-5555")], 1)) as unknown as typeof fetch;
    // First call: long TTL so the write is honored and the next read hits cache.
    const first = await fetchNvdAdvisoriesResult("haproxy", { fetchImpl, pageDelayMs: 0 });
    expect(first.advisories.map((a) => a.cveId)).toEqual(["CVE-2024-5555"]);
    const callsAfterFirst = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length;

    const second = await fetchNvdAdvisoriesResult("haproxy", { fetchImpl, pageDelayMs: 0 });
    expect(second.advisories.map((a) => a.cveId)).toEqual(["CVE-2024-5555"]);
    // No additional fetch — the disk cache served the second call.
    expect((fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(callsAfterFirst);
  });
});

describe("fetchNvdAdvisories backward-compatible wrapper", () => {
  it("returns just the advisory list", async () => {
    const fetchImpl = vi.fn(async () => nvdPage([nvdItem("CVE-2024-1234")], 1)) as unknown as typeof fetch;
    const advisories = await fetchNvdAdvisories("redis", 0, fetchImpl);
    expect(advisories.map((a) => a.cveId)).toEqual(["CVE-2024-1234"]);
  });
});

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Advisory, ComponentName, VersionRange } from "./types.js";
import type { Severity } from "../../types.js";

/**
 * Tier 2 (optional, gated by onlineCveLookup=false default): NVD API 2.0
 * keyword lookup per detected component, cached on disk with a 24h TTL.
 * Designed to degrade silently — offline advisories remain the source of truth.
 */

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
/** NVD API 2.0 max page size. */
const RESULTS_PER_PAGE = 2000;
/**
 * Page cap so a huge product (openssl/php have thousands of CVEs) cannot make a
 * single component's lookup unbounded. Combined with RESULTS_PER_PAGE this
 * covers up to 20k CVEs per component before truncation is reported.
 */
const DEFAULT_MAX_PAGES = 10;
/**
 * Delay between page requests to stay under NVD's unauthenticated rate limit
 * (5 requests / 30s ⇒ ~6s spacing). Injectable so tests run instantly.
 */
const DEFAULT_PAGE_DELAY_MS = 6_500;

/** CPE product names for keyword/cpe queries per component. */
const COMPONENT_CPE: Record<ComponentName, string> = {
  nginx: "cpe:2.3:a:nginx:nginx",
  openssl: "cpe:2.3:a:openssl:openssl",
  curl: "cpe:2.3:a:haxx:curl",
  redis: "cpe:2.3:a:redis:redis",
  node: "cpe:2.3:a:nodejs:node.js",
  httpd: "cpe:2.3:a:apache:http_server",
  haproxy: "cpe:2.3:a:haproxy:haproxy",
  php: "cpe:2.3:a:php:php",
  python3: "cpe:2.3:a:python:python",
  java: "cpe:2.3:a:oracle:jdk",
  envoy: "cpe:2.3:a:envoyproxy:envoy",
};

function cacheDir(): string {
  return join(homedir(), ".aws-security", "nvd-cache");
}

function severityFromCvss(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

/** Result of a component lookup — advisories plus whether the feed was truncated. */
export interface NvdLookupResult {
  advisories: Advisory[];
  /** True when NVD reported more results than we fetched (page cap hit). */
  truncated: boolean;
  /** Optional human-readable warning to surface into scan warnings. */
  warning?: string;
}

interface NvdCacheEntry {
  fetchedAt: number;
  advisories: Advisory[];
  truncated?: boolean;
  /** Raw NVD items fetched / reported total, kept so a cached truncated result
   * can regenerate an accurate warning instead of "fetched N of N". */
  fetched?: number;
  totalResults?: number;
}

function readCache(component: ComponentName, ttlMs: number): NvdCacheEntry | undefined {
  try {
    const raw = readFileSync(join(cacheDir(), `${component}.json`), "utf8");
    const entry: NvdCacheEntry = JSON.parse(raw);
    if (Date.now() - entry.fetchedAt < ttlMs) return entry;
  } catch {
    // cache miss
  }
  return undefined;
}

function writeCache(
  component: ComponentName,
  advisories: Advisory[],
  truncated: boolean,
  fetched: number,
  totalResults: number,
): void {
  try {
    mkdirSync(cacheDir(), { recursive: true });
    const entry: NvdCacheEntry = { fetchedAt: Date.now(), advisories, truncated, fetched, totalResults };
    writeFileSync(join(cacheDir(), `${component}.json`), JSON.stringify(entry));
  } catch {
    // cache write is best-effort
  }
}

function truncationWarning(component: ComponentName, fetched: number, total: number): string {
  return `NVD lookup for ${component} truncated: fetched ${fetched} of ${total} advisories. Recent CVEs may be missing; offline advisories remain authoritative.`;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function parseNvdItem(item: any, component: ComponentName): Advisory | undefined {
  const cve = item?.cve;
  const cveId: string | undefined = cve?.id;
  if (!cveId) return undefined;

  const metrics = cve.metrics ?? {};
  const cvssData =
    metrics.cvssMetricV40?.[0]?.cvssData ??
    metrics.cvssMetricV31?.[0]?.cvssData ??
    metrics.cvssMetricV30?.[0]?.cvssData;
  const score: number = cvssData?.baseScore ?? 0;
  if (score < 7.0) return undefined; // critical/high only

  const ranges: VersionRange[] = [];
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const cpe of node.cpeMatch ?? []) {
        if (!cpe.vulnerable) continue;
        const range: VersionRange = {};
        if (cpe.versionStartIncluding) { range.min = cpe.versionStartIncluding; range.minInclusive = true; }
        if (cpe.versionStartExcluding) { range.min = cpe.versionStartExcluding; range.minInclusive = false; }
        if (cpe.versionEndIncluding) { range.max = cpe.versionEndIncluding; range.maxInclusive = true; }
        if (cpe.versionEndExcluding) { range.max = cpe.versionEndExcluding; range.maxInclusive = false; }
        if (range.min !== undefined || range.max !== undefined) ranges.push(range);
      }
    }
  }
  if (ranges.length === 0) return undefined;

  const summary: string =
    cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? cveId;

  return {
    cveId,
    component,
    affectedRanges: ranges,
    fixedIn: [],
    severity: severityFromCvss(score),
    cvss: score,
    summary: summary.slice(0, 300),
    source: `https://nvd.nist.gov/vuln/detail/${cveId}`,
  };
}

export interface NvdFetchOptions {
  ttlMs?: number;
  fetchImpl?: typeof fetch;
  /** Max pages to fetch before reporting truncation. */
  maxPages?: number;
  /** Delay between page requests (rate-limit spacing); 0 disables in tests. */
  pageDelayMs?: number;
}

/**
 * Fetch advisories for a component from NVD (virtualMatchString query),
 * paginating via `startIndex` until `totalResults` is exhausted or the page cap
 * is hit. NVD returns oldest-first, so pagination is what keeps recent CVEs from
 * being silently dropped. Errors and timeouts yield an empty result — Tier 2
 * must never break the scan. When the feed is truncated, a warning is returned.
 */
export async function fetchNvdAdvisoriesResult(
  component: ComponentName,
  options: NvdFetchOptions = {},
): Promise<NvdLookupResult> {
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
  const pageDelayMs = options.pageDelayMs ?? DEFAULT_PAGE_DELAY_MS;

  const cached = readCache(component, ttlMs);
  if (cached) {
    return {
      advisories: cached.advisories,
      truncated: cached.truncated ?? false,
      warning: cached.truncated
        ? truncationWarning(
            component,
            cached.fetched ?? cached.advisories.length,
            cached.totalResults ?? cached.advisories.length,
          )
        : undefined,
    };
  }

  const advisories: Advisory[] = [];
  let startIndex = 0;
  let totalResults = Infinity;
  let pagesFetched = 0;
  let httpError = false;
  try {
    while (startIndex < totalResults && pagesFetched < maxPages) {
      const url =
        `${NVD_API}?virtualMatchString=${encodeURIComponent(COMPONENT_CPE[component])}` +
        `&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
      const resp = await fetchImpl(url, { signal: AbortSignal.timeout(30_000) });
      if (!resp.ok) {
        // Give up on error but keep whatever earlier pages produced.
        httpError = true;
        break;
      }
      const data: any = await resp.json();
      for (const item of data.vulnerabilities ?? []) {
        const adv = parseNvdItem(item, component);
        if (adv) advisories.push(adv);
      }
      pagesFetched++;
      totalResults = typeof data.totalResults === "number" ? data.totalResults : advisories.length;
      const pageCount = data.vulnerabilities?.length ?? 0;
      startIndex += pageCount;
      if (pageCount === 0) break; // defensive: no forward progress
      if (startIndex < totalResults && pagesFetched < maxPages && pageDelayMs > 0) {
        await sleep(pageDelayMs);
      }
    }
    // Truncation only makes sense once NVD reported a real total (at least one
    // OK page). An HTTP error before that is a failed lookup, not a truncated
    // one — reporting "fetched 0 of Infinity" would be misleading.
    const truncated = Number.isFinite(totalResults) && startIndex < totalResults;
    // Only persist a successful result — caching an error's empty page would
    // suppress retries for the full TTL. Fetched/total are stored so cache hits
    // can regenerate an accurate warning.
    if (!httpError) writeCache(component, advisories, truncated, startIndex, totalResults);
    return {
      advisories,
      truncated,
      warning: truncated ? truncationWarning(component, startIndex, totalResults) : undefined,
    };
  } catch {
    return { advisories: [], truncated: false };
  }
}

/**
 * Backward-compatible wrapper returning just the advisory list.
 * @deprecated prefer {@link fetchNvdAdvisoriesResult} to surface truncation warnings.
 */
export async function fetchNvdAdvisories(
  component: ComponentName,
  ttlMs: number = DEFAULT_TTL_MS,
  fetchImpl: typeof fetch = fetch,
): Promise<Advisory[]> {
  const { advisories } = await fetchNvdAdvisoriesResult(component, { ttlMs, fetchImpl });
  return advisories;
}

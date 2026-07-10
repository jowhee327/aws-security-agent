import type { Advisory } from "./types.js";

/**
 * Tier 1 offline advisory table for the Channel-B component list.
 * Curated by hand and unit-tested; extend as new gap-relevant CVEs surface.
 * Severity follows the repo model (CRITICAL >= 9.0, HIGH >= 7.0).
 */
export const OFFLINE_ADVISORIES: Advisory[] = [
  {
    // Reference entry — the Eli Lilly / ZHY case this scanner exists for.
    cveId: "CVE-2026-42945",
    component: "nginx",
    affectedRanges: [{ min: "0.6.27", max: "1.30.0", minInclusive: true, maxInclusive: true }],
    fixedIn: ["1.30.1", "1.31.0"],
    severity: "CRITICAL",
    cvss: 9.2,
    summary: "nginx ngx_http_rewrite_module buffer overflow allows remote code execution via crafted rewrite rules.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
  },
  {
    cveId: "CVE-2025-1974",
    component: "nginx",
    affectedRanges: [{ min: "1.25.0", max: "1.27.4", minInclusive: true, maxInclusive: false }],
    fixedIn: ["1.27.4"],
    severity: "HIGH",
    cvss: 8.8,
    summary: "nginx HTTP/3 QUIC module use-after-free may allow remote code execution.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2025-1974",
  },
  {
    cveId: "CVE-2022-3602",
    component: "openssl",
    affectedRanges: [{ min: "3.0.0", max: "3.0.7", minInclusive: true, maxInclusive: false }],
    fixedIn: ["3.0.7"],
    severity: "HIGH",
    cvss: 7.5,
    summary: "OpenSSL X.509 email address punycode buffer overflow (stack overwrite) during certificate verification.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2022-3602",
  },
  {
    cveId: "CVE-2023-38545",
    component: "curl",
    affectedRanges: [{ min: "7.69.0", max: "8.4.0", minInclusive: true, maxInclusive: false }],
    fixedIn: ["8.4.0"],
    severity: "CRITICAL",
    cvss: 9.8,
    summary: "curl SOCKS5 heap buffer overflow during hostname resolution handoff.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
  },
  {
    cveId: "CVE-2022-0543",
    component: "redis",
    affectedRanges: [{ max: "6.2.7", maxInclusive: false }],
    fixedIn: ["6.2.7", "7.0.0"],
    severity: "CRITICAL",
    cvss: 10.0,
    summary: "Redis Lua sandbox escape on Debian-packaged builds allows remote code execution.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
  },
  {
    cveId: "CVE-2024-27316",
    component: "httpd",
    affectedRanges: [{ min: "2.4.17", max: "2.4.59", minInclusive: true, maxInclusive: false }],
    fixedIn: ["2.4.59"],
    severity: "HIGH",
    cvss: 7.5,
    summary: "Apache httpd HTTP/2 memory exhaustion via CONTINUATION frames flood.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2024-27316",
  },
  {
    cveId: "CVE-2023-25725",
    component: "haproxy",
    affectedRanges: [{ max: "2.7.3", maxInclusive: false }],
    fixedIn: ["2.7.3", "2.6.9", "2.5.12"],
    severity: "CRITICAL",
    cvss: 9.1,
    summary: "HAProxy request smuggling via empty header name allows ACL bypass.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2023-25725",
  },
  {
    cveId: "CVE-2024-4577",
    component: "php",
    affectedRanges: [
      { min: "8.1.0", max: "8.1.29", minInclusive: true, maxInclusive: false },
      { min: "8.2.0", max: "8.2.20", minInclusive: true, maxInclusive: false },
      { min: "8.3.0", max: "8.3.8", minInclusive: true, maxInclusive: false },
    ],
    fixedIn: ["8.1.29", "8.2.20", "8.3.8"],
    severity: "CRITICAL",
    cvss: 9.8,
    summary: "PHP CGI argument injection on Windows locales; widely exploited for remote code execution.",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
  },
];

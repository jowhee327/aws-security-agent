import { describe, it, expect } from "vitest";
import { generateMarkdownReport } from "../src/tools/report-tool.js";
import type { FullScanResult } from "../src/types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { legacyScan } from "./fixtures/report-baseline/legacy-scan.js";
import { bulkInspector, cveFinding, moduleOf, scanOf, stripVersion } from "./fixtures/report-baseline/exploit-scan.js";

describe("generateMarkdownReport", () => {
  it("includes expected headers and finding titles", () => {
    const mockResult: FullScanResult = {
      scanStart: "2026-01-15T10:00:00.000Z",
      scanEnd: "2026-01-15T10:00:05.000Z",
      region: "us-east-1",
      accountId: "123456789012",
      modules: [
        {
          module: "network_reachability",
          status: "success",
          resourcesScanned: 3,
          findingsCount: 1,
          scanTimeMs: 500,
          findings: [
            {
              severity: "CRITICAL",
              title: "EC2 instance i-abc123 has SSH (22) reachable from 0.0.0.0/0",
              resourceType: "AWS::EC2::Instance",
              resourceId: "i-abc123",
              resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
              region: "us-east-1",
              description: "SSH reachable from the internet",
              impact: "SSH exposed",
              riskScore: 9.0,
              remediationSteps: ["Restrict port 22"],
              priority: "P0",
            },
          ],
        },
      ],
      summary: {
        totalFindings: 1,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        modulesSuccess: 1,
        modulesError: 0,
      },
    };

    const report = generateMarkdownReport(mockResult, "en");

    expect(report).toContain("# AWS Security Scan Report");
    expect(report).toContain("## Executive Summary");
    expect(report).toContain("## Findings by Severity");
    expect(report).toContain("## Scan Statistics");
    expect(report).toContain("i-abc123 has SSH");
    expect(report).toContain("123456789012");
  });

  it("shows 'No security issues' when 0 findings", () => {
    const emptyResult: FullScanResult = {
      scanStart: "2026-01-15T10:00:00.000Z",
      scanEnd: "2026-01-15T10:00:01.000Z",
      region: "us-east-1",
      accountId: "123456789012",
      modules: [
        {
          module: "service_detection",
          status: "success",
          resourcesScanned: 5,
          findingsCount: 0,
          scanTimeMs: 200,
          findings: [],
        },
      ],
      summary: {
        totalFindings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        modulesSuccess: 1,
        modulesError: 0,
      },
    };

    const report = generateMarkdownReport(emptyResult, "en");

    expect(report).toContain("No security issues");
  });
});

// ---------------------------------------------------------------------------
// T5 — CVE exploitability prioritization
// ---------------------------------------------------------------------------

describe("generateMarkdownReport — exploitability", () => {
  it("legacy fixture without exploitability is byte-identical to the pre-T5 output (zh + en)", () => {
    for (const lang of ["zh", "en"] as const) {
      const md = stripVersion(generateMarkdownReport(legacyScan(), lang));
      expect(md).toBe(readFileSync(join(__dirname, "fixtures/report-baseline", `md.${lang}.md`), "utf8"));
    }
  });

  it("adds the funnel and a P0/P1 Top 10 table", () => {
    const urgent = Array.from({ length: 12 }, (_, i) =>
      cveFinding({ cve: `CVE-2099-01${String(i).padStart(2, "0")}`, exploit: true, epss: 0.5, resourceId: `i-${i}` }),
    );
    const scan = scanOf([
      moduleOf("inspector_findings", [
        cveFinding({ cve: "CVE-2026-31431", reach: "internet_open", resourceId: "i-pipe|name" }),
        ...urgent,
        cveFinding({ cve: "CVE-2099-0002", epss: 0.0001 }),
      ]),
    ]);
    const md = generateMarkdownReport(scan, "en");
    expect(md).toContain("## 🎯 Exploitability Assessment");
    expect(md).toContain("| CVE findings | 14 | 14 |");
    expect(md).toContain("| Public exploit | 12 | 12 |");
    expect(md).toContain("| EPSS high (≥ 0.1) | 12 | 12 |");
    expect(md).toContain("| CISA KEV (exploited in the wild) | 1 | 1 |");
    expect(md).toContain("| Publicly exposed (0.0.0.0/0 or allow-listed public IPs) | 1 | 1 |");
    expect(md).toContain("| P0 (fix now) | 1 | 1 |");
    expect(md).toContain("- **By exploitability priority:** P0 1 | P1 12 | P2 0 | P3 1");
    expect(md).toContain("CISA KEV snapshot: 2026-11-03");
    expect(md).toContain("### P0 / P1 Top 10");
    const table = md.slice(md.indexOf("### P0 / P1 Top 10"), md.indexOf("## Findings by Severity"));
    const rows = table.split("\n").filter((l) => /^\| P[01] \|/.test(l));
    expect(rows).toHaveLength(10);
    expect(rows[0]).toContain("| P0 | CVE-2026-31431 | i-pipe\\|name |");
    expect(table).toContain("3 more P0/P1 findings not shown");
    expect(table).toContain("NOT penetration testing");
    // individual entries carry the exploitability line
    expect(md).toContain("- **Exploitability priority:** P0 — In CISA KEV");
    // exploitability section comes before the severity listing
    expect(md.indexOf("## 🎯 Exploitability Assessment")).toBeLessThan(md.indexOf("## Findings by Severity"));
  });

  it("lists inspector_findings hard-capped at top 200, rest as a CVE summary table", () => {
    const urgent = Array.from({ length: 210 }, (_, i) =>
      cveFinding({ cve: `CVE-2099-5${String(i).padStart(3, "0")}`, exploit: true, epss: 0.5, resourceId: `i-${i}` }),
    );
    const bulk = bulkInspector(400, 250);
    const other = moduleOf("network_reachability", [
      { ...bulk[0], title: "Port 22 open", module: "network_reachability", exploitability: undefined, riskScore: 9 },
    ]);
    const scan = scanOf([other, moduleOf("inspector_findings", [...bulk, ...urgent])]);
    const md = generateMarkdownReport(scan, "zh");
    const entries = md.match(/^#### /gm) ?? [];
    // Intentional change (Codex final review, fix round 2): Markdown now uses the same
    // hard cap of 200 as HTML — previously all 210 P0/P1 were kept (211 entries). The
    // 10 overflowing P0/P1 go to the CVE summary table instead.
    expect(entries).toHaveLength(201);
    expect(md).toContain("#### Port 22 open");
    expect(md).toContain("### 其余 410 条发现按 CVE 汇总（260 个 CVE）");
    expect(md).toContain("仅按可利用性优先级逐条列出前 200 条");
    expect(md).toContain("> 另有 410 条 Inspector 发现以 CVE 汇总表呈现（见下方）。");
    const summaryRows = md.split("\n").filter((l) => /^\| CVE-2099-1\d{4} \| \d+ \| \d+ \| P3 \|$/.test(l));
    expect(summaryRows).toHaveLength(250);
    // recommendations only enumerate the listed findings
    const recs = md.slice(md.indexOf("## 建议"));
    expect(recs.split("\n").filter((l) => /^\d+\. \[/.test(l))).toHaveLength(201);
  });

  it("210 P0/P1 inspector findings: exactly 200 individual entries, 10 overflow at the top of the CVE table", () => {
    const urgent = Array.from({ length: 210 }, (_, i) =>
      cveFinding({ cve: `CVE-2099-5${String(i).padStart(3, "0")}`, exploit: true, epss: 0.5, resourceId: `i-${i}` }),
    );
    const md = generateMarkdownReport(scanOf([moduleOf("inspector_findings", [...bulkInspector(30, 20), ...urgent])]), "en");
    const entries = md.match(/^#### /gm) ?? [];
    expect(entries).toHaveLength(200);
    expect(md).toContain("> 40 more Inspector findings are summarized in the CVE table below.");
    expect(md).toContain("### Remaining 40 findings summarized by CVE (30 CVEs)");
    const listedCves = new Set((md.match(/^#### CVE-2099-5\d{3}/gm) ?? []).map((l) => l.slice(5)));
    expect(listedCves.size).toBe(200);
    const table = md.slice(md.indexOf("### Remaining 40 findings"));
    const rows = table.split("\n").filter((l) => /^\| CVE-2099-\d+ \| \d+ \| \d+ \| P\d \|$/.test(l));
    expect(rows).toHaveLength(30);
    // overflowing P1 CVEs first, none of them also listed individually
    const top = rows.slice(0, 10);
    expect(top.every((r) => r.endsWith("| P1 |"))).toBe(true);
    for (const r of top) expect(listedCves.has(r.split(" | ")[0].slice(2))).toBe(false);
    expect(rows.slice(10).every((r) => r.endsWith("| P3 |"))).toBe(true);
    // the P0/P1 Top 10 section is unchanged
    expect(md).toContain("### P0 / P1 Top 10");
    expect(md).toContain("200 more P0/P1 findings not shown");
  });

  it("no overflow note when inspector findings fit under the cap", () => {
    const md = generateMarkdownReport(scanOf([moduleOf("inspector_findings", bulkInspector(20))]), "en");
    expect(md).not.toContain("summarized in the CVE table below");
    expect(md).not.toContain("summarized by CVE");
  });
});

import { describe, it, expect } from "vitest";
import { generateHtmlReport, generateMlps3HtmlReport } from "../../src/tools/html-report.js";
import type { FullScanResult } from "../../src/types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { legacyScan } from "../fixtures/report-baseline/legacy-scan.js";
import { bulkInspector, cveFinding, moduleOf, scanOf, stripVersion } from "../fixtures/report-baseline/exploit-scan.js";
import type { Finding } from "../../src/types.js";

function makeResult(modules: Array<{
  module: string;
  findings: Array<{
    severity: string;
    title: string;
    description: string;
    riskScore: number;
    resourceId: string;
    resourceArn: string;
    region: string;
    resourceType: string;
    impact: string;
    remediationSteps: string[];
    priority: string;
    module?: string;
  }>;
}>): FullScanResult {
  const allFindings = modules.flatMap((m) => m.findings);
  return {
    scanStart: "2026-04-10T10:00:00.000Z",
    scanEnd: "2026-04-10T10:01:00.000Z",
    region: "us-east-1",
    accountId: "123456789012",
    modules: modules.map((m) => ({
      module: m.module,
      status: "success" as const,
      resourcesScanned: 3,
      findingsCount: m.findings.length,
      scanTimeMs: 100,
      findings: m.findings.map((f) => ({
        ...f,
        severity: f.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        priority: f.priority as "P0" | "P1" | "P2" | "P3",
      })),
    })),
    summary: {
      totalFindings: allFindings.length,
      critical: allFindings.filter((f) => f.severity === "CRITICAL").length,
      high: allFindings.filter((f) => f.severity === "HIGH").length,
      medium: allFindings.filter((f) => f.severity === "MEDIUM").length,
      low: allFindings.filter((f) => f.severity === "LOW").length,
      modulesSuccess: modules.length,
      modulesError: 0,
    },
  };
}

const sampleFinding = {
  severity: "CRITICAL",
  title: "EC2 instance i-abc123 has SSH (22) reachable from 0.0.0.0/0",
  description: "SSH reachable from the internet via SG + NACL analysis",
  riskScore: 9.0,
  resourceId: "i-abc123",
  resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
  region: "us-east-1",
  resourceType: "AWS::EC2::Instance",
  impact: "SSH exposed to the internet",
  remediationSteps: ["Restrict port 22 to known IPs"],
  priority: "P0",
  module: "network_reachability",
};

describe("generateHtmlReport", () => {
  it("produces valid HTML with expected structure", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<html lang=\"en\">");
    expect(html).toContain("AWS Security Scan Report");
    expect(html).toContain("123456789012");
    expect(html).toContain("us-east-1");
    expect(html).toContain("Security Score");
  });

  it("includes finding details and severity badge", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("i-abc123 has SSH");
    expect(html).toContain("CRITICAL");
    expect(html).toContain("Restrict port 22");
    expect(html).toContain("sev-critical");
    expect(html).toContain("badge-critical");
  });

  it("includes SVG donut chart with arcs", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("<svg");
    expect(html).toContain("viewBox");
    expect(html).toContain("stroke-dasharray");
    expect(html).toContain("#ef4444"); // critical color
  });

  it("includes bar chart with module name", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("Network Reachability");
    expect(html).toContain("<rect");
  });

  it("includes scan statistics table", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("<table>");
    expect(html).toContain("<th>Module</th>");
    expect(html).toContain("<th>Resources</th>");
  });

  it("includes recommendations section", () => {
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("Recommendations (");
    expect(html).toContain("unique)");
    expect(html).toContain("rec-fold");
  });

  it("shows clean state when no findings", () => {
    const result = makeResult([
      { module: "service_detection", findings: [] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("No security issues found.");
    expect(html).not.toContain("Recommendations");
    // Donut chart should show 0
    expect(html).toContain(">0</text>");
    // Bar chart should show all clean
    expect(html).toContain("All modules clean");
  });

  it("includes print styles", () => {
    const result = makeResult([{ module: "service_detection", findings: [] }]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("@media print");
  });

  it("calculates security score correctly", () => {
    // 1 critical = 100 - 15 = 85
    const result = makeResult([
      { module: "network_reachability", findings: [sampleFinding] },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain(">85</div>");
  });

  it("includes footer with version", () => {
    const result = makeResult([{ module: "service_detection", findings: [] }]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("AWS Security MCP Server v");
    expect(html).toContain("informational purposes only");
  });

  it("escapes HTML in finding titles", () => {
    const result = makeResult([
      {
        module: "service_detection",
        findings: [{
          ...sampleFinding,
          title: 'Test <script>alert("xss")</script>',
        }],
      },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).not.toContain('alert("xss")');
    expect(html).toContain("&lt;script&gt;");
  });

  it("handles multiple severity levels", () => {
    const result = makeResult([
      {
        module: "network_reachability",
        findings: [
          sampleFinding,
          { ...sampleFinding, severity: "HIGH", riskScore: 7.5, priority: "P1", title: "High finding" },
          { ...sampleFinding, severity: "MEDIUM", riskScore: 5.0, priority: "P2", title: "Medium finding" },
          { ...sampleFinding, severity: "LOW", riskScore: 2.0, priority: "P3", title: "Low finding" },
        ],
      },
    ]);
    const html = generateHtmlReport(result, undefined, "en");

    expect(html).toContain("badge-critical");
    expect(html).toContain("badge-high");
    expect(html).toContain("badge-medium");
    expect(html).toContain("badge-low");
  });
});

describe("generateMlps3HtmlReport", () => {
  it("produces valid HTML with Chinese headers", () => {
    const result = makeResult([
      { module: "security_hub_findings", findings: [] },
      { module: "network_reachability", findings: [] },
    ]);
    // Override region to cn-north-1
    result.region = "cn-north-1";
    const html = generateMlps3HtmlReport(result);

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain('<html lang="zh-CN">');
    expect(html).toContain("等保三级预检报告");
    expect(html).toContain("cn-north-1");
  });

  it("shows clean/issues indicators for checks", () => {
    const result = makeResult([
      {
        module: "security_hub_findings",
        findings: [{
          severity: "MEDIUM",
          title: "IAM password policy minimum length is too short — IAM.7",
          description: "The IAM password policy requires only 6 characters.",
          riskScore: 5.0,
          resourceId: "password-policy",
          resourceArn: "arn:aws:iam::123456789012:account-password-policy",
          region: "global",
          resourceType: "AWS::IAM::AccountPasswordPolicy",
          impact: "Weak passwords.",
          remediationSteps: ["Set minimum password length to at least 8 characters."],
          priority: "P2",
          module: "security_hub_findings",
        }],
      },
      { module: "network_reachability", findings: [] },
      { module: "iam_privilege_escalation", findings: [] },
      { module: "access_analyzer_findings", findings: [] },
    ]);
    const html = generateMlps3HtmlReport(result);

    // Check with findings → issues class
    expect(html).toContain("check-issues");
    // Clean check should have check-clean class
    expect(html).toContain("check-clean");
    // 发现问题 label
    expect(html).toContain("\u53d1\u73b0\u95ee\u9898");
    // 未发现问题 label
    expect(html).toContain("\u672a\u53d1\u73b0\u95ee\u9898");
  });

  it("displays fact-based summary (no pass rate)", () => {
    const result = makeResult([
      { module: "security_hub_findings", findings: [] },
      { module: "iam_privilege_escalation", findings: [] },
      { module: "network_reachability", findings: [] },
      { module: "service_detection", findings: [] },
      { module: "guardduty_findings", findings: [] },
      { module: "inspector_findings", findings: [] },
      { module: "ssl_certificate", findings: [] },
      { module: "access_analyzer_findings", findings: [] },
      { module: "config_rules_findings", findings: [] },
      { module: "patch_compliance_findings", findings: [] },
      { module: "disaster_recovery", findings: [] },
      { module: "waf_coverage", findings: [] },
    ]);
    const html = generateMlps3HtmlReport(result);

    // Should show checked count, not pass rate
    expect(html).toContain("\u5df2\u68c0\u67e5");
    expect(html).toContain("\u672a\u53d1\u73b0\u95ee\u9898");
    expect(html).not.toContain("\u901a\u8fc7\u7387");
    // All clean — no remediation section
    expect(html).not.toContain("\u5efa\u8bae\u6574\u6539\u9879");
  });

  it("shows unknown checks when modules are missing", () => {
    const result = makeResult([
      { module: "ssl_certificate", findings: [] },
    ]);
    const html = generateMlps3HtmlReport(result);

    expect(html).toContain("check-unknown");
    expect(html).toContain("未检查");
  });

  it("includes evidence-mode disclaimer", () => {
    const result = makeResult([{ module: "security_hub_findings", findings: [] }]);
    const html = generateMlps3HtmlReport(result);

    expect(html).toContain("GB/T 22239-2019");
    expect(html).toContain("184");
    expect(html).toContain("\u5408\u89c4\u5224\u5b9a");
    expect(html).toContain("\u6301\u8bc1\u6d4b\u8bc4\u673a\u6784");
  });

  it("includes MLPS category sections", () => {
    const result = makeResult([
      { module: "security_hub_findings", findings: [] },
      { module: "iam_privilege_escalation", findings: [] },
      { module: "network_reachability", findings: [] },
      { module: "service_detection", findings: [] },
      { module: "ssl_certificate", findings: [] },
      { module: "guardduty_findings", findings: [] },
      { module: "inspector_findings", findings: [] },
      { module: "access_analyzer_findings", findings: [] },
      { module: "config_rules_findings", findings: [] },
      { module: "patch_compliance_findings", findings: [] },
      { module: "disaster_recovery", findings: [] },
      { module: "waf_coverage", findings: [] },
    ]);
    const html = generateMlps3HtmlReport(result);

    // New GB/T 22239-2019 categories
    expect(html).toContain("安全物理环境");
    expect(html).toContain("安全通信网络");
    expect(html).toContain("安全区域边界");
    expect(html).toContain("安全计算环境");
    expect(html).toContain("安全管理中心");
  });

  it("includes remediation section for checks with issues", () => {
    const result = makeResult([
      {
        module: "security_hub_findings",
        findings: [{
          severity: "MEDIUM",
          title: "IAM.7 IAM password policy minimum length is too short",
          description: "The IAM password policy requires only 6 characters.",
          riskScore: 5.0,
          resourceId: "password-policy",
          resourceArn: "arn:aws:iam::123456789012:account-password-policy",
          region: "global",
          resourceType: "AWS::IAM::AccountPasswordPolicy",
          impact: "Weak passwords.",
          remediationSteps: ["Set minimum password length to at least 8 characters."],
          priority: "P2",
          module: "security_hub_findings",
        }],
      },
      { module: "iam_privilege_escalation", findings: [] },
      { module: "access_analyzer_findings", findings: [] },
    ]);
    const html = generateMlps3HtmlReport(result);

    expect(html).toContain("\u5efa\u8bae\u6574\u6539\u9879");
    expect(html).toContain("rec-fold");
    expect(html).toContain("Set minimum password length");
  });

  it("includes print styles", () => {
    const result = makeResult([{ module: "security_hub_findings", findings: [] }]);
    const html = generateMlps3HtmlReport(result);

    expect(html).toContain("@media print");
  });
});

// ---------------------------------------------------------------------------
// T5 — CVE exploitability prioritization
// ---------------------------------------------------------------------------

describe("generateHtmlReport — exploitability", () => {
  const baselineDir = join(__dirname, "../fixtures/report-baseline");

  it("legacy fixture without exploitability is byte-identical to the pre-T5 output (zh + en)", () => {
    for (const lang of ["zh", "en"] as const) {
      const html = stripVersion(generateHtmlReport(legacyScan(), undefined, lang));
      expect(html).toBe(readFileSync(join(baselineDir, `html.${lang}.html`), "utf8"));
      expect(html).not.toContain("xp-section");
    }
  });

  function top5Section(html: string): string {
    const start = html.indexOf('<div class="top5-card');
    const end = html.indexOf('id="exploitability"');
    return html.slice(start, end === -1 ? undefined : end);
  }

  it("Top 5 orders by exploitability priority (P0 > P1 > …), ties by riskScore", () => {
    const legacyCritical: Finding = {
      ...sampleFinding,
      severity: "CRITICAL",
      title: "LEGACY-P0 open SSH",
      priority: "P0",
      riskScore: 9.5,
    } as Finding;
    const scan = scanOf([
      moduleOf("network_reachability", [legacyCritical]),
      moduleOf("inspector_findings", [
        // CRITICAL CVSS 10 but no signals → P3 (riskScore 3.9)
        cveFinding({ cve: "CVE-2099-0003", epss: 0.0001, orig: 10, severity: "CRITICAL" }),
        cveFinding({ cve: "CVE-2099-0001", exploit: true, epss: 0.5, orig: 9.9 }), // P1 8.8
        cveFinding({ cve: "CVE-2026-31431", reach: "allowlist", orig: 7.0 }), // KEV P0 9.7
        cveFinding({ cve: "CVE-2099-0002", exploit: true, reach: "internet_open", orig: 9.0 }), // P0 9.9
        cveFinding({ cve: "CVE-2099-0004", epss: 0.05, orig: 9.9 }), // P2 6.9
      ]),
    ]);
    const top = top5Section(generateHtmlReport(scan, undefined, "en"));
    const order = ["CVE-2099-0002", "CVE-2026-31431", "LEGACY-P0", "CVE-2099-0001", "CVE-2099-0004"].map((s) =>
      top.indexOf(s),
    );
    expect(order.every((i) => i >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(top).not.toContain("CVE-2099-0003");
    // priority badge + localized rationale on Top cards
    expect(top).toContain('<span class="xp-badge xp-p0">P0</span>');
    expect(top).toContain("Public exploit available and the resource is open to the internet");
  });

  it("renders the exploitability block: 6 funnel numbers, P0/P1 table, disclaimer, KEV date", () => {
    const scan = scanOf([
      moduleOf("inspector_findings", [
        cveFinding({ cve: "CVE-2026-31431", reach: "allowlist", reachDetail: "public IP 1.2.3.4; SG sg-1 allows 1.2.3.4/32" }),
        cveFinding({ cve: "CVE-2099-0001", exploit: true, epss: 0.5, reach: "internal" }),
        cveFinding({ cve: "CVE-2099-0001", exploit: true, epss: 0.5, reach: "internal", resourceId: "i-0abc000000000002" }),
        cveFinding({ cve: "CVE-2099-0002", epss: 0.0001 }),
      ]),
    ]);
    const html = generateHtmlReport(scan, undefined, "zh");
    expect(html).toContain("🎯 可利用性研判");
    const block = html.slice(html.indexOf('id="exploitability"'), html.indexOf("</section>", html.indexOf('id="exploitability"')));
    const layers = [...block.matchAll(/data-layer="(\w+)"><div class="xp-funnel-count">(\d+)<\/div><div class="xp-funnel-cves">(\d+)/g)].map(
      (m) => [m[1], Number(m[2]), Number(m[3])],
    );
    expect(layers).toEqual([
      ["total", 4, 3],
      ["exploitAvailable", 2, 1],
      ["epssHigh", 2, 1],
      ["kev", 1, 1],
      ["reachable", 1, 1],
      ["p0", 1, 1],
    ]);
    expect(block).toContain("各层独立统计");
    expect(block).toContain("P0 / P1 漏洞清单");
    expect(block).toContain("CISA KEV 快照日期：2026-11-03");
    expect(block).toContain("2026-05-01"); // KEV dateAdded of CVE-2026-31431
    expect(block).toContain("public IP 1.2.3.4");
    expect(block).toContain("不是渗透测试");
    expect(block).not.toContain("KEV 快照已过期");
    // P0/P1 table rows: 1 P0 + 2 P1; P3 not listed
    expect((block.match(/<tr><td><span class="xp-badge/g) ?? []).length).toBe(3);
    expect(block).not.toContain("CVE-2099-0002");
    // footer disclaimer
    const footer = html.slice(html.indexOf("<footer>"));
    expect(footer).toContain("不是渗透测试");
  });

  it("flags a KEV snapshot older than 90 days", () => {
    const scan = scanOf([moduleOf("inspector_findings", [cveFinding({ cve: "CVE-2099-0002", epss: 0.0001 })])], "2027-03-01T08:00:00.000Z");
    const html = generateHtmlReport(scan, undefined, "en");
    expect(html).toContain("The KEV snapshot is 118 days old");
    expect(html).toContain("No P0 / P1 vulnerabilities.");
  });

  it("inspector_findings module: ≤ 200 cards (P0/P1 first) + CVE summary table for the rest", () => {
    const urgent = [
      cveFinding({ cve: "CVE-2026-31431", reach: "allowlist" }),
      cveFinding({ cve: "CVE-2099-0001", exploit: true, epss: 0.5 }),
    ];
    const scan = scanOf([moduleOf("inspector_findings", [...bulkInspector(450, 300), ...urgent])]);
    const html = generateHtmlReport(scan, undefined, "en");
    const cards = html.match(/<div class="finding-card [^"]+" data-severity="\w+" data-module="inspector_findings">/g) ?? [];
    expect(cards.length).toBe(200);
    const moduleBody = html.slice(html.indexOf('<details class="module-fold" data-module="inspector_findings">'));
    expect(moduleBody.indexOf("CVE-2026-31431")).toBeLessThan(moduleBody.indexOf("CVE-2099-1"));
    expect(moduleBody).toContain("P0 — fix immediately");
    expect(moduleBody).toContain("Remaining 252 findings summarized by CVE");
    expect(moduleBody).toContain("Only the top 200 findings by exploitability priority are listed individually");
    expect(moduleBody).toContain("252 more Inspector findings are summarized in the CVE table below.");
    // inspector now shows in the stats table
    expect(html).toMatch(/<tr><td>Inspector<\/td><td>5<\/td><td>452<\/td>/);
  });

  it("210 P0/P1 inspector findings: exactly 200 cards, 10 overflow at the top of the CVE table", () => {
    const urgent = Array.from({ length: 210 }, (_, i) =>
      cveFinding({ cve: `CVE-2099-5${String(i).padStart(3, "0")}`, exploit: true, epss: 0.5, resourceId: `i-${i}` }),
    );
    const scan = scanOf([moduleOf("inspector_findings", [...bulkInspector(30, 20), ...urgent])]);
    for (const lang of ["en", "zh"] as const) {
      const html = generateHtmlReport(scan, undefined, lang);
      const cards = html.match(/<div class="finding-card [^"]+" data-severity="\w+" data-module="inspector_findings">/g) ?? [];
      expect(cards.length).toBe(200);
      const moduleBody = html.slice(html.indexOf('<details class="module-fold" data-module="inspector_findings">'));
      expect(moduleBody).toContain(
        lang === "en" ? "40 more Inspector findings are summarized in the CVE table below." : "另有 40 条 Inspector 发现以 CVE 汇总表呈现（见下方）。",
      );
      const summary = moduleBody.slice(moduleBody.indexOf('class="severity-group-fold xp-cve-summary"'));
      const rows = summary.match(/<tr><td>CVE-2099-\d+<\/td><td>\d+<\/td><td>\d+<\/td><td>[^]*?<\/tr>/g) ?? [];
      expect(rows).toHaveLength(30);
      expect(rows.slice(0, 10).every((r) => /<td>CVE-2099-52\d\d<\/td>/.test(r) && r.includes("P1"))).toBe(true);
      expect(rows.slice(10).every((r) => r.includes("P3"))).toBe(true);
    }
  });

  it("detection-only inspector_findings (no findings) stays hidden", () => {
    const scan = scanOf([
      moduleOf("inspector_findings", [], { dataSource: "detection-only" }),
      moduleOf("security_hub_findings", [cveFinding({ cve: "CVE-2099-0001", exploit: true, module: "security_hub_findings" })]),
    ]);
    const html = generateHtmlReport(scan, undefined, "en");
    expect(html).not.toContain('data-module="inspector_findings"');
    expect(html).not.toMatch(/<tr><td>Inspector<\/td><td>5<\/td>/);
    // SH Inspector sub-category card carries the exploitability badge + rationale
    expect(html).toContain('<span class="xp-badge xp-p2">P2</span>');
    expect(html).toContain("Exploitability priority:</strong> Public exploit available, but no internet exposure");
  });
});

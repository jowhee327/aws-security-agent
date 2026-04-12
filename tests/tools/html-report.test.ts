import { describe, it, expect } from "vitest";
import { generateHtmlReport, generateMlps3HtmlReport } from "../../src/tools/html-report.js";
import type { FullScanResult } from "../../src/types.js";

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

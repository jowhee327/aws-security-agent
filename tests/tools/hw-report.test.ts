import { describe, it, expect } from "vitest";
import { generateHwDefenseHtmlReport } from "../../src/tools/hw-report.js";
import type { FullScanResult } from "../../src/types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { legacyScan } from "../fixtures/report-baseline/legacy-scan.js";
import { bulkInspector, cveFinding, moduleOf, scanOf, stripVersion } from "../fixtures/report-baseline/exploit-scan.js";

function makeScanResult(overrides?: Partial<FullScanResult>): FullScanResult {
  return {
    scanStart: "2026-04-12T10:00:00Z",
    scanEnd: "2026-04-12T10:01:00Z",
    region: "cn-north-1",
    accountId: "123456789012",
    modules: [],
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      modulesSuccess: 0,
      modulesError: 0,
    },
    ...overrides,
  };
}

describe("generateHwDefenseHtmlReport", () => {
  it("generates valid HTML with all 8 sections", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult());
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("护网");
    // Check all 8 SOP sections are present
    expect(html).toContain("攻击面收敛");
    expect(html).toContain("漏洞与补丁管理");
    expect(html).toContain("身份与凭证安全");
    expect(html).toContain("传输与实例安全");
    expect(html).toContain("安全服务状态");
    expect(html).toContain("应急响应准备");
    expect(html).toContain("环境处置");
    expect(html).toContain("护网后优化");
  });

  it("maps network findings to attack_surface section", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult({
      modules: [{
        module: "network_reachability",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 1,
        scanTimeMs: 100,
        findings: [{
          severity: "HIGH",
          title: "EC2 instance has open SSH port",
          resourceType: "AWS::EC2::Instance",
          resourceId: "i-123",
          resourceArn: "arn:aws:ec2:cn-north-1:123:instance/i-123",
          region: "cn-north-1",
          description: "Port 22 is open to 0.0.0.0/0",
          impact: "Direct SSH access from internet",
          riskScore: 8.0,
          remediationSteps: ["Restrict SSH access"],
          priority: "P1",
        }],
      }],
      summary: { totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
    }));
    expect(html).toContain("EC2 instance has open SSH port");
    expect(html).toContain("攻击面收敛");
    expect(html).toContain("badge-high");
  });

  it("maps IAM findings to identity_credential section", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult({
      modules: [{
        module: "iam_privilege_escalation",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 1,
        scanTimeMs: 100,
        findings: [{
          severity: "CRITICAL",
          title: "IAM user has iam:* permissions",
          resourceType: "AWS::IAM::User",
          resourceId: "admin-user",
          resourceArn: "arn:aws:iam::123:user/admin-user",
          region: "cn-north-1",
          description: "Full IAM admin",
          impact: "Can escalate to any role",
          riskScore: 9.5,
          remediationSteps: ["Restrict IAM permissions"],
          priority: "P0",
        }],
      }],
      summary: { totalFindings: 1, critical: 1, high: 0, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
    }));
    expect(html).toContain("IAM user has iam:* permissions");
    expect(html).toContain("身份与凭证安全");
    expect(html).toContain("badge-critical");
  });

  it("SH findings are deduplicated across sections (no double-counting)", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult({
      modules: [{
        module: "security_hub_findings",
        status: "success",
        resourcesScanned: 10,
        findingsCount: 3,
        scanTimeMs: 200,
        findings: [
          {
            severity: "MEDIUM",
            title: "EC2.19 Security groups should not allow unrestricted access",
            resourceType: "AWS::EC2::SecurityGroup",
            resourceId: "sg-12345",
            resourceArn: "arn:aws:ec2:cn-north-1:123:security-group/sg-12345",
            region: "cn-north-1",
            description: "Unrestricted network access to SecurityGroup",
            impact: "Source: Security Hub (FSBP) — unrestricted network access",
            riskScore: 6.0,
            remediationSteps: ["Restrict security group rules"],
            priority: "P2",
            module: "security_hub_findings",
          },
          {
            severity: "HIGH",
            title: "IAM.7 IAM password policy minimum length is too short",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            resourceId: "password-policy",
            resourceArn: "arn:aws:iam::123:account-password-policy",
            region: "global",
            description: "Weak IAM password policy",
            impact: "Source: Security Hub (FSBP) — weak IAM password",
            riskScore: 7.0,
            remediationSteps: ["Set minimum password length to 14"],
            priority: "P1",
            module: "security_hub_findings",
          },
          {
            severity: "HIGH",
            title: "CVE-2024-1234 vulnerability in openssl",
            resourceType: "AWS::EC2::Instance",
            resourceId: "i-vuln123",
            resourceArn: "arn:aws:ec2:cn-north-1:123:instance/i-vuln123",
            region: "cn-north-1",
            description: "Software vulnerability found",
            impact: "Source: Inspector — software vulnerability CVE-2024-1234",
            riskScore: 7.5,
            remediationSteps: ["Update openssl"],
            priority: "P1",
            module: "security_hub_findings",
          },
        ],
      }],
      summary: { totalFindings: 3, critical: 0, high: 2, medium: 1, low: 0, modulesSuccess: 1, modulesError: 0 },
    }));

    // Each SH finding should appear exactly once (no double-counting)
    const networkMatches = html.match(/EC2\.19 Security groups should not allow/g);
    expect(networkMatches).toHaveLength(1);

    const iamMatches = html.match(/IAM\.7 IAM password policy/g);
    expect(iamMatches).toHaveLength(1);

    const patchMatches = html.match(/CVE-2024-1234 vulnerability/g);
    expect(patchMatches).toHaveLength(1);
  });

  it("includes manual checklist items", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult());
    // Checkbox visual marker (□)
    expect(html).toContain("&#9633;");
    // Key manual items from various SOP sections
    expect(html).toContain("准备专用隔离安全组");
    expect(html).toContain("WAR-ROOM");
    expect(html).toContain("非核心系统在护网期间关闭");
    expect(html).toContain("针对攻击报告逐项应答与修复");
    expect(html).toContain("MFA");
    // Manual section headers
    expect(html).toContain("人工确认事项");
    // CSS class for manual items
    expect(html).toContain("hw-manual-item");
  });

  it("empty scan results produces clean report", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult(), "en");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("HW Defense Security Assessment Report");
    // Total findings should be 0
    expect(html).toContain(">0</div>");
    // Manual items should still be present
    expect(html).toContain("Manual Verification Items");
    // Sections without auto checks should show appropriate message
    expect(html).toContain("No automated checks for this section");
  });

  it("generates English report with lang=en", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult({
      modules: [{
        module: "network_reachability",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 1,
        scanTimeMs: 100,
        findings: [{
          severity: "HIGH",
          title: "Open SSH port",
          resourceType: "AWS::EC2::Instance",
          resourceId: "i-123",
          resourceArn: "arn:aws:ec2:us-east-1:123:instance/i-123",
          region: "us-east-1",
          description: "Port 22 open",
          impact: "SSH exposed",
          riskScore: 8.0,
          remediationSteps: ["Restrict SSH"],
          priority: "P1",
        }],
      }],
      summary: { totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
    }), "en");
    expect(html).toContain('<html lang="en">');
    expect(html).toContain("HW Defense Security Assessment Report");
    expect(html).toContain("Attack Surface Reduction");
    expect(html).toContain("Emergency Response Readiness");
    expect(html).toContain("Automated Checks");
    expect(html).toContain("Manual Verification Items");
  });

  it("escapes HTML in finding titles (XSS safe)", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult({
      modules: [{
        module: "network_reachability",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 1,
        scanTimeMs: 100,
        findings: [{
          severity: "HIGH",
          title: 'Test <script>alert("xss")</script>',
          resourceType: "AWS::EC2::Instance",
          resourceId: "i-123",
          resourceArn: "arn:aws:ec2:cn-north-1:123:instance/i-123",
          region: "cn-north-1",
          description: "XSS test",
          impact: "test",
          riskScore: 8.0,
          remediationSteps: ["Fix it"],
          priority: "P1",
        }],
      }],
      summary: { totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
    }));
    expect(html).not.toContain('alert("xss")');
    expect(html).toContain("&lt;script&gt;");
  });

  it("includes print styles", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult());
    expect(html).toContain("@media print");
  });

  it("includes footer with version", () => {
    const html = generateHwDefenseHtmlReport(makeScanResult(), "en");
    expect(html).toContain("AWS Security MCP Server v");
  });
});

// ---------------------------------------------------------------------------
// T5 — CVE exploitability prioritization
// ---------------------------------------------------------------------------

describe("generateHwDefenseHtmlReport — exploitability", () => {
  const baselineDir = join(__dirname, "../fixtures/report-baseline");

  function vulnSection(html: string): string {
    const start = Math.max(html.indexOf("漏洞与补丁管理"), html.indexOf("Vulnerability &amp; Patch Management"));
    return html.slice(start, html.indexOf("</details>\n<details", start));
  }

  it("legacy fixture without exploitability is byte-identical to the pre-T5 output (zh + en)", () => {
    for (const lang of ["zh", "en"] as const) {
      const html = stripVersion(generateHwDefenseHtmlReport(legacyScan(), lang));
      expect(html).toBe(readFileSync(join(baselineDir, `hw.${lang}.html`), "utf8"));
    }
  });

  it("vulnerability_patch pulls inspector_findings and lists P0/P1 (with rationale) first", () => {
    const scan = scanOf([
      moduleOf("inspector_findings", [
        cveFinding({ cve: "CVE-2099-0003", epss: 0.0001, orig: 10, severity: "CRITICAL" }), // P3
        cveFinding({ cve: "CVE-2099-0001", exploit: true, epss: 0.5 }), // P1
        cveFinding({ cve: "CVE-2026-31431", reach: "internet_open", severity: "MEDIUM" }), // P0
        cveFinding({ cve: "CVE-2099-0004", epss: 0.05, severity: "CRITICAL" }), // P2
      ], { dataSource: "inspector2" }),
    ]);
    const sec = vulnSection(generateHwDefenseHtmlReport(scan, "zh"));
    expect(sec).toContain("优先修复（P0 / P1） (2)");
    expect(sec).toContain("其余漏洞 (2)");
    const pos = ["优先修复", "CVE-2026-31431", "CVE-2099-0001", "其余漏洞", "CVE-2099-0004", "CVE-2099-0003"].map((s) =>
      sec.indexOf(s),
    );
    expect(pos.every((i) => i >= 0)).toBe(true);
    expect([...pos].sort((a, b) => a - b)).toEqual(pos);
    expect(sec).toContain("位于 CISA KEV（已被在野利用），且资源对全网开放 &middot; 对全网开放");
    expect(sec).toContain('<span class="xp-badge xp-p0">P0</span>');
    expect(sec).not.toContain("暂无自动检查");
  });

  it("caps non-urgent vulnerability groups and notes the remainder", () => {
    const scan = scanOf([
      moduleOf("inspector_findings", [cveFinding({ cve: "CVE-2026-31431", reach: "internet_open" }), ...bulkInspector(300, 260)]),
    ]);
    const sec = vulnSection(generateHwDefenseHtmlReport(scan, "en"));
    expect((sec.match(/class="hw-finding-group"/g) ?? []).length).toBe(201);
    expect(sec).toContain("60 more vulnerability groups not expanded");
  });

  it("detection-only inspector_findings alone does not count as an automated check", () => {
    const scan = scanOf([moduleOf("inspector_findings", [], { dataSource: "detection-only" })]);
    const sec = vulnSection(generateHwDefenseHtmlReport(scan, "zh"));
    expect(sec).not.toContain("hw-clean");
  });
});

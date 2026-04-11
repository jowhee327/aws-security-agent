import { describe, it, expect } from "vitest";
import { generateMlps3Report, evaluateFullCheck } from "../../src/tools/mlps-report.js";
import type { MlpsChecklistItem, MlpsCheckMapping } from "../../src/tools/mlps-report.js";
import type { FullScanResult, Finding } from "../../src/types.js";

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
    region: "cn-north-1",
    accountId: "123456789012",
    modules: modules.map((m) => ({
      module: m.module,
      status: "success" as const,
      resourcesScanned: 1,
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

describe("generateMlps3Report", () => {
  it("generates report with clean/issues indicators for findings", () => {
    const result = makeResult([
      {
        module: "security_hub_findings",
        findings: [
          {
            severity: "MEDIUM",
            title: "IAM.7 IAM password policy minimum length is too short",
            description: "The IAM password policy requires only 6 characters.",
            riskScore: 5.0,
            resourceId: "password-policy",
            resourceArn: "arn:aws:iam::123456789012:account-password-policy",
            region: "global",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            impact: "Weak passwords can be easily cracked.",
            remediationSteps: ["Set minimum password length to at least 8 characters."],
            priority: "P2",
            module: "security_hub_findings",
          },
        ],
      },
    ]);

    const report = generateMlps3Report(result);

    // Header
    expect(report).toContain("# 等保三级预检报告");
    expect(report).toContain("Account: 123456789012");
    expect(report).toContain("cn-north-1");

    // Password policy should have issues (finding matches "IAM.7" pattern)
    expect(report).toContain("\u274c");
    expect(report).toContain("密码策略");
    expect(report).toContain("发现问题");

    // Audit function should be clean (security_hub_findings present, no CloudTrail finding)
    expect(report).toContain("\u2705");
    expect(report).toContain("审计功能");
    expect(report).toContain("未发现问题");

    // Summary — no 通过率, uses fact-based summary
    expect(report).toContain("已检查");
    expect(report).not.toContain("通过率");

    // Remediation section
    expect(report).toContain("建议整改项");
  });

  it("generates all-clean report when no findings exist", () => {
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

    const report = generateMlps3Report(result);

    // All checks should be clean (no ❌ issues)
    expect(report).not.toContain("\u274c");
    expect(report).toContain("未发现问题");
    expect(report).not.toContain("通过率");
    // No remediation section
    expect(report).not.toContain("建议整改项");
  });

  it("marks checks as unknown when required module is missing or errored", () => {
    // Only provide security_hub_findings — other required modules (service_detection, etc.) are missing
    const result = makeResult([
      {
        module: "security_hub_findings",
        findings: [
          {
            severity: "MEDIUM",
            title: "IAM.7 IAM password policy minimum length is too short",
            description: "The IAM password policy requires only 6 characters.",
            riskScore: 5.0,
            resourceId: "password-policy",
            resourceArn: "arn:aws:iam::123456789012:account-password-policy",
            region: "global",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            impact: "Weak passwords.",
            remediationSteps: ["Fix it."],
            priority: "P2",
            module: "security_hub_findings",
          },
        ],
      },
    ]);

    const report = generateMlps3Report(result);

    // Password policy check should have issues (security_hub_findings present, finding matches "IAM.7")
    expect(report).toContain("\u274c");
    expect(report).toContain("发现问题");
    // Checks with missing modules (e.g., service_detection for GuardDuty) should show ⚠️ 未检查
    expect(report).toContain("\u26a0\ufe0f");
    expect(report).toContain("未检查");
  });
});

// ---------------------------------------------------------------------------
// evaluateFullCheck — new 3-tier evaluation logic
// ---------------------------------------------------------------------------

const dummyItem: MlpsChecklistItem = {
  id: "L3-TEST-01",
  categoryCn: "测试",
  categoryEn: "Test",
  controlCn: "测试控制",
  controlEn: "Test Control",
  requirementCn: "测试要求",
  requirementEn: "Test Requirement",
  referenceStatus: "",
  referenceComment: "",
};

function makeFinding(overrides: Partial<Finding> & { title: string; module: string }): Finding {
  return {
    severity: "MEDIUM",
    resourceType: "AWS::EC2::Instance",
    resourceId: "i-abc123",
    resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
    region: "us-east-1",
    description: "Test finding",
    impact: "Test impact",
    riskScore: 5.0,
    remediationSteps: ["Fix it."],
    priority: "P2",
    ...overrides,
  };
}

const allModulesPresent = [
  { module: "security_hub_findings", status: "success" },
  { module: "network_reachability", status: "success" },
  { module: "guardduty_findings", status: "success" },
  { module: "waf_coverage", status: "success" },
  { module: "iam_privilege_escalation", status: "success" },
  { module: "service_detection", status: "success" },
];

describe("evaluateFullCheck — securityHubControlIds", () => {
  it("returns clean when no Security Hub findings match the specific control IDs", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["security_hub_findings"],
      securityHubControlIds: ["IAM.7", "IAM.10"],
    };
    // Finding has a different control ID
    const findings = [
      makeFinding({ title: "EC2.2 Default VPC in use", module: "security_hub_findings" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("clean");
    expect(result.relatedFindings).toHaveLength(0);
  });

  it("returns issues when Security Hub findings match specific control IDs", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["security_hub_findings"],
      securityHubControlIds: ["IAM.7", "IAM.10"],
    };
    const findings = [
      makeFinding({ title: "IAM.7 Password policy too weak", module: "security_hub_findings" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    expect(result.relatedFindings).toHaveLength(1);
  });

  it("returns issues when 4+ Security Hub findings match specific control IDs", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["security_hub_findings"],
      securityHubControlIds: ["IAM.7", "IAM.10"],
    };
    const findings = [
      makeFinding({ title: "IAM.7 Password policy too weak - resource 1", module: "security_hub_findings" }),
      makeFinding({ title: "IAM.7 Password policy too weak - resource 2", module: "security_hub_findings" }),
      makeFinding({ title: "IAM.10 Password expiry not set - resource 1", module: "security_hub_findings" }),
      makeFinding({ title: "IAM.10 Password expiry not set - resource 2", module: "security_hub_findings" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    expect(result.relatedFindings).toHaveLength(4);
  });

  it("hybrid: matches Security Hub by control ID and other scanners by module", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["network_reachability", "security_hub_findings"],
      securityHubControlIds: ["EC2.18"],
    };
    // Security Hub finding for a DIFFERENT control — should NOT match
    // network_reachability finding — SHOULD match (module-level)
    const findings = [
      makeFinding({ title: "IAM.7 Password issue", module: "security_hub_findings" }),
      makeFinding({ title: "SG allows SSH from 0.0.0.0/0", module: "network_reachability" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    // Only the network_reachability finding should be related (not IAM.7)
    expect(result.relatedFindings).toHaveLength(1);
    expect(result.relatedFindings[0].module).toBe("network_reachability");
  });

  it("hybrid: returns issues when 4+ findings from mixed modules", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["network_reachability", "security_hub_findings"],
      securityHubControlIds: ["EC2.18"],
    };
    const findings = [
      makeFinding({ title: "EC2.18 SG unrestricted - res 1", module: "security_hub_findings" }),
      makeFinding({ title: "EC2.18 SG unrestricted - res 2", module: "security_hub_findings" }),
      makeFinding({ title: "SG allows SSH from 0.0.0.0/0", module: "network_reachability" }),
      makeFinding({ title: "SG allows RDP from 0.0.0.0/0", module: "network_reachability" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    expect(result.relatedFindings).toHaveLength(4);
  });
});

describe("evaluateFullCheck — module-level (no patterns, no control IDs)", () => {
  it("returns clean when scanner modules have no findings", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["guardduty_findings", "waf_coverage"],
    };
    const result = evaluateFullCheck(dummyItem, mapping, [], allModulesPresent);
    expect(result.status).toBe("clean");
  });

  it("returns issues when scanner modules have findings", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["guardduty_findings"],
    };
    const findings = [
      makeFinding({ title: "Trojan detected", module: "guardduty_findings" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    expect(result.relatedFindings).toHaveLength(1);
  });

  it("ignores findings from unrelated modules", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["guardduty_findings"],
    };
    // Finding from a different module should be ignored
    const findings = [
      makeFinding({ title: "SG issue", module: "network_reachability" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("clean");
  });
});

describe("evaluateFullCheck — findingPatterns (legacy)", () => {
  it("returns clean when no findings match the patterns", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["service_detection"],
      findingPatterns: ["CloudWatch"],
    };
    const findings = [
      makeFinding({ title: "Security Hub not enabled", module: "service_detection" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("clean");
  });

  it("returns issues when a finding matches the pattern", () => {
    const mapping: MlpsCheckMapping = {
      id: "L3-TEST-01",
      type: "auto",
      modules: ["service_detection"],
      findingPatterns: ["CloudWatch"],
    };
    const findings = [
      makeFinding({ title: "CloudWatch monitoring not configured", module: "service_detection" }),
    ];
    const result = evaluateFullCheck(dummyItem, mapping, findings, allModulesPresent);
    expect(result.status).toBe("issues");
    expect(result.relatedFindings).toHaveLength(1);
  });
});

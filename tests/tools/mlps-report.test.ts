import { describe, it, expect } from "vitest";
import { generateMlps3Report } from "../../src/tools/mlps-report.js";
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
  it("generates report with pass/fail indicators for findings", () => {
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

    // Password policy should FAIL (finding matches "IAM.7" pattern)
    expect(report).toContain("\u274c");
    expect(report).toContain("密码策略");

    // Audit function should PASS (security_hub_findings present, no CloudTrail finding)
    expect(report).toContain("\u2705");
    expect(report).toContain("审计功能");

    // Summary
    expect(report).toContain("通过率:");

    // Remediation section
    expect(report).toContain("建议整改项");
  });

  it("generates all-pass report when no findings exist", () => {
    const result = makeResult([
      { module: "security_hub_findings", findings: [] },
      { module: "iam_privilege_escalation", findings: [] },
      { module: "network_reachability", findings: [] },
      { module: "service_detection", findings: [] },
      { module: "guardduty_findings", findings: [] },
      { module: "inspector_findings", findings: [] },
      { module: "ssl_certificate", findings: [] },
    ]);

    const report = generateMlps3Report(result);

    // All checks should pass
    expect(report).not.toContain("\u274c");
    expect(report).toContain("通过率: 100%");
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

    // Password policy check should FAIL (security_hub_findings present, finding matches "IAM.7")
    expect(report).toContain("\u274c");
    // Checks with missing modules (e.g., service_detection for GuardDuty) should show ⚠️ 未检查
    expect(report).toContain("\u26a0\ufe0f");
    expect(report).toContain("未检查");
    // Summary should show 未检查 count and note about pass rate
    expect(report).toContain("未检查项不计入通过率");
  });
});

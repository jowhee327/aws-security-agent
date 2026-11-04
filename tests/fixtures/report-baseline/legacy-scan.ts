/**
 * Legacy scan fixture (no `exploitability` / `dataSource` fields) used to pin
 * report output byte-for-byte against the pre-exploitability renderers.
 * Baselines in this directory were generated from the report functions BEFORE
 * the T5 changes (VERSION replaced with the __VERSION__ placeholder).
 */
import type { Finding, FullScanResult, ScanResult } from "../../../src/types.js";

function f(partial: Partial<Finding> & Pick<Finding, "severity" | "title" | "riskScore">): Finding {
  return {
    resourceType: "AWS::EC2::Instance",
    resourceId: "i-0legacy0001",
    resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001",
    region: "us-east-1",
    description: "Legacy finding description",
    impact: "Legacy impact",
    remediationSteps: ["Review and fix", "Documentation: https://docs.aws.amazon.com/x"],
    priority: partial.severity === "CRITICAL" ? "P0" : partial.severity === "HIGH" ? "P1" : partial.severity === "MEDIUM" ? "P2" : "P3",
    ...partial,
  };
}

function mod(module: string, findings: Finding[], extra?: Partial<ScanResult>): ScanResult {
  return {
    module,
    status: "success",
    resourcesScanned: 7,
    findingsCount: findings.length,
    scanTimeMs: 120,
    findings,
    ...extra,
  };
}

export function legacyScan(): FullScanResult {
  const modules: ScanResult[] = [
    mod("network_reachability", [
      f({ severity: "CRITICAL", title: "EC2 instance i-0legacy0001 has SSH (22) reachable from 0.0.0.0/0", riskScore: 9.4, remediationSteps: ["Restrict port 22 on sg-0abc1234 to known IPs"] }),
      f({ severity: "HIGH", title: "EC2 instance i-0legacy0002 has RDP (3389) reachable", riskScore: 8.1, resourceId: "i-0legacy0002" }),
    ]),
    mod("security_hub_findings", [
      f({ severity: "CRITICAL", title: "CVE-2024-4577 - php", riskScore: 9.8, impact: "Source: Inspector (package vulnerability)", resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003", resourceId: "arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003", description: "PHP CGI argument injection <b>bold</b>" }),
      f({ severity: "HIGH", title: "CVE-2023-1111 - openssl", riskScore: 7.5, impact: "Source: Inspector (package vulnerability)" }),
      f({ severity: "MEDIUM", title: "KB5034441 - Windows security update", riskScore: 5.0, impact: "Source: Inspector (package vulnerability)", remediationSteps: ["Install KB5034441"] }),
      f({ severity: "HIGH", title: "EC2.19 Security groups should not allow unrestricted access to ports with high risk", riskScore: 7.0, impact: "Source: Security Hub (Foundational Security Best Practices)", remediationSteps: ["Remove unrestricted rules"] }),
      f({ severity: "MEDIUM", title: "Unusual API call", riskScore: 5.5, impact: "Source: GuardDuty (threat detection)", remediationSteps: ["Investigate"] }),
    ]),
    mod("inspector_findings", [], { warnings: ["Inspector is not enabled in this region"] }),
    mod("patch_compliance_findings", [
      f({ severity: "HIGH", title: "Instance i-0legacy0004 missing critical patches", riskScore: 7.8, resourceId: "i-0legacy0004" }),
    ]),
    mod("iam_privilege_escalation", [
      f({ severity: "LOW", title: "Role 'dev' can pass role", riskScore: 2.5, resourceType: "AWS::IAM::Role", resourceId: "dev", resourceArn: "arn:aws:iam::123456789012:role/dev" }),
    ]),
    mod("ssl_certificate", [], { status: "error", error: "boom" }),
  ];
  const all = modules.flatMap((m) => m.findings);
  return {
    scanStart: "2026-05-01T08:00:00.000Z",
    scanEnd: "2026-05-01T08:02:05.000Z",
    region: "us-east-1",
    accountId: "123456789012",
    modules,
    summary: {
      totalFindings: all.length,
      critical: all.filter((x) => x.severity === "CRITICAL").length,
      high: all.filter((x) => x.severity === "HIGH").length,
      medium: all.filter((x) => x.severity === "MEDIUM").length,
      low: all.filter((x) => x.severity === "LOW").length,
      modulesSuccess: 5,
      modulesError: 1,
    },
  };
}

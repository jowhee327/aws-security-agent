/** T8 — HTML report redaction must collapse Huawei `hws:` URNs like AWS ARNs, without changing AWS behaviour. */
import { describe, it, expect } from "vitest";
import { generateHtmlReport, getRecommendationTemplate } from "../../src/tools/html-report.js";
import type { FullScanResult } from "../../src/types.js";

/** Verbatim copy of the pre-T8 template normalizer (AWS-only ARN pattern) used as the AWS oracle. */
function legacyTemplate(rem: string): string {
  return rem
    .replace(/\b(i-[0-9a-f]+)\b/g, '{instance}')
    .replace(/\b(vol-[0-9a-f]+)\b/g, '{volume}')
    .replace(/\b(sg-[0-9a-f]+)\b/g, '{sg}')
    .replace(/\b(eipalloc-[0-9a-f]+)\b/g, '{eip}')
    .replace(/\b(arn:aws[-\w]*:[^"\s]+)\b/g, '{arn}')
    .replace(/"[^"]+"/g, '{name}')
    .replace(/bucket \S+/g, 'bucket {name}')
    .replace(/instance \S+/g, 'instance {id}')
    .replace(/volume \S+/g, 'volume {id}')
    .replace(/rule \S+/g, 'rule {name}');
}

describe("getRecommendationTemplate", () => {
  it("collapses Huawei Cloud hws: URNs to {arn}", () => {
    const out = getRecommendationTemplate("Review the ACL of hws:cn-north-4:d0m41n:obs:bucket:my-bucket and remove Everyone grants");
    expect(out).toBe("Review the ACL of {arn} and remove Everyone grants");
    expect(out).not.toContain("hws:");
    expect(getRecommendationTemplate("Rotate key hws:global:d0m41n:iam:accesskey:AKIDEXAMPLE")).toBe("Rotate key {arn}");
    expect(getRecommendationTemplate("Detach hws:cn-east-3:d0m41n:evs:volume:3f2a-uuid now")).toBe("Detach {arn} now");
  });

  it("is byte-identical to the legacy normalizer for AWS inputs", () => {
    const samples = [
      "Terminate instance i-0abc123def and delete volume vol-0123456789abcdef0",
      "Remove rule sg-0a1b2c3d from security group",
      "Release eipalloc-0abcdef1234567890",
      'Enable Block Public Access on bucket "my-bucket"',
      "Review policy arn:aws:iam::123456789012:policy/AdminAccess attached to the role",
      "Review arn:aws-cn:s3:::my-bucket/* and restrict access",
      "Rotate key arn:aws-us-gov:iam::123456789012:user/bob",
      "No identifiers here; plain remediation text.",
      "Fix rule http-80 and rule ssh-22",
    ];
    for (const s of samples) {
      expect(getRecommendationTemplate(s)).toBe(legacyTemplate(s));
    }
  });
});

describe("generateHtmlReport with a Huawei Cloud result", () => {
  const hwResult: FullScanResult = {
    scanStart: "2026-09-13T01:00:00.000Z",
    scanEnd: "2026-09-13T01:00:05.000Z",
    region: "cn-north-4",
    accountId: "d0m41n",
    provider: "huaweicloud",
    modules: [
      {
        module: "public_access_verify",
        status: "success",
        resourcesScanned: 3,
        findingsCount: 1,
        scanTimeMs: 100,
        findings: [
          {
            severity: "CRITICAL",
            title: "OBS bucket is publicly readable",
            resourceType: "obs:bucket",
            resourceId: "public-bkt",
            resourceArn: "hws:cn-north-4:d0m41n:obs:bucket:public-bkt",
            region: "cn-north-4",
            description: "ACL grants Everyone READ",
            impact: "Data exposure",
            riskScore: 9.5,
            remediationSteps: ["Remove Everyone grants from hws:cn-north-4:d0m41n:obs:bucket:public-bkt"],
            priority: "P0",
            provider: "huaweicloud",
          },
        ],
      },
    ],
    summary: { totalFindings: 1, critical: 1, high: 0, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
  };

  it("renders the URN as-is and uses Huawei Cloud titles", () => {
    const zh = generateHtmlReport(hwResult, undefined, "zh");
    expect(zh).toContain("hws:cn-north-4:d0m41n:obs:bucket:public-bkt");
    expect(zh).toContain("华为云安全扫描报告");
    expect(zh).not.toContain("AWS 安全扫描报告");
    const en = generateHtmlReport(hwResult, undefined, "en");
    expect(en).toContain("Huawei Cloud Security Scan Report");
  });

  it("keeps AWS titles for results without a provider", () => {
    const awsResult: FullScanResult = { ...hwResult, provider: undefined, accountId: "123456789012", region: "us-east-1" };
    expect(generateHtmlReport(awsResult, undefined, "zh")).toContain("AWS 安全扫描报告");
    expect(generateHtmlReport(awsResult, undefined, "en")).toContain("AWS Security Scan Report");
  });
});

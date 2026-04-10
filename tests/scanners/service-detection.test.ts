import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { ServiceDetectionScanner } from "../../src/scanners/service-detection.js";
import type { ScanContext } from "../../src/types.js";
import type { ServiceDetectionResult } from "../../src/scanners/service-detection.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

const ctxChina: ScanContext = {
  region: "cn-north-1",
  partition: "aws-cn",
  accountId: "123456789012",
};

type ScanResultWithDetection = Awaited<ReturnType<ServiceDetectionScanner["scan"]>> & {
  serviceDetection?: ServiceDetectionResult;
};

describe("ServiceDetectionScanner", () => {
  const scanner = new ServiceDetectionScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings and 100% coverage when all services are enabled", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail", IsMultiRegionTrail: true }] };
        case "DescribeHubCommand":
          return { HubArn: "arn:aws:securityhub:us-east-1:123456789012:hub/default" };
        case "ListDetectorsCommand":
          return { DetectorIds: ["abc123"] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "ENABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [{ name: "default" }] };
        case "GetMacieSessionCommand":
          return { status: "ENABLED" };
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.serviceDetection).toBeDefined();
    expect(result.serviceDetection!.coveragePercent).toBe(100);
    expect(result.serviceDetection!.maturityLevel).toBe("comprehensive");
    expect(result.serviceDetection!.services).toHaveLength(6);
    for (const svc of result.serviceDetection!.services) {
      expect(svc.enabled).toBe(true);
    }
  });

  it("returns findings for each disabled service and ~17% coverage when only CloudTrail is enabled", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail" }] };
        case "DescribeHubCommand":
          throw new Error("SecurityHub is not enabled");
        case "ListDetectorsCommand":
          return { DetectorIds: [] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "DISABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [] };
        case "GetMacieSessionCommand":
          throw new Error("Macie is not enabled");
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    // 5 findings: Security Hub, GuardDuty, Inspector, Config, Macie (not CloudTrail)
    expect(result.findingsCount).toBe(5);
    expect(result.findings).toHaveLength(5);

    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("AWS Security Hub is not enabled");
    expect(titles).toContain("Amazon GuardDuty is not enabled");
    expect(titles).toContain("Amazon Inspector is not enabled");
    expect(titles).toContain("AWS Config is not enabled");
    expect(titles).toContain("Amazon Macie is not enabled");

    expect(result.serviceDetection).toBeDefined();
    expect(result.serviceDetection!.coveragePercent).toBe(17); // 1/6 rounded
    expect(result.serviceDetection!.maturityLevel).toBe("basic");

    // Verify severity levels
    const shFinding = result.findings.find((f) => f.title.includes("Security Hub"));
    expect(shFinding!.severity).toBe("HIGH");
    expect(shFinding!.riskScore).toBe(7.5);

    const macieFinding = result.findings.find((f) => f.title.includes("Macie"));
    expect(macieFinding!.severity).toBe("MEDIUM");
    expect(macieFinding!.riskScore).toBe(5.0);

    // All ARNs use correct partition
    for (const f of result.findings) {
      if (f.resourceArn.startsWith("arn:")) {
        expect(f.resourceArn).toContain("arn:aws:");
      }
    }
  });

  it("adds warning (not a finding) when access is denied on a service", async () => {
    const accessDeniedErr = new Error("User is not authorized to perform securityhub:DescribeHub");
    accessDeniedErr.name = "AccessDeniedException";

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail" }] };
        case "DescribeHubCommand":
          throw accessDeniedErr;
        case "ListDetectorsCommand":
          return { DetectorIds: ["abc123"] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "ENABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [{ name: "default" }] };
        case "GetMacieSessionCommand":
          return { status: "ENABLED" };
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    // No finding for Security Hub since it was access denied, not "not enabled"
    expect(result.findings.every((f) => !f.title.includes("Security Hub"))).toBe(true);
    // Should have a warning about access denied
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Security Hub") && w.includes("insufficient permissions"))).toBe(true);
  });

  it("skips Macie gracefully in China regions", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail" }] };
        case "DescribeHubCommand":
          return { HubArn: "arn:aws-cn:securityhub:cn-north-1:123456789012:hub/default" };
        case "ListDetectorsCommand":
          return { DetectorIds: ["abc123"] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "ENABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [{ name: "default" }] };
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctxChina)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    // No Macie API call should be made
    expect(result.findings.every((f) => !f.title.includes("Macie"))).toBe(true);
    // Should have warning about Macie unavailability
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Macie") && w.includes("China"))).toBe(true);
    // Macie still appears in services list but marked as not available
    const macieService = result.serviceDetection!.services.find((s) => s.name === "Macie");
    expect(macieService).toBeDefined();
    expect(macieService!.enabled).toBe(false);
    expect(macieService!.details).toContain("Not available");
  });

  it("computes intermediate maturity for 2-3 enabled services", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail" }] };
        case "DescribeHubCommand":
          return { HubArn: "arn:aws:securityhub:us-east-1:123456789012:hub/default" };
        case "ListDetectorsCommand":
          return { DetectorIds: [] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "DISABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [] };
        case "GetMacieSessionCommand":
          throw new Error("Macie is not enabled");
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.serviceDetection!.coveragePercent).toBe(33); // 2/6
    expect(result.serviceDetection!.maturityLevel).toBe("intermediate");
  });

  it("computes advanced maturity for 4-5 enabled services", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return { trailList: [{ Name: "main-trail" }] };
        case "DescribeHubCommand":
          return { HubArn: "arn:aws:securityhub:us-east-1:123456789012:hub/default" };
        case "ListDetectorsCommand":
          return { DetectorIds: ["abc123"] };
        case "BatchGetAccountStatusCommand":
          return { accounts: [{ state: { status: "ENABLED" } }] };
        case "DescribeConfigurationRecordersCommand":
          return { ConfigurationRecorders: [] };
        case "GetMacieSessionCommand":
          throw new Error("Macie is not enabled");
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.serviceDetection!.coveragePercent).toBe(67); // 4/6
    expect(result.serviceDetection!.maturityLevel).toBe("advanced");
  });
});

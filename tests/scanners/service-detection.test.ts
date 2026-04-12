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
    expect(result.serviceDetection!.services).toHaveLength(5);
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
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    // 4 findings: Security Hub, GuardDuty, Inspector, Config (not CloudTrail)
    expect(result.findingsCount).toBe(4);
    expect(result.findings).toHaveLength(4);

    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("AWS Security Hub is not enabled");
    expect(titles).toContain("Amazon GuardDuty is not enabled");
    expect(titles).toContain("Amazon Inspector is not enabled");
    expect(titles).toContain("AWS Config is not enabled");

    expect(result.serviceDetection).toBeDefined();
    expect(result.serviceDetection!.coveragePercent).toBe(20); // 1/5 rounded
    expect(result.serviceDetection!.maturityLevel).toBe("basic");

    // Verify severity levels
    const shFinding = result.findings.find((f) => f.title.includes("Security Hub"));
    expect(shFinding!.severity).toBe("HIGH");
    expect(shFinding!.riskScore).toBe(7.5);

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
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.serviceDetection!.coveragePercent).toBe(40); // 2/5
    expect(result.serviceDetection!.maturityLevel).toBe("intermediate");
  });

  it("computes advanced maturity for 4 enabled services", async () => {
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
        default:
          return {};
      }
    });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.serviceDetection!.coveragePercent).toBe(80); // 4/5
    expect(result.serviceDetection!.maturityLevel).toBe("advanced");
  });
});

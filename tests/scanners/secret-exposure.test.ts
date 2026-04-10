import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { SecretExposureScanner } from "../../src/scanners/secret-exposure.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("SecretExposureScanner", () => {
  const scanner = new SecretExposureScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns CRITICAL finding for AWS access key in Lambda env var", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListFunctionsCommand":
          return {
            Functions: [
              {
                FunctionName: "my-func",
                FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                Environment: {
                  Variables: {
                    AWS_KEY: "AKIAIOSFODNN7EXAMPLE",
                  },
                },
              },
            ],
          };
        case "DescribeInstancesCommand":
          return { Reservations: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBeGreaterThanOrEqual(1);
    const keyFinding = result.findings.find((f) => f.title.includes("AWS Access Key"));
    expect(keyFinding).toBeDefined();
    expect(keyFinding!.severity).toBe("CRITICAL");
    expect(keyFinding!.riskScore).toBe(9.5);
  });

  it("returns HIGH finding for suspicious env var name in Lambda", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListFunctionsCommand":
          return {
            Functions: [
              {
                FunctionName: "app-func",
                FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:app-func",
                Environment: {
                  Variables: {
                    DB_PASSWORD: "s3cret",
                    NORMAL_VAR: "hello",
                  },
                },
              },
            ],
          };
        case "DescribeInstancesCommand":
          return { Reservations: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(7.5);
    expect(finding.title).toContain("DB_PASSWORD");
    // Should NOT contain the actual value
    expect(finding.description).not.toContain("s3cret");
  });

  it("returns CRITICAL finding for AWS key in EC2 userData", async () => {
    const userData = Buffer.from(
      "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    ).toString("base64");

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListFunctionsCommand":
          return { Functions: [] };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  { InstanceId: "i-1234567890abcdef0" },
                ],
              },
            ],
          };
        case "DescribeInstanceAttributeCommand":
          return {
            UserData: { Value: userData },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBeGreaterThanOrEqual(1);
    const finding = result.findings.find((f) => f.title.includes("EC2") && f.title.includes("AWS Access Key"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.riskScore).toBe(9.5);
  });
});

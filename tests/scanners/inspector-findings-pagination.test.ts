import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { InspectorFindingsScanner } from "../../src/scanners/inspector-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

const ENABLED_STATUS = {
  accounts: [{ accountId: "123456789012", state: { status: "ENABLED" } }],
};

/** pages per partition; each page has 2 findings. */
const PAGES: Record<string, number> = {
  AWS_EC2_INSTANCE: 3,
  AWS_ECR_CONTAINER_IMAGE: 4,
  AWS_LAMBDA_FUNCTION: 2,
};

function page(type: string, n: number) {
  const total = PAGES[type] ?? 0;
  if (n >= total) return { findings: [] };
  const findings = [0, 1].map((i) => ({
    findingArn: `arn:aws:inspector2:us-east-1:123456789012:finding/${type}-${n}-${i}`,
    awsAccountId: "123456789012",
    type: "PACKAGE_VULNERABILITY",
    severity: "HIGH",
    title: `CVE-2026-43284 - pkg${i}`,
    resources: [{ type, id: type === "AWS_EC2_INSTANCE" ? `i-${n}${i}` : `arn:aws:x:${type}/${n}${i}` }],
    packageVulnerabilityDetails: { vulnerabilityId: "CVE-2026-43284", source: "NVD" },
  }));
  return { findings, nextToken: n + 1 < total ? `${type}#${n + 1}` : undefined };
}

type Cmd = {
  constructor: { name: string };
  input: { filterCriteria?: { resourceType?: Array<{ value?: string }> }; nextToken?: string };
};

function pageIndex(cmd: Cmd): { type: string; n: number } {
  const type = cmd.input.filterCriteria?.resourceType?.[0]?.value ?? "?";
  const n = cmd.input.nextToken ? Number(cmd.input.nextToken.split("#")[1]) : 0;
  return { type, n };
}

const EXPECTED_TOTAL = Object.values(PAGES).reduce((a, b) => a + b, 0) * 2;

describe("InspectorFindingsScanner pagination", () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it("pulls 3 partitions × multiple pages and follows every nextToken", async () => {
    mockSend.mockImplementation(async (cmd: Cmd) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      const { type, n } = pageIndex(cmd);
      return page(type, n);
    });

    const result = await new InspectorFindingsScanner().scan(ctx);

    expect(result.dataSource).toBe("inspector2");
    expect(result.findings).toHaveLength(EXPECTED_TOTAL);
    expect(new Set(result.findings.map((f) => f.sourceFindingId)).size).toBe(EXPECTED_TOTAL);
    const listCalls = mockSend.mock.calls.filter((c) => c[0].constructor.name === "ListFindingsCommand");
    // Each partition: its pages; CODE_REPOSITORY: one empty page.
    expect(listCalls).toHaveLength(3 + 4 + 2 + 1);
    for (const [type, n] of Object.entries(PAGES)) {
      expect(result.findings.filter((f) => f.sourceFindingId!.includes(`/${type}-`))).toHaveLength(n * 2);
    }
  });

  it.each([1, 2, 3])("never exceeds concurrency=%i in-flight ListFindings calls", async (limit) => {
    let inFlight = 0;
    let maxInFlight = 0;
    mockSend.mockImplementation(async (cmd: Cmd) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight--;
      const { type, n } = pageIndex(cmd);
      return page(type, n);
    });

    const result = await new InspectorFindingsScanner({ concurrency: limit }).scan(ctx);

    expect(result.findings).toHaveLength(EXPECTED_TOTAL);
    expect(maxInFlight).toBe(limit);
  });

  it("recovers from a single ThrottlingException", async () => {
    let throttled = false;
    mockSend.mockImplementation(async (cmd: Cmd) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      const { type, n } = pageIndex(cmd);
      if (type === "AWS_ECR_CONTAINER_IMAGE" && n === 1 && !throttled) {
        throttled = true;
        const err = new Error("Rate exceeded");
        err.name = "ThrottlingException";
        throw err;
      }
      return page(type, n);
    });

    const result = await new InspectorFindingsScanner({ throttleRetryDelayMs: 0 }).scan(ctx);

    expect(throttled).toBe(true);
    expect(result.dataSource).toBe("inspector2");
    expect(result.findings).toHaveLength(EXPECTED_TOTAL);
    expect(result.warnings).toBeUndefined();
  });

  it("degrades to detection-only when throttling persists after the retry", async () => {
    mockSend.mockImplementation(async (cmd: Cmd) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      const err = new Error("Rate exceeded");
      err.name = "ThrottlingException";
      throw err;
    });

    const result = await new InspectorFindingsScanner({ throttleRetryDelayMs: 0 }).scan(ctx);

    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("detection-only");
    expect(result.findings).toEqual([]);
    expect(result.warnings!.some((w) => w.includes("falling back to Security Hub"))).toBe(true);
  });

  it("stops on a repeated nextToken instead of looping forever", async () => {
    mockSend.mockImplementation(async (cmd: Cmd) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      const { type } = pageIndex(cmd);
      if (type !== "AWS_EC2_INSTANCE") return { findings: [] };
      return { ...page(type, 0), nextToken: "same" };
    });

    const result = await new InspectorFindingsScanner().scan(ctx);

    const ec2Calls = mockSend.mock.calls.filter((c) => pageIndex(c[0]).type === "AWS_EC2_INSTANCE");
    expect(ec2Calls).toHaveLength(2);
    // Same findings on both pages are de-duplicated by findingArn.
    expect(result.findings).toHaveLength(2);
    expect(result.warnings!.some((w) => w.includes("repeated nextToken"))).toBe(true);
  });
});

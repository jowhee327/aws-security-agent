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

describe("InspectorFindingsScanner (detection-only)", () => {
  const scanner = new InspectorFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings when Inspector is fully enabled", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "ENABLED" },
        resourceState: {
          ec2: { status: "ENABLED" },
          ecr: { status: "ENABLED" },
          lambda: { status: "ENABLED" },
          lambdaCode: { status: "ENABLED" },
          codeRepository: { status: "ENABLED" },
        },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("inspector_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeUndefined();
  });

  it("warns when Inspector is not enabled", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "DISABLED" },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Inspector is not enabled"))).toBe(true);
  });

  it("warns about disabled scan types (ecr, lambdaCode)", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "ENABLED" },
        resourceState: {
          ec2: { status: "ENABLED" },
          ecr: { status: "DISABLED" },
          lambda: { status: "ENABLED" },
          lambdaCode: { status: "DISABLED" },
          codeRepository: { status: "ENABLED" },
        },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings![0]).toContain("ECR");
    expect(result.warnings![0]).toContain("Lambda Code");
  });

  it("returns success with warning on AccessDeniedException", async () => {
    const err = new Error("User is not authorized to perform inspector2:BatchGetAccountStatus");
    err.name = "AccessDeniedException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Insufficient permissions"))).toBe(true);
  });

  it("returns success with warning when Inspector is not enabled (error path)", async () => {
    mockSend.mockRejectedValue(new Error("Inspector is not enabled in this account"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings!.some((w) => w.includes("Inspector is not enabled"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Direct Inspector2 pull (ListFindings)
// ---------------------------------------------------------------------------

const ENABLED_STATUS = {
  accounts: [{
    accountId: "123456789012",
    state: { status: "ENABLED" },
    resourceState: {
      ec2: { status: "ENABLED" },
      ecr: { status: "ENABLED" },
      lambda: { status: "ENABLED" },
      lambdaCode: { status: "ENABLED" },
      codeRepository: { status: "ENABLED" },
    },
  }],
};

// CVE-2026-31431 is in the bundled KEV snapshot; CVE-2026-43284 is not.
const KEV_CVE = "CVE-2026-31431";
const NON_KEV_CVE = "CVE-2026-43284";

interface InsFixture {
  arn: string;
  type?: string;
  id?: string;
  severity?: string;
  cve?: string;
  pkg?: string;
  exploit?: "YES" | "NO";
  epss?: number;
  inspectorScore?: number;
  cvss?: number;
  fix?: "YES" | "NO" | "PARTIAL";
}

function insFinding(o: InsFixture) {
  const cve = o.cve ?? NON_KEV_CVE;
  const pkg = o.pkg ?? "openssl";
  return {
    findingArn: o.arn,
    awsAccountId: "123456789012",
    type: "PACKAGE_VULNERABILITY",
    title: `${cve} - ${pkg}`,
    description: `${cve} description`,
    severity: o.severity ?? "HIGH",
    status: "ACTIVE",
    inspectorScore: o.inspectorScore,
    exploitAvailable: o.exploit,
    fixAvailable: o.fix,
    epss: o.epss === undefined ? undefined : { score: o.epss },
    remediation: { recommendation: { text: "Upgrade the package" } },
    resources: [{
      type: o.type ?? "AWS_EC2_INSTANCE",
      id: o.id ?? "i-0abc",
      partition: "aws",
      region: "us-east-1",
    }],
    packageVulnerabilityDetails: {
      vulnerabilityId: cve,
      source: "NVD",
      cvss: o.cvss === undefined ? undefined : [{ baseScore: o.cvss, scoringVector: "x", version: "3.1", source: "NVD" }],
      vulnerablePackages: [{ name: pkg, version: "1.0.0", fixedInVersion: "1.0.1" }],
      referenceUrls: ["https://ref/1", "https://ref/2", "https://ref/3"],
    },
  };
}

type ListInput = {
  filterCriteria?: {
    resourceType?: Array<{ value?: string }>;
    exploitAvailable?: Array<{ value?: string }>;
    epssScore?: Array<{ lowerInclusive?: number }>;
    findingStatus?: Array<{ comparison?: string; value?: string }>;
    findingType?: Array<{ comparison?: string; value?: string }>;
  };
  nextToken?: string;
  maxResults?: number;
};

/** Pages keyed by "<resourceType|exploit|epss>:<nextToken|start>". */
function dispatch(pages: Record<string, { findings: unknown[]; nextToken?: string }>, status: unknown = ENABLED_STATUS) {
  return async (cmd: { constructor: { name: string }; input: ListInput }) => {
    if (cmd.constructor.name === "BatchGetAccountStatusCommand") return status;
    if (cmd.constructor.name === "ListFindingsCommand") {
      const fc = cmd.input.filterCriteria ?? {};
      const stream = fc.resourceType?.[0]?.value
        ?? (fc.exploitAvailable ? "exploit" : fc.epssScore ? "epss" : "?");
      return pages[`${stream}:${cmd.input.nextToken ?? "start"}`] ?? { findings: [] };
    }
    // Intentional T3 change (plan §5 T3): L4 reachability is on by default and issues
    // read-only EC2/ECS/EKS/Lambda Describe/List/Get calls; answer them with an empty
    // inventory (EC2 → instance not found → "unknown"). No assertion was changed.
    if (/^(Describe|List|Get)/.test(cmd.constructor.name)) return {};
    throw new Error(`unexpected command ${cmd.constructor.name}`);
  };
}

describe("InspectorFindingsScanner (Inspector2 direct pull)", () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it("maps 2 pages of findings with fields, sourceFindingId and EC2 resourceArn", async () => {
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": {
        findings: [
          insFinding({ arn: "arn:aws:inspector2:us-east-1:123456789012:finding/a1", cve: KEV_CVE, pkg: "kernel", severity: "HIGH", inspectorScore: 7.8, exploit: "YES", epss: 0.02, fix: "YES" }),
          insFinding({ arn: "arn:aws:inspector2:us-east-1:123456789012:finding/a2", severity: "MEDIUM", inspectorScore: 5.0, exploit: "NO" }),
        ],
        nextToken: "p2",
      },
      "AWS_EC2_INSTANCE:p2": {
        findings: [insFinding({ arn: "arn:aws:inspector2:us-east-1:123456789012:finding/a3", severity: "CRITICAL", cvss: 9.8 })],
      },
      "AWS_ECR_CONTAINER_IMAGE:start": {
        findings: [insFinding({
          arn: "arn:aws:inspector2:us-east-1:123456789012:finding/e1",
          type: "AWS_ECR_CONTAINER_IMAGE",
          id: "arn:aws:ecr:us-east-1:123456789012:repository/app/sha256:abc",
          severity: "LOW",
        })],
      },
    }));

    const result = await new InspectorFindingsScanner().scan(ctx);

    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("inspector2");
    expect(result.findingsCount).toBe(4);
    expect(result.findings).toHaveLength(4);
    expect(result.resourcesScanned).toBe(4);
    expect(result.warnings).toBeUndefined();

    const listCalls = mockSend.mock.calls.map((c) => c[0]).filter((c) => c.constructor.name === "ListFindingsCommand");
    for (const c of listCalls) {
      expect(c.input.maxResults).toBe(100);
      expect(c.input.filterCriteria.findingStatus).toEqual([{ comparison: "EQUALS", value: "ACTIVE" }]);
      expect(c.input.filterCriteria.findingType).toEqual([{ comparison: "EQUALS", value: "PACKAGE_VULNERABILITY" }]);
    }

    const kev = result.findings.find((f) => f.sourceFindingId?.endsWith("/a1"))!;
    expect(kev.title).toBe(`${KEV_CVE} - kernel`);
    expect(kev.resourceType).toBe("AwsEc2Instance");
    expect(kev.resourceId).toBe("i-0abc");
    expect(kev.resourceArn).toBe("arn:aws:ec2:us-east-1:123456789012:instance/i-0abc");
    expect(kev.source).toBe("Inspector");
    expect(kev.module).toBe("inspector_findings");
    expect(kev.impact).toBe("Source: Inspector (package vulnerability)");
    expect(kev.severity).toBe("HIGH");
    expect(kev.priority).toBe("P1"); // severity-derived, unchanged semantics
    expect(kev.accountId).toBe("123456789012");
    expect(kev.remediationSteps).toEqual([
      "Upgrade kernel 1.0.0 to 1.0.1",
      "Upgrade the package",
      "Reference: https://ref/1",
      "Reference: https://ref/2",
    ]);
    expect(kev.exploitability).toMatchObject({
      cveId: KEV_CVE,
      exploitAvailable: true,
      epss: 0.02,
      epssLevel: "medium",
      kev: true,
      fixAvailable: "YES",
      reachability: "unknown",
      priority: "P1",
      rationaleCode: "KEV_NOT_EXPOSED",
      originalRiskScore: 7.8,
      dataSource: "inspector2",
    });
    // KEV with unknown reachability is P1 (P0 needs internet_open): 7.0 + 7.8/10 × 1.9
    expect(kev.riskScore).toBe(8.5);

    const plain = result.findings.find((f) => f.sourceFindingId?.endsWith("/a2"))!;
    expect(plain.exploitability).toMatchObject({ exploitAvailable: false, epss: null, epssLevel: "none", kev: false, priority: "P3", rationaleCode: "BASELINE" });
    expect(plain.riskScore).toBe(2.0); // 0.1 + 5.0/10*3.8

    // No inspectorScore → cvss baseScore is the original score.
    const crit = result.findings.find((f) => f.sourceFindingId?.endsWith("/a3"))!;
    expect(crit.severity).toBe("CRITICAL");
    expect(crit.exploitability!.originalRiskScore).toBe(9.8);
    expect(crit.exploitability!.exploitAvailable).toBeNull();

    // ECR: resourceId/Arn = image ARN; no score at all → severity default.
    const ecr = result.findings.find((f) => f.sourceFindingId?.endsWith("/e1"))!;
    expect(ecr.resourceType).toBe("AwsEcrContainerImage");
    expect(ecr.resourceId).toBe("arn:aws:ecr:us-east-1:123456789012:repository/app/sha256:abc");
    expect(ecr.resourceArn).toBe(ecr.resourceId);
    expect(ecr.exploitability!.originalRiskScore).toBe(3.0);
  });

  it("degrades to detection-only when Inspector is not enabled", async () => {
    mockSend.mockImplementation(dispatch({}, { accounts: [{ accountId: "123456789012", state: { status: "DISABLED" } }] }));
    const result = await new InspectorFindingsScanner().scan(ctx);
    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("detection-only");
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual(["Inspector is not enabled in this region. Enable it to scan for software vulnerabilities."]);
    expect(mockSend.mock.calls.some((c) => c[0].constructor.name === "ListFindingsCommand")).toBe(false);
  });

  it("degrades to detection-only on BatchGetAccountStatus AccessDenied", async () => {
    const err = new Error("not authorized");
    err.name = "AccessDeniedException";
    mockSend.mockRejectedValue(err);
    const result = await new InspectorFindingsScanner().scan(ctx);
    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("detection-only");
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual([
      "Insufficient permissions to access Inspector. Grant inspector2:BatchGetAccountStatus to check enablement.",
    ]);
  });

  it("degrades to detection-only on ListFindings AccessDenied, keeping enablement warnings", async () => {
    const status = structuredClone(ENABLED_STATUS);
    status.accounts[0].resourceState.ecr.status = "DISABLED";
    mockSend.mockImplementation(async (cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return status;
      const err = new Error("User is not authorized to perform inspector2:ListFindings");
      err.name = "AccessDeniedException";
      throw err;
    });
    const result = await new InspectorFindingsScanner().scan(ctx);
    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("detection-only");
    expect(result.findings).toEqual([]);
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toEqual([
      "Inspector scan types not enabled: ECR. Enable them for full vulnerability coverage.",
      "Grant inspector2:ListFindings to pull findings directly; falling back to Security Hub",
    ]);
  });

  it("degrades to detection-only (not error) on other ListFindings failures", async () => {
    mockSend.mockImplementation(async (cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "BatchGetAccountStatusCommand") return ENABLED_STATUS;
      throw new Error("InternalServerException: boom");
    });
    const result = await new InspectorFindingsScanner().scan(ctx);
    expect(result.status).toBe("success");
    expect(result.dataSource).toBe("detection-only");
    expect(result.findings).toEqual([]);
    expect(result.warnings!.some((w) => w.includes("falling back to Security Hub"))).toBe(true);
  });

  it("keeps INFORMATIONAL/UNTRIAGED only with exploit or KEV, as LOW", async () => {
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": {
        findings: [
          insFinding({ arn: "f/info-plain", severity: "INFORMATIONAL" }),
          insFinding({ arn: "f/untriaged-plain", severity: "UNTRIAGED", exploit: "NO", epss: 0.5 }),
          insFinding({ arn: "f/untriaged-exploit", severity: "UNTRIAGED", exploit: "YES" }),
          insFinding({ arn: "f/info-kev", severity: "INFORMATIONAL", cve: KEV_CVE }),
        ],
      },
    }));
    const result = await new InspectorFindingsScanner().scan(ctx);
    expect(result.findings.map((f) => f.sourceFindingId).sort()).toEqual(["f/info-kev", "f/untriaged-exploit"]);
    for (const f of result.findings) {
      expect(f.severity).toBe("LOW");
      expect(f.priority).toBe("P3");
      expect(f.exploitability!.originalRiskScore).toBe(3.0);
    }
    expect(result.resourcesScanned).toBe(4);
  });

  it("truncates at maxFindings but keeps the full exploit/EPSS signal subset", async () => {
    const plain = Array.from({ length: 6 }, (_, i) => insFinding({ arn: `f/plain-${i}` }));
    const exploitA = insFinding({ arn: "f/exploit-a", exploit: "YES" });
    const exploitB = insFinding({ arn: "f/exploit-b", exploit: "YES", epss: 0.2 });
    const epssC = insFinding({ arn: "f/epss-c", epss: 0.05 });
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": { findings: plain.slice(0, 3), nextToken: "p2" },
      "AWS_EC2_INSTANCE:p2": { findings: plain.slice(3), nextToken: "p3" },
      "AWS_EC2_INSTANCE:p3": { findings: [exploitA, exploitB, epssC] },
      "exploit:start": { findings: [exploitA], nextToken: "x2" },
      "exploit:x2": { findings: [exploitB] },
      "epss:start": { findings: [exploitB, epssC] },
    }));

    const result = await new InspectorFindingsScanner({ maxFindings: 5, concurrency: 1 }).scan(ctx);

    expect(result.dataSource).toBe("inspector2");
    expect(result.findings).toHaveLength(5);
    const ids = result.findings.map((f) => f.sourceFindingId);
    expect(ids).toEqual(expect.arrayContaining(["f/exploit-a", "f/exploit-b", "f/epss-c"]));
    expect(new Set(ids).size).toBe(5);
    expect(result.warnings).toContain("Inspector returned more than 5 findings; truncated (signal findings kept)");

    const epssCall = mockSend.mock.calls.map((c) => c[0]).find((c) => c.input?.filterCriteria?.epssScore);
    expect(epssCall.input.filterCriteria.epssScore[0].lowerInclusive).toBe(0.01);
  });

  it("does not let exploit/EPSS overlap consume the signal budget (Codex fix round 1)", async () => {
    // 5 unique signal findings with maxFindings=5; exploit-1 is returned by both
    // signal queries. The EPSS-only finding must survive and no plain one fill in.
    const plain = Array.from({ length: 5 }, (_, i) => insFinding({ arn: `f/plain-${i + 1}` }));
    const exploit = [1, 2, 3, 4].map((i) =>
      insFinding({ arn: `f/exploit-${i}`, exploit: "YES", epss: i <= 2 ? 0.02 : undefined }));
    const epssOnly = insFinding({ arn: "f/epss-only-5", epss: 0.02 });
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": { findings: plain, nextToken: "more" },
      "exploit:start": { findings: exploit },
      "epss:start": { findings: [exploit[0], epssOnly] },
    }));

    const result = await new InspectorFindingsScanner({ maxFindings: 5, concurrency: 1 }).scan(ctx);

    expect(result.findings.map((f) => f.sourceFindingId).sort()).toEqual(
      ["f/epss-only-5", "f/exploit-1", "f/exploit-2", "f/exploit-3", "f/exploit-4"]);
    expect(result.warnings).toContain("Inspector returned more than 5 findings; truncated (signal findings kept)");
    expect(result.warnings).not.toContain(
      "Inspector signal findings (exploit/EPSS) exceed 5; signal subset also truncated");
  });

  it("does not run the signal queries when under the cap", async () => {
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": { findings: [insFinding({ arn: "f/1", exploit: "YES" })] },
    }));
    await new InspectorFindingsScanner({ maxFindings: 5 }).scan(ctx);
    const inputs = mockSend.mock.calls.map((c) => c[0].input?.filterCriteria).filter(Boolean);
    expect(inputs.some((fc) => fc.exploitAvailable || fc.epssScore)).toBe(false);
  });

  it("honours epssThresholds overrides", async () => {
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": { findings: [insFinding({ arn: "f/1", epss: 0.05 })] },
    }));
    const result = await new InspectorFindingsScanner({ epssThresholds: { high: 0.04, medium: 0.001 } }).scan(ctx);
    expect(result.findings[0].exploitability).toMatchObject({ epssLevel: "high", priority: "P2", rationaleCode: "EPSS_HIGH" });
  });

  it("makes no network call for KEV by default", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    mockSend.mockImplementation(dispatch({}));
    await new InspectorFindingsScanner().scan(ctx);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("only sends read-only Inspector commands", async () => {
    mockSend.mockImplementation(dispatch({
      "AWS_EC2_INSTANCE:start": { findings: [insFinding({ arn: "f/1" })] },
    }));
    await new InspectorFindingsScanner().scan(ctx);
    for (const c of mockSend.mock.calls) {
      expect(c[0].constructor.name).toMatch(/^(Describe|List|Get|BatchGet)/);
    }
  });
});

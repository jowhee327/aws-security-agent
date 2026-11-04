/**
 * T6 — prioritize_vulnerabilities MCP tool (plan §2.10).
 * All AWS calls go through the mocked aws-client (fake account, no network).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws-cn"),
  getIamRegion: vi.fn().mockReturnValue("cn-north-1"),
}));
const mockSend = vi.fn();

import { createServer } from "../../src/index.js";
import {
  prioritizeVulnerabilities,
  DEFAULT_PRIORITIZE_LIMIT,
  MAX_PRIORITIZE_LIMIT,
  type PrioritizeResult,
} from "../../src/tools/prioritize-vulnerabilities.js";
import type { ScanContext } from "../../src/types.js";

const ACCOUNT = "123456789012";
const REGION = "cn-north-1";
// CVE-2026-31431 is in the bundled KEV snapshot; the CVE-2026-43xxx IDs used here are not.
const KEV_CVE = "CVE-2026-31431";

function newCtx(): ScanContext {
  // Fresh object per call: the reachability resolver cache is keyed by ctx identity.
  return { region: REGION, partition: "aws-cn", accountId: ACCOUNT };
}

type Cmd = { constructor: { name: string }; input: Record<string, any> };

const ENABLED_STATUS = {
  accounts: [{ accountId: ACCOUNT, state: { status: "ENABLED" }, resourceState: {} }],
};

function insFinding(o: {
  arn: string;
  cve: string;
  type?: string;
  id?: string;
  severity?: string;
  score?: number;
  exploit?: "YES" | "NO";
  epss?: number;
  fix?: "YES" | "NO";
}) {
  return {
    findingArn: `arn:aws-cn:inspector2:${REGION}:${ACCOUNT}:finding/${o.arn}`,
    awsAccountId: ACCOUNT,
    type: "PACKAGE_VULNERABILITY",
    title: `${o.cve} - pkg`,
    description: `${o.cve} description`,
    severity: o.severity ?? "HIGH",
    status: "ACTIVE",
    inspectorScore: o.score ?? 7.5,
    exploitAvailable: o.exploit ?? "NO",
    fixAvailable: o.fix,
    epss: o.epss === undefined ? undefined : { score: o.epss },
    resources: [{ type: o.type ?? "AWS_EC2_INSTANCE", id: o.id ?? "i-open", partition: "aws-cn", region: REGION }],
    packageVulnerabilityDetails: {
      vulnerabilityId: o.cve,
      source: "NVD",
      vulnerablePackages: [{ name: "pkg", version: "1.0.0", fixedInVersion: "1.0.1" }],
      referenceUrls: [],
    },
  };
}

const ECR_IDLE = `arn:aws-cn:ecr:${REGION}:${ACCOUNT}:repository/app/sha256:cccc3333`;

/** One partition page per resource type; covers every priority rule bucket we assert on. */
const INSPECTOR_PAGES: Record<string, unknown[]> = {
  AWS_EC2_INSTANCE: [
    // P0 EXPLOIT_INTERNET: exploit + 0.0.0.0/0
    insFinding({ arn: "open-exploit", cve: "CVE-2026-43001", id: "i-open", exploit: "YES", score: 8.1, fix: "YES" }),
    // P0 KEV on a deployed (allow-listed) instance
    insFinding({ arn: "allow-kev", cve: KEV_CVE, id: "i-allow", score: 7.0 }),
    // P1 EXPLOIT_ALLOWLIST
    insFinding({ arn: "allow-exploit", cve: "CVE-2026-43002", id: "i-allow", exploit: "YES", score: 9.8, severity: "CRITICAL" }),
    // P2 EPSS_MEDIUM
    insFinding({ arn: "open-epss", cve: "CVE-2026-43003", id: "i-open", epss: 0.03, score: 6.0, severity: "MEDIUM" }),
    // P3 BASELINE (CRITICAL severity but no signal)
    insFinding({ arn: "allow-base", cve: "CVE-2026-43004", id: "i-allow", score: 9.9, severity: "CRITICAL" }),
  ],
  AWS_ECR_CONTAINER_IMAGE: [
    // P1 KEV_NOT_RUNNING: image not in any running ECS task, no EKS clusters
    insFinding({ arn: "ecr-kev", cve: KEV_CVE, type: "AWS_ECR_CONTAINER_IMAGE", id: ECR_IDLE, score: 9.0 }),
  ],
};

const INSTANCES = [
  { id: "i-open", ip: "52.80.1.3", sg: "sg-world" },
  { id: "i-allow", ip: "52.80.1.1", sg: "sg-allow" },
];
const SGS = [
  { GroupId: "sg-world", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }] },
  { GroupId: "sg-allow", IpPermissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "203.0.113.10/32" }] }] },
];
const NACL = {
  NetworkAclId: "acl-open",
  Associations: [{ SubnetId: "subnet-a" }],
  Entries: [{ RuleNumber: 100, Protocol: "-1", RuleAction: "allow", Egress: false, CidrBlock: "0.0.0.0/0" }],
};

function asffFinding(o: { id: string; cve?: string; product?: string; exploit?: "YES" | "NO"; resource?: string; type?: string }) {
  return {
    Id: o.id,
    AwsAccountId: ACCOUNT,
    Region: REGION,
    Title: o.cve ? `${o.cve} - pkg` : "S3 bucket should block public access",
    Description: "desc",
    ProductName: o.product ?? "Inspector",
    GeneratorId: "AWSInspector",
    Severity: { Label: "HIGH" },
    Resources: [{ Id: o.resource ?? `arn:aws-cn:ec2:${REGION}:${ACCOUNT}:instance/i-open`, Type: o.type ?? "AwsEc2Instance" }],
    ...(o.cve ? { Vulnerabilities: [{ Id: o.cve, ExploitAvailable: o.exploit ?? "NO" }] } : {}),
  };
}

interface DispatchOpts {
  /** ListFindings throws AccessDeniedException → Security Hub fallback. */
  listDenied?: boolean;
}

function dispatch(opts: DispatchOpts = {}) {
  return async (cmd: Cmd) => {
    const name = cmd.constructor.name;
    switch (name) {
      case "BatchGetAccountStatusCommand":
        return ENABLED_STATUS;
      case "ListFindingsCommand": {
        if (opts.listDenied) {
          const e = new Error("not authorized to perform inspector2:ListFindings");
          e.name = "AccessDeniedException";
          throw e;
        }
        if (cmd.input.nextToken) return { findings: [] };
        const t = cmd.input.filterCriteria?.resourceType?.[0]?.value as string | undefined;
        return { findings: (t && INSPECTOR_PAGES[t]) ?? [] };
      }
      case "GetFindingsCommand":
        return {
          Findings: [
            asffFinding({ id: "sh-exploit", cve: "CVE-2026-43010", exploit: "YES" }),
            asffFinding({ id: "sh-kev", cve: KEV_CVE, resource: `arn:aws-cn:ec2:${REGION}:${ACCOUNT}:instance/i-allow` }),
            asffFinding({ id: "sh-fsbp", product: "Security Hub", resource: "arn:aws-cn:s3:::bucket", type: "AwsS3Bucket" }),
          ],
        };
      case "DescribeInstancesCommand": {
        const ids: string[] = cmd.input.Filters?.[0]?.Values ?? cmd.input.InstanceIds ?? [];
        return {
          Reservations: [{
            Instances: INSTANCES.filter((i) => ids.includes(i.id)).map((i) => ({
              InstanceId: i.id,
              State: { Name: "running" },
              PublicIpAddress: i.ip,
              SubnetId: "subnet-a",
              SecurityGroups: [{ GroupId: i.sg }],
              NetworkInterfaces: [{
                NetworkInterfaceId: `eni-${i.id}`,
                SubnetId: "subnet-a",
                Attachment: { DeviceIndex: 0 },
                Association: { PublicIp: i.ip },
                Groups: [{ GroupId: i.sg }],
              }],
            })),
          }],
        };
      }
      case "DescribeSecurityGroupsCommand": {
        const ids: string[] = cmd.input.Filters?.[0]?.Values ?? cmd.input.GroupIds ?? [];
        return { SecurityGroups: SGS.filter((s) => ids.includes(s.GroupId)) };
      }
      case "DescribeNetworkAclsCommand":
        return { NetworkAcls: [NACL] };
      case "ListClustersCommand":
        // Same command name in ECS and EKS: no clusters in either.
        return { clusterArns: [], clusters: [] };
      default:
        if (/^(Describe|List|Get|BatchGet)/.test(name)) return {};
        throw new Error(`unexpected command ${name}`);
    }
  };
}

function sentCommands(): string[] {
  return mockSend.mock.calls.map((c) => (c[0] as Cmd).constructor.name);
}

const PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 } as const;

function expectSorted(r: PrioritizeResult): void {
  for (let i = 1; i < r.items.length; i++) {
    expect(PRIORITY_RANK[r.items[i - 1].priority]).toBeLessThanOrEqual(PRIORITY_RANK[r.items[i].priority]);
  }
}

beforeEach(() => {
  mockSend.mockReset();
  mockSend.mockImplementation(dispatch());
});

afterEach(() => {
  // Read-only product: every AWS call must be Describe/List/Get/BatchGet.
  for (const name of sentCommands()) expect(name).toMatch(/^(Describe|List|Get|BatchGet)/);
});

describe("prioritizeVulnerabilities", () => {
  it("defaults to P0+P1, ordered by priority then riskScore, with every item field", async () => {
    const r = await prioritizeVulnerabilities(newCtx());
    expect(r.dataSource).toBe("inspector2");
    expect(r.items.map((i) => `${i.priority}:${i.cveId}:${i.resourceId}`)).toEqual([
      "P0:CVE-2026-43001:i-open",
      `P0:${KEV_CVE}:i-allow`,
      "P1:CVE-2026-43002:i-allow", // inspectorScore 9.8 ranks above the 9.0 one within P1
      `P1:${KEV_CVE}:${ECR_IDLE}`,
    ]);
    expectSorted(r);
    expect(r.matched).toBe(4);
    expect(r.truncated).toBe(false);

    const first = r.items[0];
    expect(first).toMatchObject({
      cveId: "CVE-2026-43001",
      priority: "P0",
      rationaleCode: "EXPLOIT_INTERNET",
      resourceType: "AwsEc2Instance",
      resourceId: "i-open",
      severity: "HIGH",
      exploitAvailable: true,
      epss: null,
      kev: false,
      reachability: "internet_open",
      fixAvailable: "YES",
    });
    expect(typeof first.rationale).toBe("string");
    for (const item of r.items) {
      for (const k of ["cveId", "priority", "rationale", "resourceType", "resourceId", "severity", "exploitAvailable", "epss", "kev", "reachability"]) {
        expect(item, `item has ${k}`).toHaveProperty(k);
      }
    }
    expect(r.items.find((i) => i.resourceId === ECR_IDLE)!.reachability).toBe("not_running");
    expect(r.items.find((i) => i.cveId === "CVE-2026-43002")!.reachability).toBe("allowlist");

    // Funnel covers every assessed finding, not only the returned priorities.
    expect(r.funnel.total).toEqual({ findings: 6, cves: 5 });
    expect(r.funnel.byPriority).toEqual({ P0: 2, P1: 2, P2: 1, P3: 1 });
    expect(r.funnel.kev).toEqual({ findings: 2, cves: 1 });
    expect(r.kevSnapshotDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(r.kevSnapshotDate).toBe(r.funnel.kevSnapshotDate);
    expect(r.disclaimer).toContain("NOT penetration testing");
  });

  it("filters by priorities and resource_type", async () => {
    const all = await prioritizeVulnerabilities(newCtx(), { priorities: ["P2", "P3"] });
    expect(all.items.map((i) => i.priority)).toEqual(["P2", "P3"]);

    const ecr = await prioritizeVulnerabilities(newCtx(), { resourceType: "ecr", priorities: ["P0", "P1", "P2", "P3"] });
    expect(ecr.items).toHaveLength(1);
    expect(ecr.items[0].resourceType).toBe("AwsEcrContainerImage");
    expect(ecr.funnel.total.findings).toBe(1);

    const lambda = await prioritizeVulnerabilities(newCtx(), { resourceType: "lambda" });
    expect(lambda.items).toEqual([]);
  });

  it("limit truncates (truncated:true) and is clamped to the 1..200 range", async () => {
    const r = await prioritizeVulnerabilities(newCtx(), { limit: 1 });
    expect(r.items).toHaveLength(1);
    expect(r.items[0].cveId).toBe("CVE-2026-43001");
    expect(r.matched).toBe(4);
    expect(r.truncated).toBe(true);

    const big = await prioritizeVulnerabilities(newCtx(), { limit: 10_000, priorities: ["P0", "P1", "P2", "P3"] });
    expect(big.items).toHaveLength(6);
    expect(big.truncated).toBe(false);
    expect(DEFAULT_PRIORITIZE_LIMIT).toBe(20);
    expect(MAX_PRIORITIZE_LIMIT).toBe(200);
  });

  it("include_reachability:false sends no reachability calls and leaves every item unknown", async () => {
    const r = await prioritizeVulnerabilities(newCtx(), { includeReachability: false, priorities: ["P0", "P1", "P2", "P3"] });
    expect(sentCommands().every((n) => /^(BatchGetAccountStatus|ListFindings)Command$/.test(n))).toBe(true);
    for (const i of r.items) expect(i.reachability).toBe("unknown");
    // Without reachability only KEV can reach P0 (unknown ≠ not_running).
    expect(r.items.filter((i) => i.priority === "P0").every((i) => i.kev)).toBe(true);
  });

  it("falls back to the Security Hub Inspector subset when ListFindings is denied", async () => {
    mockSend.mockImplementation(dispatch({ listDenied: true }));
    const r = await prioritizeVulnerabilities(newCtx());
    expect(r.dataSource).toBe("securityhub");
    expect(sentCommands()).toContain("GetFindingsCommand");
    expect(r.items.map((i) => `${i.priority}:${i.cveId}`)).toEqual([
      "P0:CVE-2026-43010", // exploit + i-open internet_open (reachability resolved in fallback)
      `P0:${KEV_CVE}`,
    ]);
    expect(r.items[0].reachability).toBe("internet_open");
    // Non-Inspector Security Hub findings are never included.
    expect(r.funnel.total.findings).toBe(2);
    expect(r.warnings?.some((w) => w.includes("Grant inspector2:ListFindings"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MCP layer
// ---------------------------------------------------------------------------

interface ToolResult { content: Array<{ text: string }>; isError?: boolean }

async function connect() {
  const server = createServer(REGION);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "t6-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, args: Record<string, unknown>): Promise<ToolResult> {
  return (await client.callTool({ name: "prioritize_vulnerabilities", arguments: args })) as unknown as ToolResult;
}

describe("prioritize_vulnerabilities MCP tool", () => {
  it("has the plan §2.10 schema", async () => {
    const { client, close } = await connect();
    try {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === "prioritize_vulnerabilities");
      expect(tool).toBeDefined();
      expect(tool!.description).toMatch(/not penetration testing/i);
      const props = tool!.inputSchema.properties as Record<string, any>;
      expect(Object.keys(props).sort()).toEqual(
        ["include_reachability", "limit", "priorities", "provider", "region", "resource_type"],
      );
      expect(tool!.inputSchema.required ?? []).toEqual([]);
      expect(props.priorities.type).toBe("array");
      expect(props.priorities.items.enum).toEqual(["P0", "P1", "P2", "P3"]);
      expect(props.priorities.description).toContain('["P0","P1"]');
      expect(props.limit.type).toBe("integer");
      expect(props.limit.maximum).toBe(200);
      expect(props.limit.description).toContain("default: 20");
      expect(props.resource_type.enum).toEqual(["ec2", "ecr", "lambda"]);
      expect(props.include_reachability.type).toBe("boolean");
      expect(props.provider.enum).toEqual(["aws", "huaweicloud"]);
    } finally {
      await close();
    }
  });

  it("returns a summary + JSON payload sorted by priority (defaults P0/P1, limit 20)", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, {});
      expect(res.isError).toBeFalsy();
      expect(res.content[0].text).toContain("P0 2, P1 2, P2 1, P3 1");
      const json = JSON.parse(res.content[1].text) as PrioritizeResult;
      for (const k of ["funnel", "kevSnapshotDate", "disclaimer", "items", "truncated"]) expect(json).toHaveProperty(k);
      expect(json.accountId).toBe(ACCOUNT);
      expect(json.region).toBe(REGION);
      expect(json.items.map((i) => i.priority)).toEqual(["P0", "P0", "P1", "P1"]);
      expectSorted(json);
    } finally {
      await close();
    }
  });

  it("rejects limit > 200", async () => {
    const { client, close } = await connect();
    try {
      let rejected = false;
      try {
        const res = await call(client, { limit: 201 });
        rejected = res.isError === true;
      } catch {
        rejected = true;
      }
      expect(rejected).toBe(true);
      expect(sentCommands()).toEqual([]);
    } finally {
      await close();
    }
  });

  it('errors for provider "huaweicloud" without any cloud call', async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, { provider: "huaweicloud" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("AWS-only");
      expect(sentCommands()).toEqual([]);
    } finally {
      await close();
    }
  });
});

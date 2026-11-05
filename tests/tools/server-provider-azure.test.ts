/**
 * MCP tool layer — provider module aliases on individual scanner tools + Azure list_org_accounts.
 *  - scan_security_hub_findings resolves the provider alias (azure -> defender_assessment_findings,
 *    huaweicloud -> rms_compliance_findings, alicloud -> config_compliance_findings); aws unchanged.
 *  - list_org_accounts returns an Azure-specific multi-subscription message.
 * The runner and the provider registry are mocked: nothing touches any cloud.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const mocks = vi.hoisted(() => {
  const scanners = new Map<string, { moduleName: string; scan: ReturnType<typeof vi.fn> }>();
  const makeScanners = (provider: string, modules: string[]) =>
    modules.map((moduleName) => {
      const s = {
        moduleName,
        scan: vi.fn(async (ctx: { region: string }) => ({
          module: moduleName,
          status: "success",
          resourcesScanned: 1,
          findingsCount: 0,
          scanTimeMs: 1,
          findings: [],
          warnings: [`scanned ${ctx.region}`],
        })),
      };
      scanners.set(`${provider}:${moduleName}`, s);
      return s;
    });
  return {
    scanners,
    makeScanners,
    buildScanContext: vi.fn(async (region: string, provider: string = "aws") =>
      provider === "aws"
        ? { region, partition: "aws", accountId: "123456789012" }
        : { region, partition: provider, accountId: "1234567890123456", provider }),
  };
});

vi.mock("../../src/scanners/runner.js", () => ({
  runAllScanners: vi.fn(),
  runMultiAccountScanners: vi.fn(),
  buildScanContext: mocks.buildScanContext,
  HUAWEI_ALL_REGIONS: "all",
}));

// AWS scanners are the built-in set (not the registry): stub Security Hub so the aws path is observable.
vi.mock("../../src/scanners/security-hub-findings.js", () => ({
  SecurityHubFindingsScanner: class {
    moduleName = "security_hub_findings";
    scan = mocks.makeScanners("aws", ["security_hub_findings"])[0].scan;
  },
}));

vi.mock("../../src/providers/registry.js", () => {
  const providers: Record<string, { id: string; scanners: () => unknown[] }> = {
    aws: { id: "aws", scanners: () => [] },
    huaweicloud: { id: "huaweicloud", scanners: () => mocks.makeScanners("huaweicloud", ["rms_compliance_findings", "service_detection"]) },
    alicloud: { id: "alicloud", scanners: () => mocks.makeScanners("alicloud", ["config_compliance_findings", "service_detection"]) },
    azure: { id: "azure", scanners: () => mocks.makeScanners("azure", ["defender_assessment_findings", "service_detection"]) },
  };
  return {
    DEFAULT_PROVIDER_ID: "aws",
    isProviderId: (id: string) => id in providers,
    listProviderIds: () => ["aws", "huaweicloud", "alicloud", "azure"],
    getProvider: (id: string = "aws") => {
      const p = providers[id];
      if (!p) throw new Error(`Unknown cloud provider "${id}"`);
      return p;
    },
  };
});

import { createServer } from "../../src/index.js";

interface ToolResult { content: Array<{ text: string }>; isError?: boolean }

async function connect(): Promise<{ client: Client; close: () => Promise<void> }> {
  const server = createServer("us-east-1");
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "azure-tool-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

const ALL_HUB_MODULES = [
  "aws:security_hub_findings",
  "huaweicloud:rms_compliance_findings",
  "alicloud:config_compliance_findings",
  "azure:defender_assessment_findings",
];

function expectOnlyScanned(key: string): void {
  expect(mocks.scanners.get(key)?.scan, key).toHaveBeenCalledTimes(1);
  // Scanner sets are built lazily per provider; an unbuilt provider's scanner cannot have run.
  for (const k of ALL_HUB_MODULES.filter((m) => m !== key)) {
    const s = mocks.scanners.get(k);
    if (s) expect(s.scan, k).not.toHaveBeenCalled();
  }
}

describe("MCP tools — scan_security_hub_findings resolves provider module aliases", () => {
  beforeEach(() => {
    mocks.buildScanContext.mockClear();
    for (const s of mocks.scanners.values()) s.scan.mockClear();
  });

  it.each([
    ["azure", "azure:defender_assessment_findings", "defender_assessment_findings"],
    ["huaweicloud", "huaweicloud:rms_compliance_findings", "rms_compliance_findings"],
    ["alicloud", "alicloud:config_compliance_findings", "config_compliance_findings"],
  ])("provider %s runs its aliased module", async (provider, key, module) => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_security_hub_findings", { provider });
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("all", provider);
      expectOnlyScanned(key);
      expect(JSON.parse(res.content[1].text).module).toBe(module);
    } finally {
      await close();
    }
  });

  it.each([[undefined], ["aws"]])("provider %s still runs security_hub_findings unchanged", async (provider) => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_security_hub_findings", provider ? { provider } : {});
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("us-east-1", "aws");
      expectOnlyScanned("aws:security_hub_findings");
      expect(JSON.parse(res.content[1].text).module).toBe("security_hub_findings");
    } finally {
      await close();
    }
  });

  it("non-aliased tools are unaffected for azure (missing module -> unavailable error with the raw name)", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_guardduty_findings", { provider: "azure" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain('module "guardduty_findings" is not available for provider "azure"');
      expect(mocks.buildScanContext).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

describe("MCP tools — list_org_accounts for azure", () => {
  it("returns an Azure-specific multi-subscription message", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_org_accounts", { provider: "azure" });
      expect(res.isError).toBe(true);
      const text = res.content[0].text;
      expect(text).toContain('not supported for provider "azure"');
      expect(text).toContain("every subscription visible to the service principal");
      expect(text).toContain("subscription ID");
      expect(text).not.toMatch(/Huawei|Phase 2|assumeAgency/);
    } finally {
      await close();
    }
  });

  it("keeps the existing huaweicloud text byte-identical", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_org_accounts", { provider: "huaweicloud" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toBe(
        `Error: list_org_accounts is not supported for provider "huaweicloud" yet (Huawei Cloud multi-account via Organizations + STS assumeAgency is planned for Phase 2).`,
      );
    } finally {
      await close();
    }
  });

  it("returns an Alibaba Cloud-specific single-account message for alicloud", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_org_accounts", { provider: "alicloud" });
      expect(res.isError).toBe(true);
      const text = res.content[0].text;
      expect(text).toContain('not supported for provider "alicloud"');
      expect(text).toContain("not supported in this release");
      expect(text).not.toMatch(/Huawei|Phase 2|assumeAgency/);
    } finally {
      await close();
    }
  });
});

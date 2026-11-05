/**
 * Phase 2 — MCP tool layer: the Alibaba-only `scan_config_compliance_findings` tool.
 *  - Registered when a provider ships `config_compliance_findings`; provider defaults to alicloud.
 *  - Providers whose scanner set lacks the module (aws, huaweicloud) get an error result.
 * The runner and the provider registry are mocked: nothing touches any cloud (EXPERIMENTAL provider).
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

vi.mock("../../src/providers/registry.js", () => {
  const providers: Record<string, { id: string; scanners: () => unknown[] }> = {
    aws: { id: "aws", scanners: () => [] },
    huaweicloud: { id: "huaweicloud", scanners: () => mocks.makeScanners("huaweicloud", ["rms_compliance_findings", "service_detection"]) },
    alicloud: { id: "alicloud", scanners: () => mocks.makeScanners("alicloud", ["config_compliance_findings", "service_detection"]) },
  };
  return {
    DEFAULT_PROVIDER_ID: "aws",
    isProviderId: (id: string) => id in providers,
    listProviderIds: () => ["aws", "huaweicloud", "alicloud"],
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
  const client = new Client({ name: "alicloud-tool-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

describe("MCP tools — scan_config_compliance_findings (Alibaba Cloud, experimental)", () => {
  beforeEach(() => {
    mocks.buildScanContext.mockClear();
    for (const s of mocks.scanners.values()) s.scan.mockClear();
  });

  it("is registered with an optional provider param", async () => {
    const { client, close } = await connect();
    try {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === "scan_config_compliance_findings");
      expect(tool).toBeDefined();
      expect(tool!.description).toContain("Config Compliance Findings (Alibaba Cloud");
      const providerProp = (tool!.inputSchema.properties as Record<string, { enum?: string[] }>).provider;
      expect(providerProp.enum).toEqual(["aws", "huaweicloud", "alicloud"]);
      expect(tool!.inputSchema.required ?? []).not.toContain("provider");
      // The Huawei-only RMS tool is still registered alongside it.
      expect(tools.some((t) => t.name === "scan_rms_compliance_findings")).toBe(true);
    } finally {
      await close();
    }
  });

  it("defaults to alicloud (only provider with the module)", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_config_compliance_findings", {});
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("all", "alicloud");
      expect(mocks.scanners.get("alicloud:config_compliance_findings")!.scan).toHaveBeenCalledTimes(1);
    } finally {
      await close();
    }
  });

  it("returns an error result for providers without the module (aws, huaweicloud)", async () => {
    const { client, close } = await connect();
    try {
      for (const provider of ["aws", "huaweicloud"]) {
        const res = await call(client, "scan_config_compliance_findings", { provider });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toContain(`module "config_compliance_findings" is not available for provider "${provider}"`);
      }
      expect(mocks.buildScanContext).not.toHaveBeenCalled();
      expect(mocks.scanners.get("alicloud:config_compliance_findings")!.scan).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it("list_modules describes config_compliance_findings for alicloud", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_modules", { provider: "alicloud" });
      expect(res.isError).toBeFalsy();
      expect(res.content.map((c) => c.text).join("\n")).toContain("Alibaba Cloud only: Config compliance findings");
    } finally {
      await close();
    }
  });
});

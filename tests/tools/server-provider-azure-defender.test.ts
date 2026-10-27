/**
 * Phase 2 (Azure) T8 — MCP tool layer: the Azure-only `scan_defender_assessment_findings` tool.
 *  - Registered when a provider ships `defender_assessment_findings`; provider defaults to azure.
 *  - Providers whose scanner set lacks the module (aws, huaweicloud, alicloud) get an error result.
 *  - The provider param lists azure and carries the EXPERIMENTAL / China-default note.
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
        : { region, partition: provider, accountId: "00000000-0000-0000-0000-00000000fake", provider }),
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
    azure: {
      id: "azure",
      scanners: () => mocks.makeScanners("azure", ["defender_assessment_findings", "disk_encryption_findings", "service_detection"]),
    },
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
  const client = new Client({ name: "azure-defender-tool-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

describe("MCP tools — scan_defender_assessment_findings (Azure, experimental)", () => {
  beforeEach(() => {
    mocks.buildScanContext.mockClear();
    for (const s of mocks.scanners.values()) s.scan.mockClear();
  });

  it("is registered with an optional provider param that lists azure with the experimental note", async () => {
    const { client, close } = await connect();
    try {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === "scan_defender_assessment_findings");
      expect(tool).toBeDefined();
      expect(tool!.description).toContain("Defender for Cloud Assessment Findings (Azure, experimental)");
      const providerProp = (tool!.inputSchema.properties as Record<string, { enum?: string[]; description?: string }>).provider;
      expect(providerProp.enum).toEqual(["aws", "huaweicloud", "alicloud", "azure"]);
      expect(tool!.inputSchema.required ?? []).not.toContain("provider");
      const desc = providerProp.description ?? "";
      expect(desc).toContain(
        "With azure (EXPERIMENTAL — not yet validated against a live account), the China cloud (21Vianet) is the default; set AZURE_CLOUD=global for public cloud. region is an Azure subscription ID; omit or \"all\" to scan every visible subscription.",
      );
      // Existing huaweicloud / alicloud wording is kept verbatim (appended, not rewritten).
      expect(desc.startsWith("Cloud provider to scan (default: aws). With huaweicloud, `region` is a Huawei Cloud region ID")).toBe(true);
      expect(desc).toContain(
        "With alicloud (EXPERIMENTAL — not yet validated against a live account), region is an Alibaba Cloud region ID (e.g. cn-hangzhou); omit or \"all\" to scan every region; single-account only in this phase.",
      );
      // The other provider-specific tools are still registered alongside it.
      expect(tools.some((t) => t.name === "scan_rms_compliance_findings")).toBe(true);
      expect(tools.some((t) => t.name === "scan_config_compliance_findings")).toBe(true);
    } finally {
      await close();
    }
  });

  it("defaults to azure (only provider with the module) and scans every subscription", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_defender_assessment_findings", {});
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("all", "azure");
      expect(mocks.scanners.get("azure:defender_assessment_findings")!.scan).toHaveBeenCalledTimes(1);
      expect(JSON.parse(res.content[1].text).module).toBe("defender_assessment_findings");
    } finally {
      await close();
    }
  });

  it("passes an explicit subscription ID through as region", async () => {
    const { client, close } = await connect();
    try {
      const sub = "22222222-2222-2222-2222-222222222222";
      const res = await call(client, "scan_defender_assessment_findings", { region: sub, provider: "azure" });
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith(sub, "azure");
    } finally {
      await close();
    }
  });

  it("returns an error result for providers without the module (aws, huaweicloud, alicloud)", async () => {
    const { client, close } = await connect();
    try {
      for (const provider of ["aws", "huaweicloud", "alicloud"]) {
        const res = await call(client, "scan_defender_assessment_findings", { provider });
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toContain(`module "defender_assessment_findings" is not available for provider "${provider}"`);
      }
      expect(mocks.buildScanContext).not.toHaveBeenCalled();
      expect(mocks.scanners.get("azure:defender_assessment_findings")!.scan).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it("list_modules describes the Azure-only modules", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_modules", { provider: "azure" });
      expect(res.isError).toBeFalsy();
      const text = res.content.map((c) => c.text).join("\n");
      expect(text).toContain("Azure only: Microsoft Defender for Cloud assessments");
      expect(text).toContain("Azure only: unencrypted managed disks");
    } finally {
      await close();
    }
  });
});

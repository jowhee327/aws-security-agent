/**
 * Phase 2 (Azure) T8 — acceptance at the MCP layer with the REAL provider registry:
 *  - `scan_all` with provider:"azure" hands the 12 Azure scanners to the runner (region
 *    "all" = every visible subscription unless a subscription ID is given).
 *  - Calls without `provider` are routed exactly as before (AWS scanner set, server region).
 *  - The Azure cloud defaults to China (21Vianet) when AZURE_CLOUD is unset.
 * Only the runner is mocked (no scan executes): nothing touches any cloud, no credentials.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const mocks = vi.hoisted(() => {
  const emptySummary = { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, modulesSuccess: 0, modulesError: 0 };
  const fakeResult = (scanners: Array<{ moduleName: string }>, region: string, provider?: string) => ({
    scanStart: "2026-10-27T00:00:00.000Z",
    scanEnd: "2026-10-27T00:00:01.000Z",
    region,
    accountId: provider === "azure" ? "00000000-0000-0000-0000-00000000fake" : "123456789012",
    ...(provider && provider !== "aws" ? { provider } : {}),
    modules: scanners.map((s) => ({ module: s.moduleName, status: "success", resourcesScanned: 0, findingsCount: 0, scanTimeMs: 0, findings: [] })),
    summary: { ...emptySummary, modulesSuccess: scanners.length },
  });
  return {
    runAllScanners: vi.fn(async (scanners: Array<{ moduleName: string }>, region: string, opts?: { provider?: string }) =>
      fakeResult(scanners, region, opts?.provider)),
    runMultiAccountScanners: vi.fn(async (scanners: Array<{ moduleName: string }>, region: string, opts: { provider?: string }) =>
      fakeResult(scanners, region, opts.provider)),
    buildScanContext: vi.fn(async (region: string) => ({ region, partition: "aws", accountId: "123456789012" })),
  };
});

vi.mock("../../src/scanners/runner.js", () => ({
  runAllScanners: mocks.runAllScanners,
  runMultiAccountScanners: mocks.runMultiAccountScanners,
  buildScanContext: mocks.buildScanContext,
  HUAWEI_ALL_REGIONS: "all",
}));

import { createServer } from "../../src/index.js";
import { getProvider } from "../../src/providers/registry.js";
import { DEFAULT_AZURE_CLOUD, resolveAzureCloud } from "../../src/providers/azure/index.js";

const AZURE_MODULES = [
  "config_rules_findings", "service_detection", "defender_assessment_findings", "public_access_verify",
  "secret_exposure", "disk_encryption_findings", "network_reachability", "idle_resources", "tag_compliance",
  "guardduty_findings", "inspector_findings", "iam_privilege_escalation",
];

const AWS_MODULES = [
  "service_detection", "secret_exposure", "ssl_certificate", "dns_dangling", "network_reachability",
  "iam_privilege_escalation", "public_access_verify", "tag_compliance", "idle_resources", "disaster_recovery",
  "security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings",
  "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings", "imdsv2_enforcement",
  "waf_coverage", "ecr_image_cve",
];

const AZURE_ENV = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLOUD", "AZURE_SUBSCRIPTION_ID"];

interface ToolResult { content: Array<{ text: string }>; isError?: boolean }

async function connect(): Promise<{ client: Client; close: () => Promise<void> }> {
  const server = createServer("us-east-1");
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "azure-scan-all-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

function moduleNames(c: unknown[]): string[] {
  return (c[0] as Array<{ moduleName: string }>).map((s) => s.moduleName);
}

describe("MCP scan_all — provider:'azure' (real registry, mocked runner)", () => {
  beforeEach(() => {
    // Blank every Azure env var: the test never sees (or needs) real credentials.
    for (const name of AZURE_ENV) vi.stubEnv(name, "");
    mocks.runAllScanners.mockClear();
    mocks.runMultiAccountScanners.mockClear();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("hands exactly the 12 Azure scanners to the runner with region 'all'", async () => {
    expect(getProvider("azure").scanners().map((s) => s.moduleName)).toEqual(AZURE_MODULES);
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_all", { provider: "azure" });
      expect(res.isError).toBeFalsy();
      expect(mocks.runAllScanners).toHaveBeenCalledTimes(1);
      const [, region, opts] = mocks.runAllScanners.mock.calls[0];
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(AZURE_MODULES);
      expect(region).toBe("all");
      expect(opts).toEqual({ provider: "azure" });
      expect(JSON.parse(res.content[1].text).provider).toBe("azure");
    } finally {
      await close();
    }
  });

  it("passes an explicit subscription ID through as region", async () => {
    const { client, close } = await connect();
    try {
      const sub = "22222222-2222-2222-2222-222222222222";
      await call(client, "scan_all", { provider: "azure", region: sub });
      expect(mocks.runAllScanners.mock.calls[0][1]).toBe(sub);
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toHaveLength(12);
    } finally {
      await close();
    }
  });

  it("scan_group aggregation resolves security_hub_findings to defender_assessment_findings for azure", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_group", { group: "aggregation", provider: "azure" });
      expect(res.isError).toBeFalsy();
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toContain("defender_assessment_findings");
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).not.toContain("security_hub_findings");
    } finally {
      await close();
    }
  });

  it("calls without provider keep the AWS scanner set and server region", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_all", {});
      expect(res.isError).toBeFalsy();
      const [, region, opts] = mocks.runAllScanners.mock.calls[0];
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(AWS_MODULES);
      expect(region).toBe("us-east-1");
      expect(opts).toEqual({ provider: "aws" });
      expect(JSON.parse(res.content[1].text).provider).toBeUndefined();
      expect(res.content[0].text).toContain("Scan complete for account 123456789012 in us-east-1");
    } finally {
      await close();
    }
  });

  it("defaults the Azure cloud to China (21Vianet)", () => {
    expect(DEFAULT_AZURE_CLOUD).toBe("china");
    expect(resolveAzureCloud()).toBe("china");
    const ctx = getProvider("azure").contextFor!({ region: "22222222-2222-2222-2222-222222222222" }, "00000000-0000-0000-0000-00000000fake");
    expect(ctx.cloud).toBe("china");
    expect(ctx.subscriptionId).toBe("22222222-2222-2222-2222-222222222222");
  });
});

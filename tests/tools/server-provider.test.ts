/**
 * T8 — MCP tool layer: `provider` parameter routing.
 *  - Tool schemas are identical to the pre-multicloud baseline (captured from `main`)
 *    except for the added optional `provider` field.
 *  - Default provider is aws; provider:"huaweicloud" routes to the Huawei scanner set.
 * The runner and the provider registry are mocked: nothing touches AWS or Huawei Cloud.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const HW_MODULES = [
  "config_rules_findings",
  "public_access_verify",
  "secret_exposure",
  "ssl_certificate",
  "idle_resources",
  "tag_compliance",
  "rms_compliance_findings",
  "service_detection",
];

const mocks = vi.hoisted(() => {
  const emptySummary = { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, modulesSuccess: 0, modulesError: 0 };
  const fakeResult = (scanners: Array<{ moduleName: string }>, region: string, provider?: string) => ({
    scanStart: "2026-09-13T00:00:00.000Z",
    scanEnd: "2026-09-13T00:00:01.000Z",
    region,
    accountId: provider === "huaweicloud" ? "d0m41n" : "123456789012",
    ...(provider === "huaweicloud" ? { provider } : {}),
    modules: scanners.map((s) => ({ module: s.moduleName, status: "success", resourcesScanned: 0, findingsCount: 0, scanTimeMs: 0, findings: [] })),
    summary: { ...emptySummary, modulesSuccess: scanners.length },
  });
  const hwScanners = new Map<string, { moduleName: string; scan: ReturnType<typeof vi.fn> }>();
  return {
    fakeResult,
    hwScanners,
    runAllScanners: vi.fn(async (scanners: Array<{ moduleName: string }>, region: string, opts?: { provider?: string }) =>
      fakeResult(scanners, region, opts?.provider)),
    runMultiAccountScanners: vi.fn(async (scanners: Array<{ moduleName: string }>, region: string, opts: { provider?: string }) =>
      fakeResult(scanners, region, opts.provider)),
    buildScanContext: vi.fn(async (region: string, provider: string = "aws") =>
      provider === "aws"
        ? { region, partition: "aws", accountId: "123456789012" }
        : { region, partition: "huaweicloud", accountId: "d0m41n", provider, projectId: "p-1", domainId: "d0m41n" }),
  };
});

vi.mock("../../src/scanners/runner.js", () => ({
  runAllScanners: mocks.runAllScanners,
  runMultiAccountScanners: mocks.runMultiAccountScanners,
  buildScanContext: mocks.buildScanContext,
  HUAWEI_ALL_REGIONS: "all",
}));

vi.mock("../../src/providers/registry.js", () => {
  const hwProvider = {
    id: "huaweicloud",
    scanners: () =>
      HW_MODULES.map((moduleName) => {
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
        mocks.hwScanners.set(moduleName, s);
        return s;
      }),
  };
  return {
    DEFAULT_PROVIDER_ID: "aws",
    isProviderId: (id: string) => id === "aws" || id === "huaweicloud",
    listProviderIds: () => ["aws", "huaweicloud"],
    getProvider: (id: string = "aws") => {
      if (id === "huaweicloud") return hwProvider;
      if (id === "aws") return { id: "aws", scanners: () => [] };
      throw new Error(`Unknown cloud provider "${id}"`);
    },
  };
});

import { createServer, providerFromEnv, type CreateServerOptions } from "../../src/index.js";

const AWS_MODULES = [
  "service_detection", "secret_exposure", "ssl_certificate", "dns_dangling", "network_reachability",
  "iam_privilege_escalation", "public_access_verify", "tag_compliance", "idle_resources", "disaster_recovery",
  "security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings",
  "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings", "imdsv2_enforcement",
  "waf_coverage", "ecr_image_cve",
];

interface ToolText { text: string }
interface ToolResult { content: ToolText[]; isError?: boolean }

async function connect(opts?: CreateServerOptions): Promise<{ client: Client; server: McpServer; close: () => Promise<void> }> {
  const server = createServer("us-east-1", opts);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "t8-test", version: "0.0.0" });
  await client.connect(clientTransport);
  return { client, server, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

function moduleNames(call: unknown[]): string[] {
  return (call[0] as Array<{ moduleName: string }>).map((s) => s.moduleName);
}

describe("MCP tools — provider parameter", () => {
  beforeEach(() => {
    mocks.runAllScanners.mockClear();
    mocks.runMultiAccountScanners.mockClear();
    mocks.buildScanContext.mockClear();
    for (const s of mocks.hwScanners.values()) s.scan.mockClear();
  });

  it("tool schemas equal the pre-multicloud baseline except for the optional provider field", async () => {
    const baseline = JSON.parse(readFileSync(join(__dirname, "..", "fixtures", "tool-schema-baseline.json"), "utf8")) as Array<{
      name: string; description: string; inputSchema: { type: string; properties?: Record<string, unknown>; required?: string[]; $schema?: string };
    }>;
    const { client, close } = await connect();
    try {
      const { tools } = await client.listTools();
      const byName = new Map(tools.map((t) => [t.name, t]));
      expect(baseline.length).toBe(35);
      for (const b of baseline) {
        const cur = byName.get(b.name);
        expect(cur, `tool ${b.name} still registered`).toBeDefined();
        expect(cur!.description).toBe(b.description);
        const schema = JSON.parse(JSON.stringify(cur!.inputSchema)) as typeof b.inputSchema;
        const props = { ...(schema.properties ?? {}) };
        const providerProp = props.provider as { type?: string; enum?: string[] } | undefined;
        if (providerProp) {
          expect(providerProp.enum).toEqual(["aws", "huaweicloud"]);
          expect(schema.required ?? []).not.toContain("provider");
          delete props.provider;
        }
        schema.properties = props;
        // Baseline tools that took no parameters were registered without a schema and
        // therefore carry no "$schema" key; adding the optional provider param introduces it.
        if (Object.keys(props).length === 0 && !b.inputSchema.$schema) delete schema.$schema;
        expect(schema, `schema of ${b.name}`).toEqual(b.inputSchema);
      }
      // Every scan tool now accepts provider; the only additional tool is the Huawei-only RMS one.
      const extra = tools.map((t) => t.name).filter((n) => !baseline.some((b) => b.name === n));
      expect(extra).toEqual(["scan_rms_compliance_findings"]);
      for (const t of tools) {
        if (t.name.startsWith("scan_") || t.name === "detect_services" || t.name === "list_modules" || t.name === "list_org_accounts") {
          expect((t.inputSchema.properties as Record<string, unknown>).provider, `${t.name} has provider`).toBeDefined();
        }
      }
    } finally {
      await close();
    }
  });

  it("scan_all defaults to aws with the server region and the full AWS scanner set", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_all", {});
      expect(res.isError).toBeFalsy();
      expect(mocks.runAllScanners).toHaveBeenCalledTimes(1);
      const [, region, opts] = mocks.runAllScanners.mock.calls[0];
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(AWS_MODULES);
      expect(region).toBe("us-east-1");
      expect(opts).toEqual({ provider: "aws" });
      const parsed = JSON.parse(res.content[1].text);
      expect(parsed.provider).toBeUndefined();
      expect(res.content[0].text).toContain("Scan complete for account 123456789012 in us-east-1");
    } finally {
      await close();
    }
  });

  it("scan_all provider:'aws' is routed identically to the default", async () => {
    const { client, close } = await connect();
    try {
      const a = await call(client, "scan_all", { region: "cn-north-1" });
      const b = await call(client, "scan_all", { region: "cn-north-1", provider: "aws" });
      expect(b).toEqual(a);
      expect(mocks.runAllScanners.mock.calls[1][1]).toBe("cn-north-1");
      expect(mocks.runAllScanners.mock.calls[1][2]).toEqual({ provider: "aws" });
    } finally {
      await close();
    }
  });

  it("scan_all provider:'huaweicloud' uses the Huawei scanner set and 'all' regions when region is omitted", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_all", { provider: "huaweicloud" });
      expect(res.isError).toBeFalsy();
      const [, region, opts] = mocks.runAllScanners.mock.calls[0];
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(HW_MODULES);
      expect(region).toBe("all");
      expect(opts).toEqual({ provider: "huaweicloud" });
      expect(JSON.parse(res.content[1].text).provider).toBe("huaweicloud");

      await call(client, "scan_all", { provider: "huaweicloud", region: "cn-north-4" });
      expect(mocks.runAllScanners.mock.calls[1][1]).toBe("cn-north-4");
    } finally {
      await close();
    }
  });

  it("scan_all org_mode with huaweicloud goes through runMultiAccountScanners with the provider", async () => {
    const { client, close } = await connect();
    try {
      await call(client, "scan_all", { provider: "huaweicloud", org_mode: true, region: "cn-north-4" });
      expect(mocks.runMultiAccountScanners).toHaveBeenCalledTimes(1);
      const [, region, opts] = mocks.runMultiAccountScanners.mock.calls[0];
      expect(region).toBe("cn-north-4");
      expect(opts).toEqual({ orgMode: true, roleName: "AWSSecurityMCPAudit", accountIds: undefined, provider: "huaweicloud" });
    } finally {
      await close();
    }
  });

  it("scan_<module> with provider:'huaweicloud' runs the Huawei scanner with a Huawei context", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_secret_exposure", { provider: "huaweicloud", region: "cn-north-4" });
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("cn-north-4", "huaweicloud");
      const hw = mocks.hwScanners.get("secret_exposure")!;
      expect(hw.scan).toHaveBeenCalledTimes(1);
      expect(hw.scan.mock.calls[0][0]).toMatchObject({ provider: "huaweicloud", projectId: "p-1", domainId: "d0m41n" });
      const parsed = JSON.parse(res.content[1].text);
      expect(parsed.module).toBe("secret_exposure");
      expect(parsed.warnings).toEqual(["scanned cn-north-4"]);
    } finally {
      await close();
    }
  });

  it("scan_<module> for a module the provider lacks returns an error result, not an exception", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_dns_dangling", { provider: "huaweicloud" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain('module "dns_dangling" is not available for provider "huaweicloud"');
      expect(res.content[0].text).toContain("rms_compliance_findings");
      expect(mocks.buildScanContext).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it("scan_rms_compliance_findings defaults to huaweicloud (only provider with the module) and errors for aws", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_rms_compliance_findings", {});
      expect(res.isError).toBeFalsy();
      expect(mocks.buildScanContext).toHaveBeenCalledWith("all", "huaweicloud");
      expect(mocks.hwScanners.get("rms_compliance_findings")!.scan).toHaveBeenCalledTimes(1);

      const aws = await call(client, "scan_rms_compliance_findings", { provider: "aws" });
      expect(aws.isError).toBe(true);
      expect(aws.content[0].text).toContain('not available for provider "aws"');
    } finally {
      await close();
    }
  });

  it("scan_ecr_image_cve is AWS-only", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_ecr_image_cve", { provider: "huaweicloud" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toMatch(/AWS-only/);
      expect(mocks.buildScanContext).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it("scan_group with huaweicloud substitutes rms_compliance_findings for security_hub_findings and warns about missing modules", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "scan_group", { group: "hw_defense", provider: "huaweicloud", region: "cn-north-4" });
      expect(res.isError).toBeFalsy();
      const names = moduleNames(mocks.runAllScanners.mock.calls[0]);
      expect(names).toContain("rms_compliance_findings");
      expect(names).not.toContain("security_hub_findings");
      expect(names).toEqual(expect.arrayContaining(["service_detection", "public_access_verify", "ssl_certificate", "secret_exposure"]));
      expect(names).not.toContain("network_reachability");
      expect(res.content[0].text).toMatch(/requested module\(s\) not available: .*network_reachability/);
      expect(res.content[0].text).toContain("dns_dangling");

      mocks.runAllScanners.mockClear();
      const agg = await call(client, "scan_group", { group: "aggregation", provider: "huaweicloud", region: "cn-north-4" });
      expect(agg.isError).toBeFalsy();
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(["rms_compliance_findings", "config_rules_findings"]);
    } finally {
      await close();
    }
  });

  it("scan_group default provider keeps the AWS module resolution", async () => {
    const { client, close } = await connect();
    try {
      await call(client, "scan_group", { group: "aggregation" });
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual([
        "security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings",
        "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings",
      ]);
      expect(mocks.runAllScanners.mock.calls[0][1]).toBe("us-east-1");
    } finally {
      await close();
    }
  });

  it("list_modules lists the provider's module set (aws by default)", async () => {
    const { client, close } = await connect();
    try {
      const aws = JSON.parse((await call(client, "list_modules", {})).content[0].text) as Array<{ name: string }>;
      expect(aws.map((m) => m.name)).toEqual(AWS_MODULES);
      const hw = JSON.parse((await call(client, "list_modules", { provider: "huaweicloud" })).content[0].text) as Array<{ name: string; description: string }>;
      expect(hw.map((m) => m.name)).toEqual(HW_MODULES);
      expect(hw.find((m) => m.name === "rms_compliance_findings")!.description).toMatch(/Huawei Cloud/);
    } finally {
      await close();
    }
  });

  it("list_org_accounts rejects huaweicloud in Phase 1", async () => {
    const { client, close } = await connect();
    try {
      const res = await call(client, "list_org_accounts", { provider: "huaweicloud" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toMatch(/not supported for provider "huaweicloud"/);
    } finally {
      await close();
    }
  });

  it("redacts credential material from Huawei Cloud tool errors; AWS tool errors are verbatim", async () => {
    const FAKE_AK = "FAKEAK0123456789ABCD";
    const header = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;
    const { client, close } = await connect();
    try {
      mocks.runAllScanners.mockRejectedValueOnce(new Error(`boom Authorization: ${header}`));
      const hw = await call(client, "scan_all", { provider: "huaweicloud" });
      expect(hw.isError).toBe(true);
      expect(hw.content[0].text).toBe("Error: boom Authorization=[REDACTED]");

      mocks.buildScanContext.mockRejectedValueOnce(new Error(`IAM rejected ak=${FAKE_AK}`));
      const mod = await call(client, "scan_idle_resources", { provider: "huaweicloud" });
      expect(mod.isError).toBe(true);
      expect(mod.content[0].text).toBe("Error: IAM rejected ak=[REDACTED]");

      mocks.runAllScanners.mockRejectedValueOnce(new Error(`boom Authorization: ${header}`));
      const grp = await call(client, "scan_group", { group: "quick", provider: "huaweicloud" });
      expect(grp.isError).toBe(true);
      expect(grp.content[0].text).not.toContain(FAKE_AK);

      // AWS: byte-identical pass-through of the message.
      mocks.runAllScanners.mockRejectedValueOnce(new Error(`boom Authorization: ${header}`));
      const aws = await call(client, "scan_all", {});
      expect(aws.isError).toBe(true);
      expect(aws.content[0].text).toBe(`Error: boom Authorization: ${header}`);
    } finally {
      await close();
    }
  });

  it("generate_maturity_report uses Huawei Cloud impact / priority / roadmap tables for provider huaweicloud and AWS tables otherwise", async () => {
    const base = {
      scanStart: "2026-09-13T00:00:00.000Z",
      scanEnd: "2026-09-13T00:00:01.000Z",
      summary: { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, modulesSuccess: 1, modulesError: 0 },
    };
    const sd = (services: Array<{ name: string; enabled: boolean | null }>, maturityLevel: string) => ({
      module: "service_detection",
      status: "success",
      resourcesScanned: services.length,
      findingsCount: 0,
      scanTimeMs: 1,
      findings: [],
      serviceDetection: {
        services,
        coveragePercent: Math.round((services.filter((s) => s.enabled).length / services.length) * 100),
        maturityLevel,
      },
    });
    const { client, close } = await connect();
    try {
      const hwResult = {
        ...base,
        region: "cn-north-4",
        accountId: "d0m41n",
        provider: "huaweicloud",
        modules: [sd([
          { name: "CTS", enabled: true },
          { name: "RMS (Config)", enabled: true },
          { name: "SecMaster", enabled: false },
          { name: "HSS", enabled: false },
        ], "intermediate")],
      };
      const hw = await call(client, "generate_maturity_report", { scan_results: JSON.stringify(hwResult) });
      expect(hw.isError).toBeUndefined();
      const text = hw.content[0].text;
      expect(text).toContain("# Huawei Cloud Security Maturity Assessment");
      expect(text).toContain("| CTS | \u2705 Enabled | API activity audit logging |");
      expect(text).toContain("| RMS (Config) | \u2705 Enabled | Configuration tracking + compliance rules |");
      expect(text).toContain("| HSS | \u274c Not Enabled | Host vulnerability / intrusion detection |");
      expect(text).toContain("| SecMaster | \u274c Not Enabled | Centralized security operations |");
      // Priority order CTS → RMS → HSS → SecMaster (only disabled ones listed), with Huawei free-tier notes.
      expect(text).toContain("1. Enable HSS \u2014 check the console for the current free-trial / basic edition offer");
      expect(text).toContain("2. Enable SecMaster \u2014 check the console for the current free-trial offer");
      // Roadmap: 4 services → top level is Advanced, never Comprehensive.
      expect(text).toContain("- **Current**: Intermediate (2/4 services)");
      expect(text).toContain("- **Next milestone**: Advanced (4/4) \u2014 enable HSS + SecMaster");
      expect(text).toContain("- **Target**: Advanced (4/4)");
      expect(text).not.toContain("Comprehensive");
      expect(text).not.toContain("Security Hub");

      // All four enabled → no roadmap beyond "Current".
      const hwFull = { ...hwResult, modules: [sd([
        { name: "CTS", enabled: true }, { name: "RMS (Config)", enabled: true }, { name: "HSS", enabled: true }, { name: "SecMaster", enabled: true },
      ], "advanced")] };
      const full = await call(client, "generate_maturity_report", { scan_results: JSON.stringify(hwFull) });
      expect(full.content[0].text).toContain("- **Current**: Advanced (4/4 services)");
      expect(full.content[0].text).not.toContain("Target");

      // AWS (no provider field): unchanged tables.
      const awsResult = {
        ...base,
        region: "us-east-1",
        accountId: "123456789012",
        modules: [sd([
          { name: "CloudTrail", enabled: true },
          { name: "Security Hub", enabled: false },
          { name: "GuardDuty", enabled: false },
          { name: "Inspector", enabled: false },
          { name: "AWS Config", enabled: false },
        ], "basic")],
      };
      const aws = await call(client, "generate_maturity_report", { scan_results: JSON.stringify(awsResult) });
      const awsText = aws.content[0].text;
      expect(awsText).toContain("# AWS Security Maturity Assessment");
      expect(awsText).toContain("| Security Hub | \u274c Not Enabled | +300 security checks |");
      expect(awsText).toContain("1. Enable Security Hub \u2014 free trial available");
      expect(awsText).toContain("2. Enable GuardDuty \u2014 free trial available");
      expect(awsText).toContain("3. Enable Inspector \u2014 free trial available");
      expect(awsText).toContain("4. Enable AWS Config");
      expect(awsText).toContain("- **Next milestone**: Intermediate (2/5) \u2014 enable Security Hub + GuardDuty");
      expect(awsText).toContain("- **Target**: Comprehensive (5/5)");
      expect(awsText).not.toContain("CTS");
    } finally {
      await close();
    }
  });

  it("createServer defaultProvider makes provider-less calls route to Huawei Cloud", async () => {
    const { client, close } = await connect({ defaultProvider: "huaweicloud" });
    try {
      await call(client, "scan_all", {});
      expect(moduleNames(mocks.runAllScanners.mock.calls[0])).toEqual(HW_MODULES);
      expect(mocks.runAllScanners.mock.calls[0][2]).toEqual({ provider: "huaweicloud" });
      // Explicit provider still wins.
      await call(client, "scan_all", { provider: "aws" });
      expect(moduleNames(mocks.runAllScanners.mock.calls[1])).toEqual(AWS_MODULES);
    } finally {
      await close();
    }
  });

  it("providerFromEnv reads CLOUD_PROVIDER / AWS_SECURITY_MCP_PROVIDER and ignores invalid values", () => {
    expect(providerFromEnv({})).toBeUndefined();
    expect(providerFromEnv({ CLOUD_PROVIDER: "huaweicloud" })).toBe("huaweicloud");
    expect(providerFromEnv({ AWS_SECURITY_MCP_PROVIDER: "AWS" })).toBe("aws");
    expect(providerFromEnv({ CLOUD_PROVIDER: "gcp" })).toBeUndefined();
    expect(providerFromEnv({ CLOUD_PROVIDER: "gcp", AWS_SECURITY_MCP_PROVIDER: "huaweicloud" })).toBe("huaweicloud");
  });
});

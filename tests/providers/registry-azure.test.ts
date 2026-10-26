/**
 * Phase 2 (Azure) T0 — Azure provider registration (skeleton) + credential discrimination.
 * Fake service principal only; no network, no @azure SDK.
 */
import { readFileSync } from "node:fs";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import {
  getProvider,
  isProviderId,
  listProviderIds,
  PROVIDER_IDS,
  EXPERIMENTAL_PROVIDER_IDS,
} from "../../src/providers/registry.js";
import { PROVIDER_MODULE_ALIASES, resolveModuleAlias } from "../../src/providers/module-aliases.js";
import {
  AZURE_GLOBAL_MODULES,
  AZURE_MULTI_ACCOUNT_WARNING,
  AZURE_NO_SUBSCRIPTION,
  DEFAULT_AZURE_CLOUD,
  resolveAzureCloud,
} from "../../src/providers/azure/index.js";
import { providerName } from "../../src/i18n/index.js";
import {
  isAwsCredentials,
  isAlibabaCloudCredentials,
  isAzureCredentials,
  isHuaweiCloudCredentials,
  type AlibabaCloudCredentials,
  type AwsCredentials,
  type AzureCredentials,
  type HuaweiCloudCredentials,
} from "../../src/types.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const FAKE_SUB = "22222222-2222-2222-2222-22222222fake";

const FAKE_AZ: AzureCredentials = {
  kind: "azure",
  tenantId: FAKE_TENANT,
  clientId: FAKE_CLIENT,
  clientSecret: FAKE_SECRET,
  cloud: "china",
  source: "explicit",
};
const FAKE_ALI: AlibabaCloudCredentials = {
  accessKeyId: "LTAI5tFAKEFAKEFAKE0000001",
  accessKeySecret: "FakeSecretKeyDoNotUseXXXXXXXXXXXX01",
  kind: "alicloud",
};
const FAKE_AWS: AwsCredentials = {
  accessKeyId: "AKIAFAKEFAKEFAKE0001",
  secretAccessKey: "FakeAwsSecretDoNotUseXXXXXXXXXXXXXXXXX01",
  sessionToken: "FwoFAKEFAKEFAKE",
};
const FAKE_HW: HuaweiCloudCredentials = {
  ak: "FAKEHWAKFAKEHWAK0001",
  sk: "FakeHwSecretDoNotUseXXXXXXXXXXXXXXXXXX01",
};

const AZURE_ENV = [
  "AZURE_TENANT_ID",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  "AZURE_CLOUD",
  "AZURE_SUBSCRIPTION_ID",
] as const;

beforeEach(() => {
  // Never let a real environment leak into these tests: blank every Azure variable.
  for (const name of AZURE_ENV) vi.stubEnv(name, "");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("provider registry — azure", () => {
  it("appends azure to PROVIDER_IDS", () => {
    expect(PROVIDER_IDS).toEqual(["aws", "huaweicloud", "alicloud", "azure"]);
    expect(PROVIDER_IDS).toContain("azure");
  });

  it("registers azure as experimental without changing the stable listing", () => {
    expect(isProviderId("azure")).toBe(true);
    expect(EXPERIMENTAL_PROVIDER_IDS.has("azure")).toBe(true);
    expect(EXPERIMENTAL_PROVIDER_IDS.has("alicloud")).toBe(true);
    expect(listProviderIds()).toEqual(["aws", "huaweicloud"]);
    expect(listProviderIds({ includeExperimental: true })).toEqual(["aws", "huaweicloud", "alicloud", "azure"]);
  });

  it("getProvider('azure') returns the skeleton provider with its hooks", () => {
    const p = getProvider("azure");
    expect(p.id).toBe("azure");
    expect(p.displayName).toBe("Azure");
    expect(p.partitionFor?.(FAKE_SUB)).toBe("azure");
    expect(p.defaultRegion).toBe(AZURE_NO_SUBSCRIPTION);
    expect(p.supportsMultiAccount).toBe(false);
    expect(p.scanners()).toEqual([]);
    expect(p.redactDiagnostic?.("plain text")).toBe("plain text");
    expect(p.globalModules).toBe(AZURE_GLOBAL_MODULES);
    expect([...AZURE_GLOBAL_MODULES]).toEqual(["iam_privilege_escalation"]);
    expect(p.regionalMessages?.multiAccountUnsupported).toBe(AZURE_MULTI_ACCOUNT_WARNING);
  });

  it("listAccounts / assumeCrossAccount throw the multi-subscription not-implemented error", async () => {
    const p = getProvider("azure");
    const msg = /not implemented \(Azure uses multi-subscription enumeration, not cross-account assume\)/;
    await expect(p.listAccounts!({ region: FAKE_SUB })).rejects.toThrow(msg);
    await expect(p.assumeCrossAccount!({ id: FAKE_TENANT }, { region: FAKE_SUB })).rejects.toThrow(msg);
  });

  it("toResourceUrn passes native ARM resource IDs through", () => {
    const p = getProvider("azure");
    const id = `/subscriptions/${FAKE_SUB}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1`;
    expect(p.toResourceUrn("storage:account", id, { region: FAKE_SUB }, FAKE_TENANT)).toBe(id);
    expect(p.toResourceUrn("storage:account", "sa1", { region: FAKE_SUB }, FAKE_TENANT)).toBe(
      `azure:${FAKE_SUB}:storage:account:sa1`,
    );
  });

  it("contextFor injects subscriptionId / tenantId / cloud (china by default)", () => {
    const p = getProvider("azure");
    expect(p.contextFor?.({ region: FAKE_SUB, domainId: FAKE_TENANT }, FAKE_TENANT)).toEqual({
      subscriptionId: FAKE_SUB,
      tenantId: FAKE_TENANT,
      cloud: "china",
    });
    // Tenant falls back to the account ID; the placeholder scope carries no subscription.
    expect(p.contextFor?.({ region: AZURE_NO_SUBSCRIPTION }, FAKE_TENANT)).toEqual({
      tenantId: FAKE_TENANT,
      cloud: "china",
    });
    expect(p.contextFor?.({ region: FAKE_SUB }, "unknown")).toEqual({ subscriptionId: FAKE_SUB, cloud: "china" });

    vi.stubEnv("AZURE_CLOUD", "global");
    expect(p.contextFor?.({ region: FAKE_SUB }, FAKE_TENANT)?.cloud).toBe("global");
  });

  it("getAccountId resolves the tenant ID (scope → explicit creds → env), else unknown", async () => {
    const p = getProvider("azure");
    await expect(p.getAccountId({ region: FAKE_SUB, domainId: "tenant-from-scope" })).resolves.toBe("tenant-from-scope");
    await expect(p.getAccountId({ region: FAKE_SUB }, FAKE_AZ)).resolves.toBe(FAKE_TENANT);
    await expect(p.getAccountId({ region: FAKE_SUB })).resolves.toBe("unknown");
    // Non-Azure credentials are ignored.
    await expect(p.getAccountId({ region: FAKE_SUB }, FAKE_AWS)).resolves.toBe("unknown");

    vi.stubEnv("AZURE_TENANT_ID", FAKE_TENANT);
    vi.stubEnv("AZURE_CLIENT_ID", FAKE_CLIENT);
    vi.stubEnv("AZURE_CLIENT_SECRET", FAKE_SECRET);
    await expect(p.getAccountId({ region: FAKE_SUB })).resolves.toBe(FAKE_TENANT);
  });

  it("resolveAzureCloud defaults to china and accepts Global aliases", () => {
    expect(DEFAULT_AZURE_CLOUD).toBe("china");
    expect(resolveAzureCloud(undefined)).toBe("china");
    expect(resolveAzureCloud("")).toBe("china");
    expect(resolveAzureCloud("china")).toBe("china");
    expect(resolveAzureCloud("AzureChinaCloud")).toBe("china");
    expect(resolveAzureCloud("global")).toBe("global");
    expect(resolveAzureCloud(" GLOBAL ")).toBe("global");
    expect(resolveAzureCloud("AzureCloud")).toBe("global");
    expect(resolveAzureCloud("public")).toBe("global");
  });

  it("aliases security_hub_findings to defender_assessment_findings for azure only", () => {
    expect(resolveModuleAlias("security_hub_findings", "azure")).toBe("defender_assessment_findings");
    expect(resolveModuleAlias("guardduty_findings", "azure")).toBe("guardduty_findings");
    expect(PROVIDER_MODULE_ALIASES.azure).toEqual({ security_hub_findings: "defender_assessment_findings" });
    // Existing providers unchanged.
    expect(resolveModuleAlias("security_hub_findings", "aws")).toBe("security_hub_findings");
    expect(resolveModuleAlias("security_hub_findings", "huaweicloud")).toBe("rms_compliance_findings");
    expect(resolveModuleAlias("security_hub_findings", "alicloud")).toBe("config_compliance_findings");
  });

  it("has a display name", () => {
    expect(providerName("azure", "en")).toBe("Azure");
    expect(providerName("azure", "zh")).toBe("Azure");
  });

  it("does not statically import any @azure / Graph SDK (lazy-load rule)", () => {
    for (const file of ["src/providers/azure/index.ts", "src/providers/azure/subscriptions.ts"]) {
      const src = readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
      expect(src).not.toMatch(/from\s+["'](@azure|@microsoft)\//);
    }
  });
});

describe("credential discrimination — azure", () => {
  it("isAzureCredentials matches only kind=azure", () => {
    expect(isAzureCredentials(FAKE_AZ)).toBe(true);
    expect(isAzureCredentials({ ...FAKE_AZ, cloud: "global", source: "env" })).toBe(true);
    expect(isAzureCredentials(FAKE_AWS)).toBe(false);
    expect(isAzureCredentials(FAKE_ALI)).toBe(false);
    expect(isAzureCredentials(FAKE_HW)).toBe(false);
    expect(isAzureCredentials(undefined)).toBe(false);
  });

  it("isAwsCredentials / isAlibabaCloudCredentials / isHuaweiCloudCredentials never classify Azure credentials", () => {
    expect(isAwsCredentials(FAKE_AZ)).toBe(false);
    expect(isAlibabaCloudCredentials(FAKE_AZ)).toBe(false);
    expect(isHuaweiCloudCredentials(FAKE_AZ)).toBe(false);
    // A malformed object carrying AWS field names stays non-AWS because kind is set.
    expect(
      isAwsCredentials({ ...FAKE_AZ, accessKeyId: "x", secretAccessKey: "y" } as unknown as AwsCredentials),
    ).toBe(false);
  });

  it("existing guards keep their behaviour", () => {
    expect(isAwsCredentials(FAKE_AWS)).toBe(true);
    expect(isAlibabaCloudCredentials(FAKE_ALI)).toBe(true);
    expect(isHuaweiCloudCredentials(FAKE_HW)).toBe(true);
  });
});

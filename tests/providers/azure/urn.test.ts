/**
 * Phase 2 (Azure) T1 — resource URNs (plan §3.6) + provider wiring (redactDiagnostic,
 * listRegions, toResourceUrn) + static source guards (lazy SDK imports, no stdout).
 * Subscription enumeration is mocked; fake service principal only, no network.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ listAzureSubscriptions: vi.fn() }));

vi.mock("../../../src/providers/azure/subscriptions.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../src/providers/azure/subscriptions.js")>();
  return { ...actual, listAzureSubscriptions: mocks.listAzureSubscriptions };
});

import { azureProvider, AZURE_NO_SUBSCRIPTION } from "../../../src/providers/azure/index.js";
import { parseAzureResourceId, toAzureUrn } from "../../../src/providers/azure/urn.js";
import { AzureCloudError, redactAzureDiagnostic } from "../../../src/providers/azure/errors.js";
import type { AzureCredentials } from "../../../src/types.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const SUB_A = "aaaaaaaa-0000-0000-0000-00000000fake";
const FAKE_JWT =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY2hpbmFjbG91ZGFwaS5jbiIsImZha2UiOnRydWV9.RmFrZVNpZ25hdHVyZURvTm90VXNlMDAwMDAwMDAwMA";

const FAKE_AZ: AzureCredentials = { kind: "azure", tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET, cloud: "china" };

const KV_ID = `/subscriptions/${SUB_A}/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-prod`;

describe("toAzureUrn", () => {
  it("passes a native ARM resource ID through (trimmed)", () => {
    expect(toAzureUrn({ id: `  ${KV_ID} `, resourceType: "Microsoft.KeyVault/vaults", name: "kv-prod" })).toBe(KV_ID);
  });

  it("builds subscription / resource-group templates when there is no id", () => {
    expect(toAzureUrn({ subscriptionId: SUB_A, resourceGroup: "rg-1", resourceType: "Microsoft.KeyVault/vaults", name: "kv-prod" })).toBe(
      KV_ID,
    );
    expect(toAzureUrn({ subscriptionId: SUB_A, resourceType: "Microsoft.Security/pricings", name: "VirtualMachines" })).toBe(
      `/subscriptions/${SUB_A}/providers/Microsoft.Security/pricings/VirtualMachines`,
    );
  });

  it("tenant-level resources use /tenants/<tenant>/providers/…; neither → /providers/…", () => {
    expect(toAzureUrn({ tenantId: FAKE_TENANT, resourceType: "Microsoft.Graph/directoryRoles", name: "role-1" })).toBe(
      `/tenants/${FAKE_TENANT}/providers/Microsoft.Graph/directoryRoles/role-1`,
    );
    expect(toAzureUrn({ resourceType: "Microsoft.Graph/users", name: "u1" })).toBe("/providers/Microsoft.Graph/users/u1");
  });

  it("subscription wins over tenant; a non-ARM id is used as the name", () => {
    expect(toAzureUrn({ id: "sa1", subscriptionId: SUB_A, tenantId: FAKE_TENANT, resourceType: "Microsoft.Storage/storageAccounts", name: "" })).toBe(
      `/subscriptions/${SUB_A}/providers/Microsoft.Storage/storageAccounts/sa1`,
    );
  });

  it("strips stray slashes and redacts server-sourced parts", () => {
    expect(toAzureUrn({ subscriptionId: `/${SUB_A}/`, resourceType: "/Microsoft.Web/sites/", name: "app1" })).toBe(
      `/subscriptions/${SUB_A}/providers/Microsoft.Web/sites/app1`,
    );
    const urn = toAzureUrn({ subscriptionId: SUB_A, resourceType: "Microsoft.Web/sites", name: `x?sig=Secret123` });
    expect(urn).not.toContain("Secret123");
    expect(toAzureUrn({ id: `${KV_ID}?token=${FAKE_JWT}`, resourceType: "x", name: "y" })).not.toContain(FAKE_JWT);
  });
});

describe("parseAzureResourceId", () => {
  it("parses a resource-group-scoped resource", () => {
    expect(parseAzureResourceId(KV_ID)).toEqual({
      subscriptionId: SUB_A,
      resourceGroup: "rg-1",
      providerNamespace: "Microsoft.KeyVault",
      resourceType: "Microsoft.KeyVault/vaults",
      name: "kv-prod",
    });
  });

  it("parses nested types (case-insensitive keywords)", () => {
    expect(
      parseAzureResourceId(`/SUBSCRIPTIONS/${SUB_A}/resourcegroups/rg-2/Providers/Microsoft.Sql/servers/sql1/databases/db1`),
    ).toEqual({
      subscriptionId: SUB_A,
      resourceGroup: "rg-2",
      providerNamespace: "Microsoft.Sql",
      resourceType: "Microsoft.Sql/servers/databases",
      name: "sql1/db1",
    });
  });

  it("extension resources: the innermost providers/ segment wins", () => {
    const id = `/subscriptions/${SUB_A}/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1/providers/Microsoft.Authorization/roleAssignments/ra-1`;
    expect(parseAzureResourceId(id)).toMatchObject({
      subscriptionId: SUB_A,
      resourceGroup: "rg-1",
      providerNamespace: "Microsoft.Authorization",
      resourceType: "Microsoft.Authorization/roleAssignments",
      name: "ra-1",
    });
  });

  it("subscription-level, tenant-level, subscription-only and resource-group-only ids", () => {
    expect(parseAzureResourceId(`/subscriptions/${SUB_A}/providers/Microsoft.Security/pricings/VirtualMachines`)).toEqual({
      subscriptionId: SUB_A,
      providerNamespace: "Microsoft.Security",
      resourceType: "Microsoft.Security/pricings",
      name: "VirtualMachines",
    });
    expect(parseAzureResourceId(`/tenants/${FAKE_TENANT}/providers/Microsoft.Graph/directoryRoles/r1`)).toMatchObject({
      tenantId: FAKE_TENANT,
      resourceType: "Microsoft.Graph/directoryRoles",
      name: "r1",
    });
    expect(parseAzureResourceId(`/subscriptions/${SUB_A}`)).toEqual({ subscriptionId: SUB_A, name: SUB_A });
    expect(parseAzureResourceId(`/subscriptions/${SUB_A}/resourceGroups/rg-1`)).toEqual({
      subscriptionId: SUB_A,
      resourceGroup: "rg-1",
      name: "rg-1",
    });
  });

  it("returns undefined for non-ID input", () => {
    expect(parseAzureResourceId("kv-prod")).toBeUndefined();
    expect(parseAzureResourceId("/")).toBeUndefined();
    expect(parseAzureResourceId("")).toBeUndefined();
    expect(parseAzureResourceId(42 as unknown as string)).toBeUndefined();
  });

  it("round-trips with toAzureUrn", () => {
    const p = parseAzureResourceId(KV_ID)!;
    expect(toAzureUrn({ subscriptionId: p.subscriptionId, resourceGroup: p.resourceGroup, resourceType: p.resourceType!, name: p.name! })).toBe(
      KV_ID,
    );
  });
});

describe("provider wiring", () => {
  beforeEach(() => {
    mocks.listAzureSubscriptions.mockReset();
    for (const k of ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLOUD", "AZURE_SUBSCRIPTION_ID"]) {
      vi.stubEnv(k, "");
    }
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("redactDiagnostic is redactAzureDiagnostic", () => {
    expect(azureProvider.redactDiagnostic).toBe(redactAzureDiagnostic);
    expect(azureProvider.redactDiagnostic!(`Authorization: Bearer ${FAKE_JWT}`)).not.toContain(FAKE_JWT);
  });

  it("toResourceUrn: ARM ids pass through; otherwise a subscription / tenant template", () => {
    expect(azureProvider.toResourceUrn("Microsoft.KeyVault/vaults", KV_ID, { region: SUB_A, domainId: FAKE_TENANT }, FAKE_TENANT)).toBe(KV_ID);
    expect(azureProvider.toResourceUrn("Microsoft.Storage/storageAccounts", "sa1", { region: SUB_A }, FAKE_TENANT)).toBe(
      `/subscriptions/${SUB_A}/providers/Microsoft.Storage/storageAccounts/sa1`,
    );
    expect(azureProvider.toResourceUrn("Microsoft.Graph/directoryRoles", "r1", { region: AZURE_NO_SUBSCRIPTION }, FAKE_TENANT)).toBe(
      `/tenants/${FAKE_TENANT}/providers/Microsoft.Graph/directoryRoles/r1`,
    );
    expect(azureProvider.toResourceUrn("Microsoft.Graph/users", "u1", { region: AZURE_NO_SUBSCRIPTION }, "unknown")).toBe(
      "/providers/Microsoft.Graph/users/u1",
    );
  });

  it("listRegions: one scope per subscription from the enumeration", async () => {
    mocks.listAzureSubscriptions.mockResolvedValue([{ subscriptionId: SUB_A, tenantId: FAKE_TENANT, state: "Enabled" }]);
    expect(await azureProvider.listRegions(FAKE_AZ)).toEqual([{ region: SUB_A, domainId: FAKE_TENANT }]);
  });

  it("listRegions: an auth failure propagates when a subscription is requested", async () => {
    const authErr = new AzureCloudError({ kind: "auth_failed", aadsts: "AADSTS7000215", message: "Invalid client secret provided." }, "subscriptions.list");
    mocks.listAzureSubscriptions.mockRejectedValue(authErr);
    await expect(azureProvider.listRegions(FAKE_AZ, SUB_A)).rejects.toBe(authErr);
  });

  it("listRegions: a non-auth failure with a requested subscription falls back to it", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(
      new AzureCloudError({ kind: "access_denied", status: 403, code: "AuthorizationFailed", message: "denied" }, "subscriptions.list"),
    );
    expect(await azureProvider.listRegions(FAKE_AZ, SUB_A)).toEqual([{ region: SUB_A, domainId: FAKE_TENANT }]);
  });

  it("listRegions: an auth failure with only a pinned subscription still falls back", async () => {
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_A);
    mocks.listAzureSubscriptions.mockRejectedValue(new AzureCloudError({ kind: "auth_failed", message: "bad secret" }, "subscriptions.list"));
    expect(await azureProvider.listRegions(FAKE_AZ)).toEqual([{ region: SUB_A, domainId: FAKE_TENANT }]);
  });
});

describe("source guards", () => {
  const files = ["client.ts", "errors.ts", "credentials.ts", "urn.ts", "subscriptions.ts", "index.ts"];
  const read = (f: string) => readFileSync(fileURLToPath(new URL(`../../../src/providers/azure/${f}`, import.meta.url)), "utf8");

  it.each(files)("%s has no runtime top-level @azure/* or Graph import (type-only / lazy only)", (f) => {
    const src = read(f);
    const runtimeImports = src
      .split("\n")
      .filter((l) => /^\s*import\s/.test(l) && !/^\s*import\s+type\s/.test(l))
      .filter((l) => /from\s+["'](@azure\/|@microsoft\/)/.test(l));
    expect(runtimeImports).toEqual([]);
    expect(src).not.toMatch(/^\s*export\s+[^;]*from\s+["']@azure\//m);
  });

  it.each(files)("%s never writes to stdout or uses DefaultAzureCredential", (f) => {
    const src = read(f).replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");
    expect(src).not.toMatch(/console\.(log|info|debug)\s*\(/);
    expect(src).not.toMatch(/process\.stdout/);
    expect(src).not.toMatch(/\bnew\s+DefaultAzureCredential\b/);
    expect(src).not.toMatch(/JSON\.stringify\(\s*err/);
  });
});

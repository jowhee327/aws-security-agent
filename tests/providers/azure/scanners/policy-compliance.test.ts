/**
 * Phase 2 (Azure) T2 — AzurePolicyComplianceScanner (config_rules_findings): Policy
 * summarize NonCompliant counts → findings, resource samples from the paged policy-state
 * query, MLPS source, degrade / error matrix and hostile-field redaction. Every `@azure/*`
 * package is mocked; fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-policyinsights", async () => ({
  PolicyInsightsClient: (await import("./helpers.js")).fakeArmClientClass("PolicyInsightsClient"),
}));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_POLICY_NO_ASSIGNMENTS_WARNING,
  AZURE_POLICY_NON_COMPLIANT_FILTER,
  AZURE_POLICY_NOT_ENABLED_WARNING,
  AZURE_POLICY_SAMPLE_RESOURCES,
  AzurePolicyComplianceScanner,
  azurePolicyKey,
  isAzureMlps,
} from "../../../../src/providers/azure/scanners/policy-compliance.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
  FAKE_JWT,
  FAKE_TENANT,
  hostile,
  isolateAzureEnv,
  misuseError,
  notRegisteredError,
  pages,
  restoreAzureEnv,
  SUB,
  throttledError,
} from "./helpers.js";

const SUMMARIZE = "PolicyInsightsClient.policyStates.summarizeForSubscription";
const QUERY = "PolicyInsightsClient.policyStates.listQueryResultsForSubscription";

const ASSIGN_A = `/subscriptions/${SUB}/providers/Microsoft.Authorization/policyAssignments/asb-assignment`;
const ASSIGN_B = `/subscriptions/${SUB}/providers/Microsoft.Authorization/policyAssignments/storage-https`;
const DEF_1 = "/providers/Microsoft.Authorization/policyDefinitions/def-1111";
const DEF_2 = "/providers/Microsoft.Authorization/policyDefinitions/def-2222";
const DEF_3 = "/providers/Microsoft.Authorization/policyDefinitions/def-3333";

const def = (id: string, nonCompliant: number, extra: Record<string, unknown> = {}) => ({
  policyDefinitionId: id,
  effect: "Audit",
  results: { nonCompliantResources: nonCompliant },
  ...extra,
});
const assignment = (id: string, defs: unknown[], extra: Record<string, unknown> = {}) => ({
  policyAssignmentId: id,
  results: { nonCompliantResources: defs.reduce((n: number, d) => n + ((d as { results: { nonCompliantResources: number } }).results.nonCompliantResources), 0) },
  policyDefinitions: defs,
  ...extra,
});
const summary = (assignments: unknown[]) => ({ value: [{ results: {}, policyAssignments: assignments }] });
const state = (assignmentId: string, definitionId: string, resourceId: string, extra: Record<string, unknown> = {}) => ({
  resourceId,
  policyAssignmentId: assignmentId,
  policyDefinitionId: definitionId,
  complianceState: "NonCompliant",
  policyAssignmentName: assignmentId.split("/").pop(),
  policyDefinitionName: definitionId.split("/").pop(),
  ...extra,
});
const vm = (n: number) => `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-${n}`;

const scanner = new AzurePolicyComplianceScanner();
let stdoutWrites: string[];

beforeEach(() => {
  isolateAzureEnv();
  clearAzureCredentialCache();
  azureSdk.reset();
  stdoutWrites = [];
  vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    stdoutWrites.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
});
afterEach(() => {
  expect(stdoutWrites).toEqual([]);
  vi.restoreAllMocks();
  restoreAzureEnv();
});

describe("pure helpers", () => {
  it("isAzureMlps / azurePolicyKey", () => {
    expect(isAzureMlps("China MLPS Level 3")).toBe(true);
    expect(isAzureMlps(undefined, "等保2.0 三级")).toBe(true);
    expect(isAzureMlps("Microsoft cloud security benchmark")).toBe(false);
    expect(azurePolicyKey("/A", "/D")).toBe(azurePolicyKey("/a", "/d", undefined));
    expect(azurePolicyKey("/A", "/D", "ref")).not.toBe(azurePolicyKey("/A", "/D"));
  });
});

describe("AzurePolicyComplianceScanner", () => {
  it("module name is config_rules_findings", () => {
    expect(scanner.moduleName).toBe("config_rules_findings");
  });

  it("NonCompliant counts → one finding per (assignment, definition); compliant definitions skipped", async () => {
    azureSdk.on(SUMMARIZE, summary([assignment(ASSIGN_A, [def(DEF_1, 3), def(DEF_2, 0)]), assignment(ASSIGN_B, [def(DEF_3, 1)])]));
    azureSdk.on(QUERY, () => pages([[state(ASSIGN_A, DEF_1, vm(1)), state(ASSIGN_A, DEF_1, vm(2)), state(ASSIGN_B, DEF_3, vm(9))]]));

    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(2);
    expect(r.findingsCount).toBe(2);
    const [f1, f3] = r.findings;
    expect(f1.title).toBe("Azure Policy non-compliance: def-1111");
    expect(f1.severity).toBe("MEDIUM");
    expect(f1.riskScore).toBe(5.0);
    expect(f1.provider).toBe("azure");
    expect(f1.module).toBe("config_rules_findings");
    expect(f1.accountId).toBe(FAKE_TENANT);
    expect(f1.source).toBe("Policy");
    expect(f1.resourceType).toBe("Microsoft.Authorization/policyDefinitions");
    expect(f1.resourceArn.startsWith(ASSIGN_A)).toBe(true);
    expect(f1.description).toContain("3 resource(s)");
    expect(f1.description).toContain(`subscription ${SUB}`);
    expect(f1.description).toContain('assignment "asb-assignment"');
    expect(f1.description).toContain(vm(1));
    expect(f1.description).toContain(vm(2));
    expect(f1.description).toContain("Effect: Audit.");
    expect(f1.remediationSteps.some((s) => s.includes(DEF_1))).toBe(true);
    expect(f3.title).toBe("Azure Policy non-compliance: def-3333");
    expect(f3.description).toContain(vm(9));
    expect(f3.description).not.toContain(vm(1));

    // SDK call shapes: summarize("latest", sub); query filtered on NonCompliant.
    expect(azureSdk.callsFor(SUMMARIZE)[0].slice(0, 2)).toEqual(["latest", SUB]);
    const [res, sub, opts] = azureSdk.callsFor(QUERY)[0] as [string, string, { queryOptions: { filter: string } }];
    expect([res, sub]).toEqual(["latest", SUB]);
    expect(opts.queryOptions.filter).toBe(AZURE_POLICY_NON_COMPLIANT_FILTER);
    // China ARM endpoint + scope in both option shapes (AutoRest + TypeSpec clients).
    const ctor = azureSdk.ctorArgs.find((c) => c.client === "PolicyInsightsClient");
    expect(ctor?.args[1]).toBe(SUB);
    expect(ctor?.args[2]).toMatchObject({
      endpoint: "https://management.chinacloudapi.cn",
      credentialScopes: ["https://management.chinacloudapi.cn/.default"],
      credentials: { scopes: ["https://management.chinacloudapi.cn/.default"] },
    });
  });

  it("assignment without per-definition detail → one assignment-level finding", async () => {
    azureSdk.on(SUMMARIZE, summary([{ policyAssignmentId: ASSIGN_B, results: { nonCompliantResources: 4 } }]));
    azureSdk.on(QUERY, () => pages([[]]));
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(1);
    expect(r.findings[0].title).toBe("Azure Policy non-compliance: storage-https");
    expect(r.findings[0].resourceType).toBe("Microsoft.Authorization/policyAssignments");
    expect(r.findings[0].resourceArn).toBe(ASSIGN_B);
    expect(r.findings[0].description).toContain("4 resource(s)");
  });

  it("no hit: every definition compliant → no findings, no sample query", async () => {
    azureSdk.on(SUMMARIZE, summary([assignment(ASSIGN_A, [def(DEF_1, 0), def(DEF_2, 0)])]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(azureSdk.callsFor(QUERY)).toHaveLength(0);
  });

  it("no policy assignment → warning (Policy effectively unused), success", async () => {
    azureSdk.on(SUMMARIZE, summary([]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toEqual([AZURE_POLICY_NO_ASSIGNMENTS_WARNING]);
  });

  it("pagination: samples are collected across ≥2 pages of policy states (capped per finding)", async () => {
    azureSdk.on(SUMMARIZE, summary([assignment(ASSIGN_A, [def(DEF_1, 8)])]));
    const fetched = { pages: 0 };
    azureSdk.on(QUERY, () =>
      pages(
        [
          [state(ASSIGN_A, DEF_1, vm(1)), state(ASSIGN_A, DEF_1, vm(2))],
          [state(ASSIGN_A, DEF_1, vm(3)), state(ASSIGN_A, DEF_1, vm(4))],
          [state(ASSIGN_A, DEF_1, vm(5)), state(ASSIGN_A, DEF_1, vm(6)), state(ASSIGN_A, DEF_1, vm(7))],
        ],
        fetched,
      ),
    );
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    const d = r.findings[0].description;
    for (let i = 1; i <= AZURE_POLICY_SAMPLE_RESOURCES; i++) expect(d).toContain(vm(i));
    expect(d).not.toContain(vm(AZURE_POLICY_SAMPLE_RESOURCES + 1));
    expect(d).toContain(", …");
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: undefined }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("access_denied on summarize → success + insufficient-permissions warning (token redacted)", async () => {
    azureSdk.on(SUMMARIZE, () => Promise.reject(deniedError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/insufficient permissions/);
    expect(r.warnings![0]).toContain("AuthorizationFailed");
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);
    expect(JSON.stringify(r)).not.toContain("Bearer ey");
  });

  it("Microsoft.PolicyInsights not registered (Azure China) → not_enabled warning, success", async () => {
    azureSdk.on(SUMMARIZE, () => Promise.reject(notRegisteredError("Microsoft.PolicyInsights")));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0].startsWith(AZURE_POLICY_NOT_ENABLED_WARNING)).toBe(true);
    expect(r.warnings![0]).toContain("MissingSubscriptionRegistration");
  });

  it("throttled after retries → warning, success", async () => {
    azureSdk.on(SUMMARIZE, () => Promise.reject(throttledError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0]).toMatch(/throttled/);
  });

  it("auth_failed (AADSTS900023) → status error with the canonical prefix", async () => {
    azureSdk.on(SUMMARIZE, () => Promise.reject(authError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(r.error).toContain("AADSTS900023");
    expect(r.findings).toEqual([]);
  });

  it("api_misuse (InvalidApiVersion) → status error", async () => {
    azureSdk.on(SUMMARIZE, () => Promise.reject(misuseError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure Policy compliance scan failed: .*InvalidApiVersionParameter/);
    expect(r.error).not.toContain(FAKE_JWT);
  });

  it("sample query denied → findings keep counts + warning", async () => {
    azureSdk.on(SUMMARIZE, summary([assignment(ASSIGN_A, [def(DEF_1, 2)])]));
    azureSdk.on(QUERY, () => failingPages(deniedError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expect(r.findings[0].description).toContain("2 resource(s)");
    expect(r.warnings![0]).toMatch(/listQueryResultsForSubscription: insufficient permissions.*counts only/);
  });

  it("sample query auth_failed / api_misuse → status error (never downgraded)", async () => {
    azureSdk.on(SUMMARIZE, summary([assignment(ASSIGN_A, [def(DEF_1, 2)])]));
    azureSdk.on(QUERY, () => failingPages(authError()));
    const auth = await scanner.scan(azCtx());
    expect(auth.status).toBe("error");
    expect(auth.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);

    azureSdk.on(QUERY, () => failingPages(misuseError()));
    const misuse = await scanner.scan(azCtx());
    expect(misuse.status).toBe("error");
  });

  it("MLPS initiative assignment → source Policy:<assignment>", async () => {
    const mlps = `/subscriptions/${SUB}/providers/Microsoft.Authorization/policyAssignments/china-mlps-level3`;
    azureSdk.on(
      SUMMARIZE,
      summary([assignment(mlps, [def(DEF_1, 1)], { policySetDefinitionId: "/providers/Microsoft.Authorization/policySetDefinitions/mlps-l3" })]),
    );
    azureSdk.on(QUERY, () => pages([[]]));
    const r = await scanner.scan(azCtx());
    expect(r.findings[0].source).toBe("Policy:china-mlps-level3");
    expect(r.findings[0].impact).toContain("Source: Policy:china-mlps-level3");
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    const evilAssign = `/subscriptions/${SUB}/providers/Microsoft.Authorization/policyAssignments/${hostile("assign")}`;
    const evilDef = `/providers/Microsoft.Authorization/policyDefinitions/${hostile("def")}`;
    azureSdk.on(
      SUMMARIZE,
      summary([
        assignment(evilAssign, [def(evilDef, 2, { effect: hostile("effect"), policyDefinitionGroupNames: [hostile("group")], policyDefinitionReferenceId: hostile("ref") })], {
          policySetDefinitionId: hostile("set"),
        }),
      ]),
    );
    azureSdk.on(QUERY, () =>
      pages([
        [
          state(evilAssign, evilDef, `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/${hostile("site")}`, {
            policyDefinitionReferenceId: hostile("ref"),
            policyAssignmentName: hostile("assignName"),
            policyDefinitionName: hostile("defName"),
            policySetDefinitionName: hostile("setName"),
          }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expectNoLeak(r);
    // The hostile values did flow into the finding — redacted, not dropped.
    expect(r.findings[0].description).toContain("[REDACTED]");
    expect(r.findings[0].title).toContain("[REDACTED]");

    // Hostile error message on the summarize call → warning stays clean.
    azureSdk.on(SUMMARIZE, () => Promise.reject(Object.assign(deniedError(), { message: hostile("denied") })));
    const denied = await scanner.scan(azCtx());
    expect(denied.warnings).toHaveLength(1);
    expectNoLeak(denied);
  });
});

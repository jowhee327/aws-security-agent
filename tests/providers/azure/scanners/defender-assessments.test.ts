/**
 * Phase 2 (Azure) T2 — AzureDefenderAssessmentsScanner (defender_assessment_findings, the
 * security_hub_findings alias): Unhealthy → finding, severity from metadata (inline or
 * assessmentsMetadata), resource IDs, MLPS regulatory standard source, pagination, degrade /
 * error matrix and hostile-field redaction. Every `@azure/*` package is mocked; fake
 * service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-security", async () => ({ SecurityCenter: (await import("./helpers.js")).fakeArmClientClass("SecurityCenter") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import { resolveModuleAlias } from "../../../../src/providers/module-aliases.js";
import {
  AZURE_DEFENDER_MAX_ASSESSMENTS,
  AZURE_DEFENDER_NOT_ENABLED_WARNING,
  AZURE_DEFENDER_SOURCE,
  AzureDefenderAssessmentsScanner,
  assessedResourceId,
  azureDefenderRiskScore,
  isAzureUnhealthy,
} from "../../../../src/providers/azure/scanners/defender-assessments.js";
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

const LIST = "SecurityCenter.assessments.list";
const META = "SecurityCenter.assessmentsMetadata.list";
const STANDARDS = "SecurityCenter.regulatoryComplianceStandards.list";
const CONTROLS = "SecurityCenter.regulatoryComplianceControls.list";
const RC_ASSESSMENTS = "SecurityCenter.regulatoryComplianceAssessments.list";

const sa = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/${n}`;
const KEY_HTTPS = "1c5de8e1-f68d-6a17-e0d2-ec259c42768c";
const KEY_MFA = "94290b00-4d0c-d7b4-7cea-064a9554e681";

const assessment = (resourceId: string, key: string, code: string, extra: Record<string, unknown> = {}) => ({
  id: `${resourceId}/providers/Microsoft.Security/assessments/${key}`,
  name: key,
  type: "Microsoft.Security/assessments",
  resourceDetails: { source: "Azure", id: resourceId },
  displayName: `Recommendation ${key.slice(0, 4)}`,
  status: { code },
  ...extra,
});

/** Default routes: no metadata, no regulatory standards. */
function route(list: unknown, extra: Record<string, unknown> = {}) {
  azureSdk.on(LIST, typeof list === "function" ? list : () => list);
  azureSdk.on(META, () => pages([[]]));
  azureSdk.on(STANDARDS, () => pages([[]]));
  for (const [k, v] of Object.entries(extra)) azureSdk.on(k, v);
}

const scanner = new AzureDefenderAssessmentsScanner();
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
  it("severity → risk score; Unhealthy detection; assessed resource ID", () => {
    expect(azureDefenderRiskScore("High")).toBe(7.5);
    expect(azureDefenderRiskScore("medium")).toBe(5.0);
    expect(azureDefenderRiskScore("Low")).toBe(3.0);
    expect(azureDefenderRiskScore(undefined)).toBe(5.0);
    expect(isAzureUnhealthy("Unhealthy")).toBe(true);
    expect(isAzureUnhealthy("Healthy")).toBe(false);
    expect(isAzureUnhealthy("NotApplicable")).toBe(false);
    expect(assessedResourceId({ resourceDetails: { id: sa("x") } })).toBe(sa("x"));
    expect(assessedResourceId({ id: `${sa("y")}/providers/Microsoft.Security/assessments/k` })).toBe(sa("y"));
    expect(assessedResourceId({ id: "/weird" })).toBeUndefined();
  });

  it("security_hub_findings aliases to defender_assessment_findings for azure only", () => {
    expect(resolveModuleAlias("security_hub_findings", "azure")).toBe("defender_assessment_findings");
    expect(resolveModuleAlias("security_hub_findings", "aws")).toBe("security_hub_findings");
  });
});

describe("AzureDefenderAssessmentsScanner", () => {
  it("module name is defender_assessment_findings", () => {
    expect(scanner.moduleName).toBe("defender_assessment_findings");
  });

  it("Unhealthy → finding (inline metadata severity); Healthy / NotApplicable skipped", async () => {
    route(
      pages([
        [
          assessment(sa("a"), KEY_HTTPS, "Unhealthy", {
            metadata: { displayName: "Secure transfer to storage accounts should be enabled", severity: "High", description: "HTTPS only.", remediationDescription: "Enable secure transfer.", categories: ["Data"] },
            status: { code: "Unhealthy", cause: "OffByPolicy", description: "Secure transfer disabled" },
          }),
          assessment(sa("b"), KEY_HTTPS, "Healthy"),
          assessment(sa("c"), KEY_HTTPS, "NotApplicable"),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
    expect(r.findingsCount).toBe(1);
    const f = r.findings[0];
    expect(f.title).toBe(`Defender for Cloud: Recommendation ${KEY_HTTPS.slice(0, 4)}`);
    expect(f.severity).toBe("HIGH");
    expect(f.riskScore).toBe(7.5);
    expect(f.resourceArn).toBe(sa("a"));
    expect(f.resourceId).toBe("a");
    expect(f.resourceType).toBe("Microsoft.Storage/storageAccounts");
    expect(f.source).toBe(AZURE_DEFENDER_SOURCE);
    expect(f.provider).toBe("azure");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.module).toBe("defender_assessment_findings");
    expect(f.description).toContain("HTTPS only.");
    expect(f.description).toContain("Cause: OffByPolicy.");
    expect(f.description).toContain("Categories: Data.");
    expect(f.remediationSteps[0]).toBe("Enable secure transfer.");
    // Inline metadata had a severity → no metadata listing.
    expect(azureSdk.callsFor(META)).toHaveLength(0);
    expect(azureSdk.callsFor(LIST)[0]).toEqual([`/subscriptions/${SUB}`]);
    const ctor = azureSdk.ctorArgs.find((c) => c.client === "SecurityCenter");
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn", credentialScopes: ["https://management.chinacloudapi.cn/.default"] });
  });

  it("severity / display name from assessmentsMetadata when the list omits metadata", async () => {
    route(pages([[assessment(sa("a"), KEY_MFA, "Unhealthy", { displayName: undefined }), assessment(sa("b"), "unknown-key", "Unhealthy")]]), {
      [META]: () => pages([[{ name: KEY_MFA.toUpperCase(), displayName: "MFA should be enabled on accounts with owner permissions", severity: "Low" }]]),
    });
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(2);
    expect(r.findings[0].title).toBe("Defender for Cloud: MFA should be enabled on accounts with owner permissions");
    expect(r.findings[0].severity).toBe("LOW");
    expect(r.findings[1].severity).toBe("MEDIUM"); // no metadata → Medium
  });

  it("metadata listing denied → warning, findings default to Medium", async () => {
    route(pages([[assessment(sa("a"), KEY_MFA, "Unhealthy")]]), { [META]: () => failingPages(deniedError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings[0].severity).toBe("MEDIUM");
    expect(r.warnings![0]).toMatch(/assessmentsMetadata.list: insufficient permissions.*default to Medium/);
  });

  it("no hit: only Healthy assessments → no findings, no enrichment calls", async () => {
    route(pages([[assessment(sa("a"), KEY_HTTPS, "Healthy")]]));
    const r = await scanner.scan(azCtx());
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(azureSdk.callsFor(STANDARDS)).toHaveLength(0);
  });

  it("pagination: Unhealthy assessments across ≥2 pages", async () => {
    const fetched = { pages: 0 };
    route(
      pages(
        [
          [assessment(sa("p1"), KEY_HTTPS, "Unhealthy"), assessment(sa("p1h"), KEY_HTTPS, "Healthy")],
          [assessment(sa("p2"), KEY_HTTPS, "Unhealthy")],
          [assessment(sa("p3"), KEY_MFA, "Unhealthy")],
        ],
        fetched,
      ),
    );
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    expect(r.resourcesScanned).toBe(4);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["p1", "p2", "p3"]);
  });

  it("listing cap → truncation warning", async () => {
    const many = Array.from({ length: AZURE_DEFENDER_MAX_ASSESSMENTS + 1 }, (_, i) => assessment(sa(`s${i}`), KEY_HTTPS, "Healthy"));
    route(pages([many]));
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(AZURE_DEFENDER_MAX_ASSESSMENTS);
    expect(r.warnings![0]).toMatch(/truncated/);
  });

  it("Microsoft.Security not registered (Azure China) → not_enabled warning, success", async () => {
    route(() => failingPages(notRegisteredError("Microsoft.Security")));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings![0].startsWith(AZURE_DEFENDER_NOT_ENABLED_WARNING)).toBe(true);
    expect(r.warnings![0]).toContain("MissingSubscriptionRegistration");
  });

  it("access_denied → success + warning (token redacted); throttled → warning", async () => {
    route(() => failingPages(deniedError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0]).toMatch(/insufficient permissions/);
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);

    route(() => failingPages(throttledError()));
    const t = await scanner.scan(azCtx());
    expect(t.status).toBe("success");
    expect(t.warnings![0]).toMatch(/throttled/);
  });

  it("auth_failed → status error (Azure authentication failed …); api_misuse → status error", async () => {
    route(() => failingPages(authError()));
    const auth = await scanner.scan(azCtx());
    expect(auth.status).toBe("error");
    expect(auth.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);

    route(() => failingPages(misuseError()));
    const misuse = await scanner.scan(azCtx());
    expect(misuse.status).toBe("error");
    expect(misuse.error).toMatch(/^Defender for Cloud assessment scan failed: .*InvalidApiVersionParameter/);
  });

  it("auth_failed during metadata enrichment is never downgraded", async () => {
    route(pages([[assessment(sa("a"), KEY_MFA, "Unhealthy")]]), { [META]: () => failingPages(authError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("MLPS regulatory standard → source Defender:<standard> for its failed-control assessments", async () => {
    const std = "China-MLPS-Level-3";
    route(pages([[assessment(sa("a"), KEY_HTTPS, "Unhealthy"), assessment(sa("b"), KEY_MFA, "Unhealthy")]]), {
      [STANDARDS]: () =>
        pages([[{ name: "Azure-CIS-1.1.0", state: "Failed" }, { name: std, state: "Failed" }, { name: "MLPS-unsupported", state: "Unsupported" }]]),
      [CONTROLS]: (standard: unknown) =>
        standard === std ? pages([[{ name: "8.1.4", state: "Failed", failedAssessments: 1 }, { name: "8.1.5", state: "Passed", failedAssessments: 0 }]]) : pages([[]]),
      [RC_ASSESSMENTS]: (_s: unknown, control: unknown) =>
        control === "8.1.4"
          ? pages([[{ name: "rc-1", assessmentDetailsLink: `https://portal.azure.cn/#blade/Microsoft_Azure_Security/assessments/${KEY_HTTPS}` }]])
          : pages([[]]),
    });
    const r = await scanner.scan(azCtx());
    expect(r.findings.find((f) => f.resourceId === "a")?.source).toBe(`Defender:${std}`);
    expect(r.findings.find((f) => f.resourceId === "b")?.source).toBe(AZURE_DEFENDER_SOURCE);
    // Only the MLPS standard with data is expanded, only its failed control.
    expect(azureSdk.callsFor(CONTROLS)).toEqual([[std]]);
    expect(azureSdk.callsFor(RC_ASSESSMENTS)).toEqual([[std, "8.1.4"]]);
  });

  it("regulatory compliance unavailable (not enabled) → silent; denied → warning", async () => {
    route(pages([[assessment(sa("a"), KEY_HTTPS, "Unhealthy")]]), { [STANDARDS]: () => failingPages(notRegisteredError()) });
    const quiet = await scanner.scan(azCtx());
    expect(quiet.findingsCount).toBe(1);
    expect(quiet.warnings).toBeUndefined();

    route(pages([[assessment(sa("a"), KEY_HTTPS, "Unhealthy")]]), { [STANDARDS]: () => failingPages(deniedError()) });
    const denied = await scanner.scan(azCtx());
    expect(denied.findingsCount).toBe(1);
    expect(denied.warnings![0]).toMatch(/regulatoryComplianceStandards.list: insufficient permissions/);
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    const evilRes = sa(hostile("acct"));
    route(
      pages([
        [
          assessment(evilRes, hostile("key"), "Unhealthy", {
            displayName: hostile("display"),
            metadata: { description: hostile("desc"), remediationDescription: hostile("fix"), categories: [hostile("cat")] },
            status: { code: "Unhealthy", cause: hostile("cause"), description: hostile("status") },
          }),
        ],
      ]),
      {
        [META]: () => pages([[{ name: hostile("key"), displayName: hostile("metaName"), severity: "High" }]]),
        [STANDARDS]: () => pages([[{ name: `MLPS ${hostile("std")}`, state: "Failed" }]]),
        [CONTROLS]: () => pages([[{ name: "c1", failedAssessments: 1 }]]),
        [RC_ASSESSMENTS]: () => failingPages(Object.assign(deniedError(), { message: hostile("rc denied") })),
      },
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");
    expect(r.findings[0].description).toContain("[REDACTED]");
  });
});

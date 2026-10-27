/**
 * Phase 2 (Azure) T7 — AzureDefenderSubAssessmentsScanner (inspector_findings): Unhealthy
 * sub-assessments aggregated per vulnerability (CVEs, CVSS, affected resources), risk
 * scoring, findings cap + listing cap, pagination, not_enabled / degrade / error matrix and
 * hostile-field redaction. Every `@azure/*` package is mocked; fake service principal only;
 * no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-security", async () => ({ SecurityCenter: (await import("./helpers.js")).fakeArmClientClass("SecurityCenter") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_SUBASSESSMENT_MAX_FINDINGS,
  AZURE_SUBASSESSMENT_MAX_ITEMS,
  AZURE_SUBASSESSMENT_SOURCE,
  AZURE_SUBASSESSMENTS_NOT_ENABLED_WARNING,
  AzureDefenderSubAssessmentsScanner,
  aggregateAzureSubAssessments,
  azureSubAssessedResourceId,
  azureSubAssessmentCves,
  azureSubAssessmentCvss,
  azureVulnRiskScore,
  isAzureSubAssessmentUnhealthy,
} from "../../../../src/providers/azure/scanners/defender-subassessments.js";
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

const LIST = "SecurityCenter.subAssessments.listAll";
const VA_KEY = "1195afff-c881-495e-9bc5-1486211ae03f";
const vmId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/${n}`;

let seq = 0;
const sub = (
  resourceId: string,
  vuln: string,
  opts: { code?: string; severity?: string; cves?: string[]; cvss?: Record<string, number>; patchable?: boolean; extra?: Record<string, unknown> } = {},
) => ({
  id: `${resourceId}/providers/Microsoft.Security/assessments/${VA_KEY}/subAssessments/sa-${seq++}`,
  name: `sa-${seq}`,
  type: "Microsoft.Security/assessments/subAssessments",
  idPropertiesId: vuln,
  displayName: `Vulnerability ${vuln}`,
  status: { code: opts.code ?? "Unhealthy", severity: opts.severity ?? "High" },
  remediation: "Update the package.",
  category: "Ubuntu",
  resourceDetails: { source: "Azure", id: resourceId },
  additionalData: {
    assessedResourceType: "ServerVulnerabilityAssessment",
    ...(opts.cves ? { cve: opts.cves.map((title) => ({ title, link: `https://nvd.nist.gov/vuln/detail/${title}` })) } : {}),
    ...(opts.cvss ? { cvss: Object.fromEntries(Object.entries(opts.cvss).map(([k, base]) => [k, { base }])) } : {}),
    patchable: opts.patchable ?? false,
  },
  ...(opts.extra ?? {}),
});

const scanner = new AzureDefenderSubAssessmentsScanner();
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
  it("status, resource ID, CVEs, CVSS, risk score", () => {
    expect(isAzureSubAssessmentUnhealthy({ status: { code: "Unhealthy" } })).toBe(true);
    expect(isAzureSubAssessmentUnhealthy({ properties: { status: { code: "unhealthy" } } })).toBe(true);
    expect(isAzureSubAssessmentUnhealthy({ status: { code: "Healthy" } })).toBe(false);
    expect(azureSubAssessedResourceId({ resourceDetails: { id: vmId("a") } })).toBe(vmId("a"));
    expect(azureSubAssessedResourceId({ id: `${vmId("b")}/providers/Microsoft.Security/assessments/k/subAssessments/s` })).toBe(vmId("b"));
    expect(azureSubAssessedResourceId({ id: "/odd" })).toBeUndefined();
    expect(azureSubAssessmentCves({ additionalData: { cve: [{ title: "cve-2024-3094" }, { title: "Not a CVE" }, {}] } })).toEqual(["CVE-2024-3094"]);
    expect(azureSubAssessmentCvss({ additionalData: { cvss: { "2.0": { base: 7.5 }, "3.0": { base: 9.8 }, bad: { base: 42 } } } })).toBe(9.8);
    expect(azureSubAssessmentCvss({ additionalData: {} })).toBeUndefined();
    expect(azureVulnRiskScore({ severity: "high", cvss: 9.8 })).toBe(9.8);
    expect(azureVulnRiskScore({ severity: "high" })).toBe(8.0);
    expect(azureVulnRiskScore({ severity: "medium" })).toBe(5.5);
    expect(azureVulnRiskScore({ severity: "low" })).toBe(3.0);
    expect(azureVulnRiskScore({ severity: "unknown" })).toBe(5.5);
  });

  it("aggregation: one summary per vulnerability; resources / CVEs deduplicated; worst severity / CVSS kept", () => {
    const list = aggregateAzureSubAssessments([
      sub(vmId("a"), "91234", { severity: "Medium", cves: ["CVE-2024-0001"], cvss: { "3.0": 6.1 } }),
      sub(vmId("b"), "91234", { severity: "High", cves: ["CVE-2024-0001", "CVE-2024-0002"], cvss: { "3.0": 8.8 }, patchable: true }),
      sub(vmId("a"), "91234", { severity: "Low" }),
      sub(vmId("a"), "55555", { severity: "Low" }),
    ]);
    expect(list).toHaveLength(2);
    const v = list.find((s) => s.vulnId === "91234")!;
    expect(v.resources).toEqual(["a", "b"]);
    expect(v.cves).toEqual(["CVE-2024-0001", "CVE-2024-0002"]);
    expect(v.severity).toBe("high");
    expect(v.cvss).toBe(8.8);
    expect(v.patchable).toBe(true);
    expect(v.firstResourceId).toBe(vmId("a"));
  });
});

describe("AzureDefenderSubAssessmentsScanner", () => {
  it("module name is inspector_findings", () => {
    expect(scanner.moduleName).toBe("inspector_findings");
  });

  it("hit: Unhealthy sub-assessments → one finding per vulnerability; Healthy / NotApplicable skipped", async () => {
    azureSdk.on(LIST, () =>
      pages([
        [
          sub(vmId("web-1"), "91234", { severity: "High", cves: ["CVE-2024-3094"], cvss: { "3.0": 10 }, patchable: true }),
          sub(vmId("web-2"), "91234", { severity: "High", cves: ["CVE-2024-3094"] }),
          sub(vmId("db-1"), "70001", { severity: "Low" }),
          sub(vmId("web-1"), "33333", { code: "Healthy" }),
          sub(vmId("web-1"), "44444", { code: "NotApplicable" }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(5);
    expect(r.findingsCount).toBe(2);

    const [xz, low] = r.findings;
    expect(xz.title).toBe("Vulnerability Vulnerability 91234 (CVE-2024-3094) on 2 resource(s)");
    expect(xz.severity).toBe("CRITICAL");
    expect(xz.riskScore).toBe(10);
    expect(xz.resourceType).toBe("Microsoft.Security/subAssessments");
    expect(xz.resourceArn).toBe(`/subscriptions/${SUB}/providers/Microsoft.Security/subAssessments/91234`);
    expect(xz.description).toContain("on 2 resource(s) in subscription");
    expect(xz.description).toContain(": web-1, web-2");
    expect(xz.description).toContain("CVEs: CVE-2024-3094");
    expect(xz.description).toContain("Severity: high, CVSS 10");
    expect(xz.description).toContain("A patch is available");
    expect(xz.remediationSteps[0]).toBe("Update the package.");
    expect(xz.source).toBe(AZURE_SUBASSESSMENT_SOURCE);
    expect(xz.provider).toBe("azure");
    expect(xz.accountId).toBe(FAKE_TENANT);
    expect(xz.module).toBe("inspector_findings");

    // Single affected resource → the resource itself is the finding resource.
    expect(low.severity).toBe("LOW");
    expect(low.riskScore).toBe(3.0);
    expect(low.resourceArn).toBe(vmId("db-1"));
    expect(low.resourceId).toBe("db-1");
    expect(low.resourceType).toBe("Microsoft.Compute/virtualMachines");

    expect(azureSdk.callsFor(LIST)).toEqual([[`/subscriptions/${SUB}`]]);
    const ctor = azureSdk.ctorArgs.find((c) => c.client === "SecurityCenter");
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn", credentialScopes: ["https://management.chinacloudapi.cn/.default"] });
  });

  it("no hit: only Healthy sub-assessments → no findings", async () => {
    azureSdk.on(LIST, () => pages([[sub(vmId("a"), "1", { code: "Healthy" })]]));
    const r = await scanner.scan(azCtx());
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
    expect(r.warnings).toBeUndefined();
  });

  it("pagination: sub-assessments across ≥2 pages are aggregated together", async () => {
    const fetched = { pages: 0 };
    azureSdk.on(LIST, () => pages([[sub(vmId("p1"), "777")], [sub(vmId("p2"), "777")], [sub(vmId("p3"), "888", { severity: "Medium" })]], fetched));
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    expect(r.resourcesScanned).toBe(3);
    expect(r.findingsCount).toBe(2);
    expect(r.findings[0].description).toContain(": p1, p2");
  });

  it("findings cap → overflow warning with per-severity counts; highest risk kept", async () => {
    const many = [
      ...Array.from({ length: AZURE_SUBASSESSMENT_MAX_FINDINGS }, (_, i) => sub(vmId("a"), `low-${i}`, { severity: "Low" })),
      sub(vmId("a"), "crit", { severity: "High", cvss: { "3.0": 9.8 } }),
      sub(vmId("a"), "med", { severity: "Medium" }),
    ];
    azureSdk.on(LIST, () => pages([many]));
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(AZURE_SUBASSESSMENT_MAX_FINDINGS);
    expect(r.findings[0].resourceId).toBe("a");
    expect(r.findings[0].riskScore).toBe(9.8);
    expect(r.findings[1].riskScore).toBe(5.5);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain(`${AZURE_SUBASSESSMENT_MAX_FINDINGS + 2} distinct vulnerabilities (high 1, medium 1, low ${AZURE_SUBASSESSMENT_MAX_FINDINGS})`);
  });

  it("listing cap → truncation warning", async () => {
    azureSdk.on(LIST, () => pages([Array.from({ length: AZURE_SUBASSESSMENT_MAX_ITEMS + 1 }, (_, i) => sub(vmId("a"), `${i}`, { code: "Healthy" }))]));
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(AZURE_SUBASSESSMENT_MAX_ITEMS);
    expect(r.warnings).toEqual([
      `Defender for Cloud subAssessments.listAll: more than ${AZURE_SUBASSESSMENT_MAX_ITEMS} items; results were truncated to the first ${AZURE_SUBASSESSMENT_MAX_ITEMS}.`,
    ]);
  });

  it("Microsoft.Security not registered (Azure China) → not_enabled warning, success", async () => {
    azureSdk.on(LIST, () => failingPages(notRegisteredError("Microsoft.Security")));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings![0].startsWith(AZURE_SUBASSESSMENTS_NOT_ENABLED_WARNING)).toBe(true);
    expect(r.warnings![0]).toContain("MissingSubscriptionRegistration");
  });

  it("access_denied → success + warning (token redacted); throttled → warning", async () => {
    azureSdk.on(LIST, () => failingPages(deniedError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0]).toMatch(/subAssessments.listAll: insufficient permissions.*vulnerability findings not checked\.$/);
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);

    azureSdk.on(LIST, () => failingPages(throttledError()));
    const t = await scanner.scan(azCtx());
    expect(t.status).toBe("success");
    expect(t.warnings![0]).toMatch(/throttled/);
  });

  it("auth_failed → status error (Azure authentication failed …); api_misuse → status error", async () => {
    azureSdk.on(LIST, () => failingPages(authError()));
    const auth = await scanner.scan(azCtx());
    expect(auth.status).toBe("error");
    expect(auth.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);

    azureSdk.on(LIST, () => failingPages(misuseError(), [sub(vmId("a"), "1")]));
    const misuse = await scanner.scan(azCtx());
    expect(misuse.status).toBe("error");
    expect(misuse.error).toMatch(/^Defender for Cloud vulnerability scan failed: .*InvalidApiVersionParameter/);
    expect(misuse.findings).toEqual([]);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    const evil = (vuln: string, res: string) =>
      sub(vmId(res), vuln, {
        cves: [hostile("CVE-2024-1"), "CVE-2024-9999"],
        extra: {
          displayName: hostile("display"),
          remediation: hostile("fix"),
          impact: hostile("impact"),
          category: hostile("cat"),
          additionalData: { assessedResourceType: hostile("kind"), cve: [{ title: hostile("cve") }] },
        },
      });
    azureSdk.on(LIST, () => pages([[evil(hostile("vuln"), hostile("vm1")), evil(hostile("vuln2"), hostile("vm2")), evil(hostile("vuln2"), "vm3")]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(2);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");
    expect(r.findings[0].description).toContain("[REDACTED]");
    expect(r.findings[0].impact).toContain("[REDACTED]");
  });

  it("hostile error message on the listing never leaks", async () => {
    azureSdk.on(LIST, () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expectNoLeak(r);
  });
});

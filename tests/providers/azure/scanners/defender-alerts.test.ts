/**
 * Phase 2 (Azure) T7 — AzureDefenderAlertsScanner (guardduty_findings): Active alerts →
 * findings, severity mapping, sorting, findings cap + listing cap, pagination, not_enabled /
 * degrade / error matrix and hostile-field redaction. Every `@azure/*` package is mocked;
 * fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-security", async () => ({ SecurityCenter: (await import("./helpers.js")).fakeArmClientClass("SecurityCenter") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_ALERT_MAX_FINDINGS,
  AZURE_ALERT_MAX_ITEMS,
  AZURE_ALERT_RISK,
  AZURE_ALERT_SOURCE,
  AZURE_ALERTS_NOT_ENABLED_WARNING,
  AzureDefenderAlertsScanner,
  azureAlertResourceId,
  azureAlertSeverity,
  isAzureAlertActive,
  sortAzureAlerts,
} from "../../../../src/providers/azure/scanners/defender-alerts.js";
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

const LIST = "SecurityCenter.alerts.list";
const vmId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/${n}`;

let seq = 0;
const alert = (severity: string | undefined, extra: Record<string, unknown> = {}) => {
  const name = `2517-alert-${seq++}`;
  return {
    id: `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.Security/locations/chinanorth3/alerts/${name}`,
    name,
    type: "Microsoft.Security/Locations/alerts",
    alertType: "VM_SuspiciousProcess",
    alertDisplayName: "Suspicious process executed",
    severity,
    status: "Active",
    ...extra,
  };
};

const scanner = new AzureDefenderAlertsScanner();
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
  it("severity normalisation, risk table, active status, resource ID", () => {
    expect(azureAlertSeverity({ severity: "High" })).toBe("high");
    expect(azureAlertSeverity({ properties: { severity: "medium" } })).toBe("medium");
    expect(azureAlertSeverity({ severity: "Informational" })).toBe("informational");
    expect(azureAlertSeverity({ severity: "Critical?" })).toBe("unknown");
    expect(AZURE_ALERT_RISK).toEqual({ high: 8.0, medium: 6.0, low: 3.0, informational: 1.0, unknown: 6.0 });
    expect(isAzureAlertActive({ status: "Active" })).toBe(true);
    expect(isAzureAlertActive({})).toBe(true);
    expect(isAzureAlertActive({ status: "Resolved" })).toBe(false);
    expect(isAzureAlertActive({ status: "dismissed" })).toBe(false);
    expect(azureAlertResourceId({ resourceIdentifiers: [{ type: "LogAnalytics", workspaceId: "w" }, { type: "AzureResource", azureResourceId: vmId("a") }] })).toBe(vmId("a"));
    expect(azureAlertResourceId({ resourceIdentifiers: "x" })).toBeUndefined();
  });

  it("sort: most severe first, then most recent", () => {
    const a = { id: "a", severity: "Low", endTimeUtc: new Date("2026-10-20T00:00:00Z") };
    const b = { id: "b", severity: "High", endTimeUtc: new Date("2026-10-01T00:00:00Z") };
    const c = { id: "c", severity: "High", endTimeUtc: "2026-10-25T00:00:00Z" };
    const d = { id: "d", severity: "Informational" };
    expect(sortAzureAlerts([a, b, c, d]).map((x) => x.id)).toEqual(["c", "b", "a", "d"]);
  });
});

describe("AzureDefenderAlertsScanner", () => {
  it("module name is guardduty_findings", () => {
    expect(scanner.moduleName).toBe("guardduty_findings");
  });

  it("hit: Active alerts → findings with severity mapping; Resolved / Dismissed skipped", async () => {
    azureSdk.on(LIST, () =>
      pages([
        [
          alert("High", {
            compromisedEntity: "web-vm-01",
            resourceIdentifiers: [{ type: "AzureResource", azureResourceId: vmId("web-vm-01") }],
            description: "A suspicious process was executed.",
            intent: "Execution",
            startTimeUtc: new Date("2026-10-26T01:00:00Z"),
            endTimeUtc: new Date("2026-10-26T02:00:00Z"),
            remediationSteps: ["Review the process tree.", "Escalate to SOC."],
            productName: "Microsoft Defender for Cloud",
            alertUri: "https://portal.azure.cn/#blade/alert",
          }),
          alert("Medium"),
          alert("Low"),
          alert("Informational"),
          alert("High", { status: "Resolved" }),
          alert("High", { status: "Dismissed" }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(6);
    expect(r.findingsCount).toBe(4);
    expect(r.findings.map((f) => f.severity)).toEqual(["HIGH", "MEDIUM", "LOW", "LOW"]);
    expect(r.findings.map((f) => f.riskScore)).toEqual([8.0, 6.0, 3.0, 1.0]);

    const f = r.findings[0];
    expect(f.title).toBe("Defender for Cloud high alert: Suspicious process executed on web-vm-01");
    expect(f.resourceArn).toBe(vmId("web-vm-01"));
    expect(f.resourceId).toBe("web-vm-01");
    expect(f.resourceType).toBe("Microsoft.Compute/virtualMachines");
    expect(f.region).toBe("chinanorth3");
    expect(f.source).toBe(AZURE_ALERT_SOURCE);
    expect(f.provider).toBe("azure");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.module).toBe("guardduty_findings");
    expect(f.description).toContain("(type: VM_SuspiciousProcess)");
    expect(f.description).toContain("Intent: Execution");
    expect(f.description).toContain("First seen: 2026-10-26T01:00:00.000Z");
    expect(f.description).toContain("Details: A suspicious process was executed.");
    expect(f.remediationSteps.slice(0, 2)).toEqual(["Review the process tree.", "Escalate to SOC."]);

    // No resource identifier → the alert itself is the resource.
    const m = r.findings[1];
    expect(m.resourceType).toBe("Microsoft.Security/alerts");
    expect(m.resourceArn).toMatch(/\/providers\/Microsoft\.Security\/locations\/chinanorth3\/alerts\/2517-alert-/);

    expect(azureSdk.callsFor(LIST)).toEqual([[]]);
    const ctor = azureSdk.ctorArgs.find((c) => c.client === "SecurityCenter");
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn", credentialScopes: ["https://management.chinacloudapi.cn/.default"] });
  });

  it("no hit: no alerts / only resolved alerts → no findings, no warnings", async () => {
    azureSdk.on(LIST, () => pages([[alert("High", { status: "Resolved" })]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
    expect(r.warnings).toBeUndefined();
  });

  it("pagination: alerts across ≥2 pages", async () => {
    const fetched = { pages: 0 };
    azureSdk.on(LIST, () => pages([[alert("Low")], [alert("High")], [alert("Medium", { status: "Resolved" })]], fetched));
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => f.severity)).toEqual(["HIGH", "LOW"]);
  });

  it("findings cap → overflow warning with per-severity counts", async () => {
    const many = [
      ...Array.from({ length: AZURE_ALERT_MAX_FINDINGS }, () => alert("Low")),
      alert("High"),
      alert("Medium"),
    ];
    azureSdk.on(LIST, () => pages([many]));
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(AZURE_ALERT_MAX_FINDINGS);
    expect(r.findings[0].severity).toBe("HIGH");
    expect(r.findings[1].severity).toBe("MEDIUM");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain(`${AZURE_ALERT_MAX_FINDINGS + 2} active alerts (high 1, medium 1, low ${AZURE_ALERT_MAX_FINDINGS}, informational 0)`);
    expect(r.warnings![0]).toContain(`only the top ${AZURE_ALERT_MAX_FINDINGS}`);
  });

  it("listing cap → truncation warning", async () => {
    azureSdk.on(LIST, () => pages([Array.from({ length: AZURE_ALERT_MAX_ITEMS + 1 }, () => alert("High", { status: "Resolved" }))]));
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(AZURE_ALERT_MAX_ITEMS);
    expect(r.warnings).toEqual([`Defender for Cloud alerts.list: more than ${AZURE_ALERT_MAX_ITEMS} items; results were truncated to the first ${AZURE_ALERT_MAX_ITEMS}.`]);
  });

  it("Microsoft.Security not registered (Azure China) → not_enabled warning, success", async () => {
    azureSdk.on(LIST, () => failingPages(notRegisteredError("Microsoft.Security")));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings![0].startsWith(AZURE_ALERTS_NOT_ENABLED_WARNING)).toBe(true);
    expect(r.warnings![0]).toContain("MissingSubscriptionRegistration");
  });

  it("access_denied → success + warning (token redacted); throttled → warning", async () => {
    azureSdk.on(LIST, () => failingPages(deniedError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0]).toMatch(/alerts.list: insufficient permissions.*security alerts not checked\.$/);
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

    azureSdk.on(LIST, () => failingPages(misuseError(), [alert("High")]));
    const misuse = await scanner.scan(azCtx());
    expect(misuse.status).toBe("error");
    expect(misuse.error).toMatch(/^Defender for Cloud alert scan failed: .*InvalidApiVersionParameter/);
    expect(misuse.findings).toEqual([]);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    azureSdk.on(LIST, () =>
      pages([
        [
          alert("High", {
            id: `/subscriptions/${SUB}/providers/Microsoft.Security/locations/${hostile("loc")}/alerts/${hostile("id")}`,
            name: hostile("name"),
            alertDisplayName: hostile("display"),
            alertType: hostile("type"),
            description: hostile("desc"),
            intent: hostile("intent"),
            compromisedEntity: hostile("entity"),
            productName: hostile("product"),
            alertUri: `https://portal.azure.cn/?token=${FAKE_JWT}`,
            remediationSteps: [hostile("step")],
            resourceIdentifiers: [{ type: "AzureResource", azureResourceId: vmId(hostile("vm")) }],
          }),
          alert(hostile("sev"), { status: hostile("status") }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");
    expect(r.findings[0].description).toContain("[REDACTED]");
    expect(r.findings[0].remediationSteps[0]).toContain("[REDACTED]");
  });

  it("hostile error message on the listing never leaks", async () => {
    azureSdk.on(LIST, () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expectNoLeak(r);
  });
});

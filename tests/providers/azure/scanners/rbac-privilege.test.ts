/**
 * Phase 2 (Azure) T6 — AzureRbacPrivilegeScanner (iam_privilege_escalation, tenant-level global
 * module): RBAC role assignments across every visible subscription (Owner / UAA / Contributor
 * without MFA / guest + foreign principals / excessive owners), custom-role wildcard matching,
 * roleDefinition cache + getById, classic co-administrators, Entra directory roles via Graph;
 * pagination, caps, per-part degrade (Graph 403 → success + warning), error matrix and
 * hostile-field redaction. Every `@azure/*` / Graph package is mocked; fake service principal
 * only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
// Like fakeArmClientClass, but every call also receives `{ sub }` (the client's subscription) as
// its last argument, so per-subscription data can be routed under concurrency.
vi.mock("@azure/arm-authorization", async () => {
  const { azureSdk } = await import("./helpers.js");
  class FakeAuthClient {
    constructor(...args: unknown[]) {
      azureSdk.ctorArgs.push({ client: "Auth", args });
      const sub = String(args[1]);
      const group = (g: string) =>
        new Proxy({}, { get: (_t, m) => (typeof m !== "string" || m === "then" ? undefined : (...a: unknown[]) => azureSdk.invoke(`Auth.${g}.${m}`, [...a, { sub }])) });
      return new Proxy({}, { get: (_t, g) => (typeof g !== "string" || g === "then" ? undefined : group(g)) });
    }
  }
  return { AuthorizationManagementClient: FakeAuthClient };
});
vi.mock("@azure/arm-resources-subscriptions", async () => ({ SubscriptionClient: (await import("./helpers.js")).fakeArmClientClass("Subs") }));
vi.mock("@microsoft/microsoft-graph-client", async () => {
  const { azureSdk } = await import("./helpers.js");
  return {
    Client: {
      initWithMiddleware: (opts: unknown) => {
        azureSdk.ctorArgs.push({ client: "Graph", args: [opts] });
        return {
          api: (path: string) => ({
            get: async () => azureSdk.invoke("Graph.get", [path]),
            post: async (body: unknown) => azureSdk.invoke("Graph.post", [path, body]),
          }),
        };
      },
    },
  };
});

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS,
  AZURE_IAM_MAX_SUBSCRIPTIONS,
  AZURE_ROLE_CONTRIBUTOR,
  AZURE_ROLE_OWNER,
  AZURE_ROLE_USER_ACCESS_ADMIN,
  AzureRbacPrivilegeScanner,
  ENTRA_GLOBAL_ADMIN_TEMPLATE,
  ENTRA_PRIVILEGED_ROLE_ADMIN_TEMPLATE,
  azureActionMatches,
  azureIsGuestPrincipal,
  azureRoleEscalationActions,
  azureRoleGrantsAction,
  azureRoleHasFullWildcard,
  azureScopeKind,
} from "../../../../src/providers/azure/scanners/rbac-privilege.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
  FAKE_JWT,
  FAKE_SECRET,
  FAKE_TENANT,
  hostile,
  isolateAzureEnv,
  misuseError,
  pages,
  restoreAzureEnv,
  SUB,
} from "./helpers.js";

const SUB2 = "bbbbbbbb-0000-0000-0000-00000000fake";
const MG = "/providers/Microsoft.Management/managementGroups/mg-root";

const SUBS_LIST = "Subs.subscriptions.list";
const ASSIGNMENTS = "Auth.roleAssignments.listForSubscription";
const ROLE_DEFS = "Auth.roleDefinitions.list";
const ROLE_GET = "Auth.roleDefinitions.getById";
const CLASSIC = "Auth.classicAdministrators.list";
const GRAPH_GET = "Graph.get";
const GRAPH_POST = "Graph.post";

const guid = (n: number) => `${String(n).padStart(8, "0")}-1111-2222-3333-444444444444`;
const roleDefId = (sub: string, g: string) => `/subscriptions/${sub}/providers/Microsoft.Authorization/roleDefinitions/${g}`;
const CUSTOM_ESC = "c0000000-0000-0000-0000-000000000001";
const CUSTOM_SAFE = "c0000000-0000-0000-0000-000000000002";
const CUSTOM_STAR = "c0000000-0000-0000-0000-000000000003";
const READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7";

let assignmentSeq = 0;
function assignment(o: { scope: string; role: string; principal: string; type?: string; sub?: string; extra?: Record<string, unknown> }) {
  const name = `a${String(++assignmentSeq).padStart(7, "0")}-0000-0000-0000-000000000000`;
  const scope = o.scope;
  return {
    id: `${scope === "/" ? "" : scope}/providers/Microsoft.Authorization/roleAssignments/${name}`,
    name,
    type: "Microsoft.Authorization/roleAssignments",
    scope,
    roleDefinitionId: roleDefId(o.sub ?? SUB, o.role),
    principalId: o.principal,
    principalType: o.type ?? "User",
    ...o.extra,
  };
}

const customRole = (g: string, roleName: string, permissions: unknown[], extra: Record<string, unknown> = {}) => ({
  id: roleDefId(SUB, g),
  name: g,
  roleName,
  roleType: "CustomRole",
  permissions,
  assignableScopes: [`/subscriptions/${SUB}`],
  ...extra,
});

const readerDef = (id: string) => ({ id, name: READER, roleName: "Reader", roleType: "BuiltInRole", permissions: [{ actions: ["*/read"] }] });

const subRef = (subscriptionId: string, state = "Enabled") => ({ subscriptionId, tenantId: FAKE_TENANT, displayName: `sub ${subscriptionId}`, state });

interface GraphRoutes {
  principals?: unknown[] | ((body: unknown) => unknown);
  directoryRoles?: unknown;
  members?: Record<string, unknown>;
  mfa?: Record<string, boolean> | ((path: string) => unknown);
}

function routeGraph(g: GraphRoutes = {}) {
  azureSdk.on(GRAPH_POST, (path: unknown, body: unknown) => {
    if (path !== "/directoryObjects/getByIds") throw new Error(`unexpected Graph POST ${String(path)}`);
    return typeof g.principals === "function" ? g.principals(body) : { value: g.principals ?? [] };
  });
  azureSdk.on(GRAPH_GET, (p: unknown) => {
    const path = String(p);
    if (path === "/directoryRoles") {
      if (typeof g.directoryRoles === "function") return (g.directoryRoles as () => unknown)();
      return g.directoryRoles ?? { value: [] };
    }
    const m = /^\/directoryRoles\/([^/]+)\/members$/.exec(path);
    if (m) {
      const v = g.members?.[m[1]];
      if (typeof v === "function") return (v as () => unknown)();
      if (v !== undefined) return v;
      return { value: [] };
    }
    if (g.members?.[path] !== undefined) {
      const v = g.members[path];
      return typeof v === "function" ? (v as () => unknown)() : v;
    }
    const u = /^\/reports\/authenticationMethods\/userRegistrationDetails\/([^/]+)$/.exec(path);
    if (u) {
      if (typeof g.mfa === "function") return g.mfa(path);
      return { id: u[1], isMfaRegistered: g.mfa?.[u[1]] ?? true };
    }
    throw new Error(`unexpected Graph GET ${path}`);
  });
}

interface ArmRoutes {
  subs?: unknown;
  assignments?: Record<string, unknown> | unknown;
  customRoles?: Record<string, unknown> | unknown;
  getById?: unknown;
  classic?: Record<string, unknown> | unknown;
}

function perSub(v: unknown, sub: string): unknown {
  if (v && typeof v === "object" && !Array.isArray(v) && (SUB in (v as object) || SUB2 in (v as object))) {
    return (v as Record<string, unknown>)[sub] ?? [];
  }
  return v;
}

function asIter(v: unknown, ...args: unknown[]): unknown {
  if (typeof v === "function") return (v as (...a: unknown[]) => unknown)(...args);
  if (Array.isArray(v) && v.length > 0 && Array.isArray(v[0])) return pages(v as unknown[][]);
  return pages([(v as unknown[]) ?? []]);
}

/** ARM routing; per-subscription values are `{ [SUB]: …, [SUB2]: … }` maps. */
function routeArm(r: ArmRoutes = {}) {
  azureSdk.on(SUBS_LIST, () => asIter(r.subs ?? [[subRef(SUB)]]));
  azureSdk.on(ASSIGNMENTS, (...a: unknown[]) => asIter(perSub(r.assignments ?? [], subArg(a))));
  azureSdk.on(ROLE_DEFS, (...a: unknown[]) => asIter(perSub(r.customRoles ?? [], subArg(a))));
  azureSdk.on(CLASSIC, (...a: unknown[]) => asIter(perSub(r.classic ?? [], subArg(a))));
  azureSdk.on(ROLE_GET, r.getById ?? ((id: unknown) => { throw new Error(`unexpected getById ${String(id)}`); }));
}

const subArg = (args: unknown[]): string => String((args[args.length - 1] as { sub?: string })?.sub ?? SUB);

const scanner = new AzureRbacPrivilegeScanner();
let stdoutWrites: string[];

beforeEach(() => {
  isolateAzureEnv();
  clearAzureCredentialCache();
  azureSdk.reset();
  assignmentSeq = 0;
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

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

describe("pure helpers", () => {
  it.each([
    ["*", "Microsoft.Authorization/roleAssignments/write", true],
    ["Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/write", true],
    ["microsoft.authorization/*/write", "Microsoft.Authorization/roleAssignments/write", true],
    ["Microsoft.Authorization/*/read", "Microsoft.Authorization/roleAssignments/write", false],
    ["*/write", "Microsoft.Authorization/roleDefinitions/write", true],
    ["Microsoft.Compute/*", "Microsoft.Authorization/roleAssignments/write", false],
    ["Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleAssignments/write", true],
    ["Microsoft.Authorization/roleAssignments/(write)", "Microsoft.Authorization/roleAssignments/write", false],
    ["", "anything", false],
  ])("azureActionMatches(%s, %s) = %s", (pattern, action, expected) => {
    expect(azureActionMatches(pattern, action)).toBe(expected);
  });

  it("actions minus notActions, per permission block", () => {
    const write = "Microsoft.Authorization/roleAssignments/write";
    expect(azureRoleGrantsAction([{ actions: ["*"], notActions: ["Microsoft.Authorization/*/write"] }], write)).toBe(false);
    expect(azureRoleGrantsAction([{ actions: ["*"], notActions: ["Microsoft.Authorization/*/Delete"] }], write)).toBe(true);
    // A notAction in one block does not cancel another block's grant.
    expect(azureRoleGrantsAction([{ actions: ["*/read"] }, { actions: ["Microsoft.Authorization/*"], notActions: [] }], write)).toBe(true);
    expect(azureRoleGrantsAction(undefined, write)).toBe(false);
    expect(azureRoleGrantsAction([{ actions: [42, null] }], write)).toBe(false);
    expect(azureRoleEscalationActions([{ actions: ["Microsoft.Authorization/roleAssignments/*"] }])).toEqual([write]);
    expect(azureRoleEscalationActions([{ actions: ["*/read"] }])).toEqual([]);
    expect(azureRoleHasFullWildcard([{ actions: ["Microsoft.Compute/*"] }, { actions: [" * "] }])).toBe(true);
    expect(azureRoleHasFullWildcard([{ actions: ["Microsoft.Compute/*"] }])).toBe(false);
  });

  it.each([
    ["/", "root"],
    [MG, "managementGroup"],
    [`/subscriptions/${SUB}`, "subscription"],
    [`/subscriptions/${SUB}/`, "subscription"],
    [`/subscriptions/${SUB}/resourceGroups/rg1`, "resourceGroup"],
    [`/subscriptions/${SUB}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa`, "resource"],
    [undefined, "unknown"],
    ["weird", "unknown"],
  ])("azureScopeKind(%s) = %s", (scope, kind) => {
    expect(azureScopeKind(scope)).toBe(kind);
  });

  it("guest detection", () => {
    expect(azureIsGuestPrincipal({ userType: "Guest" })).toBe(true);
    expect(azureIsGuestPrincipal({ userType: "Member", userPrincipalName: "bob_contoso.com#EXT#@fake.partner.onmschina.cn" })).toBe(true);
    expect(azureIsGuestPrincipal({ userType: "Member", userPrincipalName: "alice@fake.partner.onmschina.cn" })).toBe(false);
    expect(azureIsGuestPrincipal(undefined)).toBe(false);
  });
});

/* ------------------------------------------------------------------------ */
/* Findings                                                                 */
/* ------------------------------------------------------------------------ */

const U_OWNER = guid(1);
const SP_OWNER = guid(2);
const GUEST_OWNER = guid(3);
const U_UAA = guid(4);
const U_CONTRIB_NOMFA = guid(5);
const U_CONTRIB_MFA = guid(6);
const FOREIGN = guid(7);
const U_READER = guid(8);
const U_CUSTOM = guid(9);
const U_RG_OWNER = guid(10);
const U_CUSTOM2 = guid(11);
const GA_ROLE = "d0000000-0000-0000-0000-000000000001";
const PRA_ROLE = "d0000000-0000-0000-0000-000000000002";
const OTHER_ROLE = "d0000000-0000-0000-0000-000000000003";

function fullFixture() {
  const sub = `/subscriptions/${SUB}`;
  const mgGuestOwner = assignment({ scope: MG, role: AZURE_ROLE_OWNER, principal: GUEST_OWNER });
  return {
    subs: [[subRef(SUB)], [subRef(SUB2), subRef("cccccccc-0000-0000-0000-00000000fake", "Disabled")]],
    assignments: {
      [SUB]: [
        [
          assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: U_OWNER }),
          assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: SP_OWNER, type: "ServicePrincipal" }),
          mgGuestOwner,
          assignment({ scope: `${sub}/resourceGroups/rg-app`, role: AZURE_ROLE_USER_ACCESS_ADMIN, principal: U_UAA }),
        ],
        [
          assignment({ scope: sub, role: AZURE_ROLE_CONTRIBUTOR, principal: U_CONTRIB_NOMFA }),
          assignment({ scope: sub, role: AZURE_ROLE_CONTRIBUTOR, principal: U_CONTRIB_MFA }),
          assignment({ scope: sub, role: READER, principal: FOREIGN, type: "ForeignGroup" }),
          assignment({ scope: sub, role: READER, principal: U_READER }),
          assignment({ scope: sub, role: CUSTOM_ESC, principal: U_CUSTOM }),
          assignment({ scope: `${sub}/resourceGroups/rg-app`, role: AZURE_ROLE_OWNER, principal: U_RG_OWNER }),
          assignment({ scope: sub, role: CUSTOM_STAR, principal: U_CUSTOM2 }),
        ],
      ],
      // The MG-level assignment is returned for both subscriptions (same ID → one finding).
      [SUB2]: [mgGuestOwner],
    },
    customRoles: {
      [SUB]: [
        customRole(CUSTOM_ESC, "Delegated access admin", [{ actions: ["Microsoft.Authorization/roleAssignments/*", "*/read"], notActions: [] }]),
        customRole(CUSTOM_SAFE, "VM operator", [{ actions: ["Microsoft.Compute/virtualMachines/*"], notActions: [] }]),
      ],
    },
    // CUSTOM_STAR is assigned but assignable at MG level only → resolved via getById (once).
    getById: (id: unknown) =>
      String(id).endsWith(CUSTOM_STAR)
        ? customRole(CUSTOM_STAR, "Everything but delete", [{ actions: ["*"], notActions: ["*/delete"] }], { id: String(id) })
        : readerDef(String(id)),
    classic: {
      [SUB]: [
        { id: `/subscriptions/${SUB}/providers/Microsoft.Authorization/classicAdministrators/svc`, name: "svc", emailAddress: "svc@fake.partner.onmschina.cn", role: "ServiceAdministrator;AccountAdministrator" },
        { id: `/subscriptions/${SUB}/providers/Microsoft.Authorization/classicAdministrators/co1`, name: "co1", emailAddress: "coadmin@fake.partner.onmschina.cn", role: "CoAdministrator" },
      ],
    },
  };
}

const fullGraph = (): GraphRoutes => ({
  principals: [
    { "@odata.type": "#microsoft.graph.user", id: U_OWNER, displayName: "Owner User", userPrincipalName: "owner@fake.partner.onmschina.cn", userType: "Member" },
    { "@odata.type": "#microsoft.graph.servicePrincipal", id: SP_OWNER, displayName: "deploy-sp" },
    { "@odata.type": "#microsoft.graph.user", id: GUEST_OWNER, displayName: "Guest", userPrincipalName: "ext_partner.com#EXT#@fake.partner.onmschina.cn", userType: "Guest" },
    { "@odata.type": "#microsoft.graph.user", id: U_CONTRIB_NOMFA, userPrincipalName: "nomfa@fake.partner.onmschina.cn", userType: "Member" },
    { "@odata.type": "#microsoft.graph.user", id: U_CONTRIB_MFA, userPrincipalName: "mfa@fake.partner.onmschina.cn", userType: "Member" },
  ],
  mfa: { [U_CONTRIB_NOMFA]: false, [U_CONTRIB_MFA]: true },
  directoryRoles: {
    value: [
      { id: GA_ROLE, displayName: "Global Administrator", roleTemplateId: ENTRA_GLOBAL_ADMIN_TEMPLATE },
      { id: PRA_ROLE, displayName: "Privileged Role Administrator", roleTemplateId: ENTRA_PRIVILEGED_ROLE_ADMIN_TEMPLATE },
      { id: OTHER_ROLE, displayName: "Directory Readers", roleTemplateId: "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" },
    ],
  },
  members: {
    // GA: more than the threshold, across two pages (nextLink on the China Graph host).
    [GA_ROLE]: {
      value: Array.from({ length: 3 }, (_, i) => ({ id: guid(100 + i), userPrincipalName: `ga${i}@fake.partner.onmschina.cn`, userType: "Member" })),
      "@odata.nextLink": `https://microsoftgraph.chinacloudapi.cn/v1.0/directoryRoles/${GA_ROLE}/members?$skiptoken=page2`,
    },
    [`https://microsoftgraph.chinacloudapi.cn/v1.0/directoryRoles/${GA_ROLE}/members?$skiptoken=page2`]: {
      value: Array.from({ length: AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS - 2 }, (_, i) => ({ id: guid(200 + i), userPrincipalName: `gb${i}@fake.partner.onmschina.cn` })),
    },
    [PRA_ROLE]: { value: [{ id: guid(300), userPrincipalName: "pra_ext.com#EXT#@fake.partner.onmschina.cn", userType: "Guest" }] },
  },
});

const byTitle = (r: { findings: Array<{ title: string }> }, re: RegExp) => r.findings.filter((f) => re.test(f.title));

describe("AzureRbacPrivilegeScanner — findings", () => {
  it("covers Owner / SP Owner / guest Owner / UAA / Contributor without MFA / foreign / custom wildcard / getById / classic / Entra roles", async () => {
    const fx = fullFixture();
    routeArm(fx);
    routeGraph(fullGraph());
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.module).toBe("iam_privilege_escalation");
    expect(r.warnings).toBeUndefined();

    const owner = byTitle(r, /^Owner role assigned to User owner@/);
    expect(owner).toHaveLength(1);
    expect(owner[0].riskScore).toBe(8.0);
    expect(owner[0].severity).toBe("HIGH");
    expect(owner[0].resourceArn).toMatch(new RegExp(`^/subscriptions/${SUB}/providers/Microsoft.Authorization/roleAssignments/`));
    expect(owner[0].region).toBe("global");
    expect(owner[0].accountId).toBe(FAKE_TENANT);
    expect(owner[0].provider).toBe("azure");

    expect(byTitle(r, /^Owner role assigned to ServicePrincipal deploy-sp/)[0].riskScore).toBe(7.5);

    const guest = byTitle(r, /^Owner role assigned to User ext_partner\.com#EXT#/);
    expect(guest).toHaveLength(1); // deduplicated across both subscriptions
    expect(guest[0].riskScore).toBe(9.0);
    expect(guest[0].severity).toBe("CRITICAL");
    expect(guest[0].title).toContain("managementGroup scope");
    expect(guest[0].description).toContain(SUB);
    expect(guest[0].description).toContain(SUB2);

    const uaa = byTitle(r, /^User Access Administrator role assigned/);
    expect(uaa).toHaveLength(1);
    expect(uaa[0].riskScore).toBe(8.0);
    expect(uaa[0].title).toContain("resourceGroup scope");

    const nomfa = byTitle(r, /^Contributor role assigned/);
    expect(nomfa).toHaveLength(1);
    expect(nomfa[0].title).toContain("nomfa@");
    expect(nomfa[0].riskScore).toBe(6.0);
    expect(nomfa[0].severity).toBe("MEDIUM");

    const foreign = r.findings.filter((f) => f.title.includes("ForeignGroup"));
    expect(foreign).toHaveLength(1);
    expect(foreign[0].riskScore).toBe(7.5);

    // Plain Reader, RG-scoped Owner, custom-role holders (non-external) → no assignment finding.
    expect(r.findings.some((f) => f.description.includes(U_READER))).toBe(false);
    expect(r.findings.some((f) => f.description.includes(U_RG_OWNER))).toBe(false);

    const custom = r.findings.filter((f) => f.resourceType === "Microsoft.Authorization/roleDefinitions");
    expect(custom.map((f) => f.resourceId).sort()).toEqual(["Delegated access admin", "Everything but delete"]);
    for (const f of custom) expect(f.riskScore).toBe(8.0);
    expect(custom.find((f) => f.resourceId === "Everything but delete")!.title).toContain("all actions (*)");
    expect(custom.find((f) => f.resourceId === "Delegated access admin")!.description).toContain("1 role assignment(s)");

    const classic = r.findings.filter((f) => f.resourceType === "Microsoft.Authorization/classicAdministrators");
    expect(classic).toHaveLength(1);
    expect(classic[0].title).toContain("coadmin@");
    expect(classic[0].riskScore).toBe(5.0);

    const entra = r.findings.filter((f) => f.resourceType === "microsoft.graph.directoryRole");
    expect(entra.map((f) => f.resourceArn).sort()).toEqual([`/directoryRoles/${GA_ROLE}`, `/directoryRoles/${PRA_ROLE}`]);
    const ga = entra.find((f) => f.resourceArn.endsWith(GA_ROLE))!;
    expect(ga.riskScore).toBe(7.5);
    expect(ga.title).toBe(`Entra ID Global Administrator role: ${AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS + 1} members`);
    expect(ga.description).toContain(`${AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS + 1} members`);
    expect(entra.find((f) => f.resourceArn.endsWith(PRA_ROLE))!.description).toContain("1 guest member(s)");

    expect(r.findingsCount).toBe(r.findings.length);
    expect(r.findings).toHaveLength(11); // 6 assignments + 2 custom roles + 1 classic + 2 Entra roles (3 owners: not excessive)
    expect(r.resourcesScanned).toBeGreaterThan(10);

    // Calls: 2 active subscriptions (disabled skipped); role defs listed per subscription with the
    // CustomRole filter; CUSTOM_STAR resolved once; MFA only for broad-scope Contributor users.
    expect(azureSdk.callsFor(ASSIGNMENTS)).toHaveLength(2);
    const defCalls = azureSdk.callsFor(ROLE_DEFS);
    expect(defCalls.map((c) => c[0]).sort()).toEqual([`/subscriptions/${SUB}`, `/subscriptions/${SUB2}`]);
    expect(defCalls[0][1]).toEqual({ filter: "type eq 'CustomRole'" });
    expect(azureSdk.callsFor(ROLE_GET).map((c) => c[0]).sort()).toEqual([roleDefId(SUB, CUSTOM_STAR), roleDefId(SUB, READER)].sort());
    const mfaCalls = azureSdk.callsFor(GRAPH_GET).map((c) => String(c[0])).filter((p) => p.includes("userRegistrationDetails"));
    expect(mfaCalls.sort()).toEqual([U_CONTRIB_NOMFA, U_CONTRIB_MFA].map((u) => `/reports/authenticationMethods/userRegistrationDetails/${u}`).sort());
    const post = azureSdk.callsFor(GRAPH_POST);
    expect(post).toHaveLength(1);
    expect((post[0][1] as { ids: string[] }).ids).toHaveLength(11);
    // Every ARM client is built for the China endpoint + scope; the Graph client for the China baseUrl.
    for (const c of azureSdk.ctorArgs.filter((a) => a.client === "Auth")) {
      expect(c.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn", credentialScopes: ["https://management.chinacloudapi.cn/.default"] });
    }
    expect(azureSdk.ctorArgs.find((a) => a.client === "Graph")!.args[0]).toMatchObject({ baseUrl: "https://microsoftgraph.chinacloudapi.cn/" });
  });

  it("more than 3 distinct Owner principals on a subscription (incl. inherited) → 9.0 per subscription", async () => {
    const sub = `/subscriptions/${SUB}`;
    routeArm({
      assignments: [
        assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(1) }),
        assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(2) }),
        assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(2) }), // duplicate principal
        assignment({ scope: MG, role: AZURE_ROLE_OWNER, principal: guid(3) }),
        assignment({ scope: "/", role: AZURE_ROLE_OWNER, principal: guid(4) }),
        assignment({ scope: `${sub}/resourceGroups/rg`, role: AZURE_ROLE_OWNER, principal: guid(5) }), // RG: not counted
      ],
    });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    const many = r.findings.filter((f) => f.resourceType === "Microsoft.Resources/subscriptions");
    expect(many).toHaveLength(1);
    expect(many[0].riskScore).toBe(9.0);
    expect(many[0].title).toContain("4 Owner principals");
    expect(many[0].resourceArn).toBe(`/subscriptions/${SUB}`);
    expect(byTitle(r, /root scope$/)).toHaveLength(1);
  });

  it("no hit: least-privilege tenant → success, no findings, no warnings", async () => {
    routeArm({
      assignments: [assignment({ scope: `/subscriptions/${SUB}`, role: READER, principal: guid(1) })],
      customRoles: [customRole(CUSTOM_SAFE, "VM operator", [{ actions: ["Microsoft.Compute/*"] }])],
      classic: [{ name: "svc", emailAddress: "svc@fake.partner.onmschina.cn", role: "ServiceAdministrator" }],
      getById: (rid: unknown) => readerDef(String(rid)),
    });
    routeGraph({
      principals: [{ id: guid(1), userType: "Member", userPrincipalName: "r@fake.partner.onmschina.cn" }],
      directoryRoles: { value: [{ id: GA_ROLE, roleTemplateId: ENTRA_GLOBAL_ADMIN_TEMPLATE }] },
      members: { [GA_ROLE]: { value: [{ id: guid(9), userType: "Member" }] } },
    });
    const r = await scanner.scan(azCtx());
    expect(r).toMatchObject({ status: "success", findingsCount: 0, findings: [] });
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(4); // 1 assignment + 1 custom role + 1 classic admin + 1 directory role
  });

  it("paginates role assignments (≥ 2 pages) and the subscription list", async () => {
    const fetched = { pages: 0 };
    const sub = `/subscriptions/${SUB}`;
    routeArm({
      assignments: () =>
        pages(
          [
            [assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(1) })],
            [assignment({ scope: sub, role: AZURE_ROLE_USER_ACCESS_ADMIN, principal: guid(2) })],
            [assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(3) })],
          ],
          fetched,
        ),
    });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    expect(r.findings).toHaveLength(3);
  });

  it("role definition cache: one getById per distinct unknown role, built-ins never looked up", async () => {
    const sub = `/subscriptions/${SUB}`;
    const unknown = "e0000000-0000-0000-0000-000000000001";
    routeArm({
      assignments: [
        assignment({ scope: sub, role: unknown, principal: guid(1) }),
        assignment({ scope: `${sub}/resourceGroups/a`, role: unknown, principal: guid(2) }),
        assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(3) }),
        assignment({ scope: sub, role: AZURE_ROLE_CONTRIBUTOR, principal: guid(4), type: "Group" }),
      ],
      getById: () => ({ id: roleDefId(SUB, unknown), roleName: "Backup Reader", roleType: "BuiltInRole", permissions: [{ actions: ["*/read"] }] }),
    });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(azureSdk.callsFor(ROLE_GET)).toHaveLength(1);
    expect(r.findings).toHaveLength(1); // the Owner only
  });
});

/* ------------------------------------------------------------------------ */
/* Scope / subscriptions                                                    */
/* ------------------------------------------------------------------------ */

describe("AzureRbacPrivilegeScanner — subscription coverage", () => {
  it("AZURE_SUBSCRIPTION_ID pins the RBAC scan to that subscription (no enumeration)", async () => {
    process.env.AZURE_SUBSCRIPTION_ID = SUB2;
    routeArm({ assignments: [] });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(azureSdk.callsFor(SUBS_LIST)).toHaveLength(0);
    expect(azureSdk.ctorArgs.filter((c) => c.client === "Auth").map((c) => c.args[1])).toEqual([SUB2]);
  });

  it("caps the number of subscriptions with a truncation warning", async () => {
    const many = Array.from({ length: AZURE_IAM_MAX_SUBSCRIPTIONS + 3 }, (_, i) => subRef(`${String(i).padStart(8, "0")}-0000-0000-0000-00000000fake`));
    routeArm({ subs: [many], assignments: [] });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(azureSdk.callsFor(ASSIGNMENTS)).toHaveLength(AZURE_IAM_MAX_SUBSCRIPTIONS);
    expect(r.warnings!.some((w) => w.includes(`more than ${AZURE_IAM_MAX_SUBSCRIPTIONS}`))).toBe(true);
  });

  it("subscription enumeration denied → scans the context subscription + warning", async () => {
    routeArm({ subs: () => failingPages(deniedError()), assignments: [assignment({ scope: `/subscriptions/${SUB}`, role: AZURE_ROLE_OWNER, principal: guid(1) })] });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings!.some((w) => /subscriptions\.list.*insufficient permissions/.test(w))).toBe(true);
  });

  it("no subscription at all (placeholder scope) → Entra-only scan with a warning", async () => {
    routeArm({ subs: [[]] });
    routeGraph({
      directoryRoles: { value: [{ id: PRA_ROLE, roleTemplateId: ENTRA_PRIVILEGED_ROLE_ADMIN_TEMPLATE }] },
      members: { [PRA_ROLE]: { value: [{ id: guid(1), userType: "Guest", userPrincipalName: "g#EXT#@x" }] } },
    });
    const r = await scanner.scan(azCtx({ subscriptionId: undefined, region: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(azureSdk.callsFor(ASSIGNMENTS)).toHaveLength(0);
    expect(r.findings).toHaveLength(1);
    expect(r.warnings!.some((w) => w.includes("no Azure subscription visible"))).toBe(true);
  });
});

/* ------------------------------------------------------------------------ */
/* Degrade / error matrix                                                   */
/* ------------------------------------------------------------------------ */

function graphError(statusCode: number, code: string, message: string): Error {
  return Object.assign(new Error(message), { name: "GraphError", statusCode, code, requestId: "graph-req-fake", body: JSON.stringify({ error: { code, message } }) });
}
const graphDenied = () => graphError(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.");

describe("AzureRbacPrivilegeScanner — degrade and errors", () => {
  it("RBAC works but Graph 403 everywhere → success + warnings, RBAC findings still reported", async () => {
    const sub = `/subscriptions/${SUB}`;
    routeArm({
      assignments: [
        assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(1) }),
        assignment({ scope: sub, role: AZURE_ROLE_CONTRIBUTOR, principal: guid(2) }),
        assignment({ scope: sub, role: READER, principal: guid(3), type: "ForeignGroup" }),
      ],
    });
    azureSdk.on(GRAPH_POST, () => { throw graphDenied(); });
    azureSdk.on(GRAPH_GET, () => { throw graphDenied(); });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.riskScore).sort()).toEqual([7.5, 8.0]); // Owner + ForeignGroup (no Graph needed)
    const w = r.warnings!.join("\n");
    expect(w).toMatch(/directoryObjects\.getByIds: insufficient permissions.*Authorization_RequestDenied/);
    expect(w).toMatch(/userRegistrationDetails: insufficient permissions/);
    expect(w).toMatch(/directoryRoles: insufficient permissions.*Entra ID privileged directory roles not checked/);
    expect(r.error).toBeUndefined();
  });

  it("Graph unavailable in the China cloud (404) → warning, not error", async () => {
    routeArm({ assignments: [] });
    azureSdk.on(GRAPH_POST, () => ({ value: [] }));
    azureSdk.on(GRAPH_GET, () => { throw graphError(404, "Request_ResourceNotFound", "Resource not found for the segment 'directoryRoles'."); });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings!.some((w) => w.includes("directoryRoles") && w.includes("not found"))).toBe(true);
  });

  it("role assignments 403 on one subscription → warning; the other subscription is still scanned", async () => {
    routeArm({ subs: [[subRef(SUB), subRef(SUB2)]] });
    azureSdk.on(ASSIGNMENTS, (...a: unknown[]) =>
      subArg(a) === SUB2
        ? failingPages(deniedError())
        : pages([[assignment({ scope: `/subscriptions/${SUB}`, role: AZURE_ROLE_OWNER, principal: guid(1) })]]),
    );
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings!.some((w) => w.includes(`roleAssignments.listForSubscription (subscription ${SUB2}): insufficient permissions`))).toBe(true);
  });

  it("classicAdministrators deprecated (api_misuse / 403) → warning only", async () => {
    routeArm({ assignments: [], classic: () => failingPages(misuseError()) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings!.some((w) => w.includes("classicAdministrators.list") && w.includes("deprecated"))).toBe(true);
  });

  it("custom role listing denied → warning; getById failure → aggregated warning", async () => {
    routeArm({
      assignments: [assignment({ scope: `/subscriptions/${SUB}`, role: CUSTOM_ESC, principal: guid(1) })],
      customRoles: () => failingPages(deniedError()),
      getById: () => { throw deniedError(); },
    });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    const w = r.warnings!.join("\n");
    expect(w).toContain("custom role definitions not checked");
    expect(w).toContain("1 referenced role definition(s) not resolved");
  });

  it("auth_failed (fake service principal: AADSTS900023) on subscription enumeration → status error", async () => {
    routeArm({ subs: () => failingPages(authError()) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(r.error).toContain("AADSTS900023");
    expect(azureSdk.callsFor(GRAPH_GET)).toHaveLength(0);
    expectNoLeak(r);
  });

  it("auth_failed on role assignments → status error", async () => {
    routeArm({ assignments: () => failingPages(authError()) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("auth_failed on the classic administrator API is NOT degraded", async () => {
    routeArm({ assignments: [], classic: () => failingPages(authError()) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("auth_failed on Graph (401 InvalidAuthenticationToken) → status error", async () => {
    routeArm({ assignments: [assignment({ scope: `/subscriptions/${SUB}`, role: AZURE_ROLE_OWNER, principal: guid(1) })] });
    azureSdk.on(GRAPH_POST, () => { throw graphError(401, "InvalidAuthenticationToken", "Access token validation failure."); });
    azureSdk.on(GRAPH_GET, () => ({ value: [] }));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("api_misuse on role assignments → status error", async () => {
    routeArm({ assignments: () => failingPages(misuseError()) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("InvalidApiVersionParameter");
    expect(r.error!.startsWith("Azure RBAC / Entra privilege scan failed")).toBe(true);
  });

  it("missing credentials → status error naming env vars only", async () => {
    const r = await scanner.scan(azCtx({ credentials: undefined }));
    expect(r.status).toBe("error");
    expect(r.error).toContain("AZURE_CLIENT_SECRET");
  });

  it("does not follow an @odata.nextLink outside the cloud's Graph host", async () => {
    routeArm({ assignments: [] });
    routeGraph({
      directoryRoles: { value: [{ id: GA_ROLE, roleTemplateId: ENTRA_GLOBAL_ADMIN_TEMPLATE }] },
      members: { [GA_ROLE]: { value: [{ id: guid(1) }], "@odata.nextLink": "https://evil.example.com/steal?x=1" } },
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    const paths = azureSdk.callsFor(GRAPH_GET).map((c) => String(c[0]));
    expect(paths.some((p) => p.includes("evil.example.com"))).toBe(false);
    expect(r.warnings!.some((w) => w.includes("nextLink outside the Graph endpoint"))).toBe(true);
  });

  it("never interpolates non-GUID server IDs into Graph paths", async () => {
    routeArm({ assignments: [assignment({ scope: `/subscriptions/${SUB}`, role: AZURE_ROLE_CONTRIBUTOR, principal: "../../me" })] });
    routeGraph({ directoryRoles: { value: [{ id: "../users", roleTemplateId: ENTRA_GLOBAL_ADMIN_TEMPLATE }] } });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    const paths = azureSdk.callsFor(GRAPH_GET).map((c) => String(c[0]));
    expect(paths).toEqual(["/directoryRoles"]);
    expect(azureSdk.callsFor(GRAPH_POST)).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------------ */
/* Hostile fields                                                           */
/* ------------------------------------------------------------------------ */

describe("AzureRbacPrivilegeScanner — hostile server strings", () => {
  it("fake secret / JWT in names, UPNs, scopes, actions, e-mails and error messages never reach the output", async () => {
    const sub = `/subscriptions/${SUB}`;
    const hostileErr = Object.assign(deniedError(), { message: hostile("denied") });
    routeArm({
      subs: [[subRef(SUB), subRef(SUB2)]],
      assignments: {
        [SUB]: [
          assignment({ scope: sub, role: AZURE_ROLE_OWNER, principal: guid(1), extra: { name: hostile("assignment"), condition: hostile("cond") } }),
          assignment({ scope: `${sub}/resourceGroups/${FAKE_JWT}`, role: AZURE_ROLE_USER_ACCESS_ADMIN, principal: guid(2), type: hostile("type") }),
          assignment({ scope: sub, role: CUSTOM_ESC, principal: guid(3) }),
        ],
        [SUB2]: () => failingPages(hostileErr),
      },
      customRoles: {
        [SUB]: [customRole(CUSTOM_ESC, hostile("role"), [{ actions: ["*", hostile("action")] }], { assignableScopes: [hostile("scope")] })],
      },
      classic: { [SUB]: [{ name: hostile("co"), emailAddress: `${FAKE_SECRET}@x`, role: "CoAdministrator" }] },
    });
    routeGraph({
      principals: [
        { id: guid(1), displayName: hostile("display"), userPrincipalName: `${FAKE_JWT}#EXT#@x`, userType: "Guest" },
        { id: guid(2), displayName: hostile("uaa") },
      ],
      directoryRoles: { value: [{ id: GA_ROLE, roleTemplateId: ENTRA_GLOBAL_ADMIN_TEMPLATE, displayName: hostile("ga") }] },
      members: { [GA_ROLE]: { value: [{ id: guid(9), userType: "Guest", userPrincipalName: hostile("m"), displayName: hostile("m") }] } },
      mfa: () => { throw Object.assign(graphDenied(), { message: hostile("graph") }); },
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.length).toBeGreaterThanOrEqual(5); // guest Owner, UAA, custom role, classic, GA guest
    expect(r.warnings!.length).toBeGreaterThan(0);
    expectNoLeak(r);
  });

  it("hostile auth error text is redacted in the module error", async () => {
    const err = authError();
    err.message = `${err.message} ${hostile("auth")}`;
    routeArm({ assignments: () => failingPages(err) });
    routeGraph();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expectNoLeak(r);
  });
});

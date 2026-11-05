/**
 * Phase 2 T6 — AliRamPrivilegeScanner (iam_privilege_escalation, global): policy-document
 * wildcard matching (table-driven), user / group / role paths, role trust policy, root AK,
 * console login without MFA, weak password policy, AK rotation, Marker pagination, user cap +
 * concurrency cap, degrade (access_denied) vs error (auth_failed / api_misuse), redaction.
 * aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliRamPrivilegeScanner,
  aliActionMatches,
  analyzeRamGrants,
  evaluateRamPasswordPolicy,
  isAliWildcardResource,
  parseAliPolicyDocument,
  RAM_ESCALATION_ACTIONS,
  RAM_MAX_USERS,
  RAM_CONCURRENCY,
  riskyTrustPrincipals,
  rootAccessKeyCount,
  staleAccessKeyAges,
  systemPolicyStatements,
} from "../../../../src/providers/alicloud/scanners/ram-privilege.js";
import { ALICLOUD_GLOBAL_MODULES, alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import { ALI_API } from "../../../../src/providers/alicloud/api-catalog.js";
import { AliCloudError } from "../../../../src/providers/alicloud/errors.js";
import type { ScanResult } from "../../../../src/types.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const DAY = 24 * 60 * 60 * 1000;
const OTHER_UID = "9999888877776666";

const notFound = (code: string, api = "ram:GetLoginProfile") =>
  new AliCloudError({ kind: "not_found", status: 404, code, message: "The specified entity does not exist." }, api);

const doc = (...Statement: unknown[]) => JSON.stringify({ Version: "1", Statement });
const allow = (Action: unknown, Resource: unknown = "*") => ({ Effect: "Allow", Action, Resource });

interface Pol {
  name: string;
  type?: "System" | "Custom";
  version?: string | null;
}
interface User {
  name: string;
  policies?: Pol[];
  groups?: string[];
  login?: boolean;
  /** MFA via GetUserMFAInfo (e.g. U2F). */
  mfa?: boolean;
  /** Listed by ListVirtualMFADevices. */
  virtualMfa?: boolean;
  keys?: Array<{ ageDays: number; status?: string }>;
}
interface Role {
  name: string;
  policies?: Pol[];
  trust?: unknown;
}
interface World {
  users?: User[];
  groups?: Record<string, Pol[]>;
  roles?: Role[];
  docs?: Record<string, string>;
  password?: Record<string, unknown>;
  rootKeys?: number;
}

const STRONG_PASSWORD = {
  MinimumPasswordLength: 12,
  RequireLowercaseCharacters: true,
  RequireUppercaseCharacters: true,
  RequireNumbers: true,
  RequireSymbols: true,
  MaxPasswordAge: 90,
};

const policyList = (pols: Pol[] = []) => ({
  Policies: {
    Policy: pols.map((p) => ({
      PolicyName: p.name,
      PolicyType: p.type ?? "Custom",
      ...(p.version === null ? {} : { DefaultVersion: p.version ?? "v1" }),
    })),
  },
});

function handlers(w: World, overrides: Record<string, AliHandler | object> = {}): Record<string, AliHandler | object> {
  const users = w.users ?? [];
  const user = (q: Record<string, unknown>) => users.find((u) => u.name === q.UserName);
  const role = (q: Record<string, unknown>) => (w.roles ?? []).find((r) => r.name === q.RoleName);
  const docFor = (q: Record<string, unknown>) => {
    const d = w.docs?.[String(q.PolicyName)];
    if (d === undefined) throw notFound("EntityNotExist.Policy", "ram:GetPolicyVersion");
    return d;
  };
  return {
    ListUsers: { Users: { User: users.map((u, i) => ({ UserName: u.name, UserId: `2000${i}` })) }, IsTruncated: false },
    ListVirtualMFADevices: {
      VirtualMFADevices: {
        VirtualMFADevice: users.filter((u) => u.virtualMfa).map((u) => ({ SerialNumber: `acs:ram::${UID}:mfa/${u.name}`, User: { UserName: u.name } })),
      },
    },
    ListPoliciesForUser: (q) => policyList(user(q)?.policies),
    ListGroupsForUser: (q) => ({ Groups: { Group: (user(q)?.groups ?? []).map((g) => ({ GroupName: g })) } }),
    GetLoginProfile: (q) => {
      const u = user(q);
      if (!u?.login) throw notFound("EntityNotExist.User.LoginProfile");
      return { LoginProfile: { UserName: u.name, MFABindRequired: false, PasswordResetRequired: false } };
    },
    GetUserMFAInfo: (q) => {
      if (!user(q)?.mfa) throw notFound("EntityNotExist.User.MFADevice", "ram:GetUserMFAInfo");
      return { MFADevice: { SerialNumber: "u2f-1", Type: "U2F" } };
    },
    ListAccessKeys: (q) => ({
      AccessKeys: {
        AccessKey: (user(q)?.keys ?? []).map((k, i) => ({
          AccessKeyId: `LTAI5tKEYIDKEYIDKEYID00${i}`,
          Status: k.status ?? "Active",
          CreateDate: new Date(Date.now() - k.ageDays * DAY - DAY / 2).toISOString(),
        })),
      },
    }),
    ListPoliciesForGroup: (q) => policyList(w.groups?.[String(q.GroupName)]),
    ListRoles: { Roles: { Role: (w.roles ?? []).map((r) => ({ RoleName: r.name, Arn: `acs:ram::${UID}:role/${r.name}` })) }, IsTruncated: false },
    ListPoliciesForRole: (q) => policyList(role(q)?.policies),
    GetRole: (q) => {
      const r = role(q);
      return { Role: { RoleName: r?.name, ...(r?.trust !== undefined ? { AssumeRolePolicyDocument: typeof r.trust === "string" ? r.trust : JSON.stringify(r.trust) } : {}) } };
    },
    GetPolicyVersion: (q) => ({ PolicyVersion: { VersionId: q.VersionId, IsDefaultVersion: true, PolicyDocument: docFor(q) } }),
    GetPolicy: (q) => ({ Policy: { PolicyName: q.PolicyName, PolicyType: q.PolicyType, DefaultVersion: "v1" }, DefaultPolicyVersion: { VersionId: "v1", PolicyDocument: docFor(q) } }),
    GetAccountSecurityPracticeReport: { AccountSecurityPracticeInfo: { AccountSecurityPracticeUserInfo: { RootWithAccessKey: w.rootKeys ?? 0 } } },
    GetPasswordPolicy: { PasswordPolicy: w.password ?? STRONG_PASSWORD },
    ...overrides,
  };
}

async function run(w: World, overrides: Record<string, AliHandler | object> = {}): Promise<ScanResult> {
  routeAliCall(mocks.aliCall, handlers(w, overrides));
  return new AliRamPrivilegeScanner().scan(aliCtx());
}

const byTitle = (r: ScanResult, re: RegExp) => r.findings.filter((f) => re.test(f.title));

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => {
  restoreAliEnv();
  vi.restoreAllMocks();
});

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

describe("aliActionMatches", () => {
  it.each([
    ["*", "ram:CreateUser", true],
    ["ram:*", "ram:CreateUser", true],
    ["RAM:*", "ram:CreateUser", true],
    ["ram:createuser", "ram:CreateUser", true],
    ["ram:Attach*", "ram:AttachPolicyToRole", true],
    ["ram:Attach*", "ram:DetachPolicyFromRole", false],
    ["ram:*Policy*", "ram:SetDefaultPolicyVersion", true],
    ["ram:?etUser", "ram:GetUser", true],
    ["ram:Get.User", "ram:GetXUser", false],
    ["ecs:*", "ram:GetUser", false],
    ["ram:List*", "ram:CreateAccessKey", false],
    ["", "ram:GetUser", false],
  ])("%s vs %s → %s", (pattern, action, expected) => {
    expect(aliActionMatches(pattern, action)).toBe(expected);
  });

  it("wildcard resources", () => {
    expect(isAliWildcardResource("*")).toBe(true);
    expect(isAliWildcardResource("acs:*:*:*:*")).toBe(true);
    expect(isAliWildcardResource("acs:oss:*:*:mybucket")).toBe(false);
  });
});

describe("parseAliPolicyDocument", () => {
  it("parses strings (plain + URL-encoded), objects and a single Statement object", () => {
    const plain = doc(allow("ram:*"));
    expect(parseAliPolicyDocument(plain)).toEqual([{ effect: "allow", actions: ["ram:*"], notAction: false, resources: ["*"], hasCondition: false }]);
    expect(parseAliPolicyDocument(encodeURIComponent(plain))).toHaveLength(1);
    expect(parseAliPolicyDocument({ Statement: { Effect: "Deny", Action: ["a:b", "c:d"], Resource: ["x", "y"], Condition: { Bool: { "acs:MFAPresent": "false" } } } })).toEqual([
      { effect: "deny", actions: ["a:b", "c:d"], notAction: false, resources: ["x", "y"], hasCondition: true },
    ]);
    expect(parseAliPolicyDocument("{not json")).toBeUndefined();
    expect(parseAliPolicyDocument("")).toBeUndefined();
  });
});

describe("analyzeRamGrants (table-driven)", () => {
  const analyze = (...statements: unknown[]) => analyzeRamGrants([{ source: "P (Custom)", statements: parseAliPolicyDocument(doc(...statements)) ?? [] }]);

  it.each([
    ["Action * + Resource * (strings)", allow("*", "*")],
    ["Action [*] + Resource [*] (arrays)", allow(["*"], ["*"])],
    ["Action *:* + Resource acs:*:*:*:*", allow("*:*", "acs:*:*:*:*")],
    ["NotAction (allow everything else) on *", { Effect: "Allow", NotAction: "oss:*", Resource: "*" }],
  ])("admin: %s", (_label, st) => {
    const a = analyze(st);
    expect(a.admin).toEqual(["P (Custom)"]);
  });

  it("Action * on a specific resource is not admin, but is conservatively ram:*", () => {
    const a = analyze(allow("*", "acs:oss:*:*:mybucket"));
    expect(a.admin).toEqual([]);
    expect(a.ramFull).toEqual(["P (Custom)"]);
  });

  it.each([
    ["string", allow("ram:*")],
    ["array", allow(["ecs:Describe*", "ram:*"])],
    ["upper-case", allow("RAM:*")],
  ])("ram:* (%s) → ramFull, not admin", (_label, st) => {
    const a = analyze(st);
    expect(a.admin).toEqual([]);
    expect(a.ramFull).toEqual(["P (Custom)"]);
  });

  it.each(RAM_ESCALATION_ACTIONS.map((x) => [x]))("escalation action %s (string and array forms)", (perm) => {
    for (const st of [allow(perm, `acs:ram::${UID}:*`), allow([perm, "ecs:DescribeInstances"], [`acs:ram::${UID}:user/*`])]) {
      const a = analyze(st);
      expect(a.ramFull).toEqual([]);
      expect(a.escalations.map((e) => e.permission)).toEqual([perm]);
    }
  });

  it("wildcard action patterns expand to every matching escalation action", () => {
    expect(analyze(allow("ram:Attach*")).escalations.map((e) => e.permission)).toEqual([
      "ram:AttachPolicyToUser",
      "ram:AttachPolicyToGroup",
      "ram:AttachPolicyToRole",
    ]);
    expect(analyze(allow("ram:Create*")).escalations.map((e) => e.permission)).toEqual([
      "ram:CreatePolicyVersion",
      "ram:CreateAccessKey",
      "ram:CreateLoginProfile",
    ]);
  });

  it("PassRole only escalates combined with ecs:RunInstances / fc:CreateFunction (across policies)", () => {
    expect(analyze(allow("ram:PassRole")).escalations).toEqual([]);
    expect(analyze(allow(["ram:PassRole", "ecs:RunInstances"])).escalations.map((e) => e.permission)).toEqual(["ram:PassRole + ecs:RunInstances"]);
    const a = analyzeRamGrants([
      { source: "A", statements: parseAliPolicyDocument(doc(allow("ram:PassRole"))) ?? [] },
      { source: "B", statements: parseAliPolicyDocument(doc(allow("fc:*"))) ?? [] },
    ]);
    expect(a.escalations).toEqual([{ permission: "ram:PassRole + fc:CreateFunction", sources: ["A", "B"] }]);
  });

  it("read-only and Deny statements grant nothing; Deny is reported as present", () => {
    expect(analyze(allow(["ram:List*", "ram:Get*"]))).toEqual({ admin: [], ramFull: [], escalations: [], hasDeny: false });
    const a = analyze({ Effect: "Deny", Action: "*", Resource: "*" });
    expect(a).toEqual({ admin: [], ramFull: [], escalations: [], hasDeny: true });
  });

  it("System policies are evaluated by name", () => {
    expect(analyzeRamGrants([{ source: "S", statements: systemPolicyStatements("AdministratorAccess") }]).admin).toEqual(["S"]);
    const ram = analyzeRamGrants([{ source: "S", statements: systemPolicyStatements("AliyunRAMFullAccess") }]);
    expect(ram.admin).toEqual([]);
    expect(ram.ramFull).toEqual(["S"]);
    expect(systemPolicyStatements("AliyunECSReadOnlyAccess")).toEqual([]);
  });
});

describe("riskyTrustPrincipals", () => {
  const trust = (RAM: unknown, Condition?: unknown, Effect = "Allow") => ({
    Version: "1",
    Statement: [{ Action: "sts:AssumeRole", Effect, Principal: { RAM }, ...(Condition ? { Condition } : {}) }],
  });
  const ext = { StringEquals: { "sts:ExternalId": "abc" } };

  it.each([
    ["acs:ram::*:root without ExternalId", trust(["acs:ram::*:root"]), UID, ["acs:ram::*:root"]],
    ["acs:ram::*:root with ExternalId", trust(["acs:ram::*:root"], ext), UID, []],
    ["own account root", trust(`acs:ram::${UID}:root`), UID, []],
    ["foreign account root", trust([`acs:ram::${OTHER_UID}:root`]), UID, [`acs:ram::${OTHER_UID}:root`]],
    ["foreign account with ExternalId", trust([`acs:ram::${OTHER_UID}:root`], ext), UID, []],
    ["foreign bare UID", trust([OTHER_UID]), UID, [OTHER_UID]],
    ["foreign UID, own UID unknown", trust([`acs:ram::${OTHER_UID}:root`]), "unknown", []],
    ["wildcard, own UID unknown", trust("*"), "unknown", ["*"]],
    ["Deny statement", trust(["acs:ram::*:root"], undefined, "Deny"), UID, []],
  ])("%s", (_label, d, uid, expected) => {
    expect(riskyTrustPrincipals(JSON.stringify(d), uid)).toEqual(expected);
  });

  it("ignores Service principals and unparsable documents", () => {
    expect(riskyTrustPrincipals({ Statement: [{ Effect: "Allow", Principal: { Service: ["ecs.aliyuncs.com"] } }] }, UID)).toEqual([]);
    expect(riskyTrustPrincipals("{bad", UID)).toEqual([]);
  });
});

describe("password policy / access keys / root AK", () => {
  it("evaluateRamPasswordPolicy", () => {
    expect(evaluateRamPasswordPolicy(STRONG_PASSWORD)).toEqual([]);
    expect(evaluateRamPasswordPolicy({ ...STRONG_PASSWORD, RequireSymbols: false, RequireNumbers: "false" })).toEqual([]);
    expect(evaluateRamPasswordPolicy({ ...STRONG_PASSWORD, MinimumPasswordLength: 6 })).toEqual(["minimum password length is 6 (< 8)"]);
    expect(evaluateRamPasswordPolicy({ ...STRONG_PASSWORD, MaxPasswordAge: 0 })).toEqual(["passwords never expire (MaxPasswordAge = 0)"]);
    const none = evaluateRamPasswordPolicy({
      MinimumPasswordLength: "8",
      RequireLowercaseCharacters: "false",
      RequireUppercaseCharacters: false,
      RequireNumbers: false,
      RequireSymbols: false,
      MaxPasswordAge: 30,
    });
    expect(none).toHaveLength(1);
    expect(none[0]).toMatch(/no character-class complexity/);
    expect(evaluateRamPasswordPolicy(undefined)).toEqual([]);
  });

  it("staleAccessKeyAges: active keys older than 90 days, oldest first", () => {
    const now = Date.now();
    const at = (d: number) => new Date(now - d * DAY - DAY / 2).toISOString();
    expect(
      staleAccessKeyAges(
        [
          { Status: "Active", CreateDate: at(100) },
          { Status: "Inactive", CreateDate: at(400) },
          { Status: "Active", CreateDate: at(30) },
          { Status: "Active", CreateDate: at(200) },
          { Status: "Active", CreateDate: "not a date" },
          { Status: "Active", CreateDate: at(90) },
        ],
        now,
      ),
    ).toEqual([200, 100]);
  });

  it("rootAccessKeyCount reads nested and flat shapes", () => {
    expect(rootAccessKeyCount({ AccountSecurityPracticeInfo: { AccountSecurityPracticeUserInfo: { RootWithAccessKey: 2 } } })).toBe(2);
    expect(rootAccessKeyCount({ AccountSecurityPracticeUserInfo: { RootWithAccessKey: "1" } })).toBe(1);
    expect(rootAccessKeyCount({})).toBeUndefined();
  });
});

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

describe("AliRamPrivilegeScanner — registration", () => {
  it("is a registered global module", () => {
    expect(new AliRamPrivilegeScanner().moduleName).toBe("iam_privilege_escalation");
    expect(ALICLOUD_GLOBAL_MODULES.has("iam_privilege_escalation")).toBe(true);
    expect(alibabaCloudProvider.scanners().some((s) => s instanceof AliRamPrivilegeScanner)).toBe(true);
  });

  it("IMS / RAM posture APIs are catalogued (RPC POST)", () => {
    expect(ALI_API.ims.GetPasswordPolicy).toMatchObject({ service: "ims", version: "2019-08-15", method: "POST", style: "RPC" });
    expect(ALI_API.ims.GetAccountSecurityPracticeReport).toMatchObject({ service: "ims", version: "2019-08-15", method: "POST", style: "RPC" });
    for (const a of ["GetLoginProfile", "GetUserMFAInfo", "ListVirtualMFADevices"] as const) {
      expect(ALI_API.ram[a]).toMatchObject({ service: "ram", action: a, version: "2015-05-01", method: "POST", style: "RPC" });
    }
  });
});

describe("AliRamPrivilegeScanner — user / group / role paths", () => {
  it("user with AdministratorAccess (System, by name) → CRITICAL 9.0", async () => {
    const r = await run({ users: [{ name: "alice", policies: [{ name: "AdministratorAccess", type: "System" }] }] });
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({
      severity: "CRITICAL",
      riskScore: 9.0,
      resourceType: "ACS::RAM::User",
      resourceId: "alice",
      resourceArn: `acs:ram::${UID}:user/alice`,
      region: "global",
      provider: "alicloud",
    });
    expect(f.title).toBe("RAM user alice has full administrator permissions");
    expect(f.description).toContain("AdministratorAccess (System)");
    expect(f.description).toMatch(/not evaluated precisely/);
    // System policies are evaluated by name: no document fetch.
    expect(callsFor(mocks.aliCall, "GetPolicyVersion")).toHaveLength(0);
    expect(callsFor(mocks.aliCall, "GetPolicy")).toHaveLength(0);
    expect(r.resourcesScanned).toBe(1);
  });

  it("user with a custom ram:* policy → CRITICAL ram:* finding (DefaultVersion fetched)", async () => {
    const r = await run({
      users: [{ name: "bob", policies: [{ name: "RamAll", version: "v3" }] }],
      docs: { RamAll: doc(allow("ram:*")) },
    });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ severity: "CRITICAL", riskScore: 9.0, title: "RAM user bob has ram:* wildcard permissions" });
    const calls = callsFor(mocks.aliCall, "GetPolicyVersion");
    expect(calls).toHaveLength(1);
    expect(calls[0][2]).toEqual({ PolicyType: "Custom", PolicyName: "RamAll", VersionId: "v3" });
  });

  it("escalation via a group policy → HIGH 8.0 attributed to the user, naming the group", async () => {
    const r = await run({
      users: [{ name: "carol", groups: ["ops"] }],
      groups: { ops: [{ name: "Escalate", version: "v2" }] },
      docs: { Escalate: doc(allow(["ram:CreatePolicyVersion", "ram:SetDefaultPolicyVersion"], "acs:ram:*:*:policy/*")) },
    });
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ severity: "HIGH", riskScore: 8.0, resourceId: "carol", title: "RAM user carol has privilege-escalation permissions" });
    expect(f.description).toContain("ram:CreatePolicyVersion");
    expect(f.description).toContain("ram:SetDefaultPolicyVersion");
    expect(f.description).toContain("Escalate (Custom, via group ops)");
    expect(callsFor(mocks.aliCall, "ListPoliciesForGroup")[0][2]).toEqual({ GroupName: "ops" });
  });

  it("caches policy documents across users / groups / roles", async () => {
    const shared: Pol = { name: "Shared", version: "v1" };
    const r = await run({
      users: [
        { name: "u1", policies: [shared], groups: ["g"] },
        { name: "u2", policies: [shared], groups: ["g"] },
      ],
      groups: { g: [shared] },
      roles: [{ name: "r1", policies: [shared] }],
      docs: { Shared: doc(allow("ram:AddUserToGroup")) },
    });
    expect(callsFor(mocks.aliCall, "GetPolicyVersion")).toHaveLength(1);
    expect(callsFor(mocks.aliCall, "ListPoliciesForGroup")).toHaveLength(1);
    expect(r.findings.filter((f) => f.riskScore === 8.0)).toHaveLength(3);
  });

  it("custom policy without DefaultVersion uses GetPolicy → DefaultPolicyVersion", async () => {
    const r = await run({
      users: [{ name: "dave", policies: [{ name: "NoVer", version: null }] }],
      docs: { NoVer: doc(allow("ram:PassRole"), allow("ecs:RunInstances")) },
    });
    expect(callsFor(mocks.aliCall, "GetPolicy")[0][2]).toEqual({ PolicyType: "Custom", PolicyName: "NoVer" });
    expect(callsFor(mocks.aliCall, "GetPolicyVersion")).toHaveLength(0);
    expect(r.findings[0].description).toContain("ram:PassRole + ecs:RunInstances");
  });

  it("read-only users produce nothing; unparsable documents warn", async () => {
    const r = await run({
      users: [{ name: "eve", policies: [{ name: "AliyunECSReadOnlyAccess", type: "System" }, { name: "RO" }, { name: "Broken" }] }],
      docs: { RO: doc(allow(["ram:List*", "ram:Get*"])), Broken: "{oops" },
    });
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings?.some((w) => /RAM policy "Broken": the policy document could not be parsed/.test(w))).toBe(true);
  });

  it("role with AliyunRAMFullAccess → CRITICAL; GetRole fetched for the trust policy", async () => {
    const r = await run({ roles: [{ name: "deployer", policies: [{ name: "AliyunRAMFullAccess", type: "System" }], trust: { Statement: [] } }] });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({
      severity: "CRITICAL",
      resourceType: "ACS::RAM::Role",
      resourceId: "deployer",
      resourceArn: `acs:ram::${UID}:role/deployer`,
      title: "RAM role deployer has ram:* wildcard permissions",
    });
    expect(callsFor(mocks.aliCall, "GetRole")[0][2]).toEqual({ RoleName: "deployer" });
    expect(r.resourcesScanned).toBe(1);
  });

  it("role trust acs:ram::*:root without ExternalId → HIGH 7.5; with ExternalId → none", async () => {
    const trust = (cond?: unknown) => ({
      Version: "1",
      Statement: [{ Action: "sts:AssumeRole", Effect: "Allow", Principal: { RAM: ["acs:ram::*:root"] }, ...(cond ? { Condition: cond } : {}) }],
    });
    const r = await run({
      roles: [
        { name: "open", trust: trust() },
        { name: "guarded", trust: trust({ StringEquals: { "sts:ExternalId": "s3cr3t" } }) },
        { name: "partner", trust: { Statement: [{ Effect: "Allow", Action: "sts:AssumeRole", Principal: { RAM: `acs:ram::${OTHER_UID}:root` } }] } },
        { name: "own", trust: { Statement: [{ Effect: "Allow", Action: "sts:AssumeRole", Principal: { RAM: `acs:ram::${UID}:root` } }] } },
      ],
    });
    const trustFindings = byTitle(r, /can be assumed by/);
    expect(trustFindings.map((f) => f.resourceId).sort()).toEqual(["open", "partner"]);
    const open = trustFindings.find((f) => f.resourceId === "open");
    expect(open).toMatchObject({ severity: "HIGH", riskScore: 7.5, title: "RAM role open can be assumed by any Alibaba Cloud account without an ExternalId" });
    expect(trustFindings.find((f) => f.resourceId === "partner")?.title).toBe("RAM role partner can be assumed by another account without an ExternalId");
  });

  it("uses AssumeRolePolicyDocument from ListRoles when present (no GetRole)", async () => {
    const r = await run(
      { roles: [{ name: "x" }] },
      {
        ListRoles: {
          Roles: { Role: [{ RoleName: "x", AssumeRolePolicyDocument: JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { RAM: "*" } }] }) }] },
          IsTruncated: false,
        },
      },
    );
    expect(callsFor(mocks.aliCall, "GetRole")).toHaveLength(0);
    expect(byTitle(r, /any Alibaba Cloud account/)).toHaveLength(1);
  });
});

describe("AliRamPrivilegeScanner — account posture", () => {
  it("root account AccessKey → CRITICAL 9.0 (acs:ram::<uid>:root); none when 0", async () => {
    const r = await run({ rootKeys: 1 });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({
      severity: "CRITICAL",
      riskScore: 9.0,
      resourceType: "ACS::RAM::Account",
      resourceArn: `acs:ram::${UID}:root`,
      title: "Alibaba Cloud account (root) has an AccessKey",
    });
    expect((await run({ rootKeys: 0 })).findings).toEqual([]);
  });

  it("console login without MFA → HIGH 7.0; virtual MFA / U2F / API-only users are fine", async () => {
    const r = await run({
      users: [
        { name: "nomfa", login: true },
        { name: "vmfa", login: true, virtualMfa: true },
        { name: "u2f", login: true, mfa: true },
        { name: "api", login: false },
      ],
    });
    const mfa = byTitle(r, /without MFA/);
    expect(mfa).toHaveLength(1);
    expect(mfa[0]).toMatchObject({ severity: "HIGH", riskScore: 7.0, resourceId: "nomfa", title: "RAM user nomfa has console access without MFA" });
    const mfaCalls = callsFor(mocks.aliCall, "GetUserMFAInfo").map((c) => c[2].UserName).sort();
    expect(mfaCalls).toEqual(["nomfa", "u2f"]);
  });

  it("weak password policy → MEDIUM 5.0", async () => {
    const r = await run({ password: { MinimumPasswordLength: 6, MaxPasswordAge: 0 } });
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ severity: "MEDIUM", riskScore: 5.0, resourceType: "ACS::RAM::PasswordPolicy", title: "RAM password policy is weak" });
    expect(f.description).toContain("minimum password length is 6");
    expect(f.description).toContain("no character-class complexity");
    expect(f.description).toContain("MaxPasswordAge = 0");
  });

  it("active AccessKey > 90 days → MEDIUM 5.5 without echoing the AccessKey ID", async () => {
    const r = await run({ users: [{ name: "svc", keys: [{ ageDays: 120 }, { ageDays: 10 }, { ageDays: 300, status: "Inactive" }] }, { name: "fresh", keys: [{ ageDays: 5 }] }] });
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ severity: "MEDIUM", riskScore: 5.5, resourceId: "svc", title: "RAM user svc has access keys older than 90 days" });
    expect(f.description).toContain("1 active AccessKey(s)");
    expect(f.description).toContain("oldest: 120 days");
    expect(JSON.stringify(r)).not.toContain("LTAI5tKEYID");
  });
});

describe("AliRamPrivilegeScanner — pagination and N+1 caps", () => {
  it("follows Marker / IsTruncated for ListUsers and ListRoles", async () => {
    const r = await run(
      { users: [{ name: "a" }, { name: "b" }, { name: "c" }], roles: [{ name: "r1" }, { name: "r2" }] },
      {
        ListUsers: (q) =>
          q.Marker === "m1"
            ? { Users: { User: [{ UserName: "c" }] }, IsTruncated: false }
            : { Users: { User: [{ UserName: "a" }, { UserName: "b" }] }, IsTruncated: true, Marker: "m1" },
        ListRoles: (q) =>
          q.Marker === "rm"
            ? { Roles: { Role: [{ RoleName: "r2" }] }, IsTruncated: false }
            : { Roles: { Role: [{ RoleName: "r1" }] }, IsTruncated: true, Marker: "rm" },
      },
    );
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(5);
    const userPages = callsFor(mocks.aliCall, "ListUsers");
    expect(userPages).toHaveLength(2);
    expect(userPages[0][2]).toMatchObject({ MaxItems: 100 });
    expect(userPages[1][2]).toMatchObject({ Marker: "m1" });
    expect(callsFor(mocks.aliCall, "ListRoles")).toHaveLength(2);
    expect(callsFor(mocks.aliCall, "ListPoliciesForUser").map((c) => c[2].UserName).sort()).toEqual(["a", "b", "c"]);
    expect(callsFor(mocks.aliCall, "ListPoliciesForRole").map((c) => c[2].RoleName).sort()).toEqual(["r1", "r2"]);
  });

  it(`caps users at RAM_MAX_USERS (${RAM_MAX_USERS}) with a warning and keeps concurrency ≤ ${RAM_CONCURRENCY}`, async () => {
    const users = Array.from({ length: RAM_MAX_USERS + 20 }, (_, i) => ({ name: `user${i}` }));
    let inFlight = 0;
    let maxInFlight = 0;
    const r = await run(
      { users },
      {
        ListPoliciesForUser: async () => {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          await new Promise((res) => setTimeout(res, 1));
          inFlight--;
          return { Policies: { Policy: [] } };
        },
      },
    );
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "ListPoliciesForUser")).toHaveLength(RAM_MAX_USERS);
    expect(r.warnings?.some((w) => w.includes(`more than ${RAM_MAX_USERS} RAM users`))).toBe(true);
    expect(r.warnings?.some((w) => w.includes("item cap reached"))).toBe(false);
    expect(maxInFlight).toBeLessThanOrEqual(RAM_CONCURRENCY);
    expect(maxInFlight).toBeGreaterThan(1);
  });
});

describe("AliRamPrivilegeScanner — degrade vs error", () => {
  it("access_denied on IMS degrades: module still success with warnings", async () => {
    const r = await run(
      { users: [{ name: "alice", policies: [{ name: "AdministratorAccess", type: "System" }] }] },
      {
        GetPasswordPolicy: () => {
          throw deniedError("ims:GetPasswordPolicy");
        },
        GetAccountSecurityPracticeReport: () => {
          throw deniedError("ims:GetAccountSecurityPracticeReport");
        },
      },
    );
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings?.some((w) => w.startsWith("IMS GetPasswordPolicy: insufficient permissions"))).toBe(true);
    expect(r.warnings?.some((w) => w.startsWith("IMS GetAccountSecurityPracticeReport: insufficient permissions"))).toBe(true);
  });

  it("per-user access_denied is aggregated into one warning per API", async () => {
    const r = await run(
      { users: [{ name: "a" }, { name: "b" }, { name: "c" }] },
      {
        ListAccessKeys: () => {
          throw deniedError("ram:ListAccessKeys");
        },
      },
    );
    expect(r.status).toBe("success");
    const w = (r.warnings ?? []).filter((x) => x.includes("RAM ListAccessKeys"));
    expect(w).toHaveLength(1);
    expect(w[0]).toContain("insufficient permissions");
    expect(w[0]).toContain("2 more similar failure(s)");
  });

  it("ListVirtualMFADevices denied → falls back to GetUserMFAInfo", async () => {
    const r = await run(
      { users: [{ name: "x", login: true, virtualMfa: true, mfa: false }] },
      {
        ListVirtualMFADevices: () => {
          throw deniedError("ram:ListVirtualMFADevices");
        },
      },
    );
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "GetUserMFAInfo")).toHaveLength(1);
    expect(byTitle(r, /without MFA/)).toHaveLength(1);
    expect(r.warnings?.some((w) => w.startsWith("RAM ListVirtualMFADevices: insufficient permissions"))).toBe(true);
  });

  it("ListUsers denied → roles and account posture still evaluated", async () => {
    const r = await run(
      { roles: [{ name: "adm", policies: [{ name: "AdministratorAccess", type: "System" }] }], rootKeys: 1 },
      {
        ListUsers: () => {
          throw deniedError("ram:ListUsers");
        },
      },
    );
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceType).sort()).toEqual(["ACS::RAM::Account", "ACS::RAM::Role"]);
    expect(r.warnings?.some((w) => w.startsWith("RAM ListUsers: insufficient permissions"))).toBe(true);
  });

  it.each([
    ["ListUsers", "ram:ListUsers"],
    ["GetLoginProfile", "ram:GetLoginProfile"],
    ["ListPoliciesForRole", "ram:ListPoliciesForRole"],
    ["GetAccountSecurityPracticeReport", "ims:GetAccountSecurityPracticeReport"],
    ["GetPasswordPolicy", "ims:GetPasswordPolicy"],
  ])("auth_failed on %s → status error (Alibaba Cloud authentication failed)", async (action, api) => {
    const r = await run(
      { users: [{ name: "alice", login: true }], roles: [{ name: "r" }] },
      {
        [action]: () => {
          throw authError(api);
        },
      },
    );
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.findings).toEqual([]);
    expect(r.error).not.toMatch(/not enabled/i);
  });

  it("api_misuse on GetPolicyVersion → status error (never swallowed)", async () => {
    const r = await run(
      { users: [{ name: "alice", policies: [{ name: "Custom1" }] }], docs: { Custom1: doc(allow("*")) } },
      {
        GetPolicyVersion: () => {
          throw misuseError("ram:GetPolicyVersion");
        },
      },
    );
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^RAM privilege escalation check failed: /);
    expect(r.error).toContain("MissingParameter");
    expect(r.findings).toEqual([]);
  });

  it("missing credentials → status error", async () => {
    routeAliCall(mocks.aliCall, handlers({}));
    const r = await new AliRamPrivilegeScanner().scan(aliCtx({ credentials: undefined }));
    expect(r.status).toBe("error");
    expect(mocks.aliCall).not.toHaveBeenCalled();
  });
});

describe("AliRamPrivilegeScanner — redaction / stdout", () => {
  it("AK-looking user / role / group / policy names never reach findings or warnings", async () => {
    const userAk = "LTAI5tLEAKEDUSERNAME00001";
    const roleAk = "LTAI5tLEAKEDROLENAME00002";
    const groupAk = "LTAI5tLEAKEDGROUPNAME0003";
    const polAk = "LTAI5tLEAKEDPOLICYNAME004";
    const written: string[] = [];
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      written.push(String(chunk));
      return true;
    }) as never);
    const log = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
      written.push(a.map(String).join(" "));
    });
    const r = await run(
      {
        users: [{ name: userAk, groups: [groupAk], login: true }],
        groups: { [groupAk]: [{ name: polAk, version: "v1" }] },
        roles: [{ name: roleAk, policies: [{ name: "AdministratorAccess", type: "System" }], trust: { Statement: [{ Effect: "Allow", Principal: { RAM: ["acs:ram::*:root"] } }] } }],
        docs: { [polAk]: doc(allow("ram:CreateAccessKey")) },
      },
      {
        ListAccessKeys: () => {
          throw deniedError("ram:ListAccessKeys");
        },
      },
    );
    expect(r.status).toBe("success");
    expect(r.findings.length).toBeGreaterThanOrEqual(4); // escalation + no-MFA (user), admin + trust (role)
    expect(r.warnings?.length).toBeGreaterThan(0);
    const out = JSON.stringify(r);
    for (const leaked of [userAk, roleAk, groupAk, polAk, FAKE_AK, FAKE_SK]) expect(out).not.toContain(leaked);
    // Raw names are still used as API parameters.
    expect(callsFor(mocks.aliCall, "ListPoliciesForUser")[0][2]).toEqual({ UserName: userAk });
    expect(callsFor(mocks.aliCall, "ListPoliciesForGroup")[0][2]).toEqual({ GroupName: groupAk });
    expect(callsFor(mocks.aliCall, "GetPolicyVersion")[0][2]).toMatchObject({ PolicyName: polAk });
    stdout.mockRestore();
    log.mockRestore();
    for (const leaked of [userAk, roleAk, groupAk, polAk, FAKE_AK, FAKE_SK]) expect(written.join("\n")).not.toContain(leaked);
  });
});

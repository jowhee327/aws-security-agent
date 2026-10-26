/**
 * Alibaba Cloud RAM privilege-escalation scanner (moduleName `iam_privilege_escalation`,
 * plan §4.1 P2 / §4.3 / T6). EXPERIMENTAL — not yet validated against a live account.
 *
 * GLOBAL module (RAM / IMS are account-level; listed in ALICLOUD_GLOBAL_MODULES, runs once).
 * Mirrors `src/scanners/iam-privilege-escalation.ts` (AWS), extended with roles, groups and
 * account posture:
 *  - RAM (ram.aliyuncs.com, 2015-05-01): ListUsers (Marker / MaxItems, capped at
 *    {@link RAM_MAX_USERS}); per user ListPoliciesForUser + ListGroupsForUser + GetLoginProfile
 *    (+ GetUserMFAInfo when not in ListVirtualMFADevices) + ListAccessKeys; per group
 *    ListPoliciesForGroup; ListRoles (capped at {@link RAM_MAX_ROLES}) + ListPoliciesForRole +
 *    GetRole (trust policy, only when ListRoles did not return it).
 *  - Effective policies: System policies are evaluated BY NAME ({@link RAM_SYSTEM_POLICY_GRANTS};
 *    their documents are not fetched); Custom policies by their DefaultVersion document
 *    (GetPolicyVersion, or GetPolicy → DefaultPolicyVersion when the version is unknown),
 *    cached by (PolicyType, PolicyName, DefaultVersion). A user's effective set = direct
 *    policies + policies of its groups.
 *  - IMS (ims.aliyuncs.com, 2019-08-15): GetPasswordPolicy, GetAccountSecurityPracticeReport
 *    (`AccountSecurityPracticeUserInfo.RootWithAccessKey`). Per-user login / MFA calls use the
 *    RAM 2015-05-01 equivalents because the IMS ones are keyed by UserPrincipalName, which
 *    RAM ListUsers does not return.
 *
 * Rules / riskScore (plan §4.3): AdministratorAccess or Allow `*` on `*` → 9.0; AliyunRAMFullAccess
 * or Allow `ram:*` → 9.0; privilege-escalation actions ({@link RAM_ESCALATION_ACTIONS},
 * PassRole + ecs:RunInstances / fc:CreateFunction) → 8.0; role trust policy trusting `*` or a
 * foreign account without an `sts:ExternalId` condition → 7.5; root AccessKey present → 9.0;
 * console login without MFA → 7.0; weak password policy → 5.0; active AccessKey > 90 days → 5.5.
 *
 * Actions are matched with wildcards (`ram:Attach*`, `*`); Action / Resource may be a string
 * or an array. `Effect: Deny`, `Condition` blocks and resource scoping (except for the
 * administrator rule) are NOT evaluated precisely — the check is conservative and says so in
 * every policy finding.
 *
 * N+1: per-entity calls run with a concurrency cap of {@link RAM_CONCURRENCY}. Every
 * cloud-sourced string (user / group / role / policy names) passes through
 * redactAliDiagnostic before reaching a Finding or warning; policy document content is never
 * echoed. Errors: auth_failed / api_misuse → module `status: "error"`; access denied / not
 * enabled / throttled / network → warning per sub-call (aggregated per API) and degrade.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API, type AliApiSpec } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { classifyAliError, redactAliDiagnostic, type AliErrorKind } from "../errors.js";
import { ACS_URN_PREFIX, toAliUrn } from "../urn.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliScanEnv,
  aliSoftWarning,
  aliString,
  aliUntrusted,
  isAliFatal,
  toAliError,
  type AliScanEnv,
} from "./shared.js";

/** ListUsers / ListRoles page size (RAM maximum 1000). */
export const RAM_PAGE_SIZE = 100;
/** Users / roles evaluated at most (warning when exceeded). */
export const RAM_MAX_USERS = 500;
export const RAM_MAX_ROLES = 500;
/** Concurrency cap for the per-user / per-group / per-role / per-policy calls. */
export const RAM_CONCURRENCY = 5;
/** Active AccessKeys older than this are flagged. */
export const RAM_AK_MAX_AGE_DAYS = 90;
export const RAM_MIN_PASSWORD_LENGTH = 8;

export const RAM_ADMIN_RISK = 9.0;
export const RAM_FULL_ACCESS_RISK = 9.0;
export const RAM_ESCALATION_RISK = 8.0;
export const RAM_TRUST_RISK = 7.5;
export const RAM_ROOT_AK_RISK = 9.0;
export const RAM_NO_MFA_RISK = 7.0;
export const RAM_WEAK_PASSWORD_RISK = 5.0;
export const RAM_STALE_AK_RISK = 5.5;

/** Single actions that let a principal escalate its own (or another identity's) privileges. */
export const RAM_ESCALATION_ACTIONS: readonly string[] = [
  "ram:CreatePolicyVersion",
  "ram:SetDefaultPolicyVersion",
  "ram:AttachPolicyToUser",
  "ram:AttachPolicyToGroup",
  "ram:AttachPolicyToRole",
  "ram:AddUserToGroup",
  "ram:CreateAccessKey",
  "ram:UpdateLoginProfile",
  "ram:CreateLoginProfile",
  "ram:UpdateRole",
];

/** Action pairs that together allow running code as a (more privileged) role. */
export const RAM_ESCALATION_COMBOS: ReadonlyArray<readonly [string, string]> = [
  ["ram:PassRole", "ecs:RunInstances"],
  ["ram:PassRole", "fc:CreateFunction"],
];

/** System policies evaluated by name (documents are not fetched): name → allowed action patterns. */
export const RAM_SYSTEM_POLICY_GRANTS: Readonly<Record<string, readonly string[]>> = {
  AdministratorAccess: ["*"],
  AliyunRAMFullAccess: ["ram:*"],
  AliyunECSFullAccess: ["ecs:*"],
  AliyunFCFullAccess: ["fc:*"],
};

const DAY_MS = 24 * 60 * 60 * 1000;
const MODULE_ERROR_CONTEXT = "RAM privilege escalation check failed";
const CONSERVATIVE_NOTE =
  "Deny statements, Condition blocks and resource scoping are not evaluated precisely (conservative check); verify the effective permissions before remediating.";

/** Sentinels: an Allow pattern matching these grants every action / every RAM action. */
const ANY_ACTION_SENTINEL = "zzsentinelsvc:ZzSentinelAction";
const ANY_RAM_ACTION_SENTINEL = "ram:ZzSentinelAction";

/* ------------------------------------------------------------------------ */
/* Policy documents                                                         */
/* ------------------------------------------------------------------------ */

export interface AliPolicyStatement {
  effect: "allow" | "deny";
  /** Action patterns (or NotAction patterns when `notAction`). */
  actions: string[];
  notAction: boolean;
  /** Resource patterns; `["*"]` when the statement uses NotResource (applies broadly). */
  resources: string[];
  hasCondition: boolean;
}

function stringList(v: unknown): string[] {
  return aliArray(v)
    .map((x) => (typeof x === "string" ? x.trim() : ""))
    .filter((x) => x.length > 0);
}

/** Policy document (JSON string — possibly URL-encoded — or object) → statements; undefined when unparsable. */
export function parseAliPolicyDocument(doc: unknown): AliPolicyStatement[] | undefined {
  let obj: unknown = doc;
  if (typeof doc === "string") {
    const text = doc.trim();
    if (!text) return undefined;
    try {
      obj = JSON.parse(text);
    } catch {
      try {
        obj = JSON.parse(decodeURIComponent(text));
      } catch {
        return undefined;
      }
    }
  }
  if (!obj || typeof obj !== "object") return undefined;
  const out: AliPolicyStatement[] = [];
  for (const st of aliArray<Record<string, unknown>>(aliField(obj, "Statement"))) {
    if (!st || typeof st !== "object") continue;
    const effect = (aliString(st.Effect) ?? "").toLowerCase();
    if (effect !== "allow" && effect !== "deny") continue;
    const notAction = st.NotAction !== undefined && st.Action === undefined;
    const notResource = st.NotResource !== undefined && st.Resource === undefined;
    out.push({
      effect: effect as AliPolicyStatement["effect"],
      actions: stringList(notAction ? st.NotAction : st.Action),
      notAction,
      resources: notResource ? ["*"] : stringList(st.Resource),
      hasCondition: !!st.Condition && typeof st.Condition === "object" && Object.keys(st.Condition as object).length > 0,
    });
  }
  return out;
}

function globRegex(pattern: string): RegExp {
  const src = pattern
    .split("")
    .map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\/]/g, "\\$&")))
    .join("");
  return new RegExp(`^${src}$`, "i");
}

/** Wildcard (`*`, `?`) case-insensitive match of a policy Action pattern against a concrete action. */
export function aliActionMatches(pattern: string, action: string): boolean {
  const p = pattern.trim();
  if (!p) return false;
  if (p === "*") return true;
  return globRegex(p).test(action.trim());
}

/** Resource pattern covering every resource (`*`, `acs:*:*:*:*`). */
export function isAliWildcardResource(resource: string): boolean {
  const r = resource.trim();
  return r === "*" || /^acs(?::\*){4}(?:\/\*)?$/i.test(r);
}

/** True when the (Allow) statement grants `action` (wildcards; NotAction = everything not listed). */
function statementAllows(st: AliPolicyStatement, action: string): boolean {
  if (st.effect !== "allow") return false;
  const listed = st.actions.some((p) => aliActionMatches(p, action));
  return st.notAction ? !listed : listed;
}

/** One attached policy: display label (already redacted) + its statements. */
export interface RamGrant {
  source: string;
  statements: AliPolicyStatement[];
}

export interface RamGrantAnalysis {
  /** Sources granting every action on every resource. */
  admin: string[];
  /** Sources granting every RAM action. */
  ramFull: string[];
  /** Escalation permissions (single actions and `A + B` combos) with the sources granting them. */
  escalations: Array<{ permission: string; sources: string[] }>;
  /** Some attached policy has a Deny statement (not evaluated). */
  hasDeny: boolean;
}

function sourcesAllowing(grants: readonly RamGrant[], action: string, needWildcardResource = false): string[] {
  const out = new Set<string>();
  for (const g of grants) {
    for (const st of g.statements) {
      if (!statementAllows(st, action)) continue;
      if (needWildcardResource && !st.resources.some(isAliWildcardResource)) continue;
      out.add(g.source);
    }
  }
  return [...out];
}

/** Evaluate an effective policy set (plan §4.3). Deny / Condition are not evaluated. */
export function analyzeRamGrants(grants: readonly RamGrant[]): RamGrantAnalysis {
  const hasDeny = grants.some((g) => g.statements.some((s) => s.effect === "deny"));
  const anyAction = new Set(sourcesAllowing(grants, ANY_ACTION_SENTINEL, true));
  const admin = sourcesAllowing(grants, ANY_RAM_ACTION_SENTINEL, true).filter((s) => anyAction.has(s));
  const ramFull = sourcesAllowing(grants, ANY_RAM_ACTION_SENTINEL);
  const escalations: RamGrantAnalysis["escalations"] = [];
  for (const perm of RAM_ESCALATION_ACTIONS) {
    const sources = sourcesAllowing(grants, perm);
    if (sources.length > 0) escalations.push({ permission: perm, sources });
  }
  for (const [a, b] of RAM_ESCALATION_COMBOS) {
    const sa = sourcesAllowing(grants, a);
    const sb = sourcesAllowing(grants, b);
    if (sa.length > 0 && sb.length > 0) escalations.push({ permission: `${a} + ${b}`, sources: [...new Set([...sa, ...sb])] });
  }
  return { admin, ramFull, escalations, hasDeny };
}

/** Synthetic statements for a System policy evaluated by name ([] when unknown). */
export function systemPolicyStatements(policyName: string): AliPolicyStatement[] {
  const actions = RAM_SYSTEM_POLICY_GRANTS[policyName];
  return actions ? [{ effect: "allow", actions: [...actions], notAction: false, resources: ["*"], hasCondition: false }] : [];
}

/* ------------------------------------------------------------------------ */
/* Trust policy / password policy / access keys                             */
/* ------------------------------------------------------------------------ */

function hasExternalIdCondition(cond: unknown): boolean {
  if (!cond || typeof cond !== "object") return false;
  for (const op of Object.values(cond as Record<string, unknown>)) {
    if (op && typeof op === "object" && Object.keys(op as object).some((k) => k.trim().toLowerCase() === "sts:externalid")) return true;
  }
  return false;
}

/**
 * Role trust policy → RAM principals that are `*` or belong to another account and are not
 * guarded by an `sts:ExternalId` condition (redacted). With an unknown own account UID only
 * wildcard principals are reported. Service / Federated principals are ignored.
 */
export function riskyTrustPrincipals(doc: unknown, accountId: string): string[] {
  let obj: unknown = doc;
  if (typeof doc === "string") {
    try {
      obj = JSON.parse(doc);
    } catch {
      try {
        obj = JSON.parse(decodeURIComponent(doc));
      } catch {
        return [];
      }
    }
  }
  const own = /^\d+$/.test(accountId) ? accountId : undefined;
  const out = new Set<string>();
  for (const st of aliArray<Record<string, unknown>>(aliField(obj, "Statement"))) {
    if (!st || typeof st !== "object") continue;
    if ((aliString(st.Effect) ?? "").toLowerCase() !== "allow") continue;
    if (hasExternalIdCondition(st.Condition)) continue;
    const principal = st.Principal;
    const entries = typeof principal === "string" ? [principal] : stringList(aliField(principal, "RAM"));
    for (const raw of entries) {
      const p = raw.trim();
      let uid: string | undefined;
      if (p === "*") uid = "*";
      else {
        const m = /^acs:ram::([^:]*):/i.exec(p) ?? /^(\d+)$/.exec(p);
        uid = m ? m[1] : undefined;
      }
      if (uid === undefined) continue;
      if (uid === "*" || uid.includes("*") || (own !== undefined && uid !== own)) out.add(redactAliDiagnostic(p));
    }
  }
  return [...out];
}

function truthy(v: unknown): boolean {
  return v === true || (typeof v === "string" && v.trim().toLowerCase() === "true");
}

/** Weaknesses of a `PasswordPolicy` object ([] when strong / unknown fields). */
export function evaluateRamPasswordPolicy(policy: unknown): string[] {
  if (!policy || typeof policy !== "object") return [];
  const issues: string[] = [];
  const minLen = aliNumber(aliField(policy, "MinimumPasswordLength"));
  if (minLen !== undefined && minLen < RAM_MIN_PASSWORD_LENGTH) issues.push(`minimum password length is ${minLen} (< ${RAM_MIN_PASSWORD_LENGTH})`);
  const classes = ["RequireLowercaseCharacters", "RequireUppercaseCharacters", "RequireNumbers", "RequireSymbols"];
  if (classes.every((k) => !truthy(aliField(policy, k)))) issues.push("no character-class complexity requirement (lowercase / uppercase / numbers / symbols)");
  const maxAge = aliNumber(aliField(policy, "MaxPasswordAge"));
  if (maxAge === 0) issues.push("passwords never expire (MaxPasswordAge = 0)");
  return issues;
}

/** Ages (whole days) of the ACTIVE AccessKeys older than {@link RAM_AK_MAX_AGE_DAYS}. */
export function staleAccessKeyAges(keys: readonly unknown[], nowMs: number = Date.now()): number[] {
  const ages: number[] = [];
  for (const k of keys) {
    const status = (aliString(aliField(k, "Status")) ?? "Active").toLowerCase();
    if (status !== "active") continue;
    const created = aliString(aliField(k, "CreateDate"));
    const t = created ? Date.parse(created) : NaN;
    if (Number.isNaN(t)) continue;
    const age = Math.floor((nowMs - t) / DAY_MS);
    if (age > RAM_AK_MAX_AGE_DAYS) ages.push(age);
  }
  return ages.sort((a, b) => b - a);
}

/** `RootWithAccessKey` from GetAccountSecurityPracticeReport (nested or flat); undefined when absent. */
export function rootAccessKeyCount(body: unknown): number | undefined {
  const info = aliField(body, "AccountSecurityPracticeInfo");
  const user = aliField(info, "AccountSecurityPracticeUserInfo") ?? aliField(body, "AccountSecurityPracticeUserInfo");
  return aliNumber(aliField(user, "RootWithAccessKey"));
}

/* ------------------------------------------------------------------------ */
/* Call state (fatal short-circuit + aggregated soft failures)              */
/* ------------------------------------------------------------------------ */

type CallOutcome = { ok: true; body: unknown } | { ok: false; kind: AliErrorKind; err: unknown };

class RamScanState {
  /** First auth_failed / api_misuse error (redacted AliCloudError); later calls short-circuit. */
  fatal: Error | undefined;
  private readonly soft = new Map<string, { first: string; count: number }>();

  constructor(readonly env: AliScanEnv) {}

  async call(spec: AliApiSpec, query: Record<string, unknown> = {}): Promise<CallOutcome> {
    if (this.fatal) return { ok: false, kind: "other", err: this.fatal };
    try {
      return { ok: true, body: await aliCall(spec, aliCallCtx(this.env), query) };
    } catch (err) {
      return { ok: false, kind: this.note(err, spec), err };
    }
  }

  /** Record a fatal error (first one wins); returns the error kind. */
  note(err: unknown, spec: AliApiSpec): AliErrorKind {
    if (isAliFatal(err)) this.fatal ??= toAliError(err, `${spec.service}:${spec.action}`);
    return classifyAliError(err).kind;
  }

  /** Aggregate a non-fatal failure under `label` (one warning per API, with a count). */
  softFail(label: string, err: unknown, what?: string): void {
    if (this.fatal || isAliFatal(err)) return;
    const prev = this.soft.get(label);
    if (prev) prev.count++;
    else this.soft.set(label, { first: aliSoftWarning(what ? `${label} (${what})` : label, err), count: 1 });
  }

  softWarnings(): string[] {
    return [...this.soft.values()].map((s) => (s.count > 1 ? `${s.first} (${s.count - 1} more similar failure(s) for the same API)` : s.first));
  }
}

const PAGINATE_ITEM_CAP_SUFFIX = "(item cap reached); results may be incomplete";

/** Marker-paginated RAM list (ListUsers / ListRoles), capped at `max` with an explicit warning. */
async function listRamMarker(
  state: RamScanState,
  spec: AliApiSpec,
  label: string,
  listKey: string,
  itemKey: string,
  max: number,
  noun: string,
  warnings: string[],
): Promise<Record<string, unknown>[]> {
  try {
    const page = await aliPaginate<unknown, Record<string, unknown>>({
      style: "marker",
      label,
      pageSize: RAM_PAGE_SIZE,
      maxItems: max + 1,
      fetch: (q) => aliCall(spec, aliCallCtx(state.env), q),
      items: (body) => aliArray<Record<string, unknown>>(aliField(aliField(body, listKey), itemKey)).filter((i) => i && typeof i === "object"),
    });
    warnings.push(...page.warnings.filter((w) => !w.endsWith(PAGINATE_ITEM_CAP_SUFFIX)));
    if (page.items.length > max) {
      warnings.push(`${label}: more than ${max} ${noun} in the account; only the first ${max} were evaluated.`);
      return page.items.slice(0, max);
    }
    return page.items;
  } catch (err) {
    state.note(err, spec);
    state.softFail(label, err);
    return [];
  }
}

/* ------------------------------------------------------------------------ */
/* Policy references / documents                                            */
/* ------------------------------------------------------------------------ */

interface PolicyRef {
  type: string;
  /** Raw name (API parameter); display through redactAliDiagnostic. */
  name: string;
  version?: string;
}

function policyKey(p: PolicyRef): string {
  return `${p.type.toLowerCase()}|${p.name}|${p.version ?? ""}`;
}

function isSystem(p: PolicyRef): boolean {
  return p.type.toLowerCase() === "system";
}

function parsePolicyRefs(body: unknown): PolicyRef[] {
  const out: PolicyRef[] = [];
  for (const p of aliArray(aliField(aliField(body, "Policies"), "Policy"))) {
    const name = aliString(aliField(p, "PolicyName"));
    if (!name) continue;
    out.push({ type: aliString(aliField(p, "PolicyType")) ?? "Custom", name, version: aliString(aliField(p, "DefaultVersion")) });
  }
  return out;
}

/** Fetch + parse one Custom policy's DefaultVersion document (undefined when unavailable). */
async function fetchCustomPolicy(state: RamScanState, ref: PolicyRef, warnings: string[]): Promise<AliPolicyStatement[] | undefined> {
  const display = redactAliDiagnostic(ref.name);
  let doc: unknown;
  let version = ref.version;
  if (!version) {
    const r = await state.call(ALI_API.ram.GetPolicy, { PolicyType: ref.type, PolicyName: ref.name });
    if (!r.ok) {
      if (r.kind !== "not_found") state.softFail("RAM GetPolicy", r.err, `policy "${display}"`);
      return undefined;
    }
    doc = aliField(aliField(r.body, "DefaultPolicyVersion"), "PolicyDocument");
    version = aliString(aliField(aliField(r.body, "Policy"), "DefaultVersion"));
  }
  if (doc === undefined) {
    if (!version) return undefined;
    const r = await state.call(ALI_API.ram.GetPolicyVersion, { PolicyType: ref.type, PolicyName: ref.name, VersionId: version });
    if (!r.ok) {
      if (r.kind !== "not_found") state.softFail("RAM GetPolicyVersion", r.err, `policy "${display}"`);
      return undefined;
    }
    doc = aliField(aliField(r.body, "PolicyVersion"), "PolicyDocument");
  }
  const parsed = parseAliPolicyDocument(doc);
  if (!parsed) warnings.push(`RAM policy "${display}": the policy document could not be parsed; skipped.`);
  return parsed;
}

/* ------------------------------------------------------------------------ */
/* Findings                                                                 */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider" | "region">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, region: "global", severity, priority: priorityFromSeverity(severity), provider: "alicloud" };
}

type PrincipalKind = "user" | "role";

interface Principal {
  kind: PrincipalKind;
  /** Display name (redacted). */
  name: string;
  arn: string;
  grants: RamGrant[];
}

function list(sources: readonly string[]): string {
  return sources.map((s) => `"${s}"`).join(", ");
}

function policyFindings(p: Principal): Finding[] {
  const a = analyzeRamGrants(p.grants);
  const label = p.kind === "user" ? "RAM user" : "RAM role";
  const resourceType = p.kind === "user" ? "ACS::RAM::User" : "ACS::RAM::Role";
  const base = { resourceType, resourceId: p.name, resourceArn: p.arn };
  const note = `${a.hasDeny ? "The attached policies also contain Deny statements, which may narrow this grant. " : ""}${CONSERVATIVE_NOTE}`;
  const who = p.kind === "user" ? "the user" : "anyone who can assume the role";

  if (a.admin.length > 0) {
    return [
      makeFinding({
        ...base,
        riskScore: RAM_ADMIN_RISK,
        title: `${label} ${p.name} has full administrator permissions`,
        description: `${label} "${p.name}" is granted every action on every resource (Action "*" + Resource "*") by ${list(a.admin)}. ${note}`,
        impact: `${who[0].toUpperCase()}${who.slice(1)} has unrestricted control of the account, including creating administrators, changing policies and deleting any resource.`,
        remediationSteps: [
          `Detach AdministratorAccess / full-wildcard policies from ${label.toLowerCase()} "${p.name}".`,
          "Replace them with specific, least-privilege system or custom policies.",
          "Keep administrator access on a small number of MFA-protected identities and audit it with ActionTrail.",
        ],
      }),
    ];
  }
  if (a.ramFull.length > 0) {
    return [
      makeFinding({
        ...base,
        riskScore: RAM_FULL_ACCESS_RISK,
        title: `${label} ${p.name} has ram:* wildcard permissions`,
        description: `${label} "${p.name}" is granted every RAM action (ram:* / AliyunRAMFullAccess) by ${list(a.ramFull)}, giving full control over identity and access management. ${note}`,
        impact: `${who[0].toUpperCase()}${who.slice(1)} can create, modify or delete any RAM identity or policy, e.g. attach AdministratorAccess to itself, and escalate privileges without restriction.`,
        remediationSteps: [
          `Remove AliyunRAMFullAccess / ram:* permissions from ${label.toLowerCase()} "${p.name}".`,
          "Replace them with specific, least-privilege RAM permissions (e.g. AliyunRAMReadOnlyAccess).",
          "Require MFA for sensitive RAM operations and monitor them with ActionTrail.",
        ],
      }),
    ];
  }
  if (a.escalations.length > 0) {
    const perms = a.escalations.map((e) => `${e.permission} (via ${list(e.sources)})`).join("; ");
    return [
      makeFinding({
        ...base,
        riskScore: RAM_ESCALATION_RISK,
        title: `${label} ${p.name} has privilege-escalation permissions`,
        description: `${label} "${p.name}" is allowed privilege-escalation actions: ${perms}. ${note}`,
        impact:
          "These permissions let the principal grant itself (or an identity it controls) additional policies, credentials or a more privileged role, e.g. by creating a new policy version, attaching AdministratorAccess, creating access keys / console passwords for other users, rewriting a role trust policy or passing a privileged role to an ECS instance / FC function.",
        remediationSteps: [
          `Remove or scope down the listed actions for ${label.toLowerCase()} "${p.name}" (restrict Resource to specific ARNs).`,
          "Restrict ram:PassRole to specific role ARNs and use conditions where possible.",
          "Monitor RAM policy / credential changes with ActionTrail alerts.",
        ],
      }),
    ];
  }
  return [];
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface UserRecord {
  raw: string;
  name: string;
  policies: PolicyRef[];
  groups: string[];
  /** true / false = known; undefined = unknown (call failed). */
  login?: boolean;
  mfaBindRequired?: boolean;
  mfa?: boolean;
  staleKeyAges: number[];
}

interface RoleRecord {
  raw: string;
  name: string;
  policies: PolicyRef[];
  trustDoc?: unknown;
}

export class AliRamPrivilegeScanner implements Scanner {
  readonly moduleName = "iam_privilege_escalation";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);
      const state = new RamScanState(env);
      const fail = () => aliErrorResult(this.moduleName, startMs, MODULE_ERROR_CONTEXT, state.fatal, [...warnings, ...state.softWarnings()]);
      const nowMs = Date.now();

      /* ---- Users ---- */
      const userItems = await listRamMarker(state, ALI_API.ram.ListUsers, "RAM ListUsers", "Users", "User", RAM_MAX_USERS, "RAM users", warnings);
      if (state.fatal) return fail();

      // Virtual MFA devices (one call); failure → fall back to per-user GetUserMFAInfo.
      let mfaUsers: Set<string> | undefined;
      const mfaList = await state.call(ALI_API.ram.ListVirtualMFADevices);
      if (state.fatal) return fail();
      if (mfaList.ok) {
        mfaUsers = new Set();
        for (const d of aliArray(aliField(aliField(mfaList.body, "VirtualMFADevices"), "VirtualMFADevice"))) {
          const u = aliField(d, "User");
          const n = aliString(aliField(u, "UserName"));
          if (n) mfaUsers.add(n);
        }
      } else {
        state.softFail("RAM ListVirtualMFADevices", mfaList.err);
      }

      const rawUserNames = [...new Set(userItems.map((u) => aliString(u.UserName)).filter((n): n is string => !!n))];
      const userSettled = await runWithConcurrency(
        rawUserNames.map((raw) => () => this.scanUser(state, raw, mfaUsers, nowMs)),
        RAM_CONCURRENCY,
      );
      if (state.fatal) return fail();
      const users = userSettled.flatMap((s) => (s.status === "fulfilled" ? [s.value] : []));

      /* ---- Groups ---- */
      const groupNames = [...new Set(users.flatMap((u) => u.groups))];
      const groupPolicies = new Map<string, PolicyRef[]>();
      await runWithConcurrency(
        groupNames.map((g) => async () => {
          const r = await state.call(ALI_API.ram.ListPoliciesForGroup, { GroupName: g });
          if (r.ok) groupPolicies.set(g, parsePolicyRefs(r.body));
          else if (r.kind !== "not_found") state.softFail("RAM ListPoliciesForGroup", r.err, `group "${redactAliDiagnostic(g)}"`);
        }),
        RAM_CONCURRENCY,
      );
      if (state.fatal) return fail();

      /* ---- Roles ---- */
      const roleItems = await listRamMarker(state, ALI_API.ram.ListRoles, "RAM ListRoles", "Roles", "Role", RAM_MAX_ROLES, "RAM roles", warnings);
      if (state.fatal) return fail();
      const roleSettled = await runWithConcurrency(
        roleItems
          .filter((r) => aliString(r.RoleName))
          .map((r) => () => this.scanRole(state, r)),
        RAM_CONCURRENCY,
      );
      if (state.fatal) return fail();
      const roles = roleSettled.flatMap((s) => (s.status === "fulfilled" ? [s.value] : []));

      /* ---- Policy documents (Custom: DefaultVersion; System: by name), cached ---- */
      const refs = new Map<string, PolicyRef>();
      for (const p of [...users.flatMap((u) => u.policies), ...[...groupPolicies.values()].flat(), ...roles.flatMap((r) => r.policies)]) {
        refs.set(policyKey(p), p);
      }
      const docs = new Map<string, AliPolicyStatement[]>();
      const customRefs = [...refs.entries()].filter(([, p]) => !isSystem(p));
      for (const [key, p] of refs) if (isSystem(p)) docs.set(key, systemPolicyStatements(p.name));
      await runWithConcurrency(
        customRefs.map(([key, p]) => async () => {
          const st = await fetchCustomPolicy(state, p, warnings);
          if (st) docs.set(key, st);
        }),
        RAM_CONCURRENCY,
      );
      if (state.fatal) return fail();

      const grantFor = (p: PolicyRef, via?: string): RamGrant[] => {
        const st = docs.get(policyKey(p));
        if (!st || st.length === 0) return [];
        const source = redactAliDiagnostic(`${p.name} (${p.type}${via ? `, via group ${via}` : ""})`);
        return [{ source, statements: st }];
      };

      /* ---- Policy findings ---- */
      for (const u of users) {
        const grants = [
          ...u.policies.flatMap((p) => grantFor(p)),
          ...u.groups.flatMap((g) => (groupPolicies.get(g) ?? []).flatMap((p) => grantFor(p, g))),
        ];
        findings.push(...policyFindings({ kind: "user", name: u.name, arn: toAliUrn("ram", "user", u.name, "", env.accountId), grants }));
      }
      for (const r of roles) {
        const arn = toAliUrn("ram", "role", r.name, "", env.accountId);
        findings.push(...policyFindings({ kind: "role", name: r.name, arn, grants: r.policies.flatMap((p) => grantFor(p)) }));

        const risky = r.trustDoc !== undefined ? riskyTrustPrincipals(r.trustDoc, env.accountId) : [];
        if (risky.length > 0) {
          const wildcard = risky.some((p) => p === "*" || /^acs:ram::[^:]*\*[^:]*:/i.test(p));
          findings.push(
            makeFinding({
              resourceType: "ACS::RAM::Role",
              resourceId: r.name,
              resourceArn: arn,
              riskScore: RAM_TRUST_RISK,
              title: `RAM role ${r.name} can be assumed by ${wildcard ? "any Alibaba Cloud account" : "another account"} without an ExternalId`,
              description: `The trust policy of RAM role "${r.name}" allows sts:AssumeRole for ${list(risky)} without an sts:ExternalId condition.`,
              impact:
                "Principals outside this account can obtain temporary credentials for the role (confused-deputy risk); with a wildcard principal any Alibaba Cloud account can assume it.",
              remediationSteps: [
                `Restrict the trust policy of RAM role "${r.name}" to specific trusted account UIDs / RAM roles.`,
                'Add a Condition such as {"StringEquals": {"sts:ExternalId": "<secret>"}} for third-party access.',
                "Review the role's permissions and remove it if the cross-account access is no longer needed.",
              ],
            }),
          );
        }
      }

      /* ---- Console login without MFA / stale access keys ---- */
      for (const u of users) {
        const arn = toAliUrn("ram", "user", u.name, "", env.accountId);
        if (u.login === true && u.mfa === false) {
          findings.push(
            makeFinding({
              resourceType: "ACS::RAM::User",
              resourceId: u.name,
              resourceArn: arn,
              riskScore: RAM_NO_MFA_RISK,
              title: `RAM user ${u.name} has console access without MFA`,
              description: `RAM user "${u.name}" has a console login profile but no MFA device is bound${u.mfaBindRequired ? " (MFA binding is required at next login but has not been completed)" : ""}.`,
              impact: "A leaked or guessed password alone is enough to sign in to the console as this user.",
              remediationSteps: [
                `Bind a virtual MFA (or U2F) device to RAM user "${u.name}".`,
                "Enforce MFA for console logins in the RAM security settings (SetSecurityPreference / login profile MFABindRequired).",
                "Remove the console login profile if the user only needs API access.",
              ],
            }),
          );
        }
        if (u.staleKeyAges.length > 0) {
          findings.push(
            makeFinding({
              resourceType: "ACS::RAM::User",
              resourceId: u.name,
              resourceArn: arn,
              riskScore: RAM_STALE_AK_RISK,
              title: `RAM user ${u.name} has access keys older than ${RAM_AK_MAX_AGE_DAYS} days`,
              description: `RAM user "${u.name}" has ${u.staleKeyAges.length} active AccessKey(s) not rotated for more than ${RAM_AK_MAX_AGE_DAYS} days (oldest: ${u.staleKeyAges[0]} days). AccessKey IDs are not included in this report.`,
              impact: "Long-lived AccessKeys increase the window in which a leaked key can be abused.",
              remediationSteps: [
                `Create a new AccessKey for "${u.name}", switch workloads to it, then disable and delete the old key.`,
                "Prefer RAM roles / STS temporary credentials (ECS instance RAM roles, OIDC) over long-lived AccessKeys.",
                `Rotate AccessKeys at least every ${RAM_AK_MAX_AGE_DAYS} days.`,
              ],
            }),
          );
        }
      }

      /* ---- Account posture (IMS) ---- */
      const report = await state.call(ALI_API.ims.GetAccountSecurityPracticeReport);
      if (state.fatal) return fail();
      if (report.ok) {
        const rootKeys = rootAccessKeyCount(report.body);
        if (rootKeys !== undefined && rootKeys > 0) {
          findings.push(
            makeFinding({
              resourceType: "ACS::RAM::Account",
              resourceId: "root",
              resourceArn: `${ACS_URN_PREFIX}:ram::${env.accountId}:root`,
              riskScore: RAM_ROOT_AK_RISK,
              title: "Alibaba Cloud account (root) has an AccessKey",
              description: `The Alibaba Cloud account (root identity) has ${rootKeys} AccessKey(s) (IMS GetAccountSecurityPracticeReport RootWithAccessKey).`,
              impact:
                "Root AccessKeys carry unrestricted, unscopable permissions over every resource and cannot be limited by RAM policies; a leak means full account compromise.",
              remediationSteps: [
                "Delete the root account's AccessKeys after moving workloads to RAM users / roles.",
                "Use RAM users or roles with least-privilege policies for programmatic access.",
                "Enable MFA on the root account and monitor its activity with ActionTrail.",
              ],
            }),
          );
        }
      } else if (report.kind !== "not_found") {
        state.softFail("IMS GetAccountSecurityPracticeReport", report.err);
      }

      const pw = await state.call(ALI_API.ims.GetPasswordPolicy);
      if (state.fatal) return fail();
      if (pw.ok) {
        const issues = evaluateRamPasswordPolicy(aliField(pw.body, "PasswordPolicy"));
        if (issues.length > 0) {
          findings.push(
            makeFinding({
              resourceType: "ACS::RAM::PasswordPolicy",
              resourceId: "password-policy",
              resourceArn: toAliUrn("ram", "passwordpolicy", "account", "", env.accountId),
              riskScore: RAM_WEAK_PASSWORD_RISK,
              title: "RAM password policy is weak",
              description: `The RAM user password policy is weak: ${issues.join("; ")}.`,
              impact: "Weak or non-expiring passwords make RAM console accounts easier to brute-force or reuse (MLPS 8.1.4.1 identity authentication).",
              remediationSteps: [
                `Set the minimum password length to at least ${RAM_MIN_PASSWORD_LENGTH} (12+ recommended).`,
                "Require at least three of lowercase, uppercase, numbers and symbols.",
                "Set a maximum password age (e.g. 90 days) and password reuse prevention.",
              ],
            }),
          );
        }
      } else if (pw.kind !== "not_found") {
        state.softFail("IMS GetPasswordPolicy", pw.err);
      }

      warnings.push(...state.softWarnings());
      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings } : {}),
        resourcesScanned: users.length + roles.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, MODULE_ERROR_CONTEXT, err, warnings);
    }
  }

  /** Per-user calls (sequential within the user; users run with the concurrency cap). */
  private async scanUser(state: RamScanState, raw: string, mfaUsers: Set<string> | undefined, nowMs: number): Promise<UserRecord> {
    const name = aliUntrusted(raw) ?? "unknown";
    const display = `user "${name}"`;
    const rec: UserRecord = { raw, name, policies: [], groups: [], staleKeyAges: [] };
    if (state.fatal) return rec;

    const pol = await state.call(ALI_API.ram.ListPoliciesForUser, { UserName: raw });
    if (pol.ok) rec.policies = parsePolicyRefs(pol.body);
    else if (pol.kind !== "not_found") state.softFail("RAM ListPoliciesForUser", pol.err, display);

    const grp = await state.call(ALI_API.ram.ListGroupsForUser, { UserName: raw });
    if (grp.ok) {
      rec.groups = [
        ...new Set(
          aliArray(aliField(aliField(grp.body, "Groups"), "Group"))
            .map((g) => aliString(aliField(g, "GroupName")))
            .filter((g): g is string => !!g),
        ),
      ];
    } else if (grp.kind !== "not_found") state.softFail("RAM ListGroupsForUser", grp.err, display);

    const login = await state.call(ALI_API.ram.GetLoginProfile, { UserName: raw });
    if (login.ok) {
      rec.login = true;
      rec.mfaBindRequired = truthy(aliField(aliField(login.body, "LoginProfile"), "MFABindRequired"));
    } else if (login.kind === "not_found") {
      rec.login = false; // EntityNotExist.User.LoginProfile: API-only user
    } else {
      state.softFail("RAM GetLoginProfile", login.err, display);
    }

    if (rec.login) {
      if (mfaUsers?.has(raw)) rec.mfa = true;
      else {
        const mfa = await state.call(ALI_API.ram.GetUserMFAInfo, { UserName: raw });
        if (mfa.ok) rec.mfa = aliField(mfa.body, "MFADevice") !== undefined;
        else if (mfa.kind === "not_found") rec.mfa = false; // EntityNotExist.User.MFADevice
        else state.softFail("RAM GetUserMFAInfo", mfa.err, display);
      }
    }

    const keys = await state.call(ALI_API.ram.ListAccessKeys, { UserName: raw });
    if (keys.ok) rec.staleKeyAges = staleAccessKeyAges(aliArray(aliField(aliField(keys.body, "AccessKeys"), "AccessKey")), nowMs);
    else if (keys.kind !== "not_found") state.softFail("RAM ListAccessKeys", keys.err, display);

    return rec;
  }

  /** Per-role calls: attached policies + trust policy (GetRole when ListRoles omitted it). */
  private async scanRole(state: RamScanState, item: Record<string, unknown>): Promise<RoleRecord> {
    const raw = aliString(item.RoleName) ?? "";
    const name = aliUntrusted(raw) ?? "unknown";
    const display = `role "${name}"`;
    const rec: RoleRecord = { raw, name, policies: [], trustDoc: aliString(item.AssumeRolePolicyDocument) };
    if (state.fatal) return rec;

    const pol = await state.call(ALI_API.ram.ListPoliciesForRole, { RoleName: raw });
    if (pol.ok) rec.policies = parsePolicyRefs(pol.body);
    else if (pol.kind !== "not_found") state.softFail("RAM ListPoliciesForRole", pol.err, display);

    if (rec.trustDoc === undefined) {
      const role = await state.call(ALI_API.ram.GetRole, { RoleName: raw });
      if (role.ok) rec.trustDoc = aliString(aliField(aliField(role.body, "Role"), "AssumeRolePolicyDocument"));
      else if (role.kind !== "not_found") state.softFail("RAM GetRole", role.err, display);
    }
    return rec;
  }
}

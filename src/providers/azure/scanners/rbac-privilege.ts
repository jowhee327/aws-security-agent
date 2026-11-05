/**
 * Azure RBAC + Entra ID privilege scanner (moduleName `iam_privilege_escalation`, plan §2 #6 /
 * §4.1 P1 / §4.3 / T6). EXPERIMENTAL — not yet validated against a live account; field names
 * follow the `@azure/arm-authorization` 9.x d.ts (AutoRest client: `properties` flattened; a
 * nested `properties` object is also accepted) and the Microsoft Graph v1.0 documentation.
 *
 * TENANT-LEVEL GLOBAL module (AZURE_GLOBAL_MODULES: the runner runs it once per scan, with the
 * first subscription's context). It therefore covers every subscription itself (plan §3.3):
 *  - `AZURE_SUBSCRIPTION_ID` pinned → that subscription only; otherwise every visible, active
 *    subscription (`listAzureSubscriptions`), capped at {@link AZURE_IAM_MAX_SUBSCRIPTIONS} and
 *    scanned {@link AZURE_IAM_SUBSCRIPTION_CONCURRENCY} at a time. When enumeration fails for a
 *    non-auth reason, the context subscription is scanned alone (warning). An explicit
 *    subscription passed as `region` is NOT distinguishable from "all" here (the runner gives
 *    a global module the first scope), so tenant-wide RBAC is reported in both cases.
 *
 * Per subscription (`AuthorizationManagementClient`):
 *  - `roleAssignments.listForSubscription()` — assignments at, above (management group / root)
 *    and below the subscription; deduplicated across subscriptions by assignment ID.
 *  - `roleDefinitions.list("/subscriptions/<id>", { filter: "type eq 'CustomRole'" })` — custom
 *    roles assignable there; cached by role GUID. Built-in Owner / Contributor / User Access
 *    Administrator are recognised by their fixed GUIDs (no lookup); any other referenced role
 *    is resolved once via `roleDefinitions.getById` (cache, ≤ {@link AZURE_IAM_MAX_ROLE_LOOKUPS},
 *    concurrency {@link AZURE_IAM_LOOKUP_CONCURRENCY}).
 *  - `classicAdministrators.list()` — classic co-administrators (the API is deprecated /
 *    retired in places: EVERY non-auth error there, api_misuse included, is a warning).
 *
 * Microsoft Graph (`graphClient`, China baseUrl microsoftgraph.chinacloudapi.cn; needs
 * `Directory.Read.All` / `RoleManagement.Read.Directory`, and `AuditLog.Read.All` for MFA):
 *  - `POST /directoryObjects/getByIds` (batches of {@link AZURE_GRAPH_GETBYIDS_BATCH}, ≤
 *    {@link AZURE_IAM_MAX_PRINCIPALS} principals) → guest users (`userType=Guest` / `#EXT#` UPN)
 *    and display names.
 *  - `GET /directoryRoles` + `/directoryRoles/<id>/members` → Global Administrator / Privileged
 *    Role Administrator membership.
 *  - `GET /reports/authenticationMethods/userRegistrationDetails/<id>` → `isMfaRegistered` for
 *    Contributor users (≤ {@link AZURE_IAM_MAX_MFA_LOOKUPS}).
 *  Each Graph part degrades independently: 403 `Authorization_RequestDenied`, API unavailable
 *  in the China cloud, throttling, … → warning; the RBAC findings are still reported (plan §6.4
 *  Q2 default). Without Graph, guests are only recognised via `principalType=ForeignGroup`.
 *
 * Rules / riskScore (plan §4.3), one finding per role assignment at its highest rule:
 *  - Owner at subscription / management group / root scope → 8.0; to a service principal 7.5;
 *    to a guest / foreign principal 9.0. More than {@link AZURE_IAM_MAX_OWNERS} distinct Owner
 *    principals on a subscription → 9.0 (one finding per subscription).
 *  - User Access Administrator (any scope) → 8.0.
 *  - Contributor (subscription scope or above) to a user without registered MFA → 6.0.
 *  - Any role to a guest / foreign principal (privileged role at any scope, other roles at
 *    subscription scope or above) → 7.5.
 *  - Custom role whose effective actions (`actions` minus `notActions`, wildcard-matched)
 *    include `*`, `Microsoft.Authorization/roleAssignments/write`, `…/roleDefinitions/write` or
 *    `…/elevateAccess/action` → 8.0 (one finding per role definition).
 *  - Entra Global Administrator / Privileged Role Administrator with more than
 *    {@link AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS} members or any guest member → 7.5.
 *  - Classic co-administrator present → 5.0.
 *
 * Every server-sourced string (names, UPNs, scopes, actions, e-mail addresses) passes through
 * aztUntrusted. Server IDs are only interpolated into Graph paths after a GUID check, and
 * `@odata.nextLink` is only followed on the cloud's own Graph host. Errors: auth_failed /
 * api_misuse (outside classic administrators) → module `status: "error"`, except a Graph
 * auth_failed after some ARM RBAC call succeeded → Entra checks skipped with a warning.
 */
import type { AuthorizationManagementClient } from "@azure/arm-authorization";
import type { Client as GraphClient } from "@microsoft/microsoft-graph-client";
import type { Scanner } from "../../../scanners/base.js";
import type { AzureCredentials, Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azureCloudConfig, azurePaginate, graphClient } from "../client.js";
import { azureCredentialFromContext, pinnedAzureSubscriptionId } from "../credentials.js";
import { classifyAzureError, extractAzureError } from "../errors.js";
import { listAzureSubscriptions } from "../subscriptions.js";
import { toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azLastSegment,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureErrorResult,
  azureSafeFinding,
  azureSafeWarnings,
  azureSoftWarning,
  azureSubscriptionFromContext,
  azureTruncationWarning,
  isAzureFatal,
} from "./shared.js";

export const AZURE_IAM_MAX_SUBSCRIPTIONS = 50;
export const AZURE_IAM_SUBSCRIPTION_CONCURRENCY = 4;
export const AZURE_IAM_MAX_ASSIGNMENTS = 5000;
export const AZURE_IAM_MAX_CUSTOM_ROLES = 1000;
export const AZURE_IAM_MAX_CLASSIC_ADMINS = 500;
export const AZURE_IAM_MAX_ROLE_LOOKUPS = 200;
export const AZURE_IAM_LOOKUP_CONCURRENCY = 4;
export const AZURE_IAM_MAX_PRINCIPALS = 2000;
export const AZURE_GRAPH_GETBYIDS_BATCH = 1000;
export const AZURE_IAM_MAX_MFA_LOOKUPS = 100;
export const AZURE_GRAPH_MAX_ITEMS = 1000;
/** Microsoft recommends at most 3 subscription Owners. */
export const AZURE_IAM_MAX_OWNERS = 3;
/** Microsoft recommends fewer than 5 Global Administrators. */
export const AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS = 4;

export const AZURE_IAM_OWNER_RISK = 8.0;
export const AZURE_IAM_OWNER_SP_RISK = 7.5;
export const AZURE_IAM_OWNER_EXTERNAL_RISK = 9.0;
export const AZURE_IAM_EXCESSIVE_OWNERS_RISK = 9.0;
export const AZURE_IAM_UAA_RISK = 8.0;
export const AZURE_IAM_CONTRIBUTOR_NO_MFA_RISK = 6.0;
export const AZURE_IAM_EXTERNAL_RISK = 7.5;
export const AZURE_IAM_CUSTOM_ROLE_RISK = 8.0;
export const AZURE_ENTRA_PRIVILEGED_ROLE_RISK = 7.5;
export const AZURE_IAM_CLASSIC_ADMIN_RISK = 5.0;

/** Built-in role GUIDs (identical in every Azure cloud). */
export const AZURE_ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
export const AZURE_ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c";
export const AZURE_ROLE_USER_ACCESS_ADMIN = "18d7d88d-d35e-4fb5-a5c3-7773c4a72b9d";

const BUILTIN_ROLE_NAMES: Readonly<Record<string, string>> = {
  [AZURE_ROLE_OWNER]: "Owner",
  [AZURE_ROLE_CONTRIBUTOR]: "Contributor",
  [AZURE_ROLE_USER_ACCESS_ADMIN]: "User Access Administrator",
};

/** Entra directory role template IDs. */
export const ENTRA_GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
export const ENTRA_PRIVILEGED_ROLE_ADMIN_TEMPLATE = "e8611ab8-c189-46e8-94e1-60213ab1f814";
const ENTRA_PRIVILEGED_ROLES: Readonly<Record<string, string>> = {
  [ENTRA_GLOBAL_ADMIN_TEMPLATE]: "Global Administrator",
  [ENTRA_PRIVILEGED_ROLE_ADMIN_TEMPLATE]: "Privileged Role Administrator",
};

/** Actions whose grant lets a principal escalate its own (or anyone's) access. */
export const AZURE_ESCALATION_ACTIONS: readonly string[] = [
  "Microsoft.Authorization/roleAssignments/write",
  "Microsoft.Authorization/roleDefinitions/write",
  "Microsoft.Authorization/elevateAccess/action",
];

const ASSIGNMENT_TYPE = "Microsoft.Authorization/roleAssignments";
const ROLE_DEF_TYPE = "Microsoft.Authorization/roleDefinitions";
const CLASSIC_TYPE = "Microsoft.Authorization/classicAdministrators";
const SUBSCRIPTION_TYPE = "Microsoft.Resources/subscriptions";
const DIRECTORY_ROLE_TYPE = "microsoft.graph.directoryRole";

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for unit tests)                                   */
/* ------------------------------------------------------------------------ */

/** Resource property: flattened (AutoRest SDK) or nested under `properties` (raw ARM). */
function prop(resource: unknown, key: string): unknown {
  const direct = azField(resource, key);
  return direct !== undefined ? direct : azField(azField(resource, "properties"), key);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

/** Azure RBAC action wildcard match (`*` = any characters), case-insensitive. */
export function azureActionMatches(pattern: string, action: string): boolean {
  if (typeof pattern !== "string" || typeof action !== "string") return false;
  const p = pattern.trim();
  if (!p) return false;
  if (p === "*") return true;
  const re = new RegExp(`^${p.split("*").map(escapeRegExp).join(".*")}$`, "i");
  return re.test(action.trim());
}

/** Whether any permission block grants `action` (`actions` match and no `notActions` match). */
export function azureRoleGrantsAction(permissions: unknown, action: string): boolean {
  for (const perm of azArray(permissions)) {
    const actions = azArray(azField(perm, "actions")).filter((a): a is string => typeof a === "string");
    const notActions = azArray(azField(perm, "notActions")).filter((a): a is string => typeof a === "string");
    if (actions.some((a) => azureActionMatches(a, action)) && !notActions.some((n) => azureActionMatches(n, action))) return true;
  }
  return false;
}

/** Escalation actions granted by a role definition's permissions (raw action names from the fixed list). */
export function azureRoleEscalationActions(permissions: unknown): string[] {
  return AZURE_ESCALATION_ACTIONS.filter((a) => azureRoleGrantsAction(permissions, a));
}

/** Whether a role definition grants the full `*` action (unrestricted). */
export function azureRoleHasFullWildcard(permissions: unknown): boolean {
  return azArray(permissions).some((perm) =>
    azArray(azField(perm, "actions")).some((a) => typeof a === "string" && a.trim() === "*"),
  );
}

export type AzureScopeKind = "root" | "managementGroup" | "subscription" | "resourceGroup" | "resource" | "unknown";

/** Classify an RBAC assignment scope. */
export function azureScopeKind(scope: string | undefined): AzureScopeKind {
  const s = (scope ?? "").trim().replace(/\/+$/, "");
  if (scope !== undefined && s === "") return "root";
  if (/^\/providers\/microsoft\.management\/managementgroups\/[^/]+$/i.test(s)) return "managementGroup";
  if (/^\/subscriptions\/[^/]+$/i.test(s)) return "subscription";
  if (/^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+$/i.test(s)) return "resourceGroup";
  if (/^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\//i.test(s)) return "resource";
  return "unknown";
}

/** Subscription scope or above (root / management group / subscription). */
export function azureScopeIsBroad(kind: AzureScopeKind): boolean {
  return kind === "root" || kind === "managementGroup" || kind === "subscription";
}

/** Lower-cased role GUID of a role definition ID (`…/roleDefinitions/<guid>`). */
export function azureRoleGuid(roleDefinitionId: string | undefined): string | undefined {
  return azLastSegment(roleDefinitionId)?.toLowerCase();
}

/** Guest user: `userType=Guest` or a `#EXT#` UPN. */
export function azureIsGuestPrincipal(obj: unknown): boolean {
  const userType = (azString(azField(obj, "userType")) ?? "").toLowerCase();
  const upn = azString(azField(obj, "userPrincipalName")) ?? "";
  return userType === "guest" || /#EXT#/i.test(upn);
}

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/* ------------------------------------------------------------------------ */

interface AssignmentEntry {
  raw: unknown;
  id: string;
  /** Subscriptions whose listing returned this assignment (raw IDs). */
  subscriptions: Set<string>;
}

interface RoleDefInfo {
  id?: string;
  name?: string;
  roleType?: string;
  permissions: unknown;
  assignableScopes: unknown;
}

interface PrincipalInfo {
  displayName?: string;
  upn?: string;
  guest: boolean;
  odataType?: string;
}

interface ClassicAdminEntry {
  raw: unknown;
  subscriptionId: string;
}

interface IamState {
  assignments: Map<string, AssignmentEntry>;
  roleDefs: Map<string, RoleDefInfo>;
  classicAdmins: ClassicAdminEntry[];
  warnings: string[];
  scanned: number;
  /** Subscriptions whose role assignments were listed. */
  scannedSubscriptions: string[];
  /** A client of a subscription whose RBAC calls worked (for getById lookups). */
  lookupClient?: AuthorizationManagementClient;
  /** Some subscription RBAC (ARM) call succeeded: the credentials are proven valid. */
  armVerified: boolean;
}

class FatalError {
  constructor(readonly err: unknown) {}
}

/** Graph auth failure after ARM RBAC succeeded: Entra enrichment is abandoned (warning already recorded). */
class GraphSkipped {}

function roleDefInfo(raw: unknown): RoleDefInfo {
  return {
    id: azString(azField(raw, "id")),
    name: azString(prop(raw, "roleName")),
    roleType: azString(prop(raw, "roleType")),
    permissions: prop(raw, "permissions"),
    assignableScopes: prop(raw, "assignableScopes"),
  };
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider" | "region">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, region: "global", severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AzureRbacPrivilegeScanner implements Scanner {
  readonly moduleName = "iam_privilege_escalation";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const errorContext = "Azure RBAC / Entra privilege scan failed";
    let creds: AzureCredentials;
    try {
      creds = azureCredentialFromContext(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, errorContext, err);
    }
    const tenantId = ctx.tenantId?.trim() || creds.tenantId;
    const state: IamState = { assignments: new Map(), roleDefs: new Map(), classicAdmins: [], warnings: [], scanned: 0, scannedSubscriptions: [], armVerified: false };

    try {
      const subs = await this.subscriptions(ctx, creds, state);
      if (subs.length > 0) {
        const { AuthorizationManagementClient } = await import("@azure/arm-authorization");
        const results = await runWithConcurrency(
          subs.map((sub) => () => this.scanSubscription(AuthorizationManagementClient, creds, sub, state)),
          AZURE_IAM_SUBSCRIPTION_CONCURRENCY,
        );
        for (const r of results) if (r.status === "rejected") throw r.reason;
        await this.resolveRoleDefinitions(state);
      }

      const principals = new Map<string, PrincipalInfo>();
      const mfa = new Map<string, boolean>();
      let directoryFindings: Finding[] = [];
      try {
        const graph = await this.graph(creds, state);
        if (graph) {
          await this.expandPrincipals(graph, state, principals);
          await this.mfaRegistration(graph, state, principals, mfa);
          directoryFindings = await this.directoryRoles(graph, creds, tenantId, state);
        }
      } catch (err) {
        if (!(err instanceof GraphSkipped)) throw err;
        principals.clear();
        mfa.clear();
        directoryFindings = [];
      }

      const findings = [
        ...this.assignmentFindings(state, principals, mfa, tenantId),
        ...this.excessiveOwnerFindings(state, principals, tenantId),
        ...this.customRoleFindings(state, tenantId),
        ...this.classicAdminFindings(state, tenantId),
        ...directoryFindings,
      ];
      return {
        module: this.moduleName,
        status: "success",
        ...(state.warnings.length > 0 ? { warnings: azureSafeWarnings(state.warnings) } : {}),
        resourcesScanned: state.scanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      const cause = err instanceof FatalError ? err.err : err;
      return azureErrorResult(this.moduleName, startMs, errorContext, cause, state.warnings);
    }
  }

  /* ---------------------------- subscriptions ---------------------------- */

  private async subscriptions(ctx: ScanContext, creds: AzureCredentials, state: IamState): Promise<string[]> {
    const pinned = pinnedAzureSubscriptionId();
    if (pinned) return [pinned];
    const fromCtx = azureSubscriptionFromContext(ctx);
    let ids: string[] = [];
    try {
      const seen = new Set<string>();
      for (const s of await listAzureSubscriptions(creds)) {
        const id = s.subscriptionId?.trim();
        const st = (s.state ?? "").toLowerCase();
        if (!id || seen.has(id.toLowerCase()) || st === "disabled" || st === "deleted") continue;
        seen.add(id.toLowerCase());
        ids.push(id);
      }
    } catch (err) {
      if (isAzureFatal(err)) throw new FatalError(err);
      state.warnings.push(`${azureSoftWarning("Azure subscriptions.list", err)} — RBAC checked for the scan's subscription only.`);
      return fromCtx ? [fromCtx] : [];
    }
    if (ids.length === 0 && fromCtx) ids = [fromCtx];
    if (ids.length === 0) {
      state.warnings.push(
        `${this.moduleName}: no Azure subscription visible to the service principal; RBAC role assignments not checked (Entra directory roles only).`,
      );
    }
    if (ids.length > AZURE_IAM_MAX_SUBSCRIPTIONS) {
      state.warnings.push(azureTruncationWarning(`${this.moduleName}: subscriptions`, AZURE_IAM_MAX_SUBSCRIPTIONS));
      ids = ids.slice(0, AZURE_IAM_MAX_SUBSCRIPTIONS);
    }
    return ids;
  }

  private async scanSubscription(
    Ctor: typeof AuthorizationManagementClient,
    creds: AzureCredentials,
    sub: string,
    state: IamState,
  ): Promise<void> {
    const client = await armClient(Ctor, creds, sub);
    const label = (api: string) => `RBAC ${api} (subscription ${aztUntrusted(sub)})`;

    // Role assignments.
    try {
      const page = await azurePaginate(client.roleAssignments.listForSubscription(), {
        max: AZURE_IAM_MAX_ASSIGNMENTS,
        collect: false,
        onItem: (a) => {
          const id = azString(azField(a, "id"));
          if (!id) return;
          const key = id.toLowerCase();
          const entry = state.assignments.get(key) ?? { raw: a, id, subscriptions: new Set<string>() };
          entry.subscriptions.add(sub);
          state.assignments.set(key, entry);
        },
      });
      state.scanned += page.count;
      state.scannedSubscriptions.push(sub);
      state.lookupClient ??= client;
      state.armVerified = true;
      if (page.truncated) state.warnings.push(azureTruncationWarning(label("roleAssignments.listForSubscription"), AZURE_IAM_MAX_ASSIGNMENTS));
    } catch (err) {
      if (isAzureFatal(err)) throw new FatalError(err);
      state.warnings.push(`${azureSoftWarning(label("roleAssignments.listForSubscription"), err)} — role assignments not checked.`);
    }

    // Custom role definitions assignable in this subscription.
    try {
      const page = await azurePaginate(client.roleDefinitions.list(`/subscriptions/${sub}`, { filter: "type eq 'CustomRole'" }), {
        max: AZURE_IAM_MAX_CUSTOM_ROLES,
        collect: false,
        onItem: (d) => {
          const guid = azureRoleGuid(azString(azField(d, "id")) ?? azString(azField(d, "name")));
          if (guid && !state.roleDefs.has(guid)) {
            state.roleDefs.set(guid, roleDefInfo(d));
            state.scanned++;
          }
        },
      });
      state.armVerified = true;
      if (page.truncated) state.warnings.push(azureTruncationWarning(label("roleDefinitions.list"), AZURE_IAM_MAX_CUSTOM_ROLES));
    } catch (err) {
      if (isAzureFatal(err)) throw new FatalError(err);
      state.warnings.push(`${azureSoftWarning(label("roleDefinitions.list"), err)} — custom role definitions not checked.`);
    }

    // Classic administrators (deprecated API: anything but an auth failure degrades).
    try {
      const page = await azurePaginate(client.classicAdministrators.list(), { max: AZURE_IAM_MAX_CLASSIC_ADMINS, collect: false, onItem: (c) => {
        state.classicAdmins.push({ raw: c, subscriptionId: sub });
      } });
      state.scanned += page.count;
      state.armVerified = true;
      if (page.truncated) state.warnings.push(azureTruncationWarning(label("classicAdministrators.list"), AZURE_IAM_MAX_CLASSIC_ADMINS));
    } catch (err) {
      if (classifyAzureError(err).kind === "auth_failed") throw new FatalError(err);
      state.warnings.push(
        `${azureSoftWarning(label("classicAdministrators.list"), err)} — classic co-administrators not checked (the classic administrator API is deprecated).`,
      );
    }
  }

  /** Resolve referenced, non-built-in, not-yet-cached role definitions via getById (cached, capped). */
  private async resolveRoleDefinitions(state: IamState): Promise<void> {
    const client = state.lookupClient;
    if (!client) return;
    const pending = new Map<string, string>(); // guid → raw roleDefinitionId
    for (const a of state.assignments.values()) {
      const rid = azString(prop(a.raw, "roleDefinitionId"));
      const guid = azureRoleGuid(rid);
      if (!rid || !guid || BUILTIN_ROLE_NAMES[guid] || state.roleDefs.has(guid) || pending.has(guid)) continue;
      pending.set(guid, rid);
    }
    let entries = [...pending.entries()];
    if (entries.length > AZURE_IAM_MAX_ROLE_LOOKUPS) {
      state.warnings.push(azureTruncationWarning("RBAC roleDefinitions.getById", AZURE_IAM_MAX_ROLE_LOOKUPS));
      entries = entries.slice(0, AZURE_IAM_MAX_ROLE_LOOKUPS);
    }
    const results = await runWithConcurrency(
      entries.map(([guid, rid]) => async () => {
        const def = await client.roleDefinitions.getById(rid);
        state.roleDefs.set(guid, roleDefInfo(def));
      }),
      AZURE_IAM_LOOKUP_CONCURRENCY,
    );
    const failures = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");
    const fatal = failures.find((f) => isAzureFatal(f.reason));
    if (fatal) throw new FatalError(fatal.reason);
    if (failures.length > 0) {
      state.warnings.push(
        `${azureSoftWarning("RBAC roleDefinitions.getById", failures[0].reason)} — ${failures.length} referenced role definition(s) not resolved.`,
      );
    }
  }

  /* -------------------------------- Graph -------------------------------- */

  private async graph(creds: AzureCredentials, state: IamState): Promise<GraphClient | undefined> {
    try {
      return await graphClient(creds);
    } catch (err) {
      this.graphFatal(state, err);
      state.warnings.push(`${azureSoftWarning("Microsoft Graph", err)} — Entra ID checks skipped; RBAC results only.`);
      return undefined;
    }
  }

  /**
   * Fatal Graph errors. api_misuse always propagates; auth_failed propagates unless ARM RBAC
   * already succeeded (credentials proven valid — e.g. wrong Graph audience in China or a
   * Graph-scope AADSTS): then the Entra checks are skipped with a warning (plan §4.2 / §6.4 Q2)
   * and the RBAC findings are still reported.
   */
  private graphFatal(state: IamState, err: unknown): void {
    if (!isAzureFatal(err)) return;
    if (!state.armVerified || classifyAzureError(err).kind !== "auth_failed") throw new FatalError(err);
    const info = extractAzureError(err);
    const code = aztUntrusted(info.aadsts ?? info.code ?? (info.status !== undefined ? `HTTP ${info.status}` : "unknown"));
    state.warnings.push(
      `Entra (Microsoft Graph) checks skipped: Azure authentication to Microsoft Graph failed (${code}) — RBAC results only (guest / MFA / directory role checks not run); check the Graph application permissions and the AZURE_CLOUD Graph endpoint.`,
    );
    throw new GraphSkipped();
  }

  /** Graph errors: fatal ones go through {@link graphFatal}; anything else → warning with the consequence. */
  private graphSoft(state: IamState, service: string, err: unknown, consequence: string): void {
    this.graphFatal(state, err);
    state.warnings.push(`${azureSoftWarning(`Microsoft Graph ${service}`, err)} — ${consequence}.`);
  }

  /** `GET` a Graph collection, following `@odata.nextLink` on the cloud's own Graph host only. */
  private async graphList(
    graph: GraphClient,
    creds: AzureCredentials,
    path: string,
    max: number,
  ): Promise<{ items: unknown[]; truncated: boolean; foreignNextLink: boolean }> {
    const graphBase = `${azureCloudConfig(creds.cloud).graphEndpoint}/`;
    const items: unknown[] = [];
    let res: unknown = await graph.api(path).get();
    for (;;) {
      for (const item of azArray(azField(res, "value"))) {
        if (items.length >= max) return { items, truncated: true, foreignNextLink: false };
        items.push(item);
      }
      const next = azString(azField(res, "@odata.nextLink"));
      if (!next) return { items, truncated: false, foreignNextLink: false };
      if (items.length >= max) return { items, truncated: true, foreignNextLink: false };
      if (!next.toLowerCase().startsWith(graphBase.toLowerCase())) return { items, truncated: true, foreignNextLink: true };
      res = await graph.api(next).get();
    }
  }

  private async expandPrincipals(graph: GraphClient, state: IamState, principals: Map<string, PrincipalInfo>): Promise<void> {
    const ids = new Set<string>();
    for (const a of state.assignments.values()) {
      const pid = azString(prop(a.raw, "principalId"));
      if (pid && GUID_RE.test(pid)) ids.add(pid.toLowerCase());
    }
    if (ids.size === 0) return;
    let list = [...ids];
    if (list.length > AZURE_IAM_MAX_PRINCIPALS) {
      state.warnings.push(azureTruncationWarning("Microsoft Graph directoryObjects.getByIds (principals)", AZURE_IAM_MAX_PRINCIPALS));
      list = list.slice(0, AZURE_IAM_MAX_PRINCIPALS);
    }
    for (let i = 0; i < list.length; i += AZURE_GRAPH_GETBYIDS_BATCH) {
      const batch = list.slice(i, i + AZURE_GRAPH_GETBYIDS_BATCH);
      try {
        const res = await graph.api("/directoryObjects/getByIds").post({ ids: batch, types: ["user", "group", "servicePrincipal"] });
        for (const obj of azArray(azField(res, "value"))) {
          const id = azString(azField(obj, "id"))?.toLowerCase();
          if (!id) continue;
          principals.set(id, {
            displayName: aztUntrustedOpt(azField(obj, "displayName")),
            upn: aztUntrustedOpt(azField(obj, "userPrincipalName")),
            guest: azureIsGuestPrincipal(obj),
            odataType: azString(azField(obj, "@odata.type")),
          });
        }
      } catch (err) {
        this.graphSoft(state, "directoryObjects.getByIds", err, "guest / external principals in RBAC assignments not identified (ForeignGroup only)");
        return;
      }
    }
  }

  /** `isMfaRegistered` for users holding Contributor at subscription scope or above. */
  private async mfaRegistration(
    graph: GraphClient,
    state: IamState,
    principals: Map<string, PrincipalInfo>,
    mfa: Map<string, boolean>,
  ): Promise<void> {
    const users = new Set<string>();
    for (const a of state.assignments.values()) {
      if (azureRoleGuid(azString(prop(a.raw, "roleDefinitionId"))) !== AZURE_ROLE_CONTRIBUTOR) continue;
      if (!azureScopeIsBroad(azureScopeKind(azString(prop(a.raw, "scope"))))) continue;
      if ((azString(prop(a.raw, "principalType")) ?? "").toLowerCase() !== "user") continue;
      const pid = azString(prop(a.raw, "principalId"))?.toLowerCase();
      if (!pid || !GUID_RE.test(pid) || principals.get(pid)?.guest) continue;
      users.add(pid);
    }
    if (users.size === 0) return;
    let list = [...users];
    if (list.length > AZURE_IAM_MAX_MFA_LOOKUPS) {
      state.warnings.push(azureTruncationWarning("Microsoft Graph userRegistrationDetails (MFA)", AZURE_IAM_MAX_MFA_LOOKUPS));
      list = list.slice(0, AZURE_IAM_MAX_MFA_LOOKUPS);
    }
    const results = await runWithConcurrency(
      list.map((id) => async () => {
        const res = await graph.api(`/reports/authenticationMethods/userRegistrationDetails/${id}`).get();
        const registered = azField(res, "isMfaRegistered");
        if (typeof registered === "boolean") mfa.set(id, registered);
      }),
      AZURE_IAM_LOOKUP_CONCURRENCY,
    );
    const failures = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");
    const fatal = failures.find((f) => isAzureFatal(f.reason));
    if (fatal) this.graphFatal(state, fatal.reason);
    if (failures.length > 0) {
      this.graphSoft(
        state,
        "userRegistrationDetails",
        failures[0].reason,
        `MFA registration not checked for ${failures.length} Contributor user(s)`,
      );
    }
  }

  private async directoryRoles(graph: GraphClient, creds: AzureCredentials, tenantId: string, state: IamState): Promise<Finding[]> {
    let roles: unknown[];
    try {
      const res = await this.graphList(graph, creds, "/directoryRoles", AZURE_GRAPH_MAX_ITEMS);
      roles = res.items;
      if (res.truncated) state.warnings.push(azureTruncationWarning("Microsoft Graph directoryRoles", AZURE_GRAPH_MAX_ITEMS));
    } catch (err) {
      this.graphSoft(state, "directoryRoles", err, "Entra ID privileged directory roles not checked");
      return [];
    }
    state.scanned += roles.length;

    const findings: Finding[] = [];
    for (const role of roles) {
      const template = azString(azField(role, "roleTemplateId"))?.toLowerCase();
      const roleName = template ? ENTRA_PRIVILEGED_ROLES[template] : undefined;
      const roleId = azString(azField(role, "id"));
      if (!roleName || !roleId || !GUID_RE.test(roleId)) continue;
      let members: unknown[];
      try {
        const res = await this.graphList(graph, creds, `/directoryRoles/${roleId}/members`, AZURE_GRAPH_MAX_ITEMS);
        members = res.items;
        if (res.foreignNextLink) state.warnings.push(`Microsoft Graph directoryRoles/members (${roleName}): nextLink outside the Graph endpoint ignored; member list may be incomplete.`);
        else if (res.truncated) state.warnings.push(azureTruncationWarning(`Microsoft Graph directoryRoles/members (${roleName})`, AZURE_GRAPH_MAX_ITEMS));
      } catch (err) {
        this.graphSoft(state, `directoryRoles/members (${roleName})`, err, `${roleName} membership not checked`);
        continue;
      }
      const f = this.directoryRoleFinding(role, roleName, members, tenantId);
      if (f) findings.push(f);
    }
    return findings;
  }

  private directoryRoleFinding(role: unknown, roleName: string, members: unknown[], tenantId: string): Finding | undefined {
    const guests = members.filter(azureIsGuestPrincipal);
    const excessive = members.length > AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS;
    if (!excessive && guests.length === 0) return undefined;
    const roleId = aztUntrusted(azField(role, "id"));
    const label = (m: unknown) =>
      aztUntrustedOpt(azField(m, "userPrincipalName")) ?? aztUntrustedOpt(azField(m, "displayName")) ?? aztUntrusted(azField(m, "id"));
    const guestList = guests.slice(0, 10).map(label).join(", ");
    const reasons = [
      ...(excessive ? [`${members.length} members (recommended: at most ${AZURE_ENTRA_MAX_PRIVILEGED_MEMBERS})`] : []),
      ...(guests.length > 0 ? [`${guests.length} guest member(s): ${guestList}${guests.length > 10 ? ", …" : ""}`] : []),
    ];
    return makeFinding({
      riskScore: AZURE_ENTRA_PRIVILEGED_ROLE_RISK,
      title: `Entra ID ${roleName} role: ${[
        ...(excessive ? [`${members.length} members`] : []),
        ...(guests.length > 0 ? [`${guests.length} guest member(s)`] : []),
      ].join("; ")}`,
      resourceType: DIRECTORY_ROLE_TYPE,
      resourceId: roleId || roleName,
      resourceArn: `/directoryRoles/${roleId}`,
      description: `The Entra ID directory role ${roleName} in tenant ${aztUntrusted(tenantId)} has ${members.length} member(s): ${reasons.join("; ")}. Members of this role control the whole tenant, including every Azure subscription (via elevate access).`,
      impact: "Every additional or external holder of a tenant-wide administrator role widens the blast radius of a single compromised account.",
      remediationSteps: [
        `Reduce ${roleName} membership to the minimum (break-glass accounts plus a few named administrators).`,
        "Remove guest / external accounts from privileged directory roles.",
        "Use Privileged Identity Management (PIM) eligible assignments with approval and MFA instead of permanent membership.",
      ],
      accountId: tenantId,
      module: this.moduleName,
    });
  }

  /* ------------------------------- findings ------------------------------ */

  private roleName(guid: string | undefined, state: IamState): string {
    if (!guid) return "unknown role";
    return BUILTIN_ROLE_NAMES[guid] ?? aztUntrustedOpt(state.roleDefs.get(guid)?.name) ?? aztUntrusted(guid);
  }

  private assignmentFindings(state: IamState, principals: Map<string, PrincipalInfo>, mfa: Map<string, boolean>, tenantId: string): Finding[] {
    const findings: Finding[] = [];
    for (const entry of state.assignments.values()) {
      const a = entry.raw;
      const guid = azureRoleGuid(azString(prop(a, "roleDefinitionId")));
      const rawScope = azString(prop(a, "scope"));
      const scopeKind = azureScopeKind(rawScope);
      const broad = azureScopeIsBroad(scopeKind);
      const principalType = azString(prop(a, "principalType")) ?? "Unknown";
      const pid = azString(prop(a, "principalId"))?.toLowerCase();
      const principal = pid ? principals.get(pid) : undefined;
      const external = principalType.toLowerCase() === "foreigngroup" || principal?.guest === true;
      const isSp = principalType.toLowerCase() === "serviceprincipal";
      const def = guid ? state.roleDefs.get(guid) : undefined;
      const customDangerous =
        def !== undefined && (def.roleType ?? "").toLowerCase() === "customrole" && azureRoleEscalationActions(def.permissions).length > 0;
      const privileged = guid === AZURE_ROLE_OWNER || guid === AZURE_ROLE_USER_ACCESS_ADMIN || customDangerous;

      let risk = 0;
      const reasons: string[] = [];
      const bump = (score: number, reason: string) => {
        risk = Math.max(risk, score);
        reasons.push(reason);
      };
      if (guid === AZURE_ROLE_OWNER && broad) {
        if (external) bump(AZURE_IAM_OWNER_EXTERNAL_RISK, "Owner granted to a guest / external principal");
        else if (isSp) bump(AZURE_IAM_OWNER_SP_RISK, "Owner granted to a service principal (credential compromise = full control)");
        else bump(AZURE_IAM_OWNER_RISK, "Owner grants full control including access management");
      }
      if (guid === AZURE_ROLE_USER_ACCESS_ADMIN) bump(AZURE_IAM_UAA_RISK, "User Access Administrator can grant any role (including Owner) to anyone");
      if (external && (privileged || broad)) bump(AZURE_IAM_EXTERNAL_RISK, "role assigned to a guest / external-tenant principal");
      if (guid === AZURE_ROLE_CONTRIBUTOR && broad && pid && mfa.get(pid) === false) {
        bump(AZURE_IAM_CONTRIBUTOR_NO_MFA_RISK, "Contributor held by a user without registered MFA");
      }
      if (risk === 0) continue;

      const roleName = this.roleName(guid, state);
      const who = principal?.upn ?? principal?.displayName ?? aztUntrusted(pid ?? "unknown principal");
      const scopeText = aztUntrusted(rawScope ?? "unknown scope");
      const name = aztUntrustedOpt(azField(a, "name")) ?? azLastSegment(aztUntrusted(entry.id)) ?? "role-assignment";
      const subs = [...entry.subscriptions].map(aztUntrusted).join(", ");
      findings.push(
        makeFinding({
          riskScore: risk,
          title: `${roleName} role assigned to ${aztUntrusted(principalType)} ${who} at ${scopeKind} scope`,
          resourceType: ASSIGNMENT_TYPE,
          resourceId: name,
          resourceArn: toAzureUrn({ id: entry.id, resourceType: ASSIGNMENT_TYPE, name, tenantId }),
          description: `Role assignment ${name}: ${roleName} → ${aztUntrusted(principalType)} ${who}${
            pid && who !== aztUntrusted(pid) ? ` (object ID ${aztUntrusted(pid)})` : ""
          } at scope ${scopeText} (seen in subscription(s) ${subs}). Reasons: ${reasons.join("; ")}.${
            aztUntrustedOpt(prop(a, "condition")) ? " The assignment has an ABAC condition that may narrow it." : ""
          }`,
          impact:
            "The principal can take over the scope's resources and, for access-management roles, grant itself or others further privileges (privilege escalation).",
          remediationSteps: [
            "Confirm the assignment is required; remove it or replace it with a narrower built-in role at the lowest scope.",
            "Use Privileged Identity Management (PIM) eligible (just-in-time) assignments for Owner / User Access Administrator.",
            ...(external ? ["Remove guest / external principals from privileged Azure roles or move them to a managed account."] : []),
            ...(reasons.some((r) => r.includes("MFA")) ? ["Require MFA (Conditional Access) for every user holding write roles."] : []),
          ],
          accountId: tenantId,
          module: this.moduleName,
        }),
      );
    }
    return findings;
  }

  private excessiveOwnerFindings(state: IamState, principals: Map<string, PrincipalInfo>, tenantId: string): Finding[] {
    const owners = new Map<string, Set<string>>(); // subscription → principal IDs
    for (const entry of state.assignments.values()) {
      const a = entry.raw;
      if (azureRoleGuid(azString(prop(a, "roleDefinitionId"))) !== AZURE_ROLE_OWNER) continue;
      const scope = azString(prop(a, "scope"));
      const kind = azureScopeKind(scope);
      if (!azureScopeIsBroad(kind)) continue;
      const pid = azString(prop(a, "principalId"))?.toLowerCase();
      if (!pid) continue;
      for (const sub of entry.subscriptions) {
        // A subscription-scoped Owner applies to its own subscription only.
        if (kind === "subscription" && scope!.toLowerCase().replace(/\/+$/, "") !== `/subscriptions/${sub.toLowerCase()}`) continue;
        const set = owners.get(sub) ?? new Set<string>();
        set.add(pid);
        owners.set(sub, set);
      }
    }
    const findings: Finding[] = [];
    for (const [sub, set] of owners) {
      if (set.size <= AZURE_IAM_MAX_OWNERS) continue;
      const names = [...set].slice(0, 10).map((p) => principals.get(p)?.upn ?? principals.get(p)?.displayName ?? aztUntrusted(p));
      const subText = aztUntrusted(sub);
      findings.push(
        makeFinding({
          riskScore: AZURE_IAM_EXCESSIVE_OWNERS_RISK,
          title: `Subscription ${subText} has ${set.size} Owner principals (more than ${AZURE_IAM_MAX_OWNERS})`,
          resourceType: SUBSCRIPTION_TYPE,
          resourceId: subText,
          resourceArn: toAzureUrn({ id: `/subscriptions/${sub}`, resourceType: SUBSCRIPTION_TYPE, name: sub }),
          description: `${set.size} distinct principals hold Owner on subscription ${subText} (directly or inherited from a management group / root scope): ${names.join(", ")}${set.size > 10 ? ", …" : ""}. Microsoft recommends at most ${AZURE_IAM_MAX_OWNERS} subscription owners.`,
          impact: "Each Owner can delete any resource and grant any access in the subscription; many owners multiply the takeover paths.",
          remediationSteps: [
            `Reduce Owner assignments on the subscription to at most ${AZURE_IAM_MAX_OWNERS}.`,
            "Grant Contributor or narrower roles for day-to-day work and use PIM for just-in-time Owner elevation.",
          ],
          accountId: tenantId,
          module: this.moduleName,
        }),
      );
    }
    return findings;
  }

  private customRoleFindings(state: IamState, tenantId: string): Finding[] {
    const assignmentsPerRole = new Map<string, number>();
    for (const entry of state.assignments.values()) {
      const guid = azureRoleGuid(azString(prop(entry.raw, "roleDefinitionId")));
      if (guid) assignmentsPerRole.set(guid, (assignmentsPerRole.get(guid) ?? 0) + 1);
    }
    const findings: Finding[] = [];
    for (const [guid, def] of state.roleDefs) {
      if ((def.roleType ?? "").toLowerCase() !== "customrole") continue;
      const escalation = azureRoleEscalationActions(def.permissions);
      if (escalation.length === 0) continue;
      const full = azureRoleHasFullWildcard(def.permissions);
      const name = aztUntrustedOpt(def.name) ?? aztUntrusted(guid);
      const count = assignmentsPerRole.get(guid) ?? 0;
      const scopes = azArray(def.assignableScopes).slice(0, 5).map(aztUntrusted).filter(Boolean).join(", ");
      findings.push(
        makeFinding({
          riskScore: AZURE_IAM_CUSTOM_ROLE_RISK,
          title: `Custom role ${name} grants ${full ? "all actions (*)" : "access-management (privilege escalation) actions"}`,
          resourceType: ROLE_DEF_TYPE,
          resourceId: name,
          resourceArn: toAzureUrn({ id: def.id, resourceType: ROLE_DEF_TYPE, name: guid, tenantId }),
          description: `Custom role definition ${name}${scopes ? ` (assignable scopes: ${scopes})` : ""} effectively grants ${escalation.join(", ")}${
            full ? " through an unrestricted `*` action" : ""
          } (actions minus notActions, wildcard-matched). It has ${count} role assignment(s) in the scanned subscriptions.`,
          impact: "Holders of this role can create role assignments or definitions and thereby grant themselves Owner-equivalent access.",
          remediationSteps: [
            "Remove `*` and Microsoft.Authorization/* write actions from the custom role (or add them to notActions).",
            "Use the built-in Role Based Access Control Administrator role with conditions if delegated access management is required.",
            "Review and remove unnecessary assignments of this role.",
          ],
          accountId: tenantId,
          module: this.moduleName,
        }),
      );
    }
    return findings;
  }

  private classicAdminFindings(state: IamState, tenantId: string): Finding[] {
    const findings: Finding[] = [];
    for (const { raw, subscriptionId } of state.classicAdmins) {
      const role = azString(prop(raw, "role")) ?? "";
      if (!/coadministrator/i.test(role)) continue;
      const who = aztUntrustedOpt(prop(raw, "emailAddress")) ?? aztUntrustedOpt(azField(raw, "name")) ?? "unknown";
      const subText = aztUntrusted(subscriptionId);
      const name = aztUntrustedOpt(azField(raw, "name")) ?? who;
      findings.push(
        makeFinding({
          riskScore: AZURE_IAM_CLASSIC_ADMIN_RISK,
          title: `Classic co-administrator ${who} on subscription ${subText}`,
          resourceType: CLASSIC_TYPE,
          resourceId: name,
          resourceArn: toAzureUrn({ id: azString(azField(raw, "id")), subscriptionId, resourceType: CLASSIC_TYPE, name }),
          description: `${who} is a classic co-administrator (role "${aztUntrusted(role)}") of subscription ${subText}. Co-administrators have Owner-equivalent access that is not governed by Azure RBAC, PIM or conditions.`,
          impact: "Classic administrators bypass RBAC governance and keep full subscription access; the classic model is retired.",
          remediationSteps: [
            "Grant the user an appropriate Azure RBAC role (preferably via PIM) if access is still required.",
            "Remove the classic co-administrator (Azure portal → Subscription → Access control (IAM) → Classic administrators).",
          ],
          accountId: tenantId,
          module: this.moduleName,
        }),
      );
    }
    return findings;
  }
}

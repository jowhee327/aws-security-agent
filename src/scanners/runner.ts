import { FullScanResult, ScanResult, ScanContext, AwsCredentials, ProviderId } from "../types.js";
import { Scanner } from "./base.js";
import { getAccountId, getPartition } from "../utils/aws-client.js";
import { assumeRole, buildRoleArn } from "../utils/assume-role.js";
import { listOrgAccounts, type OrgAccount } from "../utils/org-accounts.js";
import { runWithConcurrency } from "../utils/concurrency.js";
import { getProvider } from "../providers/registry.js";
import type { CloudProvider, RegionScope } from "../providers/types.js";
import { resolveProviderHooks, redactProviderDiagnostic, type ResolvedProviderHooks } from "../providers/hooks.js";
import {
  HUAWEI_PARTITION,
  DEFAULT_HUAWEI_REGION,
  HUAWEI_GLOBAL_MODULES,
  HUAWEI_MULTI_ACCOUNT_WARNING,
} from "../providers/huaweicloud/hooks.js";
import {
  applyExploitabilityPostProcess,
  type ExploitabilityPostProcessOptions,
} from "../exploitability/dedupe.js";

const DEFAULT_CONCURRENCY = 5;

/**
 * Provider selection for the orchestration entry points. Absent / "aws" keeps
 * the original AWS code paths untouched (STS getAccountId, Organizations,
 * assumeRole, AGGREGATION_MODULES); every other provider ("huaweicloud",
 * "alicloud", …) routes to the generic regional single-account orchestration
 * below, driven by the provider's optional hooks (see CloudProviderHooks).
 */
export interface RunnerOptions {
  provider?: ProviderId;
  /** AWS only: CVE exploitability post-processing (Security Hub ↔ Inspector dedupe, fallback reachability). */
  exploitability?: ExploitabilityPostProcessOptions;
}

/** Regional providers: pseudo-region meaning "every region returned by the provider's discovery". */
export const REGIONAL_ALL_REGIONS = "all";
/** Huawei Cloud: pseudo-region meaning "every region project returned by IAM". */
export const HUAWEI_ALL_REGIONS = REGIONAL_ALL_REGIONS;
export { HUAWEI_PARTITION, DEFAULT_HUAWEI_REGION, HUAWEI_GLOBAL_MODULES, HUAWEI_MULTI_ACCOUNT_WARNING };

/** Aggregation scanners that already pull cross-account data — run once from admin account */
const AGGREGATION_MODULES = new Set([
  "security_hub_findings",
  "guardduty_findings",
  "inspector_findings",
  "config_rules_findings",
  "access_analyzer_findings",
]);

function buildSummary(modules: ScanResult[]) {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let modulesSuccess = 0;
  let modulesError = 0;

  for (const m of modules) {
    if (m.status === "success") {
      modulesSuccess++;
    } else {
      modulesError++;
    }
    for (const f of m.findings) {
      switch (f.severity) {
        case "CRITICAL": critical++; break;
        case "HIGH": high++; break;
        case "MEDIUM": medium++; break;
        case "LOW": low++; break;
      }
    }
  }

  return {
    totalFindings: critical + high + medium + low,
    critical,
    high,
    medium,
    low,
    modulesSuccess,
    modulesError,
  };
}

async function runScannersWithContext(
  scanners: Scanner[],
  ctx: ScanContext,
  concurrency: number = DEFAULT_CONCURRENCY,
): Promise<ScanResult[]> {
  const settled = await runWithConcurrency(scanners.map((s) => () => s.scan(ctx)), concurrency);

  return settled.map((result, i) => {
    if (result.status === "fulfilled") {
      // Stamp accountId on all findings
      for (const f of result.value.findings) {
        if (!f.accountId) f.accountId = ctx.accountId;
        if (!f.accountAlias && ctx.accountAlias) f.accountAlias = ctx.accountAlias;
      }
      return result.value;
    }
    const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
    return {
      module: scanners[i].moduleName,
      status: "error" as const,
      // Non-AWS SDK / proxy errors may echo the signed request (provider redactor);
      // legacy AWS contexts carry no provider and are passed through untouched.
      error: redactProviderDiagnostic(ctx.provider, reason),
      resourcesScanned: 0,
      findingsCount: 0,
      scanTimeMs: 0,
      findings: [],
    };
  });
}

/**
 * Build the ScanContext for a single-module scan (used by the scan_<module> tools).
 * AWS: STS account ID (best effort) + partition — identical to the historical
 * `index.ts` helper. Regional providers: account / region scope resolved via the
 * provider (Huawei Cloud: domain ID / project ID).
 */
export async function buildScanContext(region: string, provider: ProviderId = "aws"): Promise<ScanContext> {
  if (provider !== "aws") {
    const p = getProvider(provider);
    const hooks = resolveProviderHooks(p);
    const { scopes, accountId } = await resolveRegionalScopes(p, hooks, region);
    return regionalContext(p, hooks, scopes[0], accountId);
  }
  let accountId: string;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }
  return { region, partition: getPartition(region), accountId };
}

export async function runAllScanners(
  scanners: Scanner[],
  region: string,
  runOpts?: RunnerOptions,
): Promise<FullScanResult> {
  if (runOpts?.provider && runOpts.provider !== "aws") {
    return runRegionalProviderScanners(getProvider(runOpts.provider), scanners, region);
  }

  const scanStart = new Date().toISOString();

  // Best-effort accountId retrieval — don't let STS failure break the whole scan
  let accountId: string;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }

  const partition = getPartition(region);
  const ctx: ScanContext = { region, partition, accountId };

  const modules = await runScannersWithContext(scanners, ctx);
  await applyExploitabilityPostProcess(modules, ctx, runOpts?.exploitability);

  const scanEnd = new Date().toISOString();

  return {
    scanStart,
    scanEnd,
    region,
    accountId,
    modules,
    summary: buildSummary(modules),
  };
}

export interface MultiAccountOptions extends RunnerOptions {
  orgMode: boolean;
  roleName: string;
  accountIds?: string[];
}

export async function runMultiAccountScanners(
  scanners: Scanner[],
  region: string,
  opts: MultiAccountOptions,
): Promise<FullScanResult> {
  if (opts.provider && opts.provider !== "aws") {
    // Regional providers are single-account for now: listAccounts / assumeCrossAccount are
    // reserved on the provider interface (see the providers' TODOs). Generic multi-account
    // orchestration for non-AWS providers is not implemented, so org_mode always falls back
    // to the current account with the provider's warning.
    const provider = getProvider(opts.provider);
    const hooks = resolveProviderHooks(provider);
    const result = await runRegionalProviderScanners(provider, scanners, region, hooks);
    if (result.modules.length > 0) {
      if (!result.modules[0].warnings) result.modules[0].warnings = [];
      result.modules[0].warnings.unshift(hooks.messages.multiAccountUnsupported);
    }
    return result;
  }

  const scanStart = new Date().toISOString();
  const partition = getPartition(region);

  // Get current (admin) account ID
  let adminAccountId: string;
  try {
    adminAccountId = await getAccountId(region);
  } catch {
    adminAccountId = "unknown";
  }

  // Discover org accounts
  let accounts: OrgAccount[];
  try {
    accounts = await listOrgAccounts(region);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    // Graceful fallback: scan current account only, with clear warning
    const result = await runAllScanners(scanners, region, { exploitability: opts.exploitability });
    if (result.modules.length > 0) {
      if (!result.modules[0].warnings) result.modules[0].warnings = [];
      result.modules[0].warnings.unshift(`org_mode enabled but Organizations listing failed: ${errMsg}. Scanning current account only.`);
    }
    return result;
  }

  // Filter to specific accounts if requested
  if (opts.accountIds?.length) {
    const idSet = new Set(opts.accountIds);
    accounts = accounts.filter((a) => idSet.has(a.id));
  }

  // Separate aggregation vs per-account scanners
  const aggregationScanners = scanners.filter((s) => AGGREGATION_MODULES.has(s.moduleName));
  const perAccountScanners = scanners.filter((s) => !AGGREGATION_MODULES.has(s.moduleName));

  const allModules: ScanResult[] = [];
  const adminCtx: ScanContext = { region, partition, accountId: adminAccountId };

  // 1. Run aggregation scanners ONCE from admin account (they already aggregate cross-account)
  if (aggregationScanners.length > 0) {
    const aggResults = await runScannersWithContext(aggregationScanners, adminCtx);
    allModules.push(...aggResults);
  }

  // 2. Run per-account scanners for each account
  for (const account of accounts) {
    let credentials: AwsCredentials | undefined;
    let accountAlias = account.name;

    // Skip assume-role for the admin account itself
    if (account.id !== adminAccountId) {
      try {
        const roleArn = buildRoleArn(account.id, opts.roleName, partition);
        credentials = await assumeRole(roleArn, region);
      } catch (err) {
        // Record a failed module for this account
        allModules.push({
          module: `assume_role_${account.id}`,
          status: "error",
          error: `Failed to assume role in account ${account.id} (${account.name}): ${err instanceof Error ? err.message : String(err)}`,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: 0,
          findings: [],
        });
        continue;
      }
    }

    const ctx: ScanContext = {
      region,
      partition,
      accountId: account.id,
      accountAlias,
      credentials,
    };

    const accountResults = await runScannersWithContext(perAccountScanners, ctx);
    allModules.push(...accountResults);
  }

  const scanEnd = new Date().toISOString();

  // Post-filter: if account_ids was specified, filter aggregation findings too
  if (opts.accountIds?.length) {
    const idSet = new Set(opts.accountIds);
    for (const mod of allModules) {
      if (AGGREGATION_MODULES.has(mod.module)) {
        mod.findings = mod.findings.filter((f) => !f.accountId || idSet.has(f.accountId));
        mod.findingsCount = mod.findings.length;
      }
    }
  }

  // Aggregation results (security_hub / inspector) were produced with adminCtx.
  await applyExploitabilityPostProcess(allModules, adminCtx, opts.exploitability);

  return {
    scanStart,
    scanEnd,
    region,
    accountId: adminAccountId,
    modules: allModules,
    summary: buildSummary(allModules),
  };
}

/* ------------------------------------------------------------------------ */
/* Regional provider orchestration (Huawei Cloud, Alibaba Cloud: single account) */
/* ------------------------------------------------------------------------ */

interface RegionalScopes {
  scopes: RegionScope[];
  accountId: string;
  /** Whether the caller asked for every region (region omitted / "all"). */
  allRegions: boolean;
  warnings: string[];
}

function isAllRegions(region: string | undefined): boolean {
  return !region || region.trim() === "" || region.trim().toLowerCase() === REGIONAL_ALL_REGIONS;
}

function fallbackRegion(provider: CloudProvider, hooks: ResolvedProviderHooks, requested: string | undefined): string {
  const r = requested ?? hooks.defaultRegion;
  if (!r) throw new Error(`Provider "${provider.id}" declares no defaultRegion; pass an explicit region.`);
  return r;
}

/**
 * Resolve a regional provider's region scopes and account identifier
 * (Huawei Cloud: region → projectId/domainId, account = domain ID). Discovery
 * failures degrade to a single scope (each scanner then resolves / reports its own
 * error) and to accountId "unknown" — the same best-effort posture as the AWS STS fallback.
 */
async function resolveRegionalScopes(
  provider: CloudProvider,
  hooks: ResolvedProviderHooks,
  region: string | undefined,
): Promise<RegionalScopes> {
  const allRegions = isAllRegions(region);
  const requested = allRegions ? undefined : region!.trim();
  const warnings: string[] = [];
  let scopes: RegionScope[];

  try {
    const discovered = await provider.listRegions(undefined, requested);
    if (allRegions) {
      scopes = discovered;
      if (scopes.length === 0) {
        const fallback = fallbackRegion(provider, hooks, undefined);
        warnings.push(hooks.messages.noRegions(fallback));
        scopes = [{ region: fallback }];
      }
    } else {
      const match = discovered.find((s) => s.region === requested);
      if (match) {
        scopes = [match];
      } else {
        const known = discovered.map((s) => s.region).join(", ") || "(none)";
        warnings.push(hooks.messages.unknownRegion(requested!, known));
        // Keep the account-level identifier (Huawei: domainId) from discovery, if any.
        scopes = [{ region: requested!, domainId: discovered[0]?.domainId }];
      }
    }
  } catch (err) {
    const msg = hooks.redactDiagnostic(err instanceof Error ? err.message : String(err));
    const fallback = fallbackRegion(provider, hooks, requested);
    warnings.push(hooks.messages.discoveryFailed(msg, fallback));
    scopes = [{ region: fallback }];
  }

  let accountId: string;
  try {
    accountId = await provider.getAccountId(scopes[0]);
  } catch {
    accountId = "unknown";
  }

  return { scopes, accountId, allRegions, warnings };
}

function regionalContext(
  provider: CloudProvider,
  hooks: ResolvedProviderHooks,
  scope: RegionScope,
  accountId: string,
): ScanContext {
  const ctx: ScanContext = {
    region: scope.region,
    partition: hooks.partitionFor(scope.region),
    accountId,
    provider: provider.id,
  };
  return Object.assign(ctx, hooks.contextFor(scope, accountId));
}

/**
 * Regional provider single-account orchestration.
 * - `region` = a provider region ID (e.g. cn-north-4 / cn-hangzhou) → scan that region.
 * - `region` omitted / "all" → every discovered region; account-wide modules
 *   (provider `globalModules`) run once, regional modules once per region.
 */
async function runRegionalProviderScanners(
  provider: CloudProvider,
  scanners: Scanner[],
  region: string | undefined,
  hooks: ResolvedProviderHooks = resolveProviderHooks(provider),
): Promise<FullScanResult> {
  const scanStart = new Date().toISOString();
  const { scopes, accountId, allRegions, warnings } = await resolveRegionalScopes(provider, hooks, region);

  const modules: ScanResult[] = [];
  if (scopes.length === 1) {
    modules.push(...(await runScannersWithContext(scanners, regionalContext(provider, hooks, scopes[0], accountId))));
  } else {
    const globalScanners = scanners.filter((s) => hooks.globalModules.has(s.moduleName));
    const regionalScanners = scanners.filter((s) => !hooks.globalModules.has(s.moduleName));
    if (globalScanners.length > 0) {
      modules.push(...(await runScannersWithContext(globalScanners, regionalContext(provider, hooks, scopes[0], accountId))));
    }
    if (regionalScanners.length > 0) {
      for (const [i, scope] of scopes.entries()) {
        const ctx = regionalContext(provider, hooks, scope, accountId);
        if (i > 0) ctx.primaryRegionScope = false;
        modules.push(...(await runScannersWithContext(regionalScanners, ctx)));
      }
    }
  }

  if (warnings.length > 0 && modules.length > 0) {
    modules[0].warnings = [...warnings, ...(modules[0].warnings ?? [])];
  }

  const scanEnd = new Date().toISOString();
  return {
    scanStart,
    scanEnd,
    region: allRegions ? REGIONAL_ALL_REGIONS : scopes[0].region,
    accountId,
    provider: provider.id,
    modules,
    summary: buildSummary(modules),
  };
}

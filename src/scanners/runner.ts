import { FullScanResult, ScanResult, ScanContext, AwsCredentials, ProviderId } from "../types.js";
import { Scanner } from "./base.js";
import { getAccountId, getPartition } from "../utils/aws-client.js";
import { assumeRole, buildRoleArn } from "../utils/assume-role.js";
import { listOrgAccounts, type OrgAccount } from "../utils/org-accounts.js";
import { runWithConcurrency } from "../utils/concurrency.js";
import { getProvider } from "../providers/registry.js";
import type { RegionScope } from "../providers/types.js";
import { HUAWEI_PARTITION, DEFAULT_HUAWEI_REGION } from "../providers/huaweicloud/index.js";

const DEFAULT_CONCURRENCY = 5;

/**
 * Provider selection for the orchestration entry points. Absent / "aws" keeps
 * the original AWS code paths untouched (STS getAccountId, Organizations,
 * assumeRole, AGGREGATION_MODULES); "huaweicloud" routes to the Huawei Cloud
 * single-account orchestration below.
 */
export interface RunnerOptions {
  provider?: ProviderId;
}

/** Huawei Cloud: pseudo-region meaning "every region project returned by IAM". */
export const HUAWEI_ALL_REGIONS = "all";
export { HUAWEI_PARTITION, DEFAULT_HUAWEI_REGION };
/**
 * Huawei Cloud modules backed by account-wide (global) services — RMS tracker and
 * RMS compliance states aggregate every region — so in multi-region mode they run
 * once instead of once per region (mirrors AGGREGATION_MODULES for AWS org mode).
 */
export const HUAWEI_GLOBAL_MODULES = new Set([
  "config_rules_findings",
  "rms_compliance_findings",
]);

export const HUAWEI_MULTI_ACCOUNT_WARNING =
  "org_mode requested but multi-account scanning (Organizations listAccounts + STS assumeAgency) is not yet supported for huaweicloud (Phase 1). Scanning the current account only.";

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
    return {
      module: scanners[i].moduleName,
      status: "error" as const,
      error: result.reason instanceof Error ? result.reason.message : String(result.reason),
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
 * `index.ts` helper. Huawei Cloud: domain ID / project ID resolved via the provider.
 */
export async function buildScanContext(region: string, provider: ProviderId = "aws"): Promise<ScanContext> {
  if (provider === "huaweicloud") {
    const { scopes, accountId } = await resolveHuaweiScopes(region);
    return huaweiContext(scopes[0], accountId);
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
  if (runOpts?.provider === "huaweicloud") {
    return runHuaweiScanners(scanners, region);
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
  if (opts.provider === "huaweicloud") {
    // Phase 1: single account. Organizations listAccounts + STS assumeAgency are
    // reserved on the provider interface (see providers/huaweicloud/index.ts TODOs).
    const result = await runHuaweiScanners(scanners, region);
    if (result.modules.length > 0) {
      if (!result.modules[0].warnings) result.modules[0].warnings = [];
      result.modules[0].warnings.unshift(HUAWEI_MULTI_ACCOUNT_WARNING);
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
    const result = await runAllScanners(scanners, region);
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

  // 1. Run aggregation scanners ONCE from admin account (they already aggregate cross-account)
  if (aggregationScanners.length > 0) {
    const adminCtx: ScanContext = { region, partition, accountId: adminAccountId };
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
/* Huawei Cloud orchestration (Phase 1: single account)                     */
/* ------------------------------------------------------------------------ */

interface HuaweiScopes {
  scopes: RegionScope[];
  accountId: string;
  /** Whether the caller asked for every region (region omitted / "all"). */
  allRegions: boolean;
  warnings: string[];
}

function isAllRegions(region: string | undefined): boolean {
  return !region || region.trim() === "" || region.trim().toLowerCase() === HUAWEI_ALL_REGIONS;
}

/**
 * Resolve the Huawei Cloud region scopes (region → projectId/domainId) and the
 * account identifier (domain ID). Discovery failures degrade to a single scope
 * without projectId (each scanner then resolves / reports its own error) and to
 * accountId "unknown" — the same best-effort posture as the AWS STS fallback.
 */
async function resolveHuaweiScopes(region: string | undefined): Promise<HuaweiScopes> {
  const provider = getProvider("huaweicloud");
  const allRegions = isAllRegions(region);
  const requested = allRegions ? undefined : region!.trim();
  const warnings: string[] = [];
  let scopes: RegionScope[];

  try {
    const discovered = await provider.listRegions(undefined, requested);
    if (allRegions) {
      scopes = discovered;
      if (scopes.length === 0) {
        warnings.push(`Huawei Cloud region discovery returned no region projects; scanning ${DEFAULT_HUAWEI_REGION} only.`);
        scopes = [{ region: DEFAULT_HUAWEI_REGION }];
      }
    } else {
      const match = discovered.find((s) => s.region === requested);
      if (match) {
        scopes = [match];
      } else {
        const known = discovered.map((s) => s.region).join(", ") || "(none)";
        warnings.push(`Huawei Cloud region "${requested}" is not among this account's IAM region projects (known: ${known}); scanning it anyway.`);
        scopes = [{ region: requested!, domainId: discovered[0]?.domainId }];
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const fallback = requested ?? DEFAULT_HUAWEI_REGION;
    warnings.push(`Huawei Cloud region discovery failed: ${msg}. Scanning ${fallback} only.`);
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

function huaweiContext(scope: RegionScope, accountId: string): ScanContext {
  const domainId = scope.domainId ?? (accountId !== "unknown" ? accountId : undefined);
  const ctx: ScanContext = {
    region: scope.region,
    partition: HUAWEI_PARTITION,
    accountId,
    provider: "huaweicloud",
  };
  if (scope.projectId) ctx.projectId = scope.projectId;
  if (domainId) ctx.domainId = domainId;
  return ctx;
}

/**
 * Huawei Cloud single-account orchestration.
 * - `region` = a Huawei region ID (e.g. cn-north-4) → scan that region project.
 * - `region` omitted / "all" → every region project from IAM; account-wide modules
 *   ({@link HUAWEI_GLOBAL_MODULES}) run once, regional modules once per region.
 */
async function runHuaweiScanners(scanners: Scanner[], region: string | undefined): Promise<FullScanResult> {
  const scanStart = new Date().toISOString();
  const { scopes, accountId, allRegions, warnings } = await resolveHuaweiScopes(region);

  const modules: ScanResult[] = [];
  if (scopes.length === 1) {
    modules.push(...(await runScannersWithContext(scanners, huaweiContext(scopes[0], accountId))));
  } else {
    const globalScanners = scanners.filter((s) => HUAWEI_GLOBAL_MODULES.has(s.moduleName));
    const regionalScanners = scanners.filter((s) => !HUAWEI_GLOBAL_MODULES.has(s.moduleName));
    if (globalScanners.length > 0) {
      modules.push(...(await runScannersWithContext(globalScanners, huaweiContext(scopes[0], accountId))));
    }
    if (regionalScanners.length > 0) {
      for (const scope of scopes) {
        modules.push(...(await runScannersWithContext(regionalScanners, huaweiContext(scope, accountId))));
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
    region: allRegions ? HUAWEI_ALL_REGIONS : scopes[0].region,
    accountId,
    provider: "huaweicloud",
    modules,
    summary: buildSummary(modules),
  };
}

import { FullScanResult, ScanResult, ScanContext, AwsCredentials } from "../types.js";
import { Scanner } from "./base.js";
import { getAccountId, getPartition } from "../utils/aws-client.js";
import { assumeRole, buildRoleArn } from "../utils/assume-role.js";
import { listOrgAccounts, type OrgAccount } from "../utils/org-accounts.js";

const DEFAULT_CONCURRENCY = 5;

async function runWithConcurrency<T>(tasks: (() => Promise<T>)[], limit: number): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = [];
  const executing: Set<Promise<void>> = new Set();

  for (let i = 0; i < tasks.length; i++) {
    const idx = i;
    const p = tasks[idx]()
      .then((value) => { results[idx] = { status: "fulfilled", value }; })
      .catch((reason) => { results[idx] = { status: "rejected", reason }; })
      .finally(() => { executing.delete(p); });
    executing.add(p);
    if (executing.size >= limit) await Promise.race(executing);
  }
  await Promise.all(executing);
  return results;
}

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

export async function runAllScanners(
  scanners: Scanner[],
  region: string,
): Promise<FullScanResult> {
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

export interface MultiAccountOptions {
  orgMode: boolean;
  roleName: string;
  accountIds?: string[];
}

export async function runMultiAccountScanners(
  scanners: Scanner[],
  region: string,
  opts: MultiAccountOptions,
): Promise<FullScanResult> {
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

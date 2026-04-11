import { FullScanResult, ScanResult, ScanContext, AwsCredentials } from "../types.js";
import { Scanner } from "./base.js";
import { getAccountId, getPartition } from "../utils/aws-client.js";
import { assumeRole, buildRoleArn } from "../utils/assume-role.js";
import { listOrgAccounts, type OrgAccount } from "../utils/org-accounts.js";

/** Aggregation scanners that already pull cross-account data — run once from admin account */
const AGGREGATION_MODULES = new Set([
  "security_hub_findings",
  "guardduty_findings",
  "inspector_findings",
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
): Promise<ScanResult[]> {
  const settled = await Promise.allSettled(scanners.map((s) => s.scan(ctx)));

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
    // FAIL LOUDLY — do not silently degrade to single-account
    const errMsg = err instanceof Error ? err.message : String(err);
    return {
      scanStart: new Date().toISOString(),
      scanEnd: new Date().toISOString(),
      region,
      accountId: adminAccountId,
      modules: [{
        module: "org_discovery",
        status: "error" as const,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: 0,
        findings: [],
        warnings: [`Organizations ListAccounts failed: ${errMsg}. Ensure you are running from the management account or a delegated admin with organizations:ListAccounts permission.`],
      }],
      summary: { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, modulesSuccess: 0, modulesError: 1 },
    };
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

  return {
    scanStart,
    scanEnd,
    region,
    accountId: adminAccountId,
    modules: allModules,
    summary: buildSummary(allModules),
  };
}

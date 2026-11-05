/**
 * prioritize_vulnerabilities (plan §2.10): lightweight "what do I fix first"
 * entry point. Runs only inspector_findings (falling back to the Security Hub
 * Inspector subset when Inspector2 cannot be pulled directly) plus the
 * exploitability post-process, and returns a priority-ordered list instead of
 * a full scan result. AWS provider only; read-only.
 */

import type { Finding, Priority, Reachability, ScanContext, ScanResult, Severity } from "../types.js";
import { InspectorFindingsScanner } from "../scanners/inspector-findings.js";
import { SecurityHubFindingsScanner } from "../scanners/security-hub-findings.js";
import { applyExploitabilityPostProcess } from "../exploitability/dedupe.js";
import { computeExploitabilityFunnel, type ExploitabilityFunnel } from "../exploitability/funnel.js";
import { getKevMeta } from "../exploitability/kev.js";
import { compareByExploitPriority } from "./exploitability-report.js";
import { getI18n } from "../i18n/index.js";

export const DEFAULT_PRIORITIES: Priority[] = ["P0", "P1"];
export const DEFAULT_PRIORITIZE_LIMIT = 20;
export const MAX_PRIORITIZE_LIMIT = 200;

export type VulnResourceType = "ec2" | "ecr" | "lambda";

/** Finding.resourceType (ASFF type name, shared by Inspector2 and Security Hub) per filter value. */
const RESOURCE_TYPE_MATCHERS: Record<VulnResourceType, RegExp> = {
  ec2: /^AwsEc2Instance$/i,
  ecr: /^AwsEcrContainerImage$/i,
  lambda: /^AwsLambdaFunction/i,
};

export interface PrioritizeOptions {
  priorities?: Priority[];
  limit?: number;
  resourceType?: VulnResourceType;
  /** L4 reachability (default true); false skips it and leaves every finding "unknown". */
  includeReachability?: boolean;
}

/** Scanner factories, injectable for tests. */
export interface PrioritizeDeps {
  inspector?: (opts: { reachability: boolean }) => { scan(ctx: ScanContext): Promise<ScanResult> };
  securityHub?: () => { scan(ctx: ScanContext): Promise<ScanResult> };
}

export interface PrioritizedItem {
  cveId: string;
  priority: Priority;
  rationale: string;
  rationaleCode: string;
  resourceType: string;
  resourceId: string;
  severity: Severity;
  exploitAvailable: boolean | null;
  epss: number | null;
  kev: boolean;
  reachability: Reachability;
  reachabilityDetail?: string;
  fixAvailable?: "YES" | "NO" | "PARTIAL";
}

export interface PrioritizeResult {
  region: string;
  accountId: string;
  /** "inspector2" = direct pull; "securityhub" = fallback to the Security Hub Inspector subset. */
  dataSource: "inspector2" | "securityhub";
  funnel: ExploitabilityFunnel;
  kevSnapshotDate: string;
  disclaimer: string;
  /** Findings matching the priority / resource-type filters (before `limit`). */
  matched: number;
  items: PrioritizedItem[];
  truncated: boolean;
  warnings?: string[];
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit)) return DEFAULT_PRIORITIZE_LIMIT;
  return Math.min(MAX_PRIORITIZE_LIMIT, Math.max(1, Math.floor(limit)));
}

function toItem(f: Finding): PrioritizedItem {
  const x = f.exploitability!;
  return {
    cveId: x.cveId,
    priority: x.priority,
    rationale: x.rationale,
    rationaleCode: x.rationaleCode,
    resourceType: f.resourceType,
    resourceId: f.resourceId,
    severity: f.severity,
    exploitAvailable: x.exploitAvailable,
    epss: x.epss,
    kev: x.kev,
    reachability: x.reachability,
    ...(x.reachabilityDetail ? { reachabilityDetail: x.reachabilityDetail } : {}),
    ...(x.fixAvailable ? { fixAvailable: x.fixAvailable } : {}),
  };
}

export async function prioritizeVulnerabilities(
  ctx: ScanContext,
  opts: PrioritizeOptions = {},
  deps: PrioritizeDeps = {},
): Promise<PrioritizeResult> {
  const reachability = opts.includeReachability !== false;
  const priorities = new Set<Priority>(opts.priorities?.length ? opts.priorities : DEFAULT_PRIORITIES);
  const limit = clampLimit(opts.limit);

  const inspector = (deps.inspector ?? ((o) => new InspectorFindingsScanner(o)))({ reachability });
  const modules: ScanResult[] = [await inspector.scan(ctx)];
  const direct = modules[0].dataSource === "inspector2";
  if (!direct) {
    const sh = await (deps.securityHub ?? (() => new SecurityHubFindingsScanner()))().scan(ctx);
    // Only the Inspector-sourced CVEs matter here.
    sh.findings = sh.findings.filter((f) => f.source === "Inspector" && f.exploitability);
    sh.findingsCount = sh.findings.length;
    modules.push(sh);
  }
  await applyExploitabilityPostProcess(modules, { ...ctx, provider: "aws" }, { reachability });

  const typeRe = opts.resourceType ? RESOURCE_TYPE_MATCHERS[opts.resourceType] : undefined;
  const assessed = modules
    .flatMap((m) => m.findings)
    .filter((f) => f.exploitability && (!typeRe || typeRe.test(f.resourceType)));

  const matched = assessed
    .filter((f) => priorities.has(f.exploitability!.priority))
    .sort(compareByExploitPriority);

  const warnings = modules.flatMap((m) => m.warnings ?? []);
  return {
    region: ctx.region,
    accountId: ctx.accountId,
    dataSource: direct ? "inspector2" : "securityhub",
    funnel: computeExploitabilityFunnel(assessed),
    kevSnapshotDate: getKevMeta().snapshotDate,
    disclaimer: getI18n("en").exploitability.disclaimer,
    matched: matched.length,
    items: matched.slice(0, limit).map(toItem),
    truncated: matched.length > limit,
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}

/** One-line text summary returned next to the JSON payload. */
export function summarizePrioritized(r: PrioritizeResult): string {
  const p = r.funnel.byPriority;
  return [
    `Exploitability prioritization for account ${r.accountId} in ${r.region} (source: ${r.dataSource}).`,
    `Assessed ${r.funnel.total.findings} CVE findings (${r.funnel.total.cves} CVEs): P0 ${p.P0}, P1 ${p.P1}, P2 ${p.P2}, P3 ${p.P3}.`,
    `Returned ${r.items.length} of ${r.matched} matching item(s)${r.truncated ? " (truncated by limit)" : ""}. KEV snapshot ${r.kevSnapshotDate}.`,
  ].join("\n");
}

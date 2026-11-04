import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
  ListFindingsCommand,
} from "@aws-sdk/client-inspector2";
import type {
  FilterCriteria,
  Finding as InspectorFinding,
  ListFindingsCommandOutput,
} from "@aws-sdk/client-inspector2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding, Severity, ExploitabilityInfo } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { priorityFromSeverity } from "../utils/risk-scoring.js";
import { runWithConcurrency } from "../utils/concurrency.js";
import { isKev, maybeRefreshKevOnline } from "../exploitability/kev.js";
import {
  adjustRiskScore,
  buildExploitability,
  EPSS_MEDIUM,
  type EpssThresholds,
} from "../exploitability/priority.js";

export const DEFAULT_MAX_FINDINGS = 20_000;
export const DEFAULT_LIST_CONCURRENCY = 3;
const PAGE_SIZE = 100;
/** One scanner-level retry after the SDK's own retries gave up on throttling. */
const DEFAULT_THROTTLE_RETRY_DELAY_MS = 2_000;

/**
 * Resource types that can carry PACKAGE_VULNERABILITY findings; each is pulled
 * as an independent nextToken stream so wall time ≈ the largest partition.
 */
export const INSPECTOR_PARTITIONS = [
  "AWS_EC2_INSTANCE",
  "AWS_ECR_CONTAINER_IMAGE",
  "AWS_LAMBDA_FUNCTION",
  "CODE_REPOSITORY",
] as const;

/** Inspector resource type → ASFF type name (matches Security Hub Inspector findings). */
const RESOURCE_TYPE_NAMES: Record<string, string> = {
  AWS_EC2_INSTANCE: "AwsEc2Instance",
  AWS_ECR_CONTAINER_IMAGE: "AwsEcrContainerImage",
  AWS_LAMBDA_FUNCTION: "AwsLambdaFunction",
  CODE_REPOSITORY: "CodeRepository",
};

const DEFAULT_SEVERITY_SCORE: Record<Severity, number> = {
  CRITICAL: 9.5,
  HIGH: 8.0,
  MEDIUM: 5.5,
  LOW: 3.0,
};

export interface InspectorFindingsOptions {
  /** Cap on findings pulled (default 20,000). Exploit/EPSS signal findings are kept first. */
  maxFindings?: number;
  /** Parallel partition streams (default 3). */
  concurrency?: number;
  epssThresholds?: EpssThresholds;
  /** L4 reachability resolution (wired in by T3; currently all findings are "unknown"). */
  reachability?: boolean;
  /** Try refreshing the CISA KEV catalog online (falls back to AWS_SECURITY_MCP_KEV_REFRESH=1). */
  kevRefresh?: boolean;
  /** Delay before the scanner-level throttling retry (tests set 0). */
  throttleRetryDelayMs?: number;
}

interface PullResult {
  findings: Finding[];
  raw: number;
  /** Stopped with pages remaining because the cap was reached. */
  truncated: boolean;
}

function isAccessDenied(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const name = err instanceof Error ? err.name : "";
  return name === "AccessDeniedException" || msg.includes("AccessDeniedException");
}

function isThrottling(err: unknown): boolean {
  const name = err instanceof Error ? err.name : "";
  return name === "ThrottlingException" || name === "TooManyRequestsException";
}

function mapExploitAvailable(v: string | undefined): boolean | null {
  if (v === "YES") return true;
  if (v === "NO") return false;
  return null;
}

function mapFixAvailable(v: string | undefined): ExploitabilityInfo["fixAvailable"] {
  return v === "YES" || v === "NO" || v === "PARTIAL" ? v : undefined;
}

function mapSeverity(sev: string | undefined, exploit: boolean | null, kev: boolean): Severity | null {
  switch (sev) {
    case "CRITICAL":
    case "HIGH":
    case "MEDIUM":
    case "LOW":
      return sev;
    default:
      // INFORMATIONAL / UNTRIAGED: only kept when there is an exploit or a KEV listing.
      return exploit === true || kev ? "LOW" : null;
  }
}

export class InspectorFindingsScanner implements Scanner {
  readonly moduleName = "inspector_findings";
  private readonly opts: InspectorFindingsOptions;

  constructor(opts: InspectorFindingsOptions = {}) {
    this.opts = opts;
  }

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    let client: Inspector2Client;
    try {
      client = createClient(Inspector2Client, region, ctx.credentials);
      const resp = await client.send(new BatchGetAccountStatusCommand({ accountIds: [] }));
      const account = resp.accounts?.[0];

      if (!account || account.state?.status !== "ENABLED") {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
        return this.detectionOnly(warnings, startMs);
      }

      // Check individual resource scan types
      const rs = account.resourceState;
      const types: Array<{ name: string; status: string | undefined }> = [
        { name: "EC2", status: rs?.ec2?.status },
        { name: "Lambda", status: rs?.lambda?.status },
        { name: "ECR", status: rs?.ecr?.status },
        { name: "Lambda Code", status: rs?.lambdaCode?.status },
        { name: "Code Repository", status: rs?.codeRepository?.status },
      ];
      const disabled = types.filter((t) => t.status && t.status !== "ENABLED");
      if (disabled.length > 0) {
        warnings.push(
          `Inspector scan types not enabled: ${disabled.map((t) => t.name).join(", ")}. Enable them for full vulnerability coverage.`,
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Insufficient permissions to access Inspector. Grant inspector2:BatchGetAccountStatus to check enablement.");
      } else {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
      }
      return this.detectionOnly(warnings, startMs);
    }

    const kev = await maybeRefreshKevOnline({ enabled: this.opts.kevRefresh });
    if (kev.warning) warnings.push(kev.warning);

    try {
      const { findings, raw } = await this.pullFindings(client, ctx, warnings);
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: raw,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
        dataSource: "inspector2",
      };
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Grant inspector2:ListFindings to pull findings directly; falling back to Security Hub");
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Inspector ListFindings failed (${msg}); falling back to Security Hub`);
      }
      return this.detectionOnly(warnings, startMs);
    }
  }

  private detectionOnly(warnings: string[], startMs: number): ScanResult {
    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : undefined,
      resourcesScanned: 0,
      findingsCount: 0,
      scanTimeMs: Date.now() - startMs,
      findings: [],
      dataSource: "detection-only",
    };
  }

  /**
   * Partitioned pull up to maxFindings. When the cap is hit, the exploit /
   * EPSS signal subset is fetched separately (server-side filters) and kept
   * in full, then normal findings fill the remaining room.
   */
  private async pullFindings(
    client: Inspector2Client,
    ctx: ScanContext,
    warnings: string[],
  ): Promise<{ findings: Finding[]; raw: number }> {
    const maxFindings = Math.max(1, this.opts.maxFindings ?? DEFAULT_MAX_FINDINGS);
    const concurrency = Math.max(1, this.opts.concurrency ?? DEFAULT_LIST_CONCURRENCY);
    const base: FilterCriteria = {
      findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }],
      findingType: [{ comparison: "EQUALS", value: "PACKAGE_VULNERABILITY" }],
    };

    const budget = { remaining: maxFindings };
    const normal = await this.runStreams(
      client,
      ctx,
      INSPECTOR_PARTITIONS.map((t) => ({ ...base, resourceType: [{ comparison: "EQUALS", value: t }] })),
      concurrency,
      budget,
      warnings,
    );
    if (!normal.truncated) return { findings: normal.findings, raw: normal.raw };

    const signalBudget = { remaining: maxFindings };
    const signal = await this.runStreams(
      client,
      ctx,
      [
        { ...base, exploitAvailable: [{ comparison: "EQUALS", value: "YES" }] },
        { ...base, epssScore: [{ lowerInclusive: this.opts.epssThresholds?.medium ?? EPSS_MEDIUM, upperInclusive: 1 }] },
      ],
      concurrency,
      signalBudget,
      warnings,
    );

    const merged = new Map<string, Finding>();
    let anon = 0;
    const keyOf = (f: Finding) => f.sourceFindingId ?? `#${anon++}`;
    for (const f of signal.findings) merged.set(keyOf(f), f);
    for (const f of normal.findings) {
      if (merged.size >= maxFindings) break;
      const key = keyOf(f);
      if (!merged.has(key)) merged.set(key, f);
    }
    warnings.push(`Inspector returned more than ${maxFindings} findings; truncated (signal findings kept)`);
    if (signal.truncated) {
      warnings.push(`Inspector signal findings (exploit/EPSS) exceed ${maxFindings}; signal subset also truncated`);
    }
    return { findings: [...merged.values()], raw: normal.raw + signal.raw };
  }

  /** Run independent paginated ListFindings streams with bounded concurrency and a shared budget. */
  private async runStreams(
    client: Inspector2Client,
    ctx: ScanContext,
    filters: FilterCriteria[],
    concurrency: number,
    budget: { remaining: number },
    warnings: string[],
  ): Promise<PullResult> {
    const settled = await runWithConcurrency(
      filters.map((filterCriteria) => () => this.pullStream(client, ctx, filterCriteria, budget, warnings)),
      concurrency,
    );
    const seen = new Set<string>();
    const findings: Finding[] = [];
    let raw = 0;
    let truncated = false;
    for (const s of settled) {
      if (s.status === "rejected") throw s.reason;
      raw += s.value.raw;
      truncated ||= s.value.truncated;
      for (const f of s.value.findings) {
        const key = f.sourceFindingId ?? "";
        if (key && seen.has(key)) continue;
        seen.add(key);
        findings.push(f);
      }
    }
    return { findings, raw, truncated };
  }

  private async pullStream(
    client: Inspector2Client,
    ctx: ScanContext,
    filterCriteria: FilterCriteria,
    budget: { remaining: number },
    warnings: string[],
  ): Promise<PullResult> {
    const findings: Finding[] = [];
    const tokens = new Set<string>();
    let raw = 0;
    let nextToken: string | undefined;

    do {
      if (budget.remaining <= 0) return { findings, raw, truncated: true };
      const resp = await this.sendPage(client, filterCriteria, nextToken);
      for (const item of resp?.findings ?? []) {
        raw++;
        const f = this.toFinding(item, ctx);
        if (!f) continue;
        if (budget.remaining <= 0) return { findings, raw, truncated: true };
        budget.remaining--;
        findings.push(f);
      }
      nextToken = resp?.nextToken;
      if (nextToken) {
        if (tokens.has(nextToken)) {
          warnings.push("Inspector ListFindings returned a repeated nextToken; stopped paginating that partition");
          break;
        }
        tokens.add(nextToken);
      }
    } while (nextToken);

    return { findings, raw, truncated: false };
  }

  /** SDK retries throttling first (default maxAttempts); one extra page-level retry if it still fails. */
  private async sendPage(
    client: Inspector2Client,
    filterCriteria: FilterCriteria,
    nextToken: string | undefined,
  ): Promise<ListFindingsCommandOutput | undefined> {
    const cmd = () => new ListFindingsCommand({ filterCriteria, maxResults: PAGE_SIZE, nextToken });
    try {
      return await client.send(cmd());
    } catch (err) {
      if (!isThrottling(err)) throw err;
      const delay = this.opts.throttleRetryDelayMs ?? DEFAULT_THROTTLE_RETRY_DELAY_MS;
      await new Promise((r) => setTimeout(r, delay));
      return await client.send(cmd());
    }
  }

  private toFinding(item: InspectorFinding, ctx: ScanContext): Finding | null {
    const vuln = item.packageVulnerabilityDetails;
    const vulnId = vuln?.vulnerabilityId;
    const exploitAvailable = mapExploitAvailable(item.exploitAvailable);
    const kev = isKev(vulnId);
    const severity = mapSeverity(item.severity, exploitAvailable, kev);
    if (!severity) return null;

    const resource = item.resources?.[0];
    const rType = resource?.type ?? "";
    const resourceId = resource?.id ?? "unknown";
    const region = resource?.region ?? ctx.region;
    const accountId = item.awsAccountId ?? ctx.accountId;
    const partition = resource?.partition ?? ctx.partition;
    let resourceArn: string;
    if (resourceId.startsWith("arn:")) {
      resourceArn = resourceId;
    } else if (rType === "AWS_EC2_INSTANCE") {
      resourceArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${resourceId}`;
    } else {
      resourceArn = item.findingArn ?? resourceId;
    }

    const pkgs = vuln?.vulnerablePackages ?? [];
    const title = item.title ?? (vulnId ? `${vulnId} - ${pkgs[0]?.name ?? "unknown"}` : "Inspector Finding");

    const remediationSteps: string[] = [];
    for (const p of pkgs) {
      if (p.fixedInVersion && p.fixedInVersion !== "NotAvailable") {
        remediationSteps.push(`Upgrade ${p.name ?? "package"} ${p.version ?? ""} to ${p.fixedInVersion}`.replace(/\s+/g, " "));
      } else if (p.remediation) {
        remediationSteps.push(p.remediation);
      }
    }
    const recText = item.remediation?.recommendation?.text ?? "";
    if (recText && !["See References", "None Provided", ""].includes(recText.trim())) {
      remediationSteps.push(recText);
    }
    for (const url of (vuln?.referenceUrls ?? []).slice(0, 2)) remediationSteps.push(`Reference: ${url}`);
    if (remediationSteps.length === 0 && vulnId) {
      remediationSteps.push(`Fix vulnerability ${vulnId}: update affected software to patched version`);
    }

    const originalRiskScore =
      item.inspectorScore ?? vuln?.cvss?.[0]?.baseScore ?? DEFAULT_SEVERITY_SCORE[severity];

    const finding: Finding = {
      severity,
      title,
      resourceType: RESOURCE_TYPE_NAMES[rType] ?? (rType || "AWS::Unknown"),
      resourceId,
      resourceArn,
      region,
      description: item.description ?? title,
      impact: "Source: Inspector (package vulnerability)",
      riskScore: originalRiskScore,
      remediationSteps,
      priority: priorityFromSeverity(severity),
      module: this.moduleName,
      accountId,
      source: "Inspector",
    };
    if (item.findingArn) finding.sourceFindingId = item.findingArn;

    if (vulnId) {
      // Reachability stays "unknown" until L4 resolution is wired in (T3).
      const exploitability = buildExploitability({
        cveId: vulnId,
        exploitAvailable,
        epss: item.epss?.score ?? null,
        fixAvailable: mapFixAvailable(item.fixAvailable),
        originalRiskScore,
        dataSource: "inspector2",
        thresholds: this.opts.epssThresholds,
      });
      finding.exploitability = exploitability;
      finding.riskScore = adjustRiskScore(originalRiskScore, exploitability.priority);
    }
    return finding;
  }
}

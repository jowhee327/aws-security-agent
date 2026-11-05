/**
 * Alibaba Cloud security service detection (moduleName `service_detection`, plan §4.1 / T2).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/service-detection.ts` and the Huawei scanner: probes which native
 * security services are in use and attaches a {@link ServiceDetectionResult} (`services[]`
 * + coverage + maturity, same algorithm via {@link buildServiceDetectionResult}) to the
 * ScanResult as `serviceDetection`.
 *
 * Probe matrix (each isolated; a degraded probe never affects the others):
 *
 * | Service      | AWS analog           | Call                                                    | enabled when                          |
 * |--------------|----------------------|---------------------------------------------------------|---------------------------------------|
 * | ActionTrail  | CloudTrail           | DescribeTrails (regional) + GetTrailStatus per trail    | ≥1 trail logging (IsLogging / Status=Enable) |
 * | Config       | AWS Config           | GetConfigurationRecorder (centralised, site endpoint)   | ConfigurationRecorderStatus=REGISTERED |
 * | Security Center (SAS) | GuardDuty + Inspector | DescribeVersionConfig (tds, site endpoint)   | paid edition (Version ∉ {1 Free, 10 value-added only}) |
 * | WAF          | AWS WAF              | WAF 3.0 DescribeInstance (site endpoint, RegionId)      | InstanceId present and Status=1        |
 * | KMS          | AWS KMS              | ListKmsInstances, then ListKeys (regional)              | ≥1 KMS instance or ≥1 customer key     |
 *
 * Semantics: not enabled (empty / free edition / not-enabled or not-found code) →
 * `enabled=false` + recommendation (+ a Finding for Config and SAS, as for AWS Config /
 * GuardDuty; ActionTrail / WAF / KMS are coverage-only); access denied → `enabled=null` +
 * "insufficient permissions" warning; throttling / network / other → `enabled=null` +
 * warning. **auth_failed or api_misuse in any probe → module `status: "error"`** (plan §6.1:
 * a fake AK answers 404 InvalidAccessKeyId.NotFound, which must never read as "not enabled").
 *
 * The 5-probe matrix uses the shared maturity scale unchanged (5 = comprehensive).
 */
import type { Scanner } from "../../../scanners/base.js";
import {
  buildServiceDetectionResult,
  type ServiceDetectionResult,
  type ServiceStatus,
} from "../../../scanners/service-detection.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, type AliSite } from "../client.js";
import { classifyAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import { ALI_CONFIG_RECORDER_REGISTERED, aliConfigRecorderUrn, configRecorderStatus } from "./config-recorder.js";
import {
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliSafeFinding,
  aliScanEnv,
  aliString,
  aliUntrusted,
  emptyScanResult,
  type AliScanEnv,
} from "./shared.js";

export const ALI_SERVICE_ACTIONTRAIL = "ActionTrail";
export const ALI_SERVICE_CONFIG = "Config";
export const ALI_SERVICE_SAS = "Security Center (SAS)";
export const ALI_SERVICE_WAF = "WAF";
export const ALI_SERVICE_KMS = "KMS";

/** Fixed `services[]` order. */
export const ALI_SERVICE_ORDER: readonly string[] = [
  ALI_SERVICE_ACTIONTRAIL,
  ALI_SERVICE_CONFIG,
  ALI_SERVICE_SAS,
  ALI_SERVICE_WAF,
  ALI_SERVICE_KMS,
];

export const ALI_SERVICE_RECOMMENDATIONS: Readonly<Record<string, string>> = {
  [ALI_SERVICE_ACTIONTRAIL]: "Create an ActionTrail trail (all regions, read + write events) delivering to OSS or SLS for API audit logging",
  [ALI_SERVICE_CONFIG]: "Enable the Cloud Config resource recorder to track configuration changes and evaluate compliance rules / packs",
  [ALI_SERVICE_SAS]: "Upgrade Security Center (SAS) to a paid edition for threat detection, vulnerability scanning and baseline checks",
  [ALI_SERVICE_WAF]: "Enable WAF 3.0 and onboard internet-facing web applications (CNAME or cloud-native SLB / ECS access)",
  [ALI_SERVICE_KMS]: "Use KMS (a KMS instance or customer master keys) to encrypt data at rest with customer-managed keys",
};

/** SAS `DescribeVersionConfig.Version` editions (SDK docs). 1 = Free, 10 = value-added services only. */
export const ALI_SAS_EDITIONS: Readonly<Record<number, string>> = {
  1: "Free Edition",
  3: "Enterprise Edition",
  5: "Advanced Edition",
  6: "Anti-virus Edition",
  7: "Ultimate Edition",
  8: "Multi-edition",
  10: "Value-added services only",
};
/** Editions treated as "not enabled" (basic protection only → low maturity). */
export const ALI_SAS_LOW_MATURITY_VERSIONS: ReadonlySet<number> = new Set([1, 10]);

/** GetTrailStatus calls per scan (N+1 cap); remaining trails fall back to `Status`. */
export const ALI_ACTIONTRAIL_MAX_STATUS_CHECKS = 10;

/** WAF 3.0 `RegionId` parameter: mainland China vs outside (follows the site). */
export function aliWafRegionId(site: AliSite): string {
  return site === "intl" ? "ap-southeast-1" : "cn-hangzhou";
}

export type AliProbeOutcome =
  | { kind: "enabled"; details: string }
  | { kind: "disabled"; details?: string }
  | { kind: "denied"; details?: string }
  | { kind: "error"; message: string }
  /** auth_failed / api_misuse: the whole module fails. */
  | { kind: "fatal"; err: unknown };

/** Classify a probe error. Never throws. */
export function aliProbeOutcomeFromError(err: unknown): AliProbeOutcome {
  const { kind } = classifyAliError(err);
  if (kind === "auth_failed" || kind === "api_misuse") return { kind: "fatal", err };
  if (kind === "access_denied") return { kind: "denied", details: describeAliError(err) };
  if (kind === "not_enabled" || kind === "not_found") return { kind: "disabled", details: describeAliError(err) };
  return { kind: "error", message: describeAliError(err) };
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

function truthy(v: unknown): boolean {
  return v === true || v === "true" || v === 1;
}

export class AliServiceDetectionScanner implements Scanner {
  readonly moduleName = "service_detection";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AliScanEnv;
    try {
      env = aliScanEnv(ctx);
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "Alibaba Cloud service detection failed", err);
    }
    const region = ctx.region;

    const outcomes = await Promise.all([
      this.probeActionTrail(env, region),
      this.probeConfig(env),
      this.probeSas(env),
      this.probeWaf(env),
      this.probeKms(env, region),
    ]);

    const fatal = outcomes.find((o): o is Extract<AliProbeOutcome, { kind: "fatal" }> => o.kind === "fatal");
    if (fatal) return aliErrorResult(this.moduleName, startMs, "Alibaba Cloud service detection failed", fatal.err);

    const [trail, config, sas, waf, kms] = outcomes;
    const services: ServiceStatus[] = [];
    const warnings: string[] = [];
    const findings: Finding[] = [];

    this.record(services, warnings, ALI_SERVICE_ACTIONTRAIL, trail);

    if (this.record(services, warnings, ALI_SERVICE_CONFIG, config)) {
      findings.push(
        makeFinding({
          riskScore: 6.0,
          title: "Alibaba Cloud Config resource recorder is not enabled",
          resourceType: "ACS::Config::ConfigurationRecorder",
          resourceId: "config-recorder",
          resourceArn: aliConfigRecorderUrn(env.accountId),
          region: "global",
          description:
            "The Cloud Config resource recorder is not enabled (not REGISTERED) for this account. Config records resource configurations and evaluates managed / custom rules and compliance packs (including the 等保 MLPS pre-check pack).",
          impact:
            "Tracks configuration changes and enables compliance rules. Without it, configuration drift and non-compliant resources go undetected and config_compliance_findings has no data.",
          remediationSteps: [
            "Open the Alibaba Cloud Config console.",
            "Enable the resource recorder (monitor all supported resource types).",
            "Optionally configure delivery to OSS / SLS for configuration snapshots and change history.",
            "Enable managed rules or a compliance pack (e.g. the 等保三级预检 MLPS template).",
          ],
          accountId: env.accountId,
          module: this.moduleName,
        }),
      );
    }

    if (this.record(services, warnings, ALI_SERVICE_SAS, sas)) {
      findings.push(
        makeFinding({
          riskScore: 7.5,
          title: "Alibaba Cloud Security Center (SAS) paid edition is not enabled",
          resourceType: "ACS::SAS::Instance",
          resourceId: "sas",
          resourceArn: toAliUrn("sas", "instance", "none", "", env.accountId),
          region: "global",
          description:
            "Security Center is not purchased or runs the Free Edition only. Paid editions provide intrusion / threat detection, vulnerability scanning and baseline checks for hosts and containers.",
          impact:
            "Detects compromised hosts, brute-force attempts, web shells, known CVEs and baseline deviations. Without a paid edition, threat detection and vulnerability management are minimal.",
          remediationSteps: [
            "Open the Alibaba Cloud Security Center console.",
            "Purchase or upgrade to a paid edition (Anti-virus / Advanced / Enterprise / Ultimate) and bind it to servers.",
            "Make sure the Security Center agent is installed and online on every ECS instance.",
            "Enable vulnerability, baseline and threat detection policies and configure alert notifications.",
          ],
          accountId: env.accountId,
          module: this.moduleName,
        }),
      );
    }

    this.record(services, warnings, ALI_SERVICE_WAF, waf);
    this.record(services, warnings, ALI_SERVICE_KMS, kms);

    const detectionResult: ServiceDetectionResult = buildServiceDetectionResult(services);

    return {
      ...emptyScanResult(this.moduleName, startMs, { warnings }),
      resourcesScanned: services.length,
      findingsCount: findings.length,
      findings,
      // Same custom property as the AWS / Huawei scanners.
      ...({ serviceDetection: detectionResult } as Record<string, unknown>),
    } as ScanResult & { serviceDetection: ServiceDetectionResult };
  }

  /** Push the ServiceStatus for `name`; returns true when the service is "not enabled". */
  /** `details` may echo server values (instance id / edition): always redacted (warnings via emptyScanResult). */
  private record(services: ServiceStatus[], warnings: string[], name: string, outcome: AliProbeOutcome): boolean {
    switch (outcome.kind) {
      case "enabled":
        services.push({ name, enabled: true, details: redactAliDiagnostic(outcome.details) });
        return false;
      case "disabled":
        services.push({
          name,
          enabled: false,
          ...(outcome.details ? { details: redactAliDiagnostic(outcome.details) } : {}),
          recommendation: ALI_SERVICE_RECOMMENDATIONS[name],
        });
        return true;
      case "denied":
        warnings.push(`${name}: insufficient permissions to check status${outcome.details ? ` (${outcome.details})` : ""}`);
        services.push({ name, enabled: null, details: "Access denied" });
        return false;
      case "error":
        warnings.push(`${name} detection failed: ${outcome.message}`);
        services.push({ name, enabled: null, details: "Detection error" });
        return false;
      case "fatal":
        // Handled by scan() before recording; kept for exhaustiveness.
        services.push({ name, enabled: null, details: "Detection error" });
        return false;
    }
  }

  private async probeActionTrail(env: AliScanEnv, region: string): Promise<AliProbeOutcome> {
    try {
      const body = await aliCall(ALI_API.actiontrail.DescribeTrails, aliCallCtx(env, region), {
        IncludeShadowTrails: false,
        IncludeOrganizationTrail: true,
      });
      const trails = asArray<Record<string, unknown>>(aliField(body, "TrailList"));
      if (trails.length === 0) return { kind: "disabled", details: "No trail configured" };

      let logging = 0;
      for (const [i, t] of trails.entries()) {
        const name = aliString(t.Name);
        const statusEnabled = aliString(t.Status)?.toLowerCase() === "enable";
        if (!name || i >= ALI_ACTIONTRAIL_MAX_STATUS_CHECKS) {
          if (statusEnabled) logging += 1;
          continue;
        }
        try {
          const st = await aliCall(ALI_API.actiontrail.GetTrailStatus, aliCallCtx(env, region), {
            Name: name,
            ...(truthy(t.IsOrganizationTrail) ? { IsOrganizationTrail: true } : {}),
          });
          const isLogging = aliField(st, "IsLogging");
          if (isLogging === undefined ? statusEnabled : truthy(isLogging)) logging += 1;
        } catch (err) {
          const outcome = aliProbeOutcomeFromError(err);
          if (outcome.kind === "fatal") return outcome;
          // GetTrailStatus unavailable: fall back to DescribeTrails' Status.
          if (statusEnabled) logging += 1;
        }
      }
      if (logging > 0) return { kind: "enabled", details: `${logging} of ${trails.length} trail(s) logging` };
      return { kind: "disabled", details: `${trails.length} trail(s) configured but none is logging` };
    } catch (err) {
      return aliProbeOutcomeFromError(err);
    }
  }

  private async probeConfig(env: AliScanEnv): Promise<AliProbeOutcome> {
    try {
      const body = await aliCall(ALI_API.config.GetConfigurationRecorder, aliCallCtx(env));
      const status = configRecorderStatus(body);
      if (status === ALI_CONFIG_RECORDER_REGISTERED) return { kind: "enabled", details: "Resource recorder registered" };
      return { kind: "disabled", details: `ConfigurationRecorderStatus=${status ?? "absent"}` };
    } catch (err) {
      return aliProbeOutcomeFromError(err);
    }
  }

  private async probeSas(env: AliScanEnv): Promise<AliProbeOutcome> {
    try {
      const body = await aliCall(ALI_API.sas.DescribeVersionConfig, aliCallCtx(env));
      const version = aliNumber(aliField(body, "Version"));
      if (version === undefined) return { kind: "disabled", details: "Security Center edition not reported (not purchased)" };
      const edition = ALI_SAS_EDITIONS[version] ?? `edition ${version}`;
      if (ALI_SAS_LOW_MATURITY_VERSIONS.has(version)) {
        return { kind: "disabled", details: `${edition} (basic protection only)` };
      }
      const trial = truthy(aliField(body, "IsTrialVersion")) ? " (trial)" : "";
      return { kind: "enabled", details: `${edition}${trial}` };
    } catch (err) {
      return aliProbeOutcomeFromError(err);
    }
  }

  private async probeWaf(env: AliScanEnv): Promise<AliProbeOutcome> {
    try {
      const body = await aliCall(ALI_API.waf.DescribeInstance, aliCallCtx(env), { RegionId: aliWafRegionId(env.site) });
      const instanceId = aliUntrusted(aliField(body, "InstanceId")); // echoed in details
      if (!instanceId) return { kind: "disabled", details: "No WAF 3.0 instance" };
      const status = aliNumber(aliField(body, "Status"));
      if (status !== undefined && status !== 1) {
        return { kind: "disabled", details: `WAF instance ${instanceId} is ${status === 2 ? "expired" : status === 3 ? "released" : `in status ${status}`}` };
      }
      const edition = aliUntrusted(aliField(body, "Edition"));
      return { kind: "enabled", details: `WAF 3.0 instance ${instanceId}${edition ? ` (${edition})` : ""}` };
    } catch (err) {
      return aliProbeOutcomeFromError(err);
    }
  }

  private async probeKms(env: AliScanEnv, region: string): Promise<AliProbeOutcome> {
    let instancesNote: string | undefined;
    try {
      const body = await aliCall(ALI_API.kms.ListKmsInstances, aliCallCtx(env, region), { PageNumber: 1, PageSize: 10 });
      const list = asArray(aliField(aliField(body, "KmsInstances"), "KmsInstance"));
      const total = aliNumber(aliField(body, "TotalCount")) ?? list.length;
      if (total > 0 || list.length > 0) return { kind: "enabled", details: `${Math.max(total, list.length)} KMS instance(s)` };
    } catch (err) {
      const outcome = aliProbeOutcomeFromError(err);
      if (outcome.kind === "fatal") return outcome;
      // No KMS instance support / permission: still try ListKeys (default-key accounts).
      instancesNote = describeAliError(err);
    }
    try {
      const body = await aliCall(ALI_API.kms.ListKeys, aliCallCtx(env, region), { PageNumber: 1, PageSize: 10 });
      const list = asArray(aliField(aliField(body, "Keys"), "Key"));
      const total = aliNumber(aliField(body, "TotalCount")) ?? list.length;
      if (total > 0 || list.length > 0) return { kind: "enabled", details: `${Math.max(total, list.length)} KMS key(s)` };
      return { kind: "disabled", details: instancesNote ? `No KMS instance or key (ListKmsInstances: ${instancesNote})` : "No KMS instance or key" };
    } catch (err) {
      return aliProbeOutcomeFromError(err);
    }
  }
}

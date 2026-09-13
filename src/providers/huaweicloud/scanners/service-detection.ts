/**
 * Huawei Cloud security service detection (moduleName `service_detection`, plan T7).
 *
 * Mirrors `src/scanners/service-detection.ts`: probes which native security
 * services are in use and attaches a {@link ServiceDetectionResult}
 * (`services[]` + coverage + maturity, same algorithm via
 * {@link buildServiceDetectionResult}) to the ScanResult as `serviceDetection`.
 *
 * Probe matrix (each isolated; a failure in one never affects the others):
 *
 * | Service   | AWS analog    | Call                                         | enabled when            |
 * |-----------|---------------|----------------------------------------------|-------------------------|
 * | CTS       | CloudTrail    | `listTrackers({})` (regional, Basic)         | ≥1 tracker              |
 * | RMS       | AWS Config    | `showTrackerConfig({domainId})` (global)     | tracker config present  |
 * | HSS       | Inspector     | `listHostStatus({region, protect_status:"opened", limit:1, offset:0})` | total_num > 0 |
 * | SecMaster | Security Hub  | `listWorkspaces({offset:0, limit:1})` (v1)   | ≥1 workspace            |
 *
 * Semantics (as on AWS): not enabled (empty list / 404 / "not opened" code) →
 * `enabled=false` + recommendation (+ a Finding for RMS / HSS / SecMaster, not
 * for CTS — CloudTrail is coverage-only on AWS too); 403 → `enabled=null` +
 * "insufficient permissions" warning; any other error → `enabled=null` + warning.
 *
 * NOTE: the shared maturity thresholds (5 = comprehensive) were designed for
 * the 5-service AWS matrix; with 4 Huawei probes the ceiling is "advanced".
 * Kept identical on purpose so the maturity report renders both providers
 * with the same scale.
 *
 * SDK notes: SecMaster is imported through the v1 deep path
 * (`@huaweicloud/huaweicloud-sdk-secmaster/v1/SecMasterClient.js`) and its
 * `listWorkspaces` REQUIRES `offset` and `limit` (the SDK throws otherwise).
 * HSS needs the `region` request field (sent as a header).
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import {
  buildServiceDetectionResult,
  type ServiceDetectionResult,
  type ServiceStatus,
} from "../../../scanners/service-detection.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import type { HuaweiCloudCredentials } from "../../../types.js";
import { hwClient } from "../client.js";
import { classifyHwError, describeHwError } from "../errors.js";
import { HWS_GLOBAL_REGION, toResourceUrn } from "../urn.js";
import { isTrackerConfigured, rmsTrackerUrn } from "./rms-tracker.js";
import { hwCredentialsFromContext, hwDomainIdFromContext, hwRegionScopeFromContext } from "./shared.js";

export const HW_SERVICE_CTS = "CTS";
export const HW_SERVICE_RMS = "RMS (Config)";
export const HW_SERVICE_HSS = "HSS";
export const HW_SERVICE_SECMASTER = "SecMaster";

export const HW_SERVICE_RECOMMENDATIONS: Readonly<Record<string, string>> = {
  [HW_SERVICE_CTS]: "Create a CTS management tracker for API audit logging",
  [HW_SERVICE_RMS]: "Enable the RMS (Config) resource recorder to track configuration changes and evaluate compliance policies",
  [HW_SERVICE_HSS]: "Enable HSS (Host Security Service) protection on ECS instances for vulnerability, intrusion and baseline detection",
  [HW_SERVICE_SECMASTER]: "Enable SecMaster and create a workspace for centralized security operations and finding aggregation",
};

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

interface LooseListTrackersResponse {
  trackers?: Array<{ id?: string; tracker_name?: string; trackerName?: string; tracker_type?: string; status?: string }>;
}
interface LooseListHostStatusResponse {
  total_num?: number;
  totalNum?: number;
  data_list?: unknown[];
  dataList?: unknown[];
}
interface LooseListWorkspacesResponse {
  workspaces?: unknown[];
  count?: number;
}
interface LooseTrackerConfig {
  retention_period_in_days?: number;
  retentionPeriodInDays?: number;
}

/** Minimal client surfaces (tests inject fakes). */
export interface CtsProbeClient {
  listTrackers(req?: unknown): Promise<unknown>;
}
export interface RmsProbeClient {
  showTrackerConfig(req?: unknown): Promise<unknown>;
}
export interface HssProbeClient {
  listHostStatus(req?: unknown): Promise<unknown>;
}
export interface SecMasterProbeClient {
  listWorkspaces(req?: unknown): Promise<unknown>;
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: {
  riskScore: number;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  remediationSteps: string[];
  accountId: string;
  module: string;
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "huaweicloud" };
}

type ProbeOutcome =
  | { kind: "enabled"; details: string }
  | { kind: "disabled"; details?: string }
  | { kind: "denied" }
  | { kind: "error"; message: string };

/** Classify a probe error into the AWS-equivalent outcome. Never throws. */
export function probeOutcomeFromError(err: unknown): ProbeOutcome {
  const info = classifyHwError(err);
  if (info.kind === "access_denied") return { kind: "denied" };
  if (info.kind === "not_enabled" || info.kind === "not_found") return { kind: "disabled", details: describeHwError(err) };
  return { kind: "error", message: describeHwError(err) };
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiServiceDetectionScanner implements Scanner {
  readonly moduleName = "service_detection";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    const services: ServiceStatus[] = [];

    let basicCreds: HuaweiCloudCredentials;
    let globalCreds: HuaweiCloudCredentials;
    let scope: { region: string; projectId: string; domainId: string };
    let domainId: string;
    try {
      basicCreds = hwCredentialsFromContext(ctx, "basic");
      globalCreds = hwCredentialsFromContext(ctx, "global");
      scope = await hwRegionScopeFromContext(ctx, basicCreds);
      domainId = await hwDomainIdFromContext(ctx, globalCreds);
      if (!scope.domainId) scope = { ...scope, domainId };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud service detection failed: ${describeHwError(err)}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }

    const region = scope.region;

    // Probes run concurrently; `services[]` order is fixed (CTS, RMS, HSS, SecMaster).
    const [cts, rms, hss, secmaster] = await Promise.all([
      this.probeCts(basicCreds, scope),
      this.probeRms(globalCreds, region, domainId),
      this.probeHss(basicCreds, scope),
      this.probeSecMaster(basicCreds, scope),
    ]);

    // --- CTS (CloudTrail analog: coverage-only, no finding) ---
    this.record(services, warnings, HW_SERVICE_CTS, cts);

    // --- RMS (AWS Config analog) ---
    if (this.record(services, warnings, HW_SERVICE_RMS, rms)) {
      findings.push(
        makeFinding({
          riskScore: 6.0,
          title: "Huawei Cloud RMS (Config) resource recorder is not enabled",
          resourceType: "HuaweiCloud::RMS::Tracker",
          resourceId: "rms-tracker",
          resourceArn: rmsTrackerUrn(domainId),
          region: HWS_GLOBAL_REGION,
          description:
            "The RMS (Config) resource recorder is not enabled for this account. RMS continuously records resource configurations and evaluates built-in / custom compliance policies (including the 等保 conformance packs).",
          impact:
            "Tracks configuration changes and enables compliance rules. Without it, configuration drift and non-compliant resources go undetected and rms_compliance_findings has no data.",
          remediationSteps: [
            "Open the Huawei Cloud Config (RMS) console.",
            "Enable the resource recorder and select all supported resource types.",
            "Configure an OBS bucket (and optionally SMN topic) for configuration snapshots and change notifications.",
            "Assign built-in policies or a conformance pack (e.g. the 等保 compliance check template).",
          ],
          accountId: domainId,
          module: this.moduleName,
        }),
      );
    }

    // --- HSS (Inspector analog) ---
    if (this.record(services, warnings, HW_SERVICE_HSS, hss)) {
      findings.push(
        makeFinding({
          riskScore: 6.0,
          title: "Huawei Cloud HSS host protection is not enabled",
          resourceType: "HuaweiCloud::HSS::Host",
          resourceId: "hss",
          resourceArn: toResourceUrn("hss", "protection", "none", region, domainId),
          region,
          description:
            "No ECS host in this region is protected by HSS (Host Security Service). HSS scans hosts for software vulnerabilities, weak passwords, baseline deviations and intrusions.",
          impact:
            "Detects known CVEs, brute-force attempts, web shells and ransomware on hosts. Without it, host-level compromise and unpatched vulnerabilities go undetected.",
          remediationSteps: [
            "Open the Huawei Cloud HSS console.",
            "Install the HSS agent on ECS instances (or enable automatic agent installation).",
            "Purchase / enable a protection edition (Basic or higher) and bind it to the hosts.",
            "Enable vulnerability, baseline and intrusion detection policies.",
          ],
          accountId: domainId,
          module: this.moduleName,
        }),
      );
    }

    // --- SecMaster (Security Hub analog) ---
    if (this.record(services, warnings, HW_SERVICE_SECMASTER, secmaster)) {
      findings.push(
        makeFinding({
          riskScore: 7.5,
          title: "Huawei Cloud SecMaster is not enabled",
          resourceType: "HuaweiCloud::SecMaster::Workspace",
          resourceId: "secmaster",
          resourceArn: toResourceUrn("secmaster", "workspace", "none", region, domainId),
          region,
          description:
            "SecMaster has no workspace in this region. SecMaster aggregates alerts and findings from HSS, WAF, CFW and other services and provides a central security operations view.",
          impact:
            "Provides centralized threat detection, alert correlation and response playbooks. Without it, security findings are fragmented across individual services.",
          remediationSteps: [
            "Open the Huawei Cloud SecMaster console.",
            "Enable SecMaster and create a workspace for this region.",
            "Enable data integration for HSS / WAF / CTS logs.",
            "Enable the built-in threat detection models and baseline checks.",
          ],
          accountId: domainId,
          module: this.moduleName,
        }),
      );
    }

    const detectionResult: ServiceDetectionResult = buildServiceDetectionResult(services);

    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : undefined,
      resourcesScanned: services.length,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
      // Attach the structured detection result as a custom property (same shape as the AWS scanner).
      ...({ serviceDetection: detectionResult } as Record<string, unknown>),
    } as ScanResult & { serviceDetection: ServiceDetectionResult };
  }

  /** Push the ServiceStatus for `name`; returns true when the service is "not enabled" (caller may add a Finding). */
  private record(services: ServiceStatus[], warnings: string[], name: string, outcome: ProbeOutcome): boolean {
    switch (outcome.kind) {
      case "enabled":
        services.push({ name, enabled: true, details: outcome.details });
        return false;
      case "disabled":
        services.push({
          name,
          enabled: false,
          ...(outcome.details ? { details: outcome.details } : {}),
          recommendation: HW_SERVICE_RECOMMENDATIONS[name],
        });
        return true;
      case "denied":
        warnings.push(`${name}: insufficient permissions to check status`);
        services.push({ name, enabled: null, details: "Access denied" });
        return false;
      case "error":
        warnings.push(`${name} detection failed: ${outcome.message}`);
        services.push({ name, enabled: null, details: "Detection error" });
        return false;
    }
  }

  private async probeCts(
    creds: HuaweiCloudCredentials,
    scope: { region: string; projectId: string; domainId: string },
  ): Promise<ProbeOutcome> {
    try {
      const { CtsClient } = await import("@huaweicloud/huaweicloud-sdk-cts");
      const client = (await hwClient(CtsClient, "cts", creds, scope)) as unknown as CtsProbeClient;
      const resp = (await client.listTrackers({})) as LooseListTrackersResponse | undefined;
      const trackers = Array.isArray(resp?.trackers) ? resp!.trackers! : [];
      if (trackers.length > 0) return { kind: "enabled", details: `${trackers.length} tracker(s) configured` };
      return { kind: "disabled" };
    } catch (err) {
      return probeOutcomeFromError(err);
    }
  }

  private async probeRms(creds: HuaweiCloudCredentials, region: string, domainId: string): Promise<ProbeOutcome> {
    try {
      const { ConfigClient } = await import("@huaweicloud/huaweicloud-sdk-config");
      const client = (await hwClient(ConfigClient, "rms", creds, { region, domainId })) as unknown as RmsProbeClient;
      const resp = await client.showTrackerConfig({ domainId });
      if (!isTrackerConfigured(resp)) return { kind: "disabled" };
      const r = resp as LooseTrackerConfig;
      const retention = r.retention_period_in_days ?? r.retentionPeriodInDays;
      return {
        kind: "enabled",
        details: retention !== undefined ? `Resource recorder configured (retention ${retention} days)` : "Resource recorder configured",
      };
    } catch (err) {
      return probeOutcomeFromError(err);
    }
  }

  private async probeHss(
    creds: HuaweiCloudCredentials,
    scope: { region: string; projectId: string; domainId: string },
  ): Promise<ProbeOutcome> {
    try {
      const { HssClient } = await import("@huaweicloud/huaweicloud-sdk-hss");
      const client = (await hwClient(HssClient, "hss", creds, scope)) as unknown as HssProbeClient;
      // `region` is a required HSS header; only protected hosts count as "enabled".
      const resp = (await client.listHostStatus({
        region: scope.region,
        protect_status: "opened",
        limit: 1,
        offset: 0,
      })) as LooseListHostStatusResponse | undefined;
      const list = resp?.data_list ?? resp?.dataList;
      const total = resp?.total_num ?? resp?.totalNum ?? (Array.isArray(list) ? list.length : 0);
      if (total > 0) return { kind: "enabled", details: `${total} protected host(s)` };
      return { kind: "disabled" };
    } catch (err) {
      return probeOutcomeFromError(err);
    }
  }

  private async probeSecMaster(
    creds: HuaweiCloudCredentials,
    scope: { region: string; projectId: string; domainId: string },
  ): Promise<ProbeOutcome> {
    try {
      const { SecMasterClient } = await import("@huaweicloud/huaweicloud-sdk-secmaster/v1/SecMasterClient.js");
      const client = (await hwClient(SecMasterClient, "secmaster", creds, scope)) as unknown as SecMasterProbeClient;
      // offset + limit are mandatory for the v1 SDK method.
      const resp = (await client.listWorkspaces({ offset: 0, limit: 1 })) as LooseListWorkspacesResponse | undefined;
      const workspaces = Array.isArray(resp?.workspaces) ? resp!.workspaces! : [];
      const count = resp?.count ?? workspaces.length;
      if (count > 0 || workspaces.length > 0) return { kind: "enabled", details: `${Math.max(count, workspaces.length)} workspace(s)` };
      return { kind: "disabled" };
    } catch (err) {
      return probeOutcomeFromError(err);
    }
  }
}

/**
 * Azure security service detection (moduleName `service_detection`, plan §4.1 / T2).
 * EXPERIMENTAL — not yet validated against a live account; field names follow the SDK d.ts.
 *
 * Mirrors `src/scanners/service-detection.ts` and the Huawei / Alibaba scanners: probes which
 * native security services are in use on the subscription and attaches a
 * {@link ServiceDetectionResult} (`services[]` + coverage + maturity, same algorithm via
 * {@link buildServiceDetectionResult}) to the ScanResult as `serviceDetection`.
 *
 * Probe matrix (each isolated; a degraded probe never affects the others):
 *
 * | Service            | AWS analog            | Call                                                        | enabled when                          |
 * |--------------------|-----------------------|-------------------------------------------------------------|---------------------------------------|
 * | Defender for Cloud | GuardDuty + Sec. Hub  | `SecurityCenter.pricings.list()`                            | ≥1 plan on `pricingTier=Standard`     |
 * | Azure Policy       | AWS Config            | `PolicyInsightsClient.policyStates.summarizeForSubscription`| ≥1 policy assignment                  |
 * | Activity Log       | CloudTrail            | `MonitorClient.diagnosticSettings.list("subscriptions/<id>")`| ≥1 setting with a destination + enabled log category |
 * | Key Vault          | AWS KMS               | `KeyVaultManagementClient.vaults.listBySubscription()`      | ≥1 vault                              |
 *
 * Semantics: not enabled (Free tier only / no assignment / no setting / no vault) →
 * `enabled=false` + recommendation (+ a Finding for Defender and Policy, as for GuardDuty /
 * AWS Config; Activity Log / Key Vault are coverage-only); resource provider not registered /
 * not available (Azure China) → `enabled=false` + not_enabled warning; access denied →
 * `enabled=null` + "insufficient permissions" warning; throttling / network / other →
 * `enabled=null` + warning. **auth_failed or api_misuse in any probe → module
 * `status: "error"`** (an AADSTS failure must never read as "not enabled").
 *
 * Four services → the top maturity level reachable is "advanced" (as for Huawei Cloud).
 */
import type { Scanner } from "../../../scanners/base.js";
import {
  buildServiceDetectionResult,
  type ServiceDetectionResult,
  type ServiceStatus,
} from "../../../scanners/service-detection.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { classifyAzureError, describeAzureError, redactAzureDiagnostic } from "../errors.js";
import { toAzureUrn } from "../urn.js";
import { AZURE_POLICY_RESOURCE } from "./policy-compliance.js";
import {
  azArray,
  azField,
  azNumber,
  azString,
  aztUntrusted,
  azureEmptyResult,
  azureErrorResult,
  azureNoSubscriptionResult,
  azureSafeFinding,
  azureScanEnv,
  type AzureScanEnv,
} from "./shared.js";

export const AZURE_SERVICE_DEFENDER = "Defender for Cloud";
export const AZURE_SERVICE_POLICY = "Azure Policy";
export const AZURE_SERVICE_ACTIVITY_LOG = "Activity Log";
export const AZURE_SERVICE_KEY_VAULT = "Key Vault";

/** Fixed `services[]` order. */
export const AZURE_SERVICE_ORDER: readonly string[] = [
  AZURE_SERVICE_DEFENDER,
  AZURE_SERVICE_POLICY,
  AZURE_SERVICE_ACTIVITY_LOG,
  AZURE_SERVICE_KEY_VAULT,
];

export const AZURE_SERVICE_RECOMMENDATIONS: Readonly<Record<string, string>> = {
  [AZURE_SERVICE_DEFENDER]:
    "Enable Microsoft Defender for Cloud plans (Standard tier: Servers, Storage, Key Vault, SQL, Containers, …) for threat detection and vulnerability assessment",
  [AZURE_SERVICE_POLICY]:
    "Assign Azure Policy initiatives (e.g. the Microsoft cloud security benchmark or a regulatory compliance initiative) to evaluate resource compliance",
  [AZURE_SERVICE_ACTIVITY_LOG]:
    "Create a subscription diagnostic setting exporting the Activity Log (Administrative, Security, Policy, …) to a Log Analytics workspace, storage account or Event Hub",
  [AZURE_SERVICE_KEY_VAULT]: "Use Azure Key Vault to manage secrets, keys and certificates (customer-managed keys for encryption at rest)",
};

/** Key vaults counted (the listing stops at the cap; the count is a lower bound beyond it). */
export const AZURE_KEY_VAULT_MAX_COUNT = 1000;
/** Diagnostic settings examined. */
export const AZURE_DIAGNOSTIC_SETTINGS_MAX = 100;

export type AzureProbeOutcome =
  | { kind: "enabled"; details: string }
  | { kind: "disabled"; details?: string; warning?: string }
  | { kind: "denied"; details?: string }
  | { kind: "error"; message: string }
  /** auth_failed / api_misuse: the whole module fails. */
  | { kind: "fatal"; err: unknown };

/** Classify a probe error. Never throws. */
export function azureProbeOutcomeFromError(service: string, err: unknown): AzureProbeOutcome {
  const { kind } = classifyAzureError(err);
  if (kind === "auth_failed" || kind === "api_misuse") return { kind: "fatal", err };
  if (kind === "access_denied") return { kind: "denied", details: describeAzureError(err) };
  if (kind === "not_enabled" || kind === "not_found") {
    const details = describeAzureError(err);
    return {
      kind: "disabled",
      details: "Resource provider not registered / service not available",
      warning: `${service}: not enabled / resource provider not registered for this subscription (${details})`,
    };
  }
  return { kind: "error", message: describeAzureError(err) };
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

export class AzureServiceDetectionScanner implements Scanner {
  readonly moduleName = "service_detection";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure service detection failed", err);
    }
    if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
    const scanEnv = env;

    const outcomes = await Promise.all([
      this.probeDefender(scanEnv),
      this.probePolicy(scanEnv),
      this.probeActivityLog(scanEnv),
      this.probeKeyVault(scanEnv),
    ]);

    const fatal = outcomes.find((o): o is Extract<AzureProbeOutcome, { kind: "fatal" }> => o.kind === "fatal");
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure service detection failed", fatal.err);

    const [defender, policy, activityLog, keyVault] = outcomes;
    const services: ServiceStatus[] = [];
    const warnings: string[] = [];
    const findings: Finding[] = [];
    const subscription = aztUntrusted(scanEnv.subscriptionId);
    const subscriptionUrn = toAzureUrn({ id: `/subscriptions/${scanEnv.subscriptionId}`, resourceType: "Microsoft.Resources/subscriptions", name: "" });

    if (this.record(services, warnings, AZURE_SERVICE_DEFENDER, defender)) {
      findings.push(
        makeFinding({
          riskScore: 7.5,
          title: "Microsoft Defender for Cloud plans are not enabled",
          resourceType: "Microsoft.Security/pricings",
          resourceId: subscription,
          resourceArn: `${subscriptionUrn}/providers/Microsoft.Security/pricings`,
          region: "global",
          description: `No Microsoft Defender for Cloud plan runs on the Standard tier in subscription ${subscription} (Free / foundational CSPM only). Defender plans provide threat detection, vulnerability assessment and regulatory compliance (including MLPS / 等保 where available).`,
          impact:
            "Detects compromised VMs, suspicious storage / Key Vault access, vulnerable images and attack paths. Without Defender plans, threat detection and vulnerability management are minimal and guardduty_findings / inspector_findings have little data.",
          remediationSteps: [
            "Open Microsoft Defender for Cloud → Environment settings → the subscription.",
            "Enable the Defender plans relevant to the workload (Servers, Storage, Key Vault, SQL, Containers, App Service, …).",
            "Note: in Azure China (21Vianet) some plans are unavailable — enable the ones offered in the region.",
            "Configure security contacts / email notifications for alerts.",
          ],
          accountId: scanEnv.tenantId,
          module: this.moduleName,
        }),
      );
    }

    if (this.record(services, warnings, AZURE_SERVICE_POLICY, policy)) {
      findings.push(
        makeFinding({
          riskScore: 6.0,
          title: "Azure Policy has no assignments on the subscription",
          resourceType: "Microsoft.Authorization/policyAssignments",
          resourceId: subscription,
          resourceArn: `${subscriptionUrn}/providers/Microsoft.Authorization/policyAssignments`,
          region: "global",
          description: `No Azure Policy assignment evaluates resources in subscription ${subscription} (or the Microsoft.PolicyInsights resource provider is unavailable). Azure Policy continuously evaluates resource configurations against built-in / custom definitions and regulatory initiatives.`,
          impact:
            "Tracks configuration compliance. Without policy assignments, misconfigurations and configuration drift go undetected and config_rules_findings has no data.",
          remediationSteps: [
            "Open Azure Policy → Assignments.",
            "Assign the Microsoft cloud security benchmark initiative (or a regulatory compliance initiative) at the subscription or management group scope.",
            "Register the Microsoft.PolicyInsights resource provider if it is not registered.",
            "Review Compliance after the first evaluation cycle and create remediation tasks.",
          ],
          accountId: scanEnv.tenantId,
          module: this.moduleName,
        }),
      );
    }

    this.record(services, warnings, AZURE_SERVICE_ACTIVITY_LOG, activityLog);
    this.record(services, warnings, AZURE_SERVICE_KEY_VAULT, keyVault);

    const detectionResult: ServiceDetectionResult = buildServiceDetectionResult(services);

    return {
      ...azureEmptyResult(this.moduleName, startMs, { warnings }),
      resourcesScanned: services.length,
      findingsCount: findings.length,
      findings,
      // Same custom property as the AWS / Huawei / Alibaba scanners.
      ...({ serviceDetection: detectionResult } as Record<string, unknown>),
    } as ScanResult & { serviceDetection: ServiceDetectionResult };
  }

  /** Push the ServiceStatus for `name`; returns true when the service is "not enabled". */
  /** `details` may echo server values (plan names, counts): always redacted (warnings via azureEmptyResult). */
  private record(services: ServiceStatus[], warnings: string[], name: string, outcome: AzureProbeOutcome): boolean {
    switch (outcome.kind) {
      case "enabled":
        services.push({ name, enabled: true, details: redactAzureDiagnostic(outcome.details) });
        return false;
      case "disabled":
        if (outcome.warning) warnings.push(outcome.warning);
        services.push({
          name,
          enabled: false,
          ...(outcome.details ? { details: redactAzureDiagnostic(outcome.details) } : {}),
          recommendation: AZURE_SERVICE_RECOMMENDATIONS[name],
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

  private async probeDefender(env: AzureScanEnv): Promise<AzureProbeOutcome> {
    try {
      const { SecurityCenter } = await import("@azure/arm-security");
      const client = await armClient(SecurityCenter, env.credentials, env.subscriptionId);
      const body = await client.pricings.list();
      const plans = azArray(azField(body, "value"));
      if (plans.length === 0) return { kind: "disabled", details: "No Defender plan reported" };
      const standard = plans.filter((p) => azString(azField(p, "pricingTier"))?.toLowerCase() === "standard");
      if (standard.length === 0) return { kind: "disabled", details: `All ${plans.length} Defender plan(s) on the Free tier` };
      const names = standard
        .map((p) => aztUntrusted(azField(p, "name")))
        .filter((n) => n)
        .slice(0, 10);
      return {
        kind: "enabled",
        details: `${standard.length} of ${plans.length} Defender plan(s) on Standard${names.length > 0 ? ` (${names.join(", ")}${standard.length > names.length ? ", …" : ""})` : ""}`,
      };
    } catch (err) {
      return azureProbeOutcomeFromError(AZURE_SERVICE_DEFENDER, err);
    }
  }

  private async probePolicy(env: AzureScanEnv): Promise<AzureProbeOutcome> {
    try {
      const { PolicyInsightsClient } = await import("@azure/arm-policyinsights");
      const client = await armClient(PolicyInsightsClient, env.credentials, env.subscriptionId);
      const body = await client.policyStates.summarizeForSubscription(AZURE_POLICY_RESOURCE, env.subscriptionId);
      let assignments = 0;
      let nonCompliant = 0;
      for (const s of azArray(azField(body, "value"))) {
        assignments += azArray(azField(s, "policyAssignments")).length;
        nonCompliant += azNumber(azField(azField(s, "results"), "nonCompliantResources")) ?? 0;
      }
      if (assignments === 0) return { kind: "disabled", details: "No policy assignment" };
      return { kind: "enabled", details: `${assignments} policy assignment(s), ${nonCompliant} non-compliant resource(s)` };
    } catch (err) {
      return azureProbeOutcomeFromError(AZURE_SERVICE_POLICY, err);
    }
  }

  private async probeActivityLog(env: AzureScanEnv): Promise<AzureProbeOutcome> {
    try {
      const { MonitorClient } = await import("@azure/arm-monitor");
      const client = await armClient(MonitorClient, env.credentials, env.subscriptionId);
      // `/{+resourceUri}/providers/Microsoft.Insights/diagnosticSettings`: no leading slash.
      const { items } = await azurePaginate(client.diagnosticSettings.list(`subscriptions/${env.subscriptionId}`), {
        max: AZURE_DIAGNOSTIC_SETTINGS_MAX,
      });
      if (items.length === 0) return { kind: "disabled", details: "No subscription diagnostic setting (Activity Log not exported)" };
      const exporting = items.filter((s) => {
        const hasDestination = ["workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId"].some((k) =>
          azString(azField(s, k)),
        );
        const logs = azArray(azField(s, "logs"));
        const anyLog = logs.some((l) => azField(l, "enabled") === true);
        return hasDestination && anyLog;
      });
      if (exporting.length === 0) {
        return { kind: "disabled", details: `${items.length} diagnostic setting(s) but none exports enabled log categories` };
      }
      return { kind: "enabled", details: `${exporting.length} diagnostic setting(s) exporting the Activity Log` };
    } catch (err) {
      return azureProbeOutcomeFromError(AZURE_SERVICE_ACTIVITY_LOG, err);
    }
  }

  private async probeKeyVault(env: AzureScanEnv): Promise<AzureProbeOutcome> {
    try {
      const { KeyVaultManagementClient } = await import("@azure/arm-keyvault");
      const client = await armClient(KeyVaultManagementClient, env.credentials, env.subscriptionId);
      const { count, truncated } = await azurePaginate(client.vaults.listBySubscription(), {
        max: AZURE_KEY_VAULT_MAX_COUNT,
        collect: false,
      });
      if (count === 0) return { kind: "disabled", details: "No key vault" };
      return { kind: "enabled", details: `${count}${truncated ? "+" : ""} key vault(s)` };
    } catch (err) {
      return azureProbeOutcomeFromError(AZURE_SERVICE_KEY_VAULT, err);
    }
  }
}

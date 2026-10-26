/**
 * Alibaba Cloud provider (Phase 2 skeleton — EXPERIMENTAL, not yet validated
 * against a live account).
 *
 * T0 wired the provider into the registry / runner; T1 adds credentials (§3.2),
 * the openapi-core client factory + API catalog (§3.5), error classification /
 * redaction (§3.6) and URNs (§3.4). Scanners land in T2–T7 (T2–T6 done).
 * SDKs (`@alicloud/openapi-core`, `@alicloud/tea-util`, `ali-oss`) must be loaded
 * lazily (`await import()`) so the default AWS path never loads them.
 * Multi-account (Resource Directory ListAccounts + STS AssumeRole) is reserved:
 * the interface methods exist but throw a clear "not implemented" error.
 */
import type { Scanner } from "../../scanners/base.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";
import type { AlibabaCloudCredentials } from "../../types.js";
import { isAlibabaCloudCredentials } from "../../types.js";
import { listAliRegions } from "./client.js";
import { AlibabaCloudCredentialsNotFoundError, loadAliCredentials, resolveAliAccountId } from "./credentials.js";
import { isAliAuthFailure, redactAliDiagnostic } from "./errors.js";
import { ALI_GLOBAL_URN_SERVICES, toAliUrn } from "./urn.js";
import { AliConfigRecorderScanner } from "./scanners/config-recorder.js";
import { AliConfigComplianceScanner } from "./scanners/config-compliance.js";
import { AliServiceDetectionScanner } from "./scanners/service-detection.js";
import { AliPublicAccessScanner } from "./scanners/public-access.js";
import { AliSecretExposureScanner } from "./scanners/secret-exposure.js";
import { AliEcsMetadataScanner } from "./scanners/ecs-metadata.js";
import { AliSslCertificateScanner } from "./scanners/ssl-certificate.js";
import { AliIdleResourcesScanner } from "./scanners/idle-resources.js";
import { AliTagComplianceScanner } from "./scanners/tag-compliance.js";
import { AliNetworkReachabilityScanner } from "./scanners/network-reachability.js";
import { AliRamPrivilegeScanner } from "./scanners/ram-privilege.js";

export * from "./api-catalog.js";
export * from "./client.js";
export * from "./credentials.js";
export * from "./errors.js";
export * from "./urn.js";
export { AliConfigRecorderScanner } from "./scanners/config-recorder.js";
export { AliConfigComplianceScanner } from "./scanners/config-compliance.js";
export { AliServiceDetectionScanner } from "./scanners/service-detection.js";
export { AliPublicAccessScanner } from "./scanners/public-access.js";
export { AliSecretExposureScanner } from "./scanners/secret-exposure.js";
export { AliEcsMetadataScanner } from "./scanners/ecs-metadata.js";
export { AliSslCertificateScanner } from "./scanners/ssl-certificate.js";
export { AliIdleResourcesScanner } from "./scanners/idle-resources.js";
export { AliTagComplianceScanner } from "./scanners/tag-compliance.js";
export { AliNetworkReachabilityScanner } from "./scanners/network-reachability.js";
export { AliRamPrivilegeScanner } from "./scanners/ram-privilege.js";

export const ALICLOUD_PARTITION = "alicloud";
export const DEFAULT_ALICLOUD_REGION = "cn-hangzhou";

/**
 * Alibaba Cloud modules backed by account-level / centralised services (RAM, IMS,
 * Config, SAS, CAS, …): in a multi-region scan they run once instead of once per region.
 */
export const ALICLOUD_GLOBAL_MODULES: ReadonlySet<string> = new Set([
  "config_rules_findings",
  "config_compliance_findings",
  "service_detection",
  "iam_privilege_escalation",
  "ssl_certificate",
  "guardduty_findings",
  "inspector_findings",
  "patch_compliance_findings",
]);

export const ALICLOUD_MULTI_ACCOUNT_WARNING =
  "org_mode requested but multi-account scanning (Resource Directory ListAccounts + STS AssumeRole) is not yet supported for alicloud (Phase 2). Scanning the current account only.";

/**
 * Credentials for provider-level calls: explicit Alibaba credentials when given, else the
 * chain (env → INI file). Returns undefined when no source yields credentials (no network).
 */
function tryResolveCredentials(creds?: CloudCredentials): AlibabaCloudCredentials | undefined {
  try {
    return loadAliCredentials({ explicit: isAlibabaCloudCredentials(creds) ? creds : undefined });
  } catch (err) {
    if (err instanceof AlibabaCloudCredentialsNotFoundError) return undefined;
    throw err;
  }
}

export const alibabaCloudProvider: CloudProvider = {
  id: "alicloud",
  displayName: "Alibaba Cloud",
  partitionFor: () => ALICLOUD_PARTITION,
  defaultRegion: DEFAULT_ALICLOUD_REGION,
  globalModules: ALICLOUD_GLOBAL_MODULES,
  redactDiagnostic: redactAliDiagnostic,
  contextFor: () => ({}),
  supportsMultiAccount: false,
  regionalMessages: {
    multiAccountUnsupported: ALICLOUD_MULTI_ACCOUNT_WARNING,
  },

  // STS GetCallerIdentity → AccountId (16-digit UID), cached per credentials;
  // best-effort "unknown" on failure (same posture as AWS).
  async getAccountId(_scope: RegionScope, creds?: CloudCredentials): Promise<string> {
    try {
      const resolved = tryResolveCredentials(creds);
      if (!resolved) return "unknown";
      return await resolveAliAccountId(resolved);
    } catch {
      return "unknown";
    }
  },

  // ECS DescribeRegions (ecs.aliyuncs.com, AcceptLanguage=en-US) → RegionIds, sorted, requested
  // region first. Without credentials (or on a non-auth failure) only the requested / default
  // region is returned; authentication failures propagate so the scan reports them.
  async listRegions(creds?: CloudCredentials, defaultRegion?: string): Promise<RegionScope[]> {
    const fallback = defaultRegion ?? DEFAULT_ALICLOUD_REGION;
    let resolved: AlibabaCloudCredentials | undefined;
    try {
      resolved = tryResolveCredentials(creds);
    } catch {
      resolved = undefined;
    }
    if (!resolved) return [{ region: fallback }];
    let regions: string[];
    try {
      regions = await listAliRegions(resolved);
    } catch (err) {
      if (isAliAuthFailure(err)) throw err;
      return [{ region: fallback }];
    }
    if (regions.length === 0) return [{ region: fallback }];
    const ordered = regions.includes(fallback) ? [fallback, ...regions.filter((r) => r !== fallback)] : regions;
    return ordered.map((region) => ({ region }));
  },

  // TODO(Phase 3 — multi-account, plan §3.8): Resource Directory `ResourceManager ListAccounts`
  // (version 2020-03-31, PageNumber/PageSize pagination; requires the RD management account or a
  // delegated administrator). The runner deliberately does NOT call this yet (`org_mode` emits
  // ALICLOUD_MULTI_ACCOUNT_WARNING and scans the current account only).
  async listAccounts(_scope: RegionScope, _creds?: CloudCredentials): Promise<AccountRef[]> {
    throw new Error("Alibaba Cloud multi-account discovery (Resource Directory ListAccounts) is not implemented in Phase 2");
  },

  // TODO(Phase 3 — multi-account, plan §3.8): STS `AssumeRole` with
  // RoleArn = `acs:ram::<memberUid>:role/<opts.roleName ?? "ResourceDirectoryAccountAccessRole">`
  // (the role Resource Directory creates in member accounts), RoleSessionName = opts.sessionName ??
  // "aws-security-mcp", DurationSeconds = 3600, ExternalId = opts.externalId (support to be confirmed
  // on a live account). The returned AccessKeyId / AccessKeySecret / SecurityToken become an
  // AlibabaCloudCredentials { kind: "alicloud" } placed on ScanContext.credentials, mirroring AWS assumeRole.
  async assumeCrossAccount(
    _target: AccountRef,
    _scope: RegionScope,
    _opts?: AssumeCrossAccountOptions,
  ): Promise<CloudCredentials> {
    throw new Error("Alibaba Cloud cross-account access (STS AssumeRole) is not implemented in Phase 2");
  },

  // T2: Config recorder / compliance + service detection; T3: public access (OSS + RDS);
  // T4: secret exposure (ECS user data + FC3 env), ECS metadata hardening, CAS certificates;
  // T5: idle resources, tag compliance, network reachability; T6: RAM privilege escalation (global);
  // remaining scanners land in T7.
  scanners(): Scanner[] {
    return [
      new AliConfigRecorderScanner(),
      new AliConfigComplianceScanner(),
      new AliServiceDetectionScanner(),
      new AliPublicAccessScanner(),
      new AliSecretExposureScanner(),
      new AliEcsMetadataScanner(),
      new AliSslCertificateScanner(),
      new AliIdleResourcesScanner(),
      new AliTagComplianceScanner(),
      new AliNetworkReachabilityScanner(),
      new AliRamPrivilegeScanner(),
    ];
  },

  // plan §3.4 — global services (RAM / CAS / Config / SAS …) use an empty region segment.
  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string {
    const [svc, ...rest] = resourceType.split(":");
    const type = rest.length > 0 ? rest.join(":") : "resource";
    const region = ALI_GLOBAL_URN_SERVICES.has(svc) ? "" : scope.region;
    return toAliUrn(svc, type, resourceId, region, accountId);
  },
};

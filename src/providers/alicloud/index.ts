/**
 * Alibaba Cloud provider (Phase 2 skeleton — EXPERIMENTAL, not yet validated
 * against a live account).
 *
 * T0 only wires the provider into the registry / runner: no scanners, no SDK
 * calls. Credentials (§3.2), the openapi-core client factory (§3.5), error
 * classification / redaction (§3.6) and URNs (§3.4) land in T1; scanners in T2–T7.
 * SDKs (`@alicloud/openapi-core`, `@alicloud/tea-util`, `ali-oss`) must be loaded
 * lazily (`await import()`) so the default AWS path never loads them.
 * Multi-account (Resource Directory ListAccounts + STS AssumeRole) is reserved:
 * the interface methods exist but throw a clear "not implemented" error.
 */
import type { Scanner } from "../../scanners/base.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";

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

export const alibabaCloudProvider: CloudProvider = {
  id: "alicloud",
  displayName: "Alibaba Cloud",
  partitionFor: () => ALICLOUD_PARTITION,
  defaultRegion: DEFAULT_ALICLOUD_REGION,
  globalModules: ALICLOUD_GLOBAL_MODULES,
  // TODO(T1): replace with redactAliDiagnostic (src/providers/alicloud/errors.ts, plan §3.6).
  redactDiagnostic: (text: string) => text,
  contextFor: () => ({}),
  supportsMultiAccount: false,
  regionalMessages: {
    multiAccountUnsupported: ALICLOUD_MULTI_ACCOUNT_WARNING,
  },

  // TODO(T1): STS GetCallerIdentity → AccountId (16-digit UID), cached per credentials;
  // best-effort "unknown" on failure (same posture as AWS).
  async getAccountId(_scope: RegionScope, _creds?: CloudCredentials): Promise<string> {
    return "unknown";
  },

  // TODO(T1): ECS DescribeRegions (ecs.aliyuncs.com, AcceptLanguage=en-US) → Regions.Region[].RegionId,
  // sorted, requested region first. Until then only the requested / default region is returned.
  async listRegions(_creds?: CloudCredentials, defaultRegion?: string): Promise<RegionScope[]> {
    return [{ region: defaultRegion ?? DEFAULT_ALICLOUD_REGION }];
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

  // Scanners are registered in T2–T7.
  scanners(): Scanner[] {
    return [];
  },

  // TODO(T1): move to urn.ts (plan §3.4) — global services (RAM / CAS / Config / SAS …) use an empty region segment.
  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string {
    const [svc, ...rest] = resourceType.split(":");
    const type = rest.length > 0 ? rest.join(":") : "resource";
    return `acs:${svc}:${scope.region}:${accountId}:${type}/${resourceId}`;
  },
};

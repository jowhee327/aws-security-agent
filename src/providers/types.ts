import type { Scanner } from "../scanners/base.js";
import type { CloudCredentials, ProviderId, ScanContext } from "../types.js";

export type {
  CloudCredentials,
  ProviderId,
  AwsCredentials,
  HuaweiCloudCredentials,
  AlibabaCloudCredentials,
  AzureCredentials,
} from "../types.js";

/**
 * Region-level scope for a scan.
 * - AWS: `region` + `partition`.
 * - Huawei Cloud: `region` + `projectId` (per-region project) + `domainId` (account).
 * - Alibaba Cloud: `region` only (the account UID is resolved separately).
 * - Azure: `region` = subscription ID, `domainId` = tenant ID (one scope per subscription).
 */
export interface RegionScope {
  region: string;
  /** Huawei Cloud: region → project_id */
  projectId?: string;
  /** Huawei Cloud: account domain ID */
  domainId?: string;
  /** AWS partition (aws / aws-cn / aws-us-gov) */
  partition?: string;
}

export interface AccountRef {
  id: string;
  name?: string;
}

export interface AssumeCrossAccountOptions {
  /** AWS: IAM role name; Huawei Cloud: agency name. */
  roleName?: string;
  externalId?: string;
  sessionName?: string;
}

/**
 * Operator-facing texts emitted by the regional (non-AWS) orchestration in
 * `scanners/runner.ts`. Every entry is optional; the runner falls back to a
 * generic wording built from {@link CloudProvider.displayName}.
 */
export interface RegionalProviderMessages {
  /** Region discovery succeeded but returned nothing; `fallback` is the region scanned instead. */
  noRegions(fallback: string): string;
  /** The requested region is not in the discovered list (`known` = comma-separated, or "(none)"). */
  unknownRegion(requested: string, known: string): string;
  /** Region discovery threw; `reason` is already redacted. */
  discoveryFailed(reason: string, fallback: string): string;
  /** `org_mode` requested but the provider has no multi-account support yet. */
  multiAccountUnsupported: string;
}

export interface CloudProvider {
  readonly id: ProviderId;
  /** Human-readable provider name used in runner warnings (e.g. "Huawei Cloud"). */
  readonly displayName?: string;
  /** Resolve the account identifier: AWS = STS account ID; Huawei Cloud = domain ID. */
  getAccountId(scope: RegionScope, creds?: CloudCredentials): Promise<string>;
  /**
   * List scannable region scopes.
   * AWS: fixed / caller supplied (`defaultRegion` echoed back).
   * Huawei Cloud: IAM keystoneListProjects (one project per region).
   */
  listRegions(creds?: CloudCredentials, defaultRegion?: string): Promise<RegionScope[]>;
  /** Multi-account discovery: AWS = Organizations; Huawei Cloud = Organizations (Phase 2). */
  listAccounts?(scope: RegionScope, creds?: CloudCredentials): Promise<AccountRef[]>;
  /** Cross-account credentials: AWS = STS assumeRole; Huawei Cloud = STS assumeAgency (Phase 2). */
  assumeCrossAccount?(
    target: AccountRef,
    scope: RegionScope,
    opts?: AssumeCrossAccountOptions,
  ): Promise<CloudCredentials>;
  /** Scanner set supported by this provider (fresh instances). */
  scanners(): Scanner[];
  /**
   * Build a provider-wide unique resource identifier for `Finding.resourceArn`.
   * AWS: ARN. Huawei Cloud: `hws:<region>:<domainId>:<svc>:<type>:<id>`.
   * `resourceType` uses the form `<service>:<type>` (e.g. `ecs:server`, `s3:bucket`).
   */
  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string;

  /* ---------------------------------------------------------------------- */
  /* Optional orchestration hooks (consumed by scanners/runner.ts / index.ts) */
  /* ---------------------------------------------------------------------- */

  /** `ScanContext.partition` for a region: aws = getPartition(region); huaweicloud = "huaweicloud"; alicloud = "alicloud". */
  partitionFor?(region: string): string;
  /** Region scanned when discovery yields nothing / fails and no region was requested (huaweicloud = cn-north-4; alicloud = cn-hangzhou). */
  readonly defaultRegion?: string;
  /** Account-level modules: in a multi-region scan they run once (on the first scope) instead of once per region. */
  readonly globalModules?: ReadonlySet<string>;
  /** Redact credential material from error / warning text (aws = identity). Must be idempotent and never throw. */
  redactDiagnostic?(text: string): string;
  /** Extra ScanContext fields for one region scope (huaweicloud: projectId / domainId). */
  contextFor?(scope: RegionScope, accountId: string): Partial<ScanContext>;
  /** Whether multi-account orchestration is implemented; false → `org_mode` falls back to the current account with a warning. */
  readonly supportsMultiAccount?: boolean;
  /** Provider-specific wording for the regional runner warnings. */
  readonly regionalMessages?: Partial<RegionalProviderMessages>;
}

/** The optional hook subset of {@link CloudProvider}. */
export type CloudProviderHooks = Pick<
  CloudProvider,
  | "displayName"
  | "partitionFor"
  | "defaultRegion"
  | "globalModules"
  | "redactDiagnostic"
  | "contextFor"
  | "supportsMultiAccount"
  | "regionalMessages"
>;

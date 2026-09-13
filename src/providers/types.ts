import type { Scanner } from "../scanners/base.js";
import type { CloudCredentials, ProviderId } from "../types.js";

export type { CloudCredentials, ProviderId, AwsCredentials, HuaweiCloudCredentials } from "../types.js";

/**
 * Region-level scope for a scan.
 * - AWS: `region` + `partition`.
 * - Huawei Cloud: `region` + `projectId` (per-region project) + `domainId` (account).
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

export interface CloudProvider {
  readonly id: ProviderId;
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
}

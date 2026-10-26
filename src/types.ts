export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Priority = "P0" | "P1" | "P2" | "P3";

export interface Finding {
  severity: Severity;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  riskScore: number;
  remediationSteps: string[];
  priority: Priority;
  module?: string;
  accountId?: string;
  accountAlias?: string;
  source?: string;
  /** Cloud provider that produced this finding; absent means "aws". */
  provider?: ProviderId;
  /** Huawei Cloud enterprise project ID, when known. */
  enterpriseProjectId?: string;
}

export interface ScanResult {
  module: string;
  status: "success" | "error";
  error?: string;
  warnings?: string[];
  resourcesScanned: number;
  findingsCount: number;
  scanTimeMs: number;
  findings: Finding[];
}

/** Cloud provider identifier. Default (and legacy) is "aws". */
export type ProviderId = "aws" | "huaweicloud" | "alicloud" | "azure";

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

/**
 * Huawei Cloud access key pair. `projectId` (regional services) and `domainId`
 * (global services) are resolved per region via IAM and may be absent here.
 *
 * NEVER log or serialize instances of this type; use
 * `createHuaweiCredentials()` which makes ak/sk non-enumerable and redacts
 * them in `toJSON()` / `util.inspect`.
 */
export interface HuaweiCloudCredentials {
  ak: string;
  sk: string;
  securityToken?: string;
  projectId?: string;
  domainId?: string;
}

/**
 * Alibaba Cloud access key pair (optionally an STS temporary credential).
 * `accessKeyId` overlaps with {@link AwsCredentials}, so the `kind` discriminator
 * is mandatory — always narrow with {@link isAlibabaCloudCredentials}.
 *
 * NEVER log or serialize instances of this type.
 */
export interface AlibabaCloudCredentials {
  accessKeyId: string;
  accessKeySecret: string;
  /** STS temporary credentials only. */
  securityToken?: string;
  kind: "alicloud";
  source?: "explicit" | "env" | "file";
}

/** Azure national cloud: China (21Vianet, the default) or Global (public). */
export type AzureCloud = "china" | "global";

/**
 * Azure service principal (client secret). `tenantId` / `clientId` are identifiers;
 * `clientSecret` is the only secret and is held in memory only. Scans iterate every
 * subscription visible to the principal (one scope per subscription).
 *
 * NEVER log or serialize instances of this type.
 */
export interface AzureCredentials {
  kind: "azure";
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /** Default "china" (21Vianet). */
  cloud: AzureCloud;
  source?: "explicit" | "env";
}

/** Provider-agnostic credentials carried on a ScanContext. */
export type CloudCredentials = AwsCredentials | HuaweiCloudCredentials | AlibabaCloudCredentials | AzureCredentials;

/** AWS credentials: `accessKeyId` + `secretAccessKey` and no provider `kind` discriminator. */
export function isAwsCredentials(c: CloudCredentials | undefined): c is AwsCredentials {
  return (
    !!c &&
    typeof (c as AwsCredentials).accessKeyId === "string" &&
    typeof (c as AwsCredentials).secretAccessKey === "string" &&
    (c as { kind?: unknown }).kind === undefined
  );
}

export function isAlibabaCloudCredentials(c: CloudCredentials | undefined): c is AlibabaCloudCredentials {
  return !!c && (c as AlibabaCloudCredentials).kind === "alicloud";
}

export function isAzureCredentials(c: CloudCredentials | undefined): c is AzureCredentials {
  return !!c && (c as AzureCredentials).kind === "azure";
}

export function isHuaweiCloudCredentials(c: CloudCredentials | undefined): c is HuaweiCloudCredentials {
  return !!c && typeof (c as HuaweiCloudCredentials).ak === "string";
}

export interface ScanContext {
  region: string;
  /** AWS partition (aws / aws-cn / aws-us-gov). Huawei Cloud contexts use "huaweicloud"; Alibaba Cloud "alicloud". */
  partition: string;
  /** AWS account ID; for Huawei Cloud this is the domain ID; for Alibaba Cloud the account UID. */
  accountId: string;
  accountAlias?: string;
  credentials?: CloudCredentials;
  /** Cloud provider; absent means "aws" (legacy behaviour). */
  provider?: ProviderId;
  /** Huawei Cloud: region-scoped project ID. */
  projectId?: string;
  /** Huawei Cloud: account domain ID. */
  domainId?: string;
  /** Huawei Cloud: enterprise project ID ("0" = default/all). */
  enterpriseProjectId?: string;
  /**
   * Regional providers, multi-region scans only: `false` on every region scope except the
   * first (absent otherwise). Lets regional modules that also see account-wide data (e.g.
   * Alibaba Cloud OSS buckets without region info) report it exactly once.
   */
  primaryRegionScope?: boolean;
  /** Azure: subscription scanned by this scope (the scope's `region` field). */
  subscriptionId?: string;
  /** Azure: Entra ID tenant (also the context `accountId`). */
  tenantId?: string;
  /** Azure: national cloud of the credentials. */
  cloud?: AzureCloud;
}

export interface FullScanResult {
  scanStart: string;
  scanEnd: string;
  region: string;
  accountId: string;
  modules: ScanResult[];
  /** Optional pre-generated AI executive summary (client AI supplies; server never calls an LLM). */
  aiSummary?: string;
  /** Cloud provider that produced this result; absent means "aws" (legacy serialization unchanged). */
  provider?: ProviderId;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    modulesSuccess: number;
    modulesError: number;
  };
}

export interface DashboardHistoryEntry {
  date: string;          // YYYY-MM-DD
  score: number;         // 0-100
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalFindings: number;
}

export interface DashboardData {
  lastScan: {
    scanStart: string;
    scanEnd: string;
    region: string;
    accountId: string;
    summary: FullScanResult["summary"];
    modules: Array<{ module: string; findingsCount: number; status: string }>;
    findings: Finding[];
    /** Optional pre-generated AI executive summary. */
    aiSummary?: string;
  };
  history: DashboardHistoryEntry[];
  meta: {
    generatedAt: string;
    version: string;
    dataRetentionDays: number;
  };
}

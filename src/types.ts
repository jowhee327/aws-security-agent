export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Priority = "P0" | "P1" | "P2" | "P3";

/** L4 reachability of the resource affected by a CVE finding. */
export type Reachability = "internet_open" | "allowlist" | "internal" | "not_running" | "unknown";

/** Bucketed EPSS score ("none" = data source did not provide one). */
export type EpssLevel = "high" | "medium" | "low" | "none";

/** Machine-readable reason for an exploitability priority (one per rule in the first-match table). */
export type RationaleCode =
  | "KEV"
  | "EXPLOIT_INTERNET"
  | "EPSS_HIGH_INTERNET"
  | "KEV_NOT_RUNNING"
  | "EXPLOIT_EPSS_HIGH"
  | "EXPLOIT_ALLOWLIST"
  | "EXPLOIT_LIMITED"
  | "EPSS_HIGH"
  | "EPSS_MEDIUM"
  | "BASELINE";

/** Threat-intel + exposure assessment attached to CVE findings (AWS provider only). */
export interface ExploitabilityInfo {
  cveId: string;
  /** null = data source did not provide the signal. */
  exploitAvailable: boolean | null;
  /** EPSS probability 0..1; null = not provided. */
  epss: number | null;
  epssLevel: EpssLevel;
  kev: boolean;
  kevDateAdded?: string;
  /** knownRansomwareCampaignUse === "Known" in the CISA KEV catalog. */
  kevRansomware?: boolean;
  fixAvailable?: "YES" | "NO" | "PARTIAL";
  reachability: Reachability;
  /** e.g. "public IP 1.2.3.4; SG sg-x allows 0.0.0.0/0 tcp/22" */
  reachabilityDetail?: string;
  /** Exploitability priority — independent of the severity-derived Finding.priority. */
  priority: Priority;
  rationaleCode: RationaleCode;
  /** One-sentence English explanation; reports localize via rationaleCode. */
  rationale: string;
  /** riskScore before band adjustment. */
  originalRiskScore: number;
  dataSource: "inspector2" | "securityhub";
}

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
  /** Exploitability assessment; present only on CVE findings. */
  exploitability?: ExploitabilityInfo;
  /** ID of the upstream finding (Inspector findingArn / Security Hub finding Id). */
  sourceFindingId?: string;
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
  /** inspector_findings only: whether findings were pulled from Inspector2 or only detection ran. */
  dataSource?: "inspector2" | "detection-only";
}

/** Cloud provider identifier. Default (and legacy) is "aws". */
export type ProviderId = "aws" | "huaweicloud";

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

/** Provider-agnostic credentials carried on a ScanContext. */
export type CloudCredentials = AwsCredentials | HuaweiCloudCredentials;

export function isAwsCredentials(c: CloudCredentials | undefined): c is AwsCredentials {
  return !!c && typeof (c as AwsCredentials).accessKeyId === "string";
}

export function isHuaweiCloudCredentials(c: CloudCredentials | undefined): c is HuaweiCloudCredentials {
  return !!c && typeof (c as HuaweiCloudCredentials).ak === "string";
}

export interface ScanContext {
  region: string;
  /** AWS partition (aws / aws-cn / aws-us-gov). Huawei Cloud contexts use "huaweicloud". */
  partition: string;
  /** AWS account ID; for Huawei Cloud this is the domain ID. */
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

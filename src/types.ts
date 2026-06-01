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

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

export interface ScanContext {
  region: string;
  partition: string;
  accountId: string;
  accountAlias?: string;
  credentials?: AwsCredentials;
}

export interface FullScanResult {
  scanStart: string;
  scanEnd: string;
  region: string;
  accountId: string;
  modules: ScanResult[];
  /** Optional pre-generated AI executive summary (client AI supplies; server never calls an LLM). */
  aiSummary?: string;
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

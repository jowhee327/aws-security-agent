export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Priority = "P0" | "P1" | "P2" | "P3";
export type Reachability = "internet_open" | "allowlist" | "internal" | "not_running" | "unknown";
export type EpssLevel = "high" | "medium" | "low" | "none";

/** CVE exploitability assessment (mirrors src/types.ts ExploitabilityInfo; AWS only). */
export interface ExploitabilityInfo {
  cveId: string;
  exploitAvailable: boolean | null;
  epss: number | null;
  epssLevel: EpssLevel;
  kev: boolean;
  kevDateAdded?: string;
  kevRansomware?: boolean;
  fixAvailable?: "YES" | "NO" | "PARTIAL";
  reachability: Reachability;
  reachabilityDetail?: string;
  /** Exploitability priority — independent of the severity-derived Finding.priority. */
  priority: Priority;
  rationaleCode: string;
  rationale: string;
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
  module: string;
  accountId?: string;
  accountAlias?: string;
  source?: string;
  exploitability?: ExploitabilityInfo;
}

export interface DashboardHistoryEntry {
  date: string;
  score: number;
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
    summary: {
      totalFindings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      modulesSuccess: number;
      modulesError: number;
      modulesDisabled?: number;
    };
    modules: Array<{ module: string; findingsCount: number; status: string }>;
    findings: Finding[];
    aiSummary?: string;
  };
  history: DashboardHistoryEntry[];
  meta: {
    generatedAt: string;
    version: string;
    dataRetentionDays: number;
  };
}

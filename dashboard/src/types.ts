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
  module: string;
  accountId?: string;
  accountAlias?: string;
  source?: string;
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
  };
  history: DashboardHistoryEntry[];
  meta: {
    generatedAt: string;
    version: string;
    dataRetentionDays: number;
  };
}

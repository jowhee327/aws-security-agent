import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Priority = "P0" | "P1" | "P2" | "P3";
interface Finding {
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
}
interface ScanResult {
    module: string;
    status: "success" | "error";
    error?: string;
    warnings?: string[];
    resourcesScanned: number;
    findingsCount: number;
    scanTimeMs: number;
    findings: Finding[];
}
interface ScanContext {
    region: string;
    partition: string;
    accountId: string;
}
interface FullScanResult {
    scanStart: string;
    scanEnd: string;
    region: string;
    accountId: string;
    modules: ScanResult[];
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
interface DashboardHistoryEntry {
    date: string;
    score: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    totalFindings: number;
}
interface DashboardData {
    lastScan: {
        scanStart: string;
        scanEnd: string;
        region: string;
        accountId: string;
        summary: FullScanResult["summary"];
        modules: Array<{
            module: string;
            findingsCount: number;
            status: string;
        }>;
        findings: Finding[];
    };
    history: DashboardHistoryEntry[];
    meta: {
        generatedAt: string;
        version: string;
        dataRetentionDays: number;
    };
}

interface Scanner {
    readonly moduleName: string;
    scan(ctx: ScanContext): Promise<ScanResult>;
}

declare function runAllScanners(scanners: Scanner[], region: string): Promise<FullScanResult>;

declare function generateMarkdownReport(scanResults: FullScanResult): string;

declare function generateHtmlReport(scanResults: FullScanResult, history?: DashboardHistoryEntry[]): string;
declare function generateMlps3HtmlReport(scanResults: FullScanResult, history?: DashboardHistoryEntry[]): string;

declare function calculateScore(summary: FullScanResult["summary"]): number;
declare function saveResults(scanResults: FullScanResult, outputDir?: string): string;

declare function createServer(defaultRegion: string): McpServer;
declare function startServer(defaultRegion: string): Promise<void>;

export { type DashboardData, type DashboardHistoryEntry, type Finding, type FullScanResult, type Priority, type ScanContext, type ScanResult, type Scanner, type Severity, calculateScore, createServer, generateHtmlReport, generateMarkdownReport, generateMlps3HtmlReport, runAllScanners, saveResults, startServer };

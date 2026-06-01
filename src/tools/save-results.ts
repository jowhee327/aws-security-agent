import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

import type {
  FullScanResult,
  DashboardData,
  DashboardHistoryEntry,
} from "../types.js";

export function calculateScore(summary: FullScanResult["summary"]): number {
  const raw =
    100 -
    summary.critical * 15 -
    summary.high * 5 -
    summary.medium * 2 -
    summary.low * 0.5;
  return Math.max(0, Math.min(100, raw));
}

export function saveResults(
  scanResults: FullScanResult,
  outputDir?: string,
): string {
  const baseDir = outputDir ?? join(homedir(), ".aws-security");
  const today = scanResults.scanStart.slice(0, 10); // YYYY-MM-DD

  // Create directories
  const scanDir = join(baseDir, "scans", today);
  const dashboardDir = join(baseDir, "dashboard");
  mkdirSync(scanDir, { recursive: true });
  mkdirSync(dashboardDir, { recursive: true });

  // Write raw scan
  writeFileSync(join(scanDir, "scan.json"), JSON.stringify(scanResults, null, 2));

  // Read existing dashboard data
  const dataPath = join(dashboardDir, "data.json");
  let existing: DashboardData | null = null;
  if (existsSync(dataPath)) {
    try {
      existing = JSON.parse(readFileSync(dataPath, "utf-8")) as DashboardData;
    } catch {
      // Corrupt or invalid JSON — start fresh
      existing = null;
    }
  }

  // Build history entry for today
  const historyEntry: DashboardHistoryEntry = {
    date: today,
    score: calculateScore(scanResults.summary),
    critical: scanResults.summary.critical,
    high: scanResults.summary.high,
    medium: scanResults.summary.medium,
    low: scanResults.summary.low,
    totalFindings: scanResults.summary.totalFindings,
  };

  // Merge history: replace same-date entry or append
  let history = existing?.history ?? [];
  const idx = history.findIndex((h) => h.date === today);
  if (idx >= 0) {
    history[idx] = historyEntry;
  } else {
    history.push(historyEntry);
  }
  // Keep only last 30 entries
  history = history.slice(-30);

  // Build dashboard data
  const dashboardData: DashboardData = {
    lastScan: {
      scanStart: scanResults.scanStart,
      scanEnd: scanResults.scanEnd,
      region: scanResults.region,
      accountId: scanResults.accountId,
      summary: scanResults.summary,
      modules: scanResults.modules.map((m) => ({
        module: m.module,
        findingsCount: m.findingsCount,
        status: m.status,
      })),
      findings: scanResults.modules.flatMap((m) =>
        m.findings.map((f) => ({ ...f, module: m.module })),
      ),
      aiSummary: scanResults.aiSummary,
    },
    history,
    meta: {
      generatedAt: new Date().toISOString(),
      version: "1.0.0",
      dataRetentionDays: 30,
    },
  };

  writeFileSync(dataPath, JSON.stringify(dashboardData, null, 2));
  return dataPath;
}

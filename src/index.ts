import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import type { Scanner } from "./scanners/base.js";
import { runAllScanners } from "./scanners/runner.js";
import { SgScanner } from "./scanners/sg.js";
import { S3Scanner } from "./scanners/s3.js";
import { IamScanner } from "./scanners/iam.js";
import { CloudTrailScanner } from "./scanners/cloudtrail.js";
import { RdsScanner } from "./scanners/rds.js";
import { EbsScanner } from "./scanners/ebs.js";
import { VpcScanner } from "./scanners/vpc.js";
import { ServiceDetectionScanner } from "./scanners/service-detection.js";
import type { ServiceDetectionResult } from "./scanners/service-detection.js";
import { generateMarkdownReport } from "./tools/report-tool.js";
import { saveResults } from "./tools/save-results.js";
import {
  SECURITY_RULES_CONTENT,
  RISK_SCORING_CONTENT,
} from "./resources/index.js";
import { getPartition, getAccountId } from "./utils/aws-client.js";
import type { FullScanResult, ScanResult, ScanContext } from "./types.js";

export { type Scanner } from "./scanners/base.js";
export { runAllScanners } from "./scanners/runner.js";
export { generateMarkdownReport } from "./tools/report-tool.js";
export { saveResults, calculateScore } from "./tools/save-results.js";
export type {
  Finding,
  ScanResult,
  ScanContext,
  FullScanResult,
  DashboardData,
  DashboardHistoryEntry,
  Severity,
  Priority,
} from "./types.js";

const MODULE_DESCRIPTIONS: Record<string, string> = {
  security_group:
    "Scans EC2 security groups for overly permissive inbound rules (SSH, RDP, database ports open to 0.0.0.0/0).",
  s3: "Checks S3 buckets for public access, missing encryption, and versioning.",
  iam: "Audits IAM users, root account, access keys, and over-permissive policies.",
  cloudtrail:
    "Validates CloudTrail logging configuration (multi-region, log validation, CloudWatch integration).",
  rds: "Scans RDS instances for public accessibility, encryption, backups, and deletion protection.",
  ebs: "Checks EBS volumes and snapshots for encryption and public sharing.",
  vpc: "Reviews VPC configuration including default VPC usage, flow logs, and default security groups.",
  service_detection:
    "Detects which AWS security services (Security Hub, GuardDuty, Inspector, Config, Macie) are enabled and assesses security maturity.",
};

function summarizeResult(result: FullScanResult): string {
  const { summary } = result;
  const lines = [
    `Scan complete for account ${result.accountId} in ${result.region}.`,
    `Total findings: ${summary.totalFindings} (${summary.critical} Critical, ${summary.high} High, ${summary.medium} Medium, ${summary.low} Low)`,
    `Modules: ${summary.modulesSuccess} succeeded, ${summary.modulesError} errored`,
  ];
  return lines.join("\n");
}

function summarizeScanResult(result: ScanResult): string {
  const lines = [
    `Module: ${result.module} — ${result.status}`,
    `Resources scanned: ${result.resourcesScanned}, Findings: ${result.findingsCount}`,
  ];
  if (result.warnings?.length) {
    lines.push(`Warnings: ${result.warnings.length}`);
  }
  return lines.join("\n");
}

async function buildScanContext(region: string): Promise<ScanContext> {
  let accountId: string;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }
  return { region, partition: getPartition(region), accountId };
}

export function createServer(defaultRegion: string): McpServer {
  const server = new McpServer(
    { name: "aws-security-mcp", version: "0.1.0" },
    { capabilities: { resources: {}, tools: {}, prompts: {} } },
  );

  const allScanners: Scanner[] = [
    new SgScanner(),
    new S3Scanner(),
    new IamScanner(),
    new CloudTrailScanner(),
    new RdsScanner(),
    new EbsScanner(),
    new VpcScanner(),
    new ServiceDetectionScanner(),
  ];

  const scannerMap = new Map<string, Scanner>();
  for (const s of allScanners) {
    scannerMap.set(s.moduleName, s);
  }

  // --- Tools ---

  // 1. scan_all
  server.tool(
    "scan_all",
    "Run all 8 security scanners in parallel (including service detection). Read-only. Does not modify any AWS resources.",
    { region: z.string().optional().describe("AWS region to scan (default: server region)") },
    async ({ region }) => {
      try {
        const r = region ?? defaultRegion;
        const result = await runAllScanners(allScanners, r);
        return {
          content: [
            { type: "text", text: summarizeResult(result) },
            { type: "text", text: JSON.stringify(result, null, 2) },
          ],
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // Individual scanner tools
  const individualScanners: Array<{ toolName: string; moduleName: string; label: string }> = [
    { toolName: "scan_sg", moduleName: "security_group", label: "Security Group" },
    { toolName: "scan_s3", moduleName: "s3", label: "S3 Bucket" },
    { toolName: "scan_iam", moduleName: "iam", label: "IAM" },
    { toolName: "scan_cloudtrail", moduleName: "cloudtrail", label: "CloudTrail" },
    { toolName: "scan_rds", moduleName: "rds", label: "RDS" },
    { toolName: "scan_ebs", moduleName: "ebs", label: "EBS" },
    { toolName: "scan_vpc", moduleName: "vpc", label: "VPC" },
    { toolName: "detect_services", moduleName: "service_detection", label: "Security Service Detection" },
  ];

  for (const { toolName, moduleName, label } of individualScanners) {
    server.tool(
      toolName,
      `Run ${label} security scanner only. Read-only. Does not modify any AWS resources.`,
      { region: z.string().optional().describe("AWS region to scan (default: server region)") },
      async ({ region }) => {
        try {
          const r = region ?? defaultRegion;
          const ctx = await buildScanContext(r);
          const scanner = scannerMap.get(moduleName)!;
          const result: ScanResult = await scanner.scan(ctx);
          return {
            content: [
              { type: "text", text: summarizeScanResult(result) },
              { type: "text", text: JSON.stringify(result, null, 2) },
            ],
          };
        } catch (err) {
          return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
        }
      },
    );
  }

  // 9. generate_report
  server.tool(
    "generate_report",
    "Generate a Markdown security report from scan results. Read-only. Does not modify any AWS resources.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const report = generateMarkdownReport(parsed);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // 10. generate_maturity_report
  server.tool(
    "generate_maturity_report",
    "Generate a security maturity assessment report from scan_all results. Requires service_detection module output. Read-only.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const sdModule = parsed.modules.find((m) => m.module === "service_detection");
        if (!sdModule) {
          return {
            content: [{ type: "text", text: "Error: scan results do not include service_detection module. Run scan_all first." }],
            isError: true,
          };
        }

        // Extract the serviceDetection data attached by the scanner
        const detection = (sdModule as ScanResult & { serviceDetection?: ServiceDetectionResult }).serviceDetection;

        // Fallback: reconstruct from findings if the structured data was lost (e.g. JSON round-trip)
        const serviceNames = ["CloudTrail", "Security Hub", "GuardDuty", "Inspector", "AWS Config", "Macie"];
        const serviceImpacts: Record<string, string> = {
          "CloudTrail": "API activity logging",
          "Security Hub": "+300 security checks",
          "GuardDuty": "Threat detection",
          "Inspector": "Vulnerability scanning",
          "AWS Config": "Configuration tracking",
          "Macie": "Sensitive data detection",
        };
        const serviceFreeTrials: Record<string, boolean> = {
          "Security Hub": true,
          "GuardDuty": true,
          "Inspector": true,
          "Macie": true,
        };

        let services: Array<{ name: string; enabled: boolean; details?: string }>;
        let coveragePercent: number;
        let maturityLevel: string;

        if (detection) {
          services = detection.services;
          coveragePercent = detection.coveragePercent;
          maturityLevel = detection.maturityLevel;
        } else {
          // Reconstruct from findings: any service mentioned in a finding title is disabled
          const disabledTitles = sdModule.findings.map((f) => f.title);
          services = serviceNames.map((name) => {
            const isDisabled = disabledTitles.some((t) => t.includes(name) || t.includes(name.replace("AWS ", "")));
            return { name, enabled: !isDisabled };
          });
          const enabledCount = services.filter((s) => s.enabled).length;
          const total = services.length;
          coveragePercent = total > 0 ? Math.round((enabledCount / total) * 100) : 0;
          if (enabledCount >= 6) maturityLevel = "comprehensive";
          else if (enabledCount >= 4) maturityLevel = "advanced";
          else if (enabledCount >= 2) maturityLevel = "intermediate";
          else maturityLevel = "basic";
        }

        const enabledCount = services.filter((s) => s.enabled).length;
        const totalServices = services.length;

        // Build the report
        const lines: string[] = [];
        lines.push("# AWS Security Maturity Assessment");
        lines.push("");
        lines.push(`## Account: ${parsed.accountId} | Region: ${parsed.region}`);
        lines.push("");
        lines.push(`## Security Service Coverage: ${coveragePercent}%`);
        lines.push(`## Maturity Level: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)}`);
        lines.push("");
        lines.push("### Service Status");
        lines.push("");
        lines.push("| Service | Status | Impact |");
        lines.push("|---------|--------|--------|");
        for (const svc of services) {
          const status = svc.enabled ? "\u2705 Enabled" : "\u274c Not Enabled";
          const impact = serviceImpacts[svc.name] ?? "";
          lines.push(`| ${svc.name} | ${status} | ${impact} |`);
        }

        // Recommendations
        const disabled = services.filter((s) => !s.enabled);
        if (disabled.length > 0) {
          lines.push("");
          lines.push("### Recommendations (Priority Order)");
          lines.push("");
          // Priority order: Security Hub, GuardDuty, Inspector, Config, Macie, CloudTrail
          const priorityOrder = ["Security Hub", "GuardDuty", "Inspector", "AWS Config", "Macie", "CloudTrail"];
          const sorted = disabled.sort(
            (a, b) => priorityOrder.indexOf(a.name) - priorityOrder.indexOf(b.name),
          );
          let idx = 1;
          for (const svc of sorted) {
            const trial = serviceFreeTrials[svc.name] ? " \u2014 free trial available" : "";
            lines.push(`${idx}. Enable ${svc.name}${trial}`);
            idx++;
          }
        }

        // Maturity roadmap
        lines.push("");
        lines.push("### Maturity Roadmap");
        lines.push("");
        lines.push(`- **Current**: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)} (${enabledCount}/${totalServices} services)`);

        if (maturityLevel !== "comprehensive") {
          const nextMilestones: Record<string, { level: string; target: number; suggestions: string[] }> = {
            basic: { level: "Intermediate", target: 2, suggestions: ["Security Hub", "GuardDuty"] },
            intermediate: { level: "Advanced", target: 4, suggestions: ["Inspector", "AWS Config"] },
            advanced: { level: "Comprehensive", target: 6, suggestions: ["Macie"] },
          };
          const next = nextMilestones[maturityLevel];
          if (next) {
            const remaining = next.suggestions.filter((s) =>
              services.some((svc) => svc.name === s && !svc.enabled),
            );
            if (remaining.length > 0) {
              lines.push(`- **Next milestone**: ${next.level} (${next.target}/${totalServices}) \u2014 enable ${remaining.join(" + ")}`);
            }
          }
          lines.push(`- **Target**: Comprehensive (${totalServices}/${totalServices})`);
        }

        lines.push("");

        const report = lines.join("\n");

        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
          isError: true,
        };
      }
    },
  );

  // 11. save_results
  server.tool(
    "save_results",
    "Saves scan results to local disk or S3 for dashboard display. Does not modify any AWS resources.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      output_dir: z.string().optional().describe("Output directory (default: ~/.aws-security)"),
    },
    async ({ scan_results, output_dir }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const dataPath = saveResults(parsed, output_dir);
        return {
          content: [
            { type: "text", text: `Dashboard data saved to ${dataPath}` },
          ],
        };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
          isError: true,
        };
      }
    },
  );

  // 11. list_modules
  server.tool(
    "list_modules",
    "List available security scan modules with descriptions. Read-only. Does not modify any AWS resources.",
    async () => {
      try {
        const modules = allScanners.map((s) => ({
          name: s.moduleName,
          description: MODULE_DESCRIPTIONS[s.moduleName] ?? s.moduleName,
        }));
        return { content: [{ type: "text", text: JSON.stringify(modules, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // --- Resources ---

  server.resource(
    "security-rules",
    "security://rules",
    { description: "Describes all 7 scan modules and their check rules", mimeType: "text/markdown" },
    async () => ({
      contents: [{ uri: "security://rules", text: SECURITY_RULES_CONTENT, mimeType: "text/markdown" }],
    }),
  );

  server.resource(
    "risk-scoring",
    "security://risk-scoring",
    { description: "Describes the risk scoring model and severity/priority mapping", mimeType: "text/markdown" },
    async () => ({
      contents: [{ uri: "security://risk-scoring", text: RISK_SCORING_CONTENT, mimeType: "text/markdown" }],
    }),
  );

  // --- Prompts ---

  server.prompt(
    "security-scan",
    "Run a full AWS security scan workflow: scan all modules, generate a report, and summarize findings.",
    async () => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: "Run scan_all to perform a full AWS security scan. Then take the JSON result and pass it to generate_report to create a Markdown report. Finally, summarize the top findings and recommend immediate actions based on priority.",
          },
        },
      ],
    }),
  );

  server.prompt(
    "analyze-finding",
    "Deep analysis of a specific security finding.",
    { finding: z.string().describe("JSON string of a single Finding object to analyze") },
    async ({ finding }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Analyze this AWS security finding in depth. Explain the risk, potential attack vectors, blast radius, and provide detailed step-by-step remediation guidance.\n\nFinding:\n${finding}`,
          },
        },
      ],
    }),
  );

  return server;
}

export async function startServer(defaultRegion: string): Promise<void> {
  const server = createServer(defaultRegion);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

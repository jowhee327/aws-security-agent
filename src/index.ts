import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import type { Scanner } from "./scanners/base.js";
import { runAllScanners, runMultiAccountScanners } from "./scanners/runner.js";
import { ServiceDetectionScanner } from "./scanners/service-detection.js";
import type { ServiceDetectionResult } from "./scanners/service-detection.js";
import { SecretExposureScanner } from "./scanners/secret-exposure.js";
import { SslCertificateScanner } from "./scanners/ssl-certificate.js";
import { DnsDanglingScanner } from "./scanners/dns-dangling.js";
import { NetworkReachabilityScanner } from "./scanners/network-reachability.js";
import { IamPrivilegeEscalationScanner } from "./scanners/iam-privilege-escalation.js";
import { PublicAccessVerifyScanner } from "./scanners/public-access-verify.js";
import { TagComplianceScanner } from "./scanners/tag-compliance.js";
import { IdleResourcesScanner } from "./scanners/idle-resources.js";
import { DisasterRecoveryScanner } from "./scanners/disaster-recovery.js";
import { SecurityHubFindingsScanner } from "./scanners/security-hub-findings.js";
import { GuardDutyFindingsScanner } from "./scanners/guardduty-findings.js";
import { InspectorFindingsScanner } from "./scanners/inspector-findings.js";
import { TrustedAdvisorFindingsScanner } from "./scanners/trusted-advisor-findings.js";
import { generateMarkdownReport } from "./tools/report-tool.js";
import { generateMlps3Report } from "./tools/mlps-report.js";
import { generateHtmlReport, generateMlps3HtmlReport } from "./tools/html-report.js";
import { saveResults } from "./tools/save-results.js";
import { SCAN_GROUPS, applyFindingsFilter } from "./tools/scan-groups.js";
import {
  SECURITY_RULES_CONTENT,
  RISK_SCORING_CONTENT,
} from "./resources/index.js";
import { getPartition, getAccountId } from "./utils/aws-client.js";
import { listOrgAccounts } from "./utils/org-accounts.js";
import type { FullScanResult, ScanResult, ScanContext } from "./types.js";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

export { type Scanner } from "./scanners/base.js";
export { runAllScanners, runMultiAccountScanners } from "./scanners/runner.js";
export { assumeRole, buildRoleArn, getCurrentAccountId } from "./utils/assume-role.js";
export { listOrgAccounts, type OrgAccount } from "./utils/org-accounts.js";
export { generateMarkdownReport } from "./tools/report-tool.js";
export { generateHtmlReport, generateMlps3HtmlReport } from "./tools/html-report.js";
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
  service_detection:
    "Detects which AWS security services (Security Hub, GuardDuty, Inspector, Config, Macie) are enabled and assesses security maturity.",
  secret_exposure:
    "Checks Lambda env vars and EC2 userData for exposed secrets (AWS keys, private keys, passwords).",
  ssl_certificate:
    "Checks ACM certificates for expiry, failed status, and upcoming renewals.",
  dns_dangling:
    "Checks Route53 CNAME records for dangling DNS (subdomain takeover risk).",
  network_reachability:
    "Analyzes true network reachability by combining Security Group + NACL rules for public EC2 instances.",
  iam_privilege_escalation:
    "Detects IAM privilege escalation paths — users/roles that can escalate to admin via policy manipulation, role creation, or service abuse.",
  public_access_verify:
    "Verifies actual public accessibility of resources marked as public (S3 HTTP check, RDS DNS resolution).",
  tag_compliance:
    "Checks EC2, RDS, and S3 resources for required tags (Environment, Project, Owner).",
  idle_resources:
    "Finds unused/idle AWS resources (unattached EBS volumes, unused EIPs, stopped instances, unused security groups) that waste money and increase attack surface.",
  disaster_recovery:
    "Assesses disaster recovery readiness — RDS Multi-AZ & backups, EBS snapshot coverage, S3 versioning & cross-region replication.",
  security_hub_findings:
    "Aggregates active findings from AWS Security Hub — replaces individual config scanners with centralized compliance checks.",
  guardduty_findings:
    "Aggregates threat detection findings from Amazon GuardDuty — account compromise, instance compromise, and reconnaissance.",
  inspector_findings:
    "Aggregates vulnerability findings from Amazon Inspector — CVEs in EC2, Lambda, and container images.",
  trusted_advisor_findings:
    "Aggregates security checks from AWS Trusted Advisor — requires Business or Enterprise Support plan.",
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
    new ServiceDetectionScanner(),
    new SecretExposureScanner(),
    new SslCertificateScanner(),
    new DnsDanglingScanner(),
    new NetworkReachabilityScanner(),
    new IamPrivilegeEscalationScanner(),
    new PublicAccessVerifyScanner(),
    new TagComplianceScanner(),
    new IdleResourcesScanner(),
    new DisasterRecoveryScanner(),
    new SecurityHubFindingsScanner(),
    new GuardDutyFindingsScanner(),
    new InspectorFindingsScanner(),
    new TrustedAdvisorFindingsScanner(),
  ];

  const scannerMap = new Map<string, Scanner>();
  for (const s of allScanners) {
    scannerMap.set(s.moduleName, s);
  }

  // --- Tools ---

  // 1. scan_all
  server.tool(
    "scan_all",
    "Run all security scanners in parallel (including service detection). Read-only. Does not modify any AWS resources. Supports multi-account org scanning.",
    {
      region: z.string().optional().describe("AWS region to scan (default: server region)"),
      org_mode: z.boolean().optional().describe("Enable multi-account scanning via AWS Organizations"),
      role_name: z.string().optional().describe("IAM role name to assume in child accounts (default: AWSSecurityMCPAudit)"),
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)"),
    },
    async ({ region, org_mode, role_name, account_ids }) => {
      try {
        const r = region ?? defaultRegion;
        let result: FullScanResult;

        if (org_mode) {
          result = await runMultiAccountScanners(allScanners, r, {
            orgMode: true,
            roleName: role_name ?? "AWSSecurityMCPAudit",
            accountIds: account_ids,
          });
        } else {
          result = await runAllScanners(allScanners, r);
        }

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
    { toolName: "detect_services", moduleName: "service_detection", label: "Security Service Detection" },
    { toolName: "scan_secret_exposure", moduleName: "secret_exposure", label: "Secret Exposure" },
    { toolName: "scan_ssl_certificate", moduleName: "ssl_certificate", label: "SSL Certificate" },
    { toolName: "scan_dns_dangling", moduleName: "dns_dangling", label: "Dangling DNS" },
    { toolName: "scan_network_reachability", moduleName: "network_reachability", label: "Network Reachability" },
    { toolName: "scan_iam_privilege_escalation", moduleName: "iam_privilege_escalation", label: "IAM Privilege Escalation" },
    { toolName: "scan_public_access_verify", moduleName: "public_access_verify", label: "Public Access Verify" },
    { toolName: "scan_tag_compliance", moduleName: "tag_compliance", label: "Tag Compliance" },
    { toolName: "scan_idle_resources", moduleName: "idle_resources", label: "Idle Resources" },
    { toolName: "scan_disaster_recovery", moduleName: "disaster_recovery", label: "Disaster Recovery" },
    { toolName: "scan_security_hub_findings", moduleName: "security_hub_findings", label: "Security Hub Findings" },
    { toolName: "scan_guardduty_findings", moduleName: "guardduty_findings", label: "GuardDuty Findings" },
    { toolName: "scan_inspector_findings", moduleName: "inspector_findings", label: "Inspector Findings" },
    { toolName: "scan_trusted_advisor_findings", moduleName: "trusted_advisor_findings", label: "Trusted Advisor Findings" },
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

  // scan_group
  server.tool(
    "scan_group",
    "Run a predefined group of security scanners for a specific scenario (e.g., MLPS compliance, network defense). Read-only. Supports multi-account org scanning.",
    {
      group: z.string().describe("Scan group ID: mlps3_precheck, hw_defense, exposure, pre_launch, data_encryption, least_privilege, log_integrity, disaster_recovery, idle_resources, tag_compliance, new_account_baseline, public_access_verify, aggregation"),
      region: z.string().optional().describe("AWS region to scan (default: server region)"),
      org_mode: z.boolean().optional().describe("Enable multi-account scanning via AWS Organizations"),
      role_name: z.string().optional().describe("IAM role name to assume in child accounts (default: AWSSecurityMCPAudit)"),
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)"),
    },
    async ({ group, region, org_mode, role_name, account_ids }) => {
      try {
        const groupDef = SCAN_GROUPS[group];
        if (!groupDef) {
          const available = Object.keys(SCAN_GROUPS).join(", ");
          return {
            content: [{ type: "text", text: `Error: Unknown scan group "${group}". Available groups: ${available}` }],
            isError: true,
          };
        }

        const r = region ?? defaultRegion;

        // Resolve scanners: "ALL" means all registered scanners
        let selectedScanners: Scanner[];
        const missingModules: string[] = [];

        if (groupDef.modules.includes("ALL")) {
          selectedScanners = allScanners;
        } else {
          selectedScanners = [];
          for (const mod of groupDef.modules) {
            const scanner = scannerMap.get(mod);
            if (scanner) {
              selectedScanners.push(scanner);
            } else {
              missingModules.push(mod);
            }
          }
        }

        if (selectedScanners.length === 0) {
          return {
            content: [{ type: "text", text: `Error: No available scanners for group "${group}". Requested modules: ${groupDef.modules.join(", ")}` }],
            isError: true,
          };
        }

        let result: FullScanResult;

        if (org_mode) {
          result = await runMultiAccountScanners(selectedScanners, r, {
            orgMode: true,
            roleName: role_name ?? "AWSSecurityMCPAudit",
            accountIds: account_ids,
          });
        } else {
          result = await runAllScanners(selectedScanners, r);
        }

        // Apply post-filter if the group defines one
        if (groupDef.findingsFilter) {
          for (const mod of result.modules) {
            const originalCount = mod.findings.length;
            mod.findings = applyFindingsFilter(mod.module, mod.findings, groupDef.findingsFilter);
            mod.findingsCount = mod.findings.length;
            if (mod.findings.length < originalCount) {
              const filtered = originalCount - mod.findings.length;
              if (!mod.warnings) mod.warnings = [];
              mod.warnings.push(`Post-filter removed ${filtered} finding(s) not matching group criteria.`);
            }
          }
          // Recalculate summary after filtering
          let critical = 0, high = 0, medium = 0, low = 0;
          for (const m of result.modules) {
            for (const f of m.findings) {
              switch (f.severity) {
                case "CRITICAL": critical++; break;
                case "HIGH": high++; break;
                case "MEDIUM": medium++; break;
                case "LOW": low++; break;
              }
            }
          }
          result.summary.totalFindings = critical + high + medium + low;
          result.summary.critical = critical;
          result.summary.high = high;
          result.summary.medium = medium;
          result.summary.low = low;
        }

        const lines: string[] = [
          `Scan group: ${groupDef.name} (${group})`,
          groupDef.description,
          "",
          summarizeResult(result),
        ];

        if (missingModules.length > 0) {
          lines.push("");
          lines.push(`Warning: ${missingModules.length} requested module(s) not available: ${missingModules.join(", ")}`);
        }

        return {
          content: [
            { type: "text", text: lines.join("\n") },
            { type: "text", text: JSON.stringify(result, null, 2) },
          ],
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // list_groups
  server.tool(
    "list_groups",
    "List available scan groups with descriptions. Read-only.",
    async () => {
      try {
        const groups = Object.entries(SCAN_GROUPS).map(([id, def]) => ({
          id,
          name: def.name,
          description: def.description,
          modules: def.modules,
          reportType: def.reportType,
        }));
        return { content: [{ type: "text", text: JSON.stringify(groups, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

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

  // generate_mlps3_report
  server.tool(
    "generate_mlps3_report",
    "Generate a GB/T 22239-2019 等保三级 compliance pre-check report from scan results. Best used with scan_group mlps3_precheck results. Read-only.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_group mlps3_precheck or scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const report = generateMlps3Report(parsed);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // generate_html_report
  server.tool(
    "generate_html_report",
    "Generate a professional HTML security report. Save the output as an .html file.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts"),
    },
    async ({ scan_results, history }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : undefined;
        const report = generateHtmlReport(parsed, historyData);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // generate_mlps3_html_report
  server.tool(
    "generate_mlps3_html_report",
    "Generate a professional HTML MLPS Level 3 compliance report (等保三级). Save as .html file.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_group mlps3_precheck or scan_all"),
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts"),
    },
    async ({ scan_results, history }) => {
      try {
        const parsed: FullScanResult = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : undefined;
        const report = generateMlps3HtmlReport(parsed, historyData);
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

        if (!detection) {
          return {
            content: [{ type: "text", text: "Error: service detection data is missing (possible JSON round-trip loss). Run scan_all to get fresh results with complete service detection data." }],
            isError: true,
          };
        }

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

        const services = detection.services;
        const coveragePercent = detection.coveragePercent;
        const maturityLevel = detection.maturityLevel;

        const enabledCount = services.filter((s) => s.enabled === true).length;
        const knownCount = services.filter((s) => s.enabled !== null).length;
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
          const status = svc.enabled === true ? "\u2705 Enabled" : svc.enabled === false ? "\u274c Not Enabled" : "\u26a0\ufe0f Unknown";
          const impact = serviceImpacts[svc.name] ?? "";
          lines.push(`| ${svc.name} | ${status} | ${impact} |`);
        }

        const unknowns = services.filter((s) => s.enabled === null);
        if (unknowns.length > 0) {
          lines.push("");
          lines.push(`> \u26a0\ufe0f ${unknowns.length} service(s) could not be checked (access denied or detection error). Re-run with appropriate permissions for accurate coverage.`);
        }

        // Recommendations
        const disabled = services.filter((s) => s.enabled === false);
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
        if (unknowns.length > 0) {
          lines.push(`- **Current**: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)} (${enabledCount}/${knownCount} known services, ${unknowns.length} unknown)`);
        } else {
          lines.push(`- **Current**: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)} (${enabledCount}/${totalServices} services)`);
        }

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
              lines.push(`- **Next milestone**: ${next.level} (${next.target}/${knownCount}) \u2014 enable ${remaining.join(" + ")}`);
            }
          }
          lines.push(`- **Target**: Comprehensive (${knownCount}/${knownCount})`);
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

  // list_org_accounts
  server.tool(
    "list_org_accounts",
    "List all accounts in the AWS Organization. Useful for discovering accounts before multi-account scanning. Read-only.",
    { region: z.string().optional().describe("AWS region (default: server region)") },
    async ({ region }) => {
      try {
        const r = region ?? defaultRegion;
        const accounts = await listOrgAccounts(r);
        return {
          content: [
            { type: "text", text: `Found ${accounts.length} active account(s) in the organization.` },
            { type: "text", text: JSON.stringify(accounts, null, 2) },
          ],
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // get_setup_template
  server.tool(
    "get_setup_template",
    "Returns the CloudFormation StackSet template for deploying the cross-account security audit IAM role. Read-only.",
    {
      format: z.enum(["yaml", "json"]).optional().describe("Template format: yaml or json (default: yaml)"),
    },
    async ({ format }) => {
      try {
        const ext = format === "json" ? "json" : "yaml";
        const templateFileName = `stackset-audit-role.${ext}`;
        // Try multiple locations for the template
        let templateContent: string;
        try {
          // When running from source
          const currentDir = dirname(fileURLToPath(import.meta.url));
          const templatePath = join(currentDir, "..", "templates", templateFileName);
          templateContent = readFileSync(templatePath, "utf-8");
        } catch {
          try {
            // When running from dist
            const currentDir = dirname(fileURLToPath(import.meta.url));
            const templatePath = join(currentDir, "..", "..", "templates", templateFileName);
            templateContent = readFileSync(templatePath, "utf-8");
          } catch {
            return {
              content: [{ type: "text", text: `Error: Template file ${templateFileName} not found. Ensure the templates/ directory is included in the package.` }],
              isError: true,
            };
          }
        }
        return {
          content: [
            { type: "text", text: `CloudFormation StackSet template (${ext.toUpperCase()}) for cross-account audit role:\n\nDeploy this as a StackSet from your Management Account to all member accounts.` },
            { type: "text", text: templateContent },
          ],
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    },
  );

  // --- Resources ---

  server.resource(
    "security-rules",
    "security://rules",
    { description: "Describes all 14 scan modules and their check rules", mimeType: "text/markdown" },
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

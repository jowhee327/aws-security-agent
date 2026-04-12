import {
  Inspector2Client,
  ListFindingsCommand,
  type FilterCriteria,
} from "@aws-sdk/client-inspector2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function inspectorSeverityToScore(label: string): number | null {
  switch (label) {
    case "CRITICAL": return 9.5;
    case "HIGH": return 8.0;
    case "MEDIUM": return 5.5;
    case "LOW": return 3.0;
    case "INFORMATIONAL": return null;
    case "UNTRIAGED": return 5.5;
    default: return null;
  }
}

export class InspectorFindingsScanner implements Scanner {
  readonly moduleName = "inspector_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(Inspector2Client, region, ctx.credentials);
      let nextToken: string | undefined;

      const filterCriteria: FilterCriteria = {
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }],
      };

      do {
        const resp = await client.send(
          new ListFindingsCommand({
            filterCriteria,
            maxResults: 100,
            nextToken,
          }),
        );

        const inspFindings = resp.findings ?? [];
        resourcesScanned += inspFindings.length;

        for (const f of inspFindings) {
          const severityLabel = f.severity ?? "INFORMATIONAL";
          const score = inspectorSeverityToScore(severityLabel);
          if (score === null) continue;

          const severity = severityFromScore(score);

          // Build title with CVE if available
          const cveId = f.packageVulnerabilityDetails?.vulnerabilityId;
          const titleBase = f.title ?? "Inspector Finding";
          const title = cveId ? `[${cveId}] ${titleBase}` : titleBase;

          const resourceId = f.resources?.[0]?.id ?? "unknown";
          const resourceType = f.resources?.[0]?.type ?? "AWS::Unknown";
          const resourceArn = resourceId.startsWith("arn:")
            ? resourceId
            : `arn:${partition}:inspector2:${region}:${accountId}:finding/${f.findingArn ?? "unknown"}`;

          const remediationSteps: string[] = [];

          // Build specific package update guidance from vulnerable packages
          const vulnPkgs = f.packageVulnerabilityDetails?.vulnerablePackages;
          if (vulnPkgs?.length) {
            for (const pkg of vulnPkgs.slice(0, 3)) {
              const name = pkg.name ?? "unknown-package";
              const installed = pkg.version ?? "unknown";
              const fixed = pkg.fixedInVersion ?? "latest";
              const cveRef = cveId ? ` to fix ${cveId}` : "";
              remediationSteps.push(`Update ${name} from ${installed} to ${fixed}${cveRef}`);
            }
          } else if (f.remediation?.recommendation?.text) {
            remediationSteps.push(f.remediation.recommendation.text);
          }

          if (f.remediation?.recommendation?.Url) {
            remediationSteps.push(`Documentation: ${f.remediation.recommendation.Url}`);
          }
          if (f.packageVulnerabilityDetails?.referenceUrls?.length) {
            remediationSteps.push(`CVE references: ${f.packageVulnerabilityDetails.referenceUrls.slice(0, 3).join(", ")}`);
          }
          if (remediationSteps.length === 0) {
            remediationSteps.push(title);
          }

          const description = f.description ?? titleBase;
          const impact = cveId
            ? `Vulnerability ${cveId} — CVSS: ${f.packageVulnerabilityDetails?.cvss?.[0]?.baseScore ?? "N/A"}`
            : `Inspector finding type: ${f.type ?? "unknown"}`;

          findings.push({
            severity,
            title,
            resourceType,
            resourceId,
            resourceArn,
            region,
            description,
            impact,
            riskScore: score,
            remediationSteps,
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: f.awsAccountId ?? accountId,
          });
        }

        nextToken = resp.nextToken;
      } while (nextToken);

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const errName = err instanceof Error ? err.name : "";

      const isAccessDenied = errName === "AccessDeniedException" || msg.includes("AccessDeniedException");
      const isNotEnabled = msg.includes("not enabled") || msg.includes("not subscribed");

      if (isAccessDenied) {
        warnings.push("Insufficient permissions to access Inspector. Grant inspector2:ListFindings to scan for vulnerabilities.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      if (isNotEnabled) {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      return {
        module: this.moduleName,
        status: "error",
        error: `Inspector findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

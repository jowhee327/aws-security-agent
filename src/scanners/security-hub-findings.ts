import {
  SecurityHubClient,
  GetFindingsCommand,
} from "@aws-sdk/client-securityhub";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function shSeverityToScore(label: string): number | null {
  switch (label) {
    case "CRITICAL": return 9.5;
    case "HIGH": return 8.0;
    case "MEDIUM": return 5.5;
    case "LOW": return 3.0;
    case "INFORMATIONAL": return null; // skip
    default: return null;
  }
}

export class SecurityHubFindingsScanner implements Scanner {
  readonly moduleName = "security_hub_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(SecurityHubClient, region, ctx.credentials);
      let nextToken: string | undefined;

      do {
        const resp = await client.send(
          new GetFindingsCommand({
            Filters: {
              WorkflowStatus: [
                { Value: "NEW", Comparison: "EQUALS" },
                { Value: "NOTIFIED", Comparison: "EQUALS" },
              ],
              RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
            },
            MaxResults: 100,
            NextToken: nextToken,
          }),
        );

        const shFindings = resp.Findings ?? [];
        resourcesScanned += shFindings.length;

        for (const f of shFindings) {
          const severityLabel = f.Severity?.Label ?? "INFORMATIONAL";
          const score = shSeverityToScore(severityLabel);
          if (score === null) continue; // skip INFORMATIONAL

          const severity = severityFromScore(score);
          const resourceId = f.Resources?.[0]?.Id ?? "unknown";
          const resourceType = f.Resources?.[0]?.Type ?? "AWS::Unknown";
          const resourceArn = resourceId.startsWith("arn:")
            ? resourceId
            : `arn:${partition}:securityhub:${region}:${accountId}:finding/${f.Id ?? "unknown"}`;

          const remediationSteps: string[] = [];
          const title = f.Title ?? "Security Hub Finding";

          // Check if Title is actually informative or just a KB/CVE number
          if (/^KB\d+$/.test(title)) {
            remediationSteps.push(`Install Windows patch ${title} via WSUS or SSM Patch Manager`);
            remediationSteps.push(`Microsoft KB article: https://support.microsoft.com/help/${title}`);
          } else if (/^CVE-/.test(title)) {
            remediationSteps.push(`Fix vulnerability ${title}: update affected software to patched version`);
          } else {
            remediationSteps.push(title);
          }

          // Add documentation URL if available and useful
          if (f.Remediation?.Recommendation?.Url) {
            remediationSteps.push(`Documentation: ${f.Remediation.Recommendation.Url}`);
          }

          // Add Recommendation.Text only if it's not generic
          const recText = f.Remediation?.Recommendation?.Text ?? "";
          if (recText && !["See References", "None Provided", ""].includes(recText.trim())) {
            remediationSteps.push(recText);
          }

          findings.push({
            severity,
            title: f.Title ?? "Security Hub Finding",
            resourceType,
            resourceId,
            resourceArn,
            region: f.Region ?? region,
            description: f.Description ?? f.Title ?? "No description",
            impact: `Source: ${f.ProductName ?? "Security Hub"} (${f.GeneratorId ?? "unknown"})`,
            riskScore: score,
            remediationSteps,
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: f.AwsAccountId ?? accountId,
          });
        }

        nextToken = resp.NextToken;
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
      const isNotEnabled =
        (err instanceof Error && err.name === "InvalidAccessException") ||
        msg.includes("not subscribed") ||
        msg.includes("not enabled");

      if (isNotEnabled) {
        warnings.push("Security Hub is not enabled in this region. Enable it to aggregate security findings.");
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
        error: `Security Hub findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

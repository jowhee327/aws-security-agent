import {
  SupportClient,
  DescribeTrustedAdvisorChecksCommand,
  DescribeTrustedAdvisorCheckResultCommand,
} from "@aws-sdk/client-support";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function taStatusToScore(status: string): number | null {
  switch (status) {
    case "error": return 8.0;      // RED = action required
    case "warning": return 5.5;    // YELLOW = investigation recommended
    case "ok": return null;        // GREEN = no issue
    case "not_available": return null;
    default: return null;
  }
}

export class TrustedAdvisorFindingsScanner implements Scanner {
  readonly moduleName = "trusted_advisor_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      // Trusted Advisor API endpoint: cn-north-1 for China, us-east-1 for standard
      const supportRegion = region.startsWith("cn-") ? "cn-north-1" : "us-east-1";
      const clientConfig: any = { region: supportRegion };
      if (ctx.credentials) clientConfig.credentials = ctx.credentials;
      const client = new SupportClient(clientConfig);

      // Step 1: List security checks
      const checksResp = await client.send(
        new DescribeTrustedAdvisorChecksCommand({ language: "en" }),
      );
      const allChecks = checksResp.checks ?? [];
      const securityChecks = allChecks.filter((c) => c.category === "security");

      if (securityChecks.length === 0) {
        warnings.push("No Trusted Advisor security checks found.");
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

      // Step 2: Get results for each security check
      for (const check of securityChecks) {
        if (!check.id) continue;

        try {
          const resultResp = await client.send(
            new DescribeTrustedAdvisorCheckResultCommand({
              checkId: check.id,
            }),
          );

          const result = resultResp.result;
          if (!result) continue;

          const status = result.status ?? "not_available";
          const score = taStatusToScore(status);

          resourcesScanned++;

          if (score === null) continue; // ok or not_available — skip

          // Map flagged resources to findings
          const flaggedResources = result.flaggedResources ?? [];

          if (flaggedResources.length === 0) {
            // Check-level finding without specific resources
            const severity = severityFromScore(score);
            findings.push({
              severity,
              title: `[Trusted Advisor] ${check.name ?? "Security Check"}`,
              resourceType: "AWS::TrustedAdvisor::Check",
              resourceId: check.id,
              resourceArn: `arn:${partition}:trustedadvisor:${region}:${accountId}:check/${check.id}`,
              region,
              description: check.description ?? check.name ?? "Security check flagged",
              impact: `Trusted Advisor status: ${status}`,
              riskScore: score,
              remediationSteps: [
                "Review this Trusted Advisor check in the AWS console.",
                "Follow the recommended actions to resolve the flagged issue.",
              ],
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId,
            });
            continue;
          }

          // Create findings for flagged resources (limit to first 25 per check)
          const metadata = check.metadata ?? [];
          for (const fr of flaggedResources.slice(0, 25)) {
            if (fr.isSuppressed) continue;

            const severity = severityFromScore(score);
            const resourceMeta = fr.metadata ?? [];

            // Try to extract resource ID from metadata
            const resourceIdIdx = metadata.indexOf("Resource ID");
            const regionIdx = metadata.indexOf("Region");
            const flaggedResourceId = resourceIdIdx >= 0 && resourceMeta[resourceIdIdx]
              ? resourceMeta[resourceIdIdx]
              : fr.resourceId ?? "unknown";
            const flaggedRegion = regionIdx >= 0 && resourceMeta[regionIdx]
              ? resourceMeta[regionIdx]
              : region;

            findings.push({
              severity,
              title: `[Trusted Advisor] ${check.name ?? "Security Check"}: ${flaggedResourceId}`,
              resourceType: "AWS::TrustedAdvisor::FlaggedResource",
              resourceId: flaggedResourceId,
              resourceArn: `arn:${partition}:trustedadvisor:${flaggedRegion}:${accountId}:check/${check.id}/${fr.resourceId ?? "unknown"}`,
              region: flaggedRegion,
              description: `${check.name}: ${resourceMeta.join(" | ")}`,
              impact: `Trusted Advisor status: ${status} — ${check.name ?? "security check"}`,
              riskScore: score,
              remediationSteps: [
                `Review Trusted Advisor check: ${check.name}`,
                "Follow the recommended actions in the AWS Trusted Advisor console.",
              ],
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId,
            });
          }
        } catch (checkErr) {
          const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
          warnings.push(`Trusted Advisor check ${check.name ?? check.id} failed: ${checkMsg}`);
        }
      }

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
      const isSubscriptionRequired =
        msg.includes("SubscriptionRequiredException") ||
        msg.includes("subscription") ||
        msg.includes("AWS Premium Support") ||
        (err instanceof Error && err.name === "SubscriptionRequiredException");

      if (isSubscriptionRequired) {
        warnings.push("Trusted Advisor requires AWS Business or Enterprise Support plan. Skipping.");
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
        error: `Trusted Advisor scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

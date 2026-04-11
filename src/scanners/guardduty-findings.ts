import {
  GuardDutyClient,
  ListDetectorsCommand,
  ListFindingsCommand,
  GetFindingsCommand,
} from "@aws-sdk/client-guardduty";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function gdSeverityToScore(severity: number): number {
  if (severity >= 7.0) return 8.0;  // HIGH
  if (severity >= 4.0) return 5.5;  // MEDIUM
  return 3.0;                        // LOW
}

export class GuardDutyFindingsScanner implements Scanner {
  readonly moduleName = "guardduty_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(GuardDutyClient, region, ctx.credentials);

      // Step 1: Get detector ID
      const detectorsResp = await client.send(new ListDetectorsCommand({}));
      const detectorIds = detectorsResp.DetectorIds ?? [];

      if (detectorIds.length === 0) {
        warnings.push("GuardDuty is not enabled in this region (no detectors found).");
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

      const detectorId = detectorIds[0];

      // Step 2: List finding IDs (not archived)
      let nextToken: string | undefined;
      const findingIds: string[] = [];

      do {
        const listResp = await client.send(
          new ListFindingsCommand({
            DetectorId: detectorId,
            FindingCriteria: {
              Criterion: {
                "service.archived": {
                  Eq: ["false"],
                },
              },
            },
            MaxResults: 50,
            NextToken: nextToken,
          }),
        );
        findingIds.push(...(listResp.FindingIds ?? []));
        nextToken = listResp.NextToken;
      } while (nextToken);

      resourcesScanned = findingIds.length;

      if (findingIds.length === 0) {
        return {
          module: this.moduleName,
          status: "success",
          warnings: warnings.length > 0 ? warnings : undefined,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      // Step 3: Get finding details (batch of 50)
      for (let i = 0; i < findingIds.length; i += 50) {
        const batch = findingIds.slice(i, i + 50);
        const detailsResp = await client.send(
          new GetFindingsCommand({
            DetectorId: detectorId,
            FindingIds: batch,
          }),
        );

        for (const gdf of detailsResp.Findings ?? []) {
          const gdSeverity = gdf.Severity ?? 0;
          const score = gdSeverityToScore(gdSeverity);
          const severity = severityFromScore(score);

          const resourceType = gdf.Resource?.ResourceType ?? "AWS::Unknown";
          const resourceId = gdf.Resource?.InstanceDetails?.InstanceId
            ?? gdf.Resource?.AccessKeyDetails?.AccessKeyId
            ?? gdf.Arn
            ?? "unknown";
          const resourceArn = gdf.Arn
            ?? `arn:${partition}:guardduty:${region}:${accountId}:detector/${detectorId}/finding/${gdf.Id ?? "unknown"}`;

          findings.push({
            severity,
            title: `[GuardDuty] ${gdf.Title ?? gdf.Type ?? "Finding"}`,
            resourceType,
            resourceId,
            resourceArn,
            region: gdf.Region ?? region,
            description: gdf.Description ?? gdf.Title ?? "No description",
            impact: `GuardDuty threat type: ${gdf.Type ?? "unknown"} (severity ${gdSeverity})`,
            riskScore: score,
            remediationSteps: [
              "Review the finding in the Amazon GuardDuty console.",
              `Finding type: ${gdf.Type ?? "unknown"}`,
              "Follow the recommended remediation in the GuardDuty documentation.",
            ],
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: gdf.AccountId ?? accountId,
          });
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
      return {
        module: this.moduleName,
        status: "error",
        error: `GuardDuty findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

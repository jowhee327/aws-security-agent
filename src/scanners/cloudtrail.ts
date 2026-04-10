import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  type Trail,
} from "@aws-sdk/client-cloudtrail";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function makeFinding(opts: {
  riskScore: number;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  remediationSteps: string[];
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}

export class CloudTrailScanner implements Scanner {
  readonly moduleName = "cloudtrail";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(CloudTrailClient, region);

      const resp = await client.send(new DescribeTrailsCommand({}));
      const trails = resp.trailList ?? [];

      if (trails.length === 0) {
        findings.push(
          makeFinding({
            riskScore: 9.5,
            title: "No CloudTrail trails configured",
            resourceType: "AWS::CloudTrail::Trail",
            resourceId: "none",
            resourceArn: "N/A",
            region,
            description:
              "No CloudTrail trails are configured in this account.",
            impact:
              "No API activity is being logged. Security incidents cannot be detected or investigated.",
            remediationSteps: [
              "Create a CloudTrail trail that logs to an S3 bucket.",
              "Enable multi-region logging.",
              "Enable log file validation.",
              "Configure CloudWatch Logs integration for real-time alerting.",
            ],
          }),
        );

        return {
          module: this.moduleName,
          status: "success",
          warnings: warnings.length > 0 ? warnings : undefined,
          resourcesScanned: 0,
          findingsCount: findings.length,
          scanTimeMs: Date.now() - startMs,
          findings,
        };
      }

      for (const trail of trails) {
        const trailName = trail.Name ?? "unknown";
        const trailArn =
          trail.TrailARN ??
          `arn:${partition}:cloudtrail:${region}:${accountId}:trail/${trailName}`;

        // Not multi-region
        if (!trail.IsMultiRegionTrail) {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: `CloudTrail trail ${trailName} is not multi-region`,
              resourceType: "AWS::CloudTrail::Trail",
              resourceId: trailName,
              resourceArn: trailArn,
              region,
              description: `Trail "${trailName}" only logs events in its home region.`,
              impact:
                "API activity in other regions will not be captured, leaving blind spots for incident response.",
              remediationSteps: [
                "Update the trail to enable multi-region logging.",
                "Alternatively, create trails in all active regions.",
              ],
            }),
          );
        }

        // No log file validation
        if (!trail.LogFileValidationEnabled) {
          findings.push(
            makeFinding({
              riskScore: 6.0,
              title: `CloudTrail trail ${trailName} has no log file validation`,
              resourceType: "AWS::CloudTrail::Trail",
              resourceId: trailName,
              resourceArn: trailArn,
              region,
              description: `Trail "${trailName}" does not have log file validation enabled.`,
              impact:
                "Log files could be modified or deleted without detection, undermining audit integrity.",
              remediationSteps: [
                "Enable log file validation on the trail.",
                "This creates digest files that can be used to verify log integrity.",
              ],
            }),
          );
        }

        // No CloudWatch Logs
        if (!trail.CloudWatchLogsLogGroupArn) {
          findings.push(
            makeFinding({
              riskScore: 5.5,
              title: `CloudTrail trail ${trailName} not integrated with CloudWatch Logs`,
              resourceType: "AWS::CloudTrail::Trail",
              resourceId: trailName,
              resourceArn: trailArn,
              region,
              description: `Trail "${trailName}" is not configured to deliver logs to CloudWatch Logs.`,
              impact:
                "Real-time monitoring and alerting on API activity is not possible without CloudWatch Logs integration.",
              remediationSteps: [
                "Configure the trail to deliver logs to a CloudWatch Logs log group.",
                "Create metric filters and alarms for critical security events.",
              ],
            }),
          );
        }

        // Check event selectors for management events
        try {
          const esResp = await client.send(
            new GetEventSelectorsCommand({ TrailName: trailArn }),
          );

          let logsManagementEvents = false;

          // Check classic event selectors
          for (const es of esResp.EventSelectors ?? []) {
            if (es.IncludeManagementEvents !== false) {
              logsManagementEvents = true;
              break;
            }
          }

          // Check advanced event selectors
          if (!logsManagementEvents && esResp.AdvancedEventSelectors) {
            for (const aes of esResp.AdvancedEventSelectors) {
              for (const fs of aes.FieldSelectors ?? []) {
                if (
                  fs.Field === "eventCategory" &&
                  fs.Equals?.includes("Management")
                ) {
                  logsManagementEvents = true;
                  break;
                }
              }
              if (logsManagementEvents) break;
            }
          }

          if (!logsManagementEvents) {
            findings.push(
              makeFinding({
                riskScore: 7.0,
                title: `CloudTrail trail ${trailName} is not logging management events`,
                resourceType: "AWS::CloudTrail::Trail",
                resourceId: trailName,
                resourceArn: trailArn,
                region,
                description: `Trail "${trailName}" is not configured to log management events.`,
                impact:
                  "Critical API calls like IAM changes, security group modifications, and resource creation/deletion are not being recorded.",
                remediationSteps: [
                  "Update event selectors to include management events.",
                  "Enable logging for both read and write management events.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Event selector check failed for trail ${trailName}: ${msg}`);
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: trails.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

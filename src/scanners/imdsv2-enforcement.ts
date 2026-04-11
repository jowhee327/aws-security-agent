import {
  EC2Client,
  DescribeInstancesCommand,
  type Instance,
} from "@aws-sdk/client-ec2";
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

export class Imdsv2EnforcementScanner implements Scanner {
  readonly moduleName = "imdsv2_enforcement";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region, ctx.credentials);

      // List all running EC2 instances
      const instances: Instance[] = [];
      let nextToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeInstancesCommand({
            Filters: [{ Name: "instance-state-name", Values: ["running"] }],
            NextToken: nextToken,
          }),
        );
        if (resp.Reservations) {
          for (const reservation of resp.Reservations) {
            if (reservation.Instances) {
              instances.push(...reservation.Instances);
            }
          }
        }
        nextToken = resp.NextToken;
      } while (nextToken);

      for (const instance of instances) {
        const instanceId = instance.InstanceId ?? "unknown";
        const instanceType = instance.InstanceType ?? "unknown";
        const state = instance.State?.Name ?? "unknown";
        const httpTokens = instance.MetadataOptions?.HttpTokens ?? "unknown";
        const hopLimit = instance.MetadataOptions?.HttpPutResponseHopLimit ?? 1;
        const instanceArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instanceId}`;

        if (httpTokens !== "required") {
          const description = [
            `EC2 instance ${instanceId} (type: ${instanceType}, state: ${state}) has HttpTokens set to "${httpTokens}".`,
            `IMDSv1 is accessible, allowing unauthenticated metadata requests.`,
          ];
          if (hopLimit > 1) {
            description.push(`HttpPutResponseHopLimit is ${hopLimit} (>1), which may allow containers to reach IMDS.`);
          }

          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: `EC2 instance ${instanceId} does not enforce IMDSv2`,
              resourceType: "AWS::EC2::Instance",
              resourceId: instanceId,
              resourceArn: instanceArn,
              region,
              description: description.join(" "),
              impact: "IMDSv1 allows attackers to steal IAM role credentials via SSRF attacks",
              remediationSteps: [
                "Enforce IMDSv2 by setting HttpTokens to 'required'.",
                "Run: aws ec2 modify-instance-metadata-options --instance-id " + instanceId + " --http-tokens required --http-endpoint enabled",
                "Set HttpPutResponseHopLimit to 1 unless running containers that need metadata access.",
                "Update launch templates and Auto Scaling groups to enforce IMDSv2 for new instances.",
              ],
            }),
          );
        } else if (hopLimit > 1) {
          // IMDSv2 enforced but hop limit is elevated — informational warning
          warnings.push(
            `Instance ${instanceId} enforces IMDSv2 but HttpPutResponseHopLimit is ${hopLimit} (>1). Verify this is intentional for containerized workloads.`,
          );
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: instances.length,
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

import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  type Trail,
} from "@aws-sdk/client-cloudtrail";
import {
  EC2Client,
  DescribeFlowLogsCommand,
  DescribeVpcsCommand,
  type Vpc,
} from "@aws-sdk/client-ec2";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLoggingCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeLoadBalancerAttributesCommand,
  type LoadBalancer,
} from "@aws-sdk/client-elastic-load-balancing-v2";
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

export class LogIntegrityScanner implements Scanner {
  readonly moduleName = "log_integrity_audit";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      // --- CloudTrail checks ---
      try {
        const ctClient = createClient(CloudTrailClient, region);
        const trailsResp = await ctClient.send(new DescribeTrailsCommand({}));
        const trails: Trail[] = trailsResp.trailList ?? [];
        resourcesScanned += trails.length;

        const hasMultiRegionTrail = trails.some(
          (t) => t.IsMultiRegionTrail && t.HomeRegion === region,
        );

        if (!hasMultiRegionTrail) {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: "No multi-region CloudTrail trail configured",
              resourceType: "AWS::CloudTrail::Trail",
              resourceId: "cloudtrail-multi-region",
              resourceArn: `arn:${partition}:cloudtrail:${region}:${accountId}:trail/*`,
              region,
              description:
                "No CloudTrail trail is configured to log events across all AWS regions.",
              impact:
                "API activity in other regions will not be logged, creating blind spots for security monitoring and incident investigation.",
              remediationSteps: [
                "Create a CloudTrail trail with IsMultiRegionTrail enabled.",
                "Ensure the trail logs management events at minimum.",
                "Configure the trail to deliver logs to a centralized S3 bucket.",
              ],
            }),
          );
        }

        for (const trail of trails) {
          if (trail.HomeRegion && trail.HomeRegion !== region) continue;
          const trailName = trail.Name ?? "unknown";
          const trailArn =
            trail.TrailARN ??
            `arn:${partition}:cloudtrail:${region}:${accountId}:trail/${trailName}`;

          // Log file validation
          if (!trail.LogFileValidationEnabled) {
            findings.push(
              makeFinding({
                riskScore: 6.0,
                title: `CloudTrail trail ${trailName} has no log file validation`,
                resourceType: "AWS::CloudTrail::Trail",
                resourceId: trailName,
                resourceArn: trailArn,
                region,
                description: `Trail "${trailName}" does not have log file validation enabled, making it impossible to verify log integrity.`,
                impact:
                  "Log files could be tampered with or deleted without detection, undermining forensic investigations.",
                remediationSteps: [
                  "Enable log file validation on the trail.",
                  "Use AWS CLI `cloudtrail validate-logs` to verify existing logs.",
                ],
              }),
            );
          }

          // CloudWatch Logs integration
          if (!trail.CloudWatchLogsLogGroupArn) {
            findings.push(
              makeFinding({
                riskScore: 5.5,
                title: `CloudTrail trail ${trailName} is not integrated with CloudWatch Logs`,
                resourceType: "AWS::CloudTrail::Trail",
                resourceId: trailName,
                resourceArn: trailArn,
                region,
                description: `Trail "${trailName}" does not deliver logs to CloudWatch Logs for real-time monitoring and alerting.`,
                impact:
                  "No real-time alerting on suspicious API activity. Security events can only be detected via delayed S3 log analysis.",
                remediationSteps: [
                  "Configure CloudWatch Logs integration for the trail.",
                  "Create metric filters and alarms for critical API calls (e.g., unauthorized access, root login).",
                ],
              }),
            );
          }

          // Check if trail is actually logging
          try {
            const statusResp = await ctClient.send(
              new GetTrailStatusCommand({ Name: trailArn }),
            );
            if (!statusResp.IsLogging) {
              findings.push(
                makeFinding({
                  riskScore: 8.0,
                  title: `CloudTrail trail ${trailName} is not actively logging`,
                  resourceType: "AWS::CloudTrail::Trail",
                  resourceId: trailName,
                  resourceArn: trailArn,
                  region,
                  description: `Trail "${trailName}" exists but is not currently logging API activity.`,
                  impact:
                    "No API activity is being recorded, leaving the account without audit trail coverage.",
                  remediationSteps: [
                    "Start logging on the trail immediately.",
                    "Investigate why logging was stopped (potential attacker action).",
                    "Set up CloudWatch alarms for StopLogging events.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Could not get trail status for ${trailName}: ${msg}`);
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`CloudTrail audit failed: ${msg}`);
      }

      // --- VPC Flow Logs checks ---
      try {
        const ec2Client = createClient(EC2Client, region);

        const vpcs: Vpc[] = [];
        let nextToken: string | undefined;
        do {
          const resp = await ec2Client.send(
            new DescribeVpcsCommand({ NextToken: nextToken }),
          );
          if (resp.Vpcs) vpcs.push(...resp.Vpcs);
          nextToken = resp.NextToken;
        } while (nextToken);
        resourcesScanned += vpcs.length;

        // Get all flow logs for VPCs
        const flowLogsResp = await ec2Client.send(
          new DescribeFlowLogsCommand({
            Filter: [{ Name: "resource-type", Values: ["VPC"] }],
          }),
        );
        const flowLogVpcIds = new Set(
          (flowLogsResp.FlowLogs ?? []).map((fl) => fl.ResourceId),
        );

        for (const vpc of vpcs) {
          const vpcId = vpc.VpcId ?? "unknown";
          if (!flowLogVpcIds.has(vpcId)) {
            const vpcArn = `arn:${partition}:ec2:${region}:${accountId}:vpc/${vpcId}`;
            findings.push(
              makeFinding({
                riskScore: 7.0,
                title: `VPC ${vpcId} has no Flow Logs enabled`,
                resourceType: "AWS::EC2::VPC",
                resourceId: vpcId,
                resourceArn: vpcArn,
                region,
                description: `VPC "${vpcId}" does not have VPC Flow Logs configured, leaving network traffic unmonitored.`,
                impact:
                  "No visibility into accepted/rejected network traffic, making it difficult to detect lateral movement, data exfiltration, or unauthorized access.",
                remediationSteps: [
                  "Enable VPC Flow Logs for this VPC (at minimum REJECT traffic).",
                  "Deliver logs to CloudWatch Logs or S3 for analysis.",
                  "Consider enabling flow logs at the VPC level rather than individual ENIs.",
                ],
              }),
            );
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`VPC Flow Logs audit failed: ${msg}`);
      }

      // --- S3 access logging checks ---
      try {
        const s3Client = createClient(S3Client, region);
        const listResp = await s3Client.send(new ListBucketsCommand({}));
        const buckets = listResp.Buckets ?? [];

        for (const bucket of buckets) {
          const name = bucket.Name ?? "unknown";
          const arn = `arn:${partition}:s3:::${name}`;

          // Determine bucket region
          let bucketRegion = region;
          try {
            const locResp = await s3Client.send(
              new GetBucketLocationCommand({ Bucket: name }),
            );
            bucketRegion =
              String(locResp.LocationConstraint ?? "") || "us-east-1";
          } catch {
            // Use default region
          }

          const bucketClient =
            bucketRegion === region
              ? s3Client
              : createClient(S3Client, bucketRegion);

          resourcesScanned++;
          try {
            const loggingResp = await bucketClient.send(
              new GetBucketLoggingCommand({ Bucket: name }),
            );
            if (!loggingResp.LoggingEnabled) {
              findings.push(
                makeFinding({
                  riskScore: 5.0,
                  title: `S3 bucket ${name} has no access logging`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `Bucket "${name}" does not have server access logging enabled.`,
                  impact:
                    "No visibility into who is accessing the bucket, making it difficult to detect unauthorized data access or exfiltration.",
                  remediationSteps: [
                    "Enable server access logging on the bucket.",
                    "Direct logs to a dedicated logging bucket.",
                    "Consider using CloudTrail S3 data events for more detailed logging.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`S3 access logging check for ${name} failed: ${msg}`);
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 access logging audit failed: ${msg}`);
      }

      // --- ELB access logging checks ---
      try {
        const elbClient = createClient(
          ElasticLoadBalancingV2Client,
          region,
        );
        const loadBalancers: LoadBalancer[] = [];
        let lbMarker: string | undefined;
        do {
          const resp = await elbClient.send(
            new DescribeLoadBalancersCommand({ Marker: lbMarker }),
          );
          if (resp.LoadBalancers) loadBalancers.push(...resp.LoadBalancers);
          lbMarker = resp.NextMarker;
        } while (lbMarker);

        resourcesScanned += loadBalancers.length;

        for (const lb of loadBalancers) {
          const lbName = lb.LoadBalancerName ?? "unknown";
          const lbArn = lb.LoadBalancerArn ?? "unknown";

          try {
            const attrsResp = await elbClient.send(
              new DescribeLoadBalancerAttributesCommand({
                LoadBalancerArn: lbArn,
              }),
            );
            const accessLogEnabled = (attrsResp.Attributes ?? []).find(
              (a) => a.Key === "access_logs.s3.enabled",
            );
            if (!accessLogEnabled || accessLogEnabled.Value !== "true") {
              findings.push(
                makeFinding({
                  riskScore: 5.5,
                  title: `ELB ${lbName} has no access logging enabled`,
                  resourceType:
                    "AWS::ElasticLoadBalancingV2::LoadBalancer",
                  resourceId: lbName,
                  resourceArn: lbArn,
                  region,
                  description: `Load balancer "${lbName}" does not have access logging enabled.`,
                  impact:
                    "No visibility into request patterns, client IPs, or error rates — limits incident investigation and abuse detection.",
                  remediationSteps: [
                    "Enable access logging on the load balancer.",
                    "Configure an S3 bucket for log delivery.",
                    "Ensure the S3 bucket policy allows ELB to write logs.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(
              `ELB access logging check for ${lbName} failed: ${msg}`,
            );
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`ELB access logging audit failed: ${msg}`);
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

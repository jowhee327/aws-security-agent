import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeFlowLogsCommand,
} from "@aws-sdk/client-ec2";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLoggingCommand,
} from "@aws-sdk/client-s3";
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeLoadBalancerAttributesCommand,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} from "@aws-sdk/client-cloudtrail";
import {
  RDSClient,
  DescribeDBInstancesCommand,
} from "@aws-sdk/client-rds";
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
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

export class LogAuditScanner implements Scanner {
  readonly moduleName = "log_audit";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    // 1. VPC Flow Logs
    try {
      const ec2 = createClient(EC2Client, region, ctx.credentials);
      const vpcIds: string[] = [];
      let vpcToken: string | undefined;
      do {
        const resp = await ec2.send(new DescribeVpcsCommand({ NextToken: vpcToken }));
        for (const vpc of resp.Vpcs ?? []) {
          if (vpc.VpcId) vpcIds.push(vpc.VpcId);
        }
        vpcToken = resp.NextToken;
      } while (vpcToken);

      resourcesScanned += vpcIds.length;

      for (const vpcId of vpcIds) {
        const fl = await ec2.send(
          new DescribeFlowLogsCommand({
            Filter: [{ Name: "resource-id", Values: [vpcId] }],
          }),
        );
        const logs = fl.FlowLogs ?? [];
        if (logs.length === 0) {
          findings.push(
            makeFinding({
              riskScore: 5.5,
              title: `VPC ${vpcId} has no Flow Logs enabled`,
              resourceType: "AWS::EC2::VPC",
              resourceId: vpcId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:vpc/${vpcId}`,
              region,
              description: `VPC ${vpcId} does not have any VPC Flow Logs configured. Network traffic is not being logged.`,
              impact: "Cannot detect anomalous network activity, lateral movement, or data exfiltration attempts",
              remediationSteps: [
                `Enable VPC Flow Logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids ${vpcId} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs`,
                "Consider logging to S3 for cost-effective long-term retention.",
              ],
            }),
          );
        } else {
          const hasActive = logs.some((l) => l.FlowLogStatus === "ACTIVE");
          if (!hasActive) {
            findings.push(
              makeFinding({
                riskScore: 3.0,
                title: `VPC ${vpcId} Flow Logs exist but none are ACTIVE`,
                resourceType: "AWS::EC2::VPC",
                resourceId: vpcId,
                resourceArn: `arn:${partition}:ec2:${region}:${accountId}:vpc/${vpcId}`,
                region,
                description: `VPC ${vpcId} has ${logs.length} Flow Log(s) but none have ACTIVE status. Logs may not be recording.`,
                impact: "Flow Logs are configured but not recording traffic — potential monitoring gap",
                remediationSteps: [
                  "Check Flow Log status and resolve any delivery errors.",
                  "Verify IAM role permissions for CloudWatch Logs or S3 delivery.",
                ],
              }),
            );
          }
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("UnauthorizedAccess") || msg.includes("not authorized")) {
        warnings.push(`VPC Flow Logs check skipped: ${msg}`);
      } else {
        warnings.push(`VPC Flow Logs check failed: ${msg}`);
      }
    }

    // 2. S3 Access Logging
    try {
      const s3 = createClient(S3Client, region, ctx.credentials);
      const bucketsResp = await s3.send(new ListBucketsCommand({}));
      const allBuckets = bucketsResp.Buckets ?? [];
      const buckets = allBuckets.slice(0, 50);

      if (allBuckets.length > 50) {
        warnings.push(`S3 access logging check limited to first 50 of ${allBuckets.length} buckets to avoid throttling.`);
      }

      resourcesScanned += buckets.length;

      for (const bucket of buckets) {
        const name = bucket.Name ?? "unknown";
        try {
          const logging = await s3.send(new GetBucketLoggingCommand({ Bucket: name }));
          if (!logging.LoggingEnabled) {
            findings.push(
              makeFinding({
                riskScore: 3.0,
                title: `S3 bucket ${name} does not have server access logging enabled`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: `arn:${partition}:s3:::${name}`,
                region,
                description: `S3 bucket "${name}" does not have server access logging configured. Access requests are not being recorded.`,
                impact: "Cannot audit who accessed objects in this bucket or detect unauthorized access patterns",
                remediationSteps: [
                  `Enable server access logging: aws s3api put-bucket-logging --bucket ${name} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>","TargetPrefix":"${name}/"}}'`,
                  "Alternatively, use S3 CloudTrail data events for more detailed logging.",
                ],
              }),
            );
          }
        } catch (bucketErr) {
          const bucketMsg = bucketErr instanceof Error ? bucketErr.message : String(bucketErr);
          warnings.push(`S3 bucket ${name} logging check failed: ${bucketMsg}`);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("not authorized")) {
        warnings.push(`S3 access logging check skipped: ${msg}`);
      } else {
        warnings.push(`S3 access logging check failed: ${msg}`);
      }
    }

    // 3. ELB Access Logging
    try {
      const elbv2 = createClient(ElasticLoadBalancingV2Client, region, ctx.credentials);
      const lbResp = await elbv2.send(new DescribeLoadBalancersCommand({}));
      const loadBalancers = lbResp.LoadBalancers ?? [];

      resourcesScanned += loadBalancers.length;

      for (const lb of loadBalancers) {
        const lbArn = lb.LoadBalancerArn ?? "unknown";
        const lbName = lb.LoadBalancerName ?? "unknown";

        try {
          const attrsResp = await elbv2.send(
            new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: lbArn }),
          );
          const attrs = attrsResp.Attributes ?? [];
          const accessLogsAttr = attrs.find((a) => a.Key === "access_logs.s3.enabled");
          const logsEnabled = accessLogsAttr?.Value === "true";

          if (!logsEnabled) {
            findings.push(
              makeFinding({
                riskScore: 5.0,
                title: `Load balancer ${lbName} does not have access logging enabled`,
                resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
                resourceId: lbName,
                resourceArn: lbArn,
                region,
                description: `Load balancer "${lbName}" (${lb.Type ?? "unknown"}) does not have access logs enabled to S3.`,
                impact: "Cannot audit request patterns, detect anomalous traffic, or troubleshoot connectivity issues",
                remediationSteps: [
                  `Enable access logging: aws elbv2 modify-load-balancer-attributes --load-balancer-arn ${lbArn} --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<log-bucket>`,
                  "Ensure the S3 bucket policy allows ELB to write logs.",
                ],
              }),
            );
          }
        } catch (lbErr) {
          const lbMsg = lbErr instanceof Error ? lbErr.message : String(lbErr);
          warnings.push(`ELB ${lbName} attribute check failed: ${lbMsg}`);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("not authorized")) {
        warnings.push(`ELB access logging check skipped: ${msg}`);
      } else {
        warnings.push(`ELB access logging check failed: ${msg}`);
      }
    }

    // 4. CloudTrail — Multi-region trail with active logging
    try {
      const ct = createClient(CloudTrailClient, region, ctx.credentials);
      const trailsResp = await ct.send(new DescribeTrailsCommand({}));
      const trails = trailsResp.trailList ?? [];
      const multiRegionTrails = trails.filter((t) => t.IsMultiRegionTrail);

      resourcesScanned += trails.length;

      if (multiRegionTrails.length === 0) {
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "No multi-region CloudTrail trail configured",
            resourceType: "AWS::CloudTrail::Trail",
            resourceId: "none",
            resourceArn: `arn:${partition}:cloudtrail:${region}:${accountId}:trail/*`,
            region,
            description: `Account ${accountId} has ${trails.length} trail(s) but none are multi-region. API activity in other regions is not being logged.`,
            impact: "Attackers can operate in non-monitored regions without detection — critical audit gap",
            remediationSteps: [
              "Create a multi-region trail: aws cloudtrail create-trail --name my-multi-region-trail --s3-bucket-name <bucket> --is-multi-region-trail",
              "Enable the trail: aws cloudtrail start-logging --name my-multi-region-trail",
              "Consider enabling CloudTrail data events for S3 and Lambda.",
            ],
          }),
        );
      } else {
        let anyLogging = false;
        for (const trail of multiRegionTrails) {
          const trailArn = trail.TrailARN ?? "unknown";
          const trailName = trail.Name ?? "unknown";
          try {
            const status = await ct.send(new GetTrailStatusCommand({ Name: trailArn }));
            if (status.IsLogging) {
              anyLogging = true;
            } else {
              findings.push(
                makeFinding({
                  riskScore: 7.0,
                  title: `CloudTrail trail ${trailName} is not logging`,
                  resourceType: "AWS::CloudTrail::Trail",
                  resourceId: trailName,
                  resourceArn: trailArn,
                  region,
                  description: `Multi-region CloudTrail trail "${trailName}" exists but IsLogging is false. API activity is not being recorded.`,
                  impact: "CloudTrail trail exists but is disabled — no API audit trail is being collected",
                  remediationSteps: [
                    `Start logging: aws cloudtrail start-logging --name ${trailName}`,
                    "Investigate why logging was stopped — could indicate tampering.",
                  ],
                }),
              );
            }
          } catch (statusErr) {
            const statusMsg = statusErr instanceof Error ? statusErr.message : String(statusErr);
            warnings.push(`CloudTrail trail ${trailName} status check failed: ${statusMsg}`);
          }
        }
        if (!anyLogging && findings.filter((f) => f.resourceType === "AWS::CloudTrail::Trail").length === multiRegionTrails.length) {
          // All multi-region trails are not logging — already covered by individual findings
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("not authorized")) {
        warnings.push(`CloudTrail check skipped: ${msg}`);
      } else {
        warnings.push(`CloudTrail check failed: ${msg}`);
      }
    }

    // 5. RDS Audit Logging
    try {
      const rds = createClient(RDSClient, region, ctx.credentials);
      let marker: string | undefined;
      const dbInstances: Array<{
        id: string;
        arn: string;
        engine: string;
        exports: string[];
      }> = [];

      do {
        const resp = await rds.send(new DescribeDBInstancesCommand({ Marker: marker }));
        for (const db of resp.DBInstances ?? []) {
          dbInstances.push({
            id: db.DBInstanceIdentifier ?? "unknown",
            arn: db.DBInstanceArn ?? `arn:${partition}:rds:${region}:${accountId}:db/${db.DBInstanceIdentifier ?? "unknown"}`,
            engine: (db.Engine ?? "unknown").toLowerCase(),
            exports: db.EnabledCloudwatchLogsExports ?? [],
          });
        }
        marker = resp.Marker;
      } while (marker);

      resourcesScanned += dbInstances.length;

      for (const db of dbInstances) {
        let hasRelevantLogs = false;

        if (db.engine.includes("mysql") || db.engine.includes("mariadb")) {
          hasRelevantLogs = db.exports.some((e) =>
            ["audit", "general", "slowquery"].includes(e),
          );
        } else if (db.engine.includes("postgres")) {
          hasRelevantLogs = db.exports.includes("postgresql");
        } else {
          // For other engines (oracle, sqlserver, etc.), any export counts
          hasRelevantLogs = db.exports.length > 0;
        }

        if (!hasRelevantLogs) {
          findings.push(
            makeFinding({
              riskScore: 3.5,
              title: `RDS instance ${db.id} has no audit logs exported to CloudWatch`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: db.id,
              resourceArn: db.arn,
              region,
              description: `RDS instance "${db.id}" (engine: ${db.engine}) does not publish any relevant logs to CloudWatch Logs. Exports: [${db.exports.join(", ") || "none"}].`,
              impact: "Database activity is not centrally logged — cannot detect suspicious queries or unauthorized access",
              remediationSteps: [
                `Enable CloudWatch log exports: aws rds modify-db-instance --db-instance-identifier ${db.id} --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","general","slowquery"]}'`,
                "For PostgreSQL, export 'postgresql' log type.",
                "Review RDS parameter group to ensure log_statement and log_min_duration_statement are configured.",
              ],
            }),
          );
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("not authorized")) {
        warnings.push(`RDS audit logging check skipped: ${msg}`);
      } else {
        warnings.push(`RDS audit logging check failed: ${msg}`);
      }
    }

    // 6. CloudWatch Log Group Retention
    try {
      const cwl = createClient(CloudWatchLogsClient, region, ctx.credentials);
      let cwToken: string | undefined;
      let totalGroups = 0;
      let noRetentionCount = 0;

      do {
        const resp = await cwl.send(new DescribeLogGroupsCommand({ nextToken: cwToken }));
        for (const lg of resp.logGroups ?? []) {
          totalGroups++;
          if (lg.retentionInDays == null) {
            noRetentionCount++;
          }
        }
        cwToken = resp.nextToken;
      } while (cwToken);

      resourcesScanned += totalGroups;

      if (noRetentionCount > 0) {
        findings.push(
          makeFinding({
            riskScore: 2.0,
            title: `${noRetentionCount} CloudWatch Log Group(s) have no retention policy`,
            resourceType: "AWS::Logs::LogGroup",
            resourceId: `${noRetentionCount}-groups`,
            resourceArn: `arn:${partition}:logs:${region}:${accountId}:log-group:*`,
            region,
            description: `${noRetentionCount} of ${totalGroups} CloudWatch Log Group(s) have no retention policy set (infinite retention). This can lead to unbounded storage costs.`,
            impact: "Unbounded log retention increases storage costs without security benefit for old logs",
            remediationSteps: [
              "Set a retention policy on log groups: aws logs put-retention-policy --log-group-name <name> --retention-in-days 90",
              "Common retention periods: 30 days (dev), 90 days (production), 365 days (compliance).",
              "Review compliance requirements before setting retention.",
            ],
          }),
        );
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("AccessDenied") || msg.includes("not authorized")) {
        warnings.push(`CloudWatch Log Group retention check skipped: ${msg}`);
      } else {
        warnings.push(`CloudWatch Log Group retention check failed: ${msg}`);
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
  }
}

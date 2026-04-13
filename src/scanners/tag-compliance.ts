import {
  EC2Client,
  DescribeInstancesCommand,
  type Instance,
} from "@aws-sdk/client-ec2";
import {
  RDSClient,
  DescribeDBInstancesCommand,
  type DBInstance,
} from "@aws-sdk/client-rds";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const DEFAULT_REQUIRED_TAGS = ["Environment", "Project", "Owner"];

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

function getMissingTags(
  tags: Array<{ Key?: string; Value?: string }>,
  requiredTags: string[],
): string[] {
  const tagKeys = new Set(tags.map((t) => t.Key ?? ""));
  return requiredTags.filter((rt) => !tagKeys.has(rt));
}

export class TagComplianceScanner implements Scanner {
  readonly moduleName = "tag_compliance";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;
    const requiredTags = DEFAULT_REQUIRED_TAGS;

    try {
      // --- EC2 instances ---
      try {
        const ec2Client = createClient(EC2Client, region, ctx.credentials);
        const instances: Instance[] = [];
        let nextToken: string | undefined;
        do {
          const resp = await ec2Client.send(
            new DescribeInstancesCommand({ NextToken: nextToken }),
          );
          for (const res of resp.Reservations ?? []) {
            if (res.Instances) instances.push(...res.Instances);
          }
          nextToken = resp.NextToken;
        } while (nextToken);

        resourcesScanned += instances.length;

        for (const instance of instances) {
          const id = instance.InstanceId ?? "unknown";
          const arn = `arn:${partition}:ec2:${region}:${accountId}:instance/${id}`;
          const tags = instance.Tags ?? [];
          const missing = getMissingTags(tags, requiredTags);

          if (missing.length > 0) {
            findings.push(
              makeFinding({
                riskScore: 4.0,
                title: `EC2 instance ${id} missing required tags: ${missing.join(", ")}`,
                resourceType: "AWS::EC2::Instance",
                resourceId: id,
                resourceArn: arn,
                region,
                description: `EC2 instance "${id}" is missing the following required tags: ${missing.join(", ")}.`,
                impact:
                  "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                remediationSteps: [
                  `Add the missing tags (${missing.join(", ")}) to instance ${id}.`,
                  "Implement AWS Config rules or Tag Policies to enforce tagging.",
                  "Use AWS Tag Editor for bulk tagging operations.",
                ],
              }),
            );
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`EC2 tag compliance check failed: ${msg}`);
      }

      // --- RDS instances ---
      try {
        const rdsClient = createClient(RDSClient, region, ctx.credentials);
        const dbInstances: DBInstance[] = [];
        let marker: string | undefined;
        do {
          const resp = await rdsClient.send(
            new DescribeDBInstancesCommand({ Marker: marker }),
          );
          if (resp.DBInstances) dbInstances.push(...resp.DBInstances);
          marker = resp.Marker;
        } while (marker);

        resourcesScanned += dbInstances.length;

        for (const db of dbInstances) {
          const dbId = db.DBInstanceIdentifier ?? "unknown";
          const dbArn =
            db.DBInstanceArn ??
            `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
          const tags = (db.TagList ?? []).map((t) => ({
            Key: t.Key,
            Value: t.Value,
          }));
          const missing = getMissingTags(tags, requiredTags);

          if (missing.length > 0) {
            findings.push(
              makeFinding({
                riskScore: 4.0,
                title: `RDS instance ${dbId} missing required tags: ${missing.join(", ")}`,
                resourceType: "AWS::RDS::DBInstance",
                resourceId: dbId,
                resourceArn: dbArn,
                region,
                description: `RDS instance "${dbId}" is missing the following required tags: ${missing.join(", ")}.`,
                impact:
                  "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                remediationSteps: [
                  `Add the missing tags (${missing.join(", ")}) to RDS instance ${dbId}.`,
                  "Implement AWS Config rules or Tag Policies to enforce tagging.",
                  "Use AWS Tag Editor for bulk tagging operations.",
                ],
              }),
            );
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`RDS tag compliance check failed: ${msg}`);
      }

      // --- S3 buckets ---
      try {
        const s3Client = createClient(S3Client, region, ctx.credentials);
        const listResp = await s3Client.send(new ListBucketsCommand({}));
        const buckets = listResp.Buckets ?? [];
        resourcesScanned += buckets.length;

        for (const bucket of buckets) {
          const name = bucket.Name ?? "unknown";
          const arn = `arn:${partition}:s3:::${name}`;

          // Resolve the bucket's actual region and create a region-specific client
          let bucketClient: S3Client;
          try {
            const locResp = await s3Client.send(new GetBucketLocationCommand({ Bucket: name }));
            const bucketRegion = locResp.LocationConstraint || "us-east-1";
            bucketClient = bucketRegion === region
              ? s3Client
              : createClient(S3Client, bucketRegion, ctx.credentials);
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name}: could not determine region, skipping: ${msg}`);
            continue;
          }

          try {
            const taggingResp = await bucketClient.send(
              new GetBucketTaggingCommand({ Bucket: name }),
            );
            const tags = (taggingResp.TagSet ?? []).map((t) => ({
              Key: t.Key,
              Value: t.Value,
            }));
            const missing = getMissingTags(tags, requiredTags);

            if (missing.length > 0) {
              findings.push(
                makeFinding({
                  riskScore: 4.0,
                  title: `S3 bucket ${name} missing required tags: ${missing.join(", ")}`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: "global",
                  description: `S3 bucket "${name}" is missing the following required tags: ${missing.join(", ")}.`,
                  impact:
                    "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                  remediationSteps: [
                    `Add the missing tags (${missing.join(", ")}) to bucket ${name}.`,
                    "Implement AWS Config rules or Tag Policies to enforce tagging.",
                    "Use AWS Tag Editor for bulk tagging operations.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            if (
              e instanceof Error &&
              e.name === "NoSuchTagSet"
            ) {
              // No tags at all — all required tags are missing
              findings.push(
                makeFinding({
                  riskScore: 4.0,
                  title: `S3 bucket ${name} missing required tags: ${requiredTags.join(", ")}`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: "global",
                  description: `S3 bucket "${name}" has no tags configured. Missing all required tags: ${requiredTags.join(", ")}.`,
                  impact:
                    "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                  remediationSteps: [
                    `Add the required tags (${requiredTags.join(", ")}) to bucket ${name}.`,
                    "Implement AWS Config rules or Tag Policies to enforce tagging.",
                    "Use AWS Tag Editor for bulk tagging operations.",
                  ],
                }),
              );
            } else {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(`S3 tag check for ${name} failed: ${msg}`);
            }
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 tag compliance check failed: ${msg}`);
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

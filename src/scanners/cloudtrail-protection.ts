import {
  CloudTrailClient,
  DescribeTrailsCommand,
} from "@aws-sdk/client-cloudtrail";
import {
  S3Client,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
} from "@aws-sdk/client-s3";
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

export class CloudTrailProtectionScanner implements Scanner {
  readonly moduleName = "cloudtrail_protection";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const ctClient = createClient(CloudTrailClient, region);

      const resp = await ctClient.send(new DescribeTrailsCommand({}));
      const trails = resp.trailList ?? [];

      if (trails.length === 0) {
        warnings.push("No CloudTrail trails found — nothing to check for log protection.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings,
        };
      }

      // Collect unique S3 buckets used by trails
      const checkedBuckets = new Set<string>();
      let resourcesScanned = 0;

      for (const trail of trails) {
        const bucketName = trail.S3BucketName;
        if (!bucketName || checkedBuckets.has(bucketName)) continue;
        checkedBuckets.add(bucketName);
        resourcesScanned++;

        const trailName = trail.Name ?? "unknown";
        const bucketArn = `arn:${partition}:s3:::${bucketName}`;

        // Determine bucket region for S3 client
        // CloudTrail buckets may be in a different region, but we try with the scan region first
        const s3Client = createClient(S3Client, region);

        // Check encryption
        try {
          await s3Client.send(
            new GetBucketEncryptionCommand({ Bucket: bucketName }),
          );
          // If we get a response, encryption is configured
        } catch (e: unknown) {
          if (
            e instanceof Error &&
            (e.name === "ServerSideEncryptionConfigurationNotFoundError" ||
              e.name === "NoSuchBucketEncryption")
          ) {
            findings.push(
              makeFinding({
                riskScore: 7.5,
                title: `CloudTrail S3 bucket ${bucketName} is not encrypted`,
                resourceType: "AWS::S3::Bucket",
                resourceId: bucketName,
                resourceArn: bucketArn,
                region,
                description: `S3 bucket "${bucketName}" used by trail "${trailName}" does not have default encryption enabled.`,
                impact:
                  "CloudTrail logs stored without encryption can be read by anyone with access to the S3 bucket, exposing sensitive API activity data.",
                remediationSteps: [
                  "Enable default encryption on the S3 bucket (SSE-S3 or SSE-KMS).",
                  "Consider using a CMK for encryption to enable key rotation and access auditing.",
                ],
              }),
            );
          } else {
            warnings.push(`Could not check encryption for bucket ${bucketName}: ${e instanceof Error ? e.message : String(e)}`);
          }
        }

        // Check versioning
        try {
          const versionResp = await s3Client.send(
            new GetBucketVersioningCommand({ Bucket: bucketName }),
          );
          if (versionResp.Status !== "Enabled") {
            findings.push(
              makeFinding({
                riskScore: 6.0,
                title: `CloudTrail S3 bucket ${bucketName} does not have versioning enabled`,
                resourceType: "AWS::S3::Bucket",
                resourceId: bucketName,
                resourceArn: bucketArn,
                region,
                description: `S3 bucket "${bucketName}" used by trail "${trailName}" does not have versioning enabled.`,
                impact:
                  "Without versioning, deleted or overwritten log files cannot be recovered. An attacker could tamper with or destroy audit logs.",
                remediationSteps: [
                  "Enable versioning on the CloudTrail S3 bucket.",
                  "Consider enabling MFA Delete for additional protection.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          warnings.push(`Could not check versioning for bucket ${bucketName}: ${e instanceof Error ? e.message : String(e)}`);
        }

        // Check Block Public Access
        try {
          const bpaResp = await s3Client.send(
            new GetPublicAccessBlockCommand({ Bucket: bucketName }),
          );
          const config = bpaResp.PublicAccessBlockConfiguration;
          if (
            !config ||
            !config.BlockPublicAcls ||
            !config.IgnorePublicAcls ||
            !config.BlockPublicPolicy ||
            !config.RestrictPublicBuckets
          ) {
            findings.push(
              makeFinding({
                riskScore: 7.5,
                title: `CloudTrail S3 bucket ${bucketName} does not have full Block Public Access`,
                resourceType: "AWS::S3::Bucket",
                resourceId: bucketName,
                resourceArn: bucketArn,
                region,
                description: `S3 bucket "${bucketName}" used by trail "${trailName}" does not have all Block Public Access settings enabled.`,
                impact:
                  "CloudTrail logs could be exposed publicly, leaking API activity, IP addresses, and resource details to attackers.",
                remediationSteps: [
                  "Enable all four Block Public Access settings on the bucket.",
                  "Verify no bucket policy grants public access.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          if (
            e instanceof Error &&
            e.name === "NoSuchPublicAccessBlockConfiguration"
          ) {
            findings.push(
              makeFinding({
                riskScore: 9.0,
                title: `CloudTrail S3 bucket ${bucketName} has no Block Public Access configuration`,
                resourceType: "AWS::S3::Bucket",
                resourceId: bucketName,
                resourceArn: bucketArn,
                region,
                description: `S3 bucket "${bucketName}" used by trail "${trailName}" has no Block Public Access configuration at all.`,
                impact:
                  "Without any Block Public Access, the bucket is at high risk of accidental or malicious public exposure of CloudTrail audit logs.",
                remediationSteps: [
                  "Immediately enable Block Public Access on this bucket.",
                  "Review bucket policy and ACLs for any existing public grants.",
                ],
              }),
            );
          } else {
            warnings.push(`Could not check Block Public Access for bucket ${bucketName}: ${e instanceof Error ? e.message : String(e)}`);
          }
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

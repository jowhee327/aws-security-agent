import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketPolicyStatusCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import {
  S3ControlClient,
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
} from "@aws-sdk/client-s3-control";
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

async function getBucketRegion(
  client: S3Client,
  bucketName: string,
  defaultRegion: string,
  warnings: string[],
): Promise<string> {
  try {
    const resp = await client.send(
      new GetBucketLocationCommand({ Bucket: bucketName }),
    );
    // AWS returns "" or undefined for us-east-1; cast to string because the SDK
    // union type does not include "" but AWS actually returns it.
    const loc = String(resp.LocationConstraint ?? "") || "us-east-1";
    return loc;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`Failed to detect region for bucket ${bucketName}, using ${defaultRegion}: ${msg}`);
    return defaultRegion;
  }
}

export class S3Scanner implements Scanner {
  readonly moduleName = "s3";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(S3Client, region);

      // Account-level Block Public Access check
      try {
        const s3Control = createClient(S3ControlClient, region);
        const accountBpa = await s3Control.send(
          new GetAccountPublicAccessBlockCommand({ AccountId: accountId }),
        );
        const cfg = accountBpa.PublicAccessBlockConfiguration;
        if (
          !cfg?.BlockPublicAcls ||
          !cfg?.IgnorePublicAcls ||
          !cfg?.BlockPublicPolicy ||
          !cfg?.RestrictPublicBuckets
        ) {
          findings.push(
            makeFinding({
              riskScore: 8.5,
              title: "Account-level S3 Block Public Access is not fully enabled",
              resourceType: "AWS::S3::AccountPublicAccessBlock",
              resourceId: accountId,
              resourceArn: `arn:${partition}:iam::${accountId}:root`,
              region: "global",
              description: `Account ${accountId} does not have all four Block Public Access settings enabled at the account level.`,
              impact:
                "Individual buckets may be exposed to public access if their bucket-level settings are also incomplete.",
              remediationSteps: [
                "Enable all four Block Public Access settings at the account level via S3 console or S3Control API.",
                "This provides a safety net for all buckets in the account.",
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
              riskScore: 8.5,
              title: "Account-level S3 Block Public Access is not configured",
              resourceType: "AWS::S3::AccountPublicAccessBlock",
              resourceId: accountId,
              resourceArn: `arn:${partition}:iam::${accountId}:root`,
              region: "global",
              description: `Account ${accountId} has no Block Public Access configuration set at the account level.`,
              impact:
                "There is no account-level safeguard against public S3 bucket access.",
              remediationSteps: [
                "Enable all four Block Public Access settings at the account level.",
              ],
            }),
          );
        } else {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Account-level BPA check failed: ${msg}`);
        }
      }

      const listResp = await client.send(new ListBucketsCommand({}));
      const buckets = listResp.Buckets ?? [];

      for (const bucket of buckets) {
        const name = bucket.Name ?? "unknown";
        const arn = `arn:${partition}:s3:::${name}`;

        // Detect the bucket's actual region and create a region-specific client
        const bucketRegion = await getBucketRegion(client, name, region, warnings);
        const bucketClient =
          bucketRegion === region
            ? client
            : createClient(S3Client, bucketRegion);

        // Check Block Public Access
        try {
          const pab = await bucketClient.send(
            new GetPublicAccessBlockCommand({ Bucket: name }),
          );
          const cfg = pab.PublicAccessBlockConfiguration;
          if (
            !cfg?.BlockPublicAcls ||
            !cfg?.IgnorePublicAcls ||
            !cfg?.BlockPublicPolicy ||
            !cfg?.RestrictPublicBuckets
          ) {
            findings.push(
              makeFinding({
                riskScore: 8.0,
                title: `S3 bucket ${name} does not have full Block Public Access`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region: bucketRegion,
                description: `Bucket "${name}" has incomplete Block Public Access settings. One or more of BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets is disabled.`,
                impact:
                  "The bucket may be exposed to public access via ACLs or policies.",
                remediationSteps: [
                  "Enable all four Block Public Access settings on the bucket.",
                  "Consider enabling Block Public Access at the account level.",
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
                riskScore: 8.0,
                title: `S3 bucket ${name} has no Block Public Access configuration`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region: bucketRegion,
                description: `Bucket "${name}" has no Block Public Access configuration set at the bucket level.`,
                impact:
                  "The bucket has no safeguard against public access via ACLs or policies.",
                remediationSteps: [
                  "Enable all four Block Public Access settings on the bucket.",
                  "Consider enabling Block Public Access at the account level.",
                ],
              }),
            );
          } else {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name} BPA check failed: ${msg}`);
          }
        }

        // Check ACL for public grants
        try {
          const acl = await bucketClient.send(
            new GetBucketAclCommand({ Bucket: name }),
          );
          for (const grant of acl.Grants ?? []) {
            const uri = grant.Grantee?.URI ?? "";
            if (
              uri.includes("AllUsers") ||
              uri.includes("AuthenticatedUsers")
            ) {
              const perm = grant.Permission ?? "unknown";
              const isWrite =
                perm === "WRITE" ||
                perm === "FULL_CONTROL" ||
                perm === "WRITE_ACP";
              findings.push(
                makeFinding({
                  riskScore: 9.5,
                  title: `S3 bucket ${name} has public ACL grant (${perm})`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `Bucket "${name}" has an ACL granting ${perm} to ${uri.includes("AllUsers") ? "AllUsers (anonymous)" : "AuthenticatedUsers"}.`,
                  impact: isWrite
                    ? "Anyone can write to or modify permissions of this bucket."
                    : "Bucket contents may be publicly readable.",
                  remediationSteps: [
                    "Remove the public ACL grant.",
                    "Enable Block Public Access to prevent future public ACLs.",
                    "Use bucket policies with specific principals instead of ACLs.",
                  ],
                }),
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Bucket ${name} ACL check failed: ${msg}`);
        }

        // Check bucket policy for wildcard principal
        try {
          const policyStatus = await bucketClient.send(
            new GetBucketPolicyStatusCommand({ Bucket: name }),
          );
          if (policyStatus.PolicyStatus?.IsPublic) {
            findings.push(
              makeFinding({
                riskScore: 9.0,
                title: `S3 bucket ${name} has a public bucket policy`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region: bucketRegion,
                description: `Bucket "${name}" has a bucket policy that AWS evaluates as public (Principal: "*" or equivalent).`,
                impact:
                  "Data in this bucket may be accessible to anyone on the internet.",
                remediationSteps: [
                  "Review and restrict the bucket policy to specific principals.",
                  "Enable Block Public Access to override public policies.",
                  "Use VPC endpoints and condition keys to restrict access.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          // NoSuchBucketPolicy is expected for buckets without a policy
          if (!(e instanceof Error && e.name === "NoSuchBucketPolicy")) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name} policy status check failed: ${msg}`);
          }
        }

        // Check encryption
        try {
          await bucketClient.send(
            new GetBucketEncryptionCommand({ Bucket: name }),
          );
        } catch (e: unknown) {
          if (
            e instanceof Error &&
            e.name === "ServerSideEncryptionConfigurationNotFoundError"
          ) {
            findings.push(
              makeFinding({
                riskScore: 6.0,
                title: `S3 bucket ${name} has no default encryption`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region: bucketRegion,
                description: `Bucket "${name}" does not have default server-side encryption enabled.`,
                impact:
                  "Objects uploaded without explicit encryption will be stored unencrypted.",
                remediationSteps: [
                  "Enable default encryption using SSE-S3 (AES-256) or SSE-KMS.",
                  "Use a bucket policy to deny unencrypted uploads (s3:PutObject without encryption header).",
                ],
              }),
            );
          } else {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name} encryption check failed: ${msg}`);
          }
        }

        // Check versioning
        try {
          const ver = await bucketClient.send(
            new GetBucketVersioningCommand({ Bucket: name }),
          );
          if (ver.Status !== "Enabled") {
            findings.push(
              makeFinding({
                riskScore: 3.0,
                title: `S3 bucket ${name} does not have versioning enabled`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region: bucketRegion,
                description: `Bucket "${name}" versioning is ${ver.Status ?? "not set"}.`,
                impact:
                  "Accidental deletion or overwrite of objects cannot be recovered.",
                remediationSteps: [
                  "Enable versioning on the bucket.",
                  "Consider adding lifecycle rules to manage version storage costs.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Bucket ${name} versioning check failed: ${msg}`);
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: buckets.length,
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

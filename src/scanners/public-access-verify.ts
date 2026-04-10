import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketPolicyStatusCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import {
  RDSClient,
  DescribeDBInstancesCommand,
  type DBInstance,
} from "@aws-sdk/client-rds";
import dns from "node:dns";
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

function s3Endpoint(bucket: string, region: string): string {
  const suffix = region.startsWith("cn-")
    ? "amazonaws.com.cn"
    : "amazonaws.com";
  return `https://${bucket}.s3.${region}.${suffix}/`;
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
    const loc = String(resp.LocationConstraint ?? "") || "us-east-1";
    return loc;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`Failed to detect region for bucket ${bucketName}, using ${defaultRegion}: ${msg}`);
    return defaultRegion;
  }
}

async function isBucketMarkedPublic(
  client: S3Client,
  bucketName: string,
  warnings: string[],
): Promise<boolean | "skip"> {
  // Check if Block Public Access is off AND (public ACL or public policy)
  let bpaBlocks = false;
  try {
    const bpa = await client.send(
      new GetPublicAccessBlockCommand({ Bucket: bucketName }),
    );
    const cfg = bpa.PublicAccessBlockConfiguration;
    bpaBlocks = !!(
      cfg?.BlockPublicAcls &&
      cfg?.IgnorePublicAcls &&
      cfg?.BlockPublicPolicy &&
      cfg?.RestrictPublicBuckets
    );
  } catch (e: unknown) {
    if (
      e instanceof Error &&
      e.name === "NoSuchPublicAccessBlockConfiguration"
    ) {
      bpaBlocks = false;
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      warnings.push(`Could not check public access for bucket ${bucketName}: ${msg}`);
      return "skip";
    }
  }

  if (bpaBlocks) return false;

  // Check ACL for public grants
  try {
    const acl = await client.send(
      new GetBucketAclCommand({ Bucket: bucketName }),
    );
    for (const grant of acl.Grants ?? []) {
      const uri = grant.Grantee?.URI ?? "";
      if (uri.includes("AllUsers") || uri.includes("AuthenticatedUsers")) {
        return true;
      }
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`Could not check ACL for bucket ${bucketName}: ${msg}`);
  }

  // Check bucket policy status
  try {
    const policyStatus = await client.send(
      new GetBucketPolicyStatusCommand({ Bucket: bucketName }),
    );
    if (policyStatus.PolicyStatus?.IsPublic) return true;
  } catch (e: unknown) {
    // NoSuchBucketPolicy is expected for buckets without policies
    if (e instanceof Error && !e.name.includes("NoSuchBucketPolicy")) {
      const msg = e instanceof Error ? e.message : String(e);
      warnings.push(`Could not check policy status for bucket ${bucketName}: ${msg}`);
    }
  }

  return false;
}

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1], 10);
    return second >= 16 && second <= 31;
  }
  if (ip.startsWith("127.")) return true;
  return false;
}

export class PublicAccessVerifyScanner implements Scanner {
  readonly moduleName = "public_access_verify";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      // --- S3 public access verification ---
      try {
        const s3Client = createClient(S3Client, region);
        const listResp = await s3Client.send(new ListBucketsCommand({}));
        const buckets = listResp.Buckets ?? [];

        for (const bucket of buckets) {
          const name = bucket.Name ?? "unknown";
          const arn = `arn:${partition}:s3:::${name}`;

          const bucketRegion = await getBucketRegion(s3Client, name, region, warnings);
          const bucketClient =
            bucketRegion === region
              ? s3Client
              : createClient(S3Client, bucketRegion);

          const markedPublic = await isBucketMarkedPublic(bucketClient, name, warnings);
          if (markedPublic === "skip" || !markedPublic) continue;

          resourcesScanned++;
          const url = s3Endpoint(name, bucketRegion);

          try {
            const resp = await fetch(url, {
              method: "HEAD",
              signal: AbortSignal.timeout(5000),
            });

            if (resp.ok || resp.status === 200) {
              findings.push(
                makeFinding({
                  riskScore: 9.5,
                  title: `S3 bucket ${name} is publicly readable (verified)`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `HTTP HEAD to ${url} returned status ${resp.status}. The bucket is confirmed publicly accessible from the internet.`,
                  impact:
                    "Anyone on the internet can read objects from this bucket, potentially exposing sensitive data.",
                  remediationSteps: [
                    "Enable Block Public Access on the bucket immediately.",
                    "Review and remove public ACL grants and public bucket policies.",
                    "Audit bucket contents for sensitive data exposure.",
                  ],
                }),
              );
            } else if (resp.status === 403) {
              findings.push(
                makeFinding({
                  riskScore: 2.0,
                  title: `S3 bucket ${name} is marked public but returns 403 (blocked)`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `Bucket "${name}" has public ACL/policy configuration but HTTP access returns 403 Forbidden, likely blocked by other controls.`,
                  impact:
                    "Currently not accessible, but the public configuration is a risk if blocking controls are removed.",
                  remediationSteps: [
                    "Clean up the public ACL or policy to match the intended access model.",
                    "Enable Block Public Access to formalize the restriction.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`HTTP check for bucket ${name} failed: ${msg}`);
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 public access verification failed: ${msg}`);
      }

      // --- RDS public DNS verification ---
      try {
        const rdsClient = createClient(RDSClient, region);
        const instances: DBInstance[] = [];
        let marker: string | undefined;
        do {
          const resp = await rdsClient.send(
            new DescribeDBInstancesCommand({ Marker: marker }),
          );
          if (resp.DBInstances) instances.push(...resp.DBInstances);
          marker = resp.Marker;
        } while (marker);

        for (const db of instances) {
          if (!db.PubliclyAccessible) continue;

          const dbId = db.DBInstanceIdentifier ?? "unknown";
          const dbArn =
            db.DBInstanceArn ??
            `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
          const endpoint = db.Endpoint?.Address;
          if (!endpoint) continue;

          resourcesScanned++;

          try {
            const addresses = await dns.promises.resolve4(endpoint);
            const hasPublicIp = addresses.some((ip) => !isPrivateIp(ip));

            if (hasPublicIp) {
              findings.push(
                makeFinding({
                  riskScore: 8.0,
                  title: `RDS instance ${dbId} endpoint resolves to public IP (verified)`,
                  resourceType: "AWS::RDS::DBInstance",
                  resourceId: dbId,
                  resourceArn: dbArn,
                  region,
                  description: `RDS endpoint ${endpoint} resolves to public IP(s): ${addresses.join(", ")}. The database is network-reachable from the internet.`,
                  impact:
                    "The database can be reached from the public internet, making it vulnerable to brute-force, credential stuffing, and exploitation of database vulnerabilities.",
                  remediationSteps: [
                    "Set PubliclyAccessible to false on the RDS instance.",
                    "Move the instance to a private subnet.",
                    "Use VPN or bastion host for database access.",
                    "Restrict security group inbound rules to known IPs.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`DNS resolution for RDS ${dbId} (${endpoint}) failed: ${msg}`);
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`RDS public access verification failed: ${msg}`);
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

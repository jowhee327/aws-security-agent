import {
  Route53Client,
  ListHostedZonesCommand,
  ListResourceRecordSetsCommand,
  type HostedZone,
  type ResourceRecordSet,
} from "@aws-sdk/client-route-53";
import {
  S3Client,
  HeadBucketCommand,
} from "@aws-sdk/client-s3";
import { promises as dns } from "dns";
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

function extractS3BucketName(target: string): string | null {
  // Matches: bucket.s3.amazonaws.com, bucket.s3-website-us-east-1.amazonaws.com,
  //          bucket.s3.cn-north-1.amazonaws.com.cn, etc.
  const s3Pattern = /^([^.]+)\.s3[.-]/;
  const m = target.match(s3Pattern);
  return m ? m[1] : null;
}

function classifyTarget(target: string): "s3" | "elb" | "cloudfront" | null {
  if (/\.s3[.-](.*\.)?amazonaws\.com(\.cn)?\.?$/.test(target)) return "s3";
  if (/\.elb\.amazonaws\.com(\.cn)?\.?$/.test(target)) return "elb";
  if (/\.cloudfront\.net\.?$/.test(target)) return "cloudfront";
  return null;
}

async function dnsResolves(hostname: string): Promise<boolean> {
  try {
    // Remove trailing dot for DNS lookup
    const h = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
    await dns.resolve(h);
    return true;
  } catch {
    return false;
  }
}

export class DnsDanglingScanner implements Scanner {
  readonly moduleName = "dns_dangling";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const route53 = createClient(Route53Client, region, ctx.credentials);

      // List hosted zones
      const zones: HostedZone[] = [];
      let marker: string | undefined;
      do {
        const resp = await route53.send(
          new ListHostedZonesCommand({ Marker: marker }),
        );
        if (resp.HostedZones) zones.push(...resp.HostedZones);
        marker = resp.IsTruncated ? resp.NextMarker : undefined;
      } while (marker);

      for (const zone of zones) {
        const zoneId = zone.Id ?? "unknown";
        const zoneName = zone.Name ?? "unknown";
        const shortZoneId = zoneId.replace("/hostedzone/", "");

        // List record sets
        const records: ResourceRecordSet[] = [];
        let nextName: string | undefined;
        let nextType: string | undefined;
        do {
          const resp = await route53.send(
            new ListResourceRecordSetsCommand({
              HostedZoneId: shortZoneId,
              StartRecordName: nextName,
              StartRecordType: nextType as ResourceRecordSet["Type"],
            }),
          );
          if (resp.ResourceRecordSets) records.push(...resp.ResourceRecordSets);
          if (resp.IsTruncated) {
            nextName = resp.NextRecordName;
            nextType = resp.NextRecordType;
          } else {
            nextName = undefined;
            nextType = undefined;
          }
        } while (nextName);

        // Filter CNAME records
        const cnameRecords = records.filter(
          (r) => r.Type === "CNAME" && r.ResourceRecords && r.ResourceRecords.length > 0,
        );

        resourcesScanned += cnameRecords.length;

        for (const record of cnameRecords) {
          const recordName = record.Name ?? "unknown";
          const target = record.ResourceRecords![0].Value ?? "";
          const recordArn = `arn:${partition}:route53:::hostedzone/${shortZoneId}`;
          const targetType = classifyTarget(target);

          if (targetType === "s3") {
            // Check if S3 bucket exists
            const bucketName = extractS3BucketName(target);
            if (bucketName) {
              let bucketExists = false;
              try {
                const s3 = createClient(S3Client, region, ctx.credentials);
                await s3.send(new HeadBucketCommand({ Bucket: bucketName }));
                bucketExists = true;
              } catch (e: unknown) {
                const errName = (e as { name?: string }).name ?? "";
                // 404 / NoSuchBucket = doesn't exist; 403 = exists but no access
                if (errName === "Forbidden" || errName === "AccessDenied" || errName === "403") {
                  bucketExists = true;
                }
              }

              if (!bucketExists) {
                findings.push(
                  makeFinding({
                    riskScore: 9.5,
                    title: `CNAME ${recordName} points to non-existent S3 bucket "${bucketName}"`,
                    resourceType: "AWS::Route53::RecordSet",
                    resourceId: recordName,
                    resourceArn: recordArn,
                    region,
                    description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to S3 bucket "${bucketName}" which does not exist. An attacker can claim this bucket for subdomain takeover.`,
                    impact:
                      "Critical subdomain takeover vulnerability. An attacker can create the S3 bucket and serve arbitrary content on your domain, enabling phishing, cookie theft, and reputation damage.",
                    remediationSteps: [
                      "Immediately create the S3 bucket to prevent takeover.",
                      "Remove the dangling DNS record if the bucket is no longer needed.",
                      "Audit all CNAME records pointing to S3 buckets.",
                    ],
                  }),
                );
              }
            }
          } else if (targetType === "elb") {
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding({
                  riskScore: 8.0,
                  title: `CNAME ${recordName} points to non-resolving ELB`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to ELB "${target}" which does not resolve. The load balancer may have been deleted.`,
                  impact:
                    "Potential subdomain takeover if the ELB DNS name can be re-registered. Dangling DNS records indicate resource lifecycle gaps.",
                  remediationSteps: [
                    "Remove the dangling DNS record.",
                    "If the ELB was deleted, clean up all associated DNS records.",
                    "Implement automated DNS record cleanup when decommissioning resources.",
                  ],
                }),
              );
            }
          } else if (targetType === "cloudfront") {
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding({
                  riskScore: 7.5,
                  title: `CNAME ${recordName} points to non-resolving CloudFront distribution`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to CloudFront "${target}" which does not resolve. The distribution may have been deleted.`,
                  impact:
                    "Potential subdomain takeover via CloudFront. An attacker may create a distribution with this alternate domain name.",
                  remediationSteps: [
                    "Remove the dangling DNS record.",
                    "If the CloudFront distribution was deleted, clean up associated DNS records.",
                    "Use CloudFront Origin Access Identity to limit exposure.",
                  ],
                }),
              );
            }
          } else if (targetType === null) {
            // Generic CNAME — just check if it resolves
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding({
                  riskScore: 5.0,
                  title: `CNAME ${recordName} target does not resolve`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to "${target}" which does not resolve.`,
                  impact:
                    "Orphaned DNS record pointing to a non-existent target. May indicate incomplete resource cleanup.",
                  remediationSteps: [
                    "Verify the target resource still exists.",
                    "Remove the DNS record if it is no longer needed.",
                    "Implement DNS record lifecycle management.",
                  ],
                }),
              );
            }
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

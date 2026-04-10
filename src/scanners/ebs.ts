import {
  EC2Client,
  DescribeVolumesCommand,
  DescribeSnapshotsCommand,
  DescribeSnapshotAttributeCommand,
  GetEbsEncryptionByDefaultCommand,
  type Volume,
  type Snapshot,
} from "@aws-sdk/client-ec2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const CONCURRENCY_LIMIT = 10;

async function withRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (e: unknown) {
      const isThrottle =
        e instanceof Error &&
        (e.name === "Throttling" ||
          e.name === "RequestLimitExceeded" ||
          e.name === "TooManyRequestsException");
      if (!isThrottle || attempt === maxRetries) throw e;
      await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
    }
  }
  throw new Error("unreachable");
}

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

async function checkPublicSnapshots(
  client: EC2Client,
  snapshots: Snapshot[],
  region: string,
  partition: string,
  accountId: string,
  findings: Finding[],
  warnings: string[],
): Promise<void> {
  // Process all snapshots with bounded concurrency
  for (let i = 0; i < snapshots.length; i += CONCURRENCY_LIMIT) {
    const batch = snapshots.slice(i, i + CONCURRENCY_LIMIT);
    const results = await Promise.allSettled(
      batch.map(async (snap) => {
        const snapId = snap.SnapshotId;
        if (!snapId) return;

        const attrResp = await withRetry(() =>
          client.send(
            new DescribeSnapshotAttributeCommand({
              SnapshotId: snapId,
              Attribute: "createVolumePermission",
            }),
          ),
        );

        const isPublic = (attrResp.CreateVolumePermissions ?? []).some(
          (p) => p.Group === "all",
        );

        if (isPublic) {
          findings.push(
            makeFinding({
              riskScore: 9.5,
              title: `EBS snapshot ${snapId} is publicly shared`,
              resourceType: "AWS::EC2::Snapshot",
              resourceId: snapId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:snapshot/${snapId}`,
              region,
              description: `EBS snapshot "${snapId}" has createVolumePermission granted to "all", making it publicly accessible.`,
              impact:
                "Anyone with an AWS account can create a volume from this snapshot and access all data contained in it.",
              remediationSteps: [
                "Remove the public createVolumePermission from the snapshot.",
                "Share snapshots only with specific AWS account IDs that need access.",
                "Enable the EBS snapshot block public access setting.",
              ],
            }),
          );
        }
      }),
    );

    for (const result of results) {
      if (result.status === "rejected") {
        const reason = result.reason;
        const msg = reason instanceof Error ? reason.message : String(reason);
        warnings.push(`Snapshot attribute check failed: ${msg}`);
      }
    }
  }
}

export class EbsScanner implements Scanner {
  readonly moduleName = "ebs";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region);
      let resourcesScanned = 0;

      // Check default encryption setting
      const encDefault = await client.send(
        new GetEbsEncryptionByDefaultCommand({}),
      );
      resourcesScanned++;

      if (!encDefault.EbsEncryptionByDefault) {
        findings.push(
          makeFinding({
            riskScore: 7.0,
            title: `EBS default encryption is not enabled in ${region}`,
            resourceType: "AWS::EC2::EBSDefaultEncryption",
            resourceId: `ebs-default-${region}`,
            resourceArn: `arn:${partition}:ec2:${region}:${accountId}:ebs-default-encryption`,
            region,
            description: `EBS default encryption is not enabled in region ${region}.`,
            impact:
              "Newly created EBS volumes will not be encrypted by default, requiring manual encryption per volume.",
            remediationSteps: [
              "Enable EBS encryption by default for the region using the EC2 console or API.",
              "This ensures all new volumes and snapshots are automatically encrypted.",
            ],
          }),
        );
      }

      // Scan volumes for unencrypted
      const volumes: Volume[] = [];
      let volToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeVolumesCommand({ NextToken: volToken }),
        );
        if (resp.Volumes) volumes.push(...resp.Volumes);
        volToken = resp.NextToken;
      } while (volToken);

      resourcesScanned += volumes.length;

      for (const vol of volumes) {
        if (!vol.Encrypted) {
          const volId = vol.VolumeId ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 6.0,
              title: `EBS volume ${volId} is not encrypted`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:volume/${volId}`,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB, ${vol.State ?? "unknown"}) is not encrypted.`,
              impact:
                "Data on this volume is stored unencrypted. A compromised snapshot or physical media could expose data.",
              remediationSteps: [
                "Create an encrypted snapshot of this volume.",
                "Create a new encrypted volume from the snapshot.",
                "Migrate data to the new encrypted volume and delete the old one.",
              ],
            }),
          );
        }
      }

      // Scan snapshots — own snapshots only
      const snapshots: Snapshot[] = [];
      let snapToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeSnapshotsCommand({
            OwnerIds: ["self"],
            NextToken: snapToken,
          }),
        );
        if (resp.Snapshots) snapshots.push(...resp.Snapshots);
        snapToken = resp.NextToken;
      } while (snapToken);

      resourcesScanned += snapshots.length;

      // Check unencrypted snapshots
      for (const snap of snapshots) {
        if (!snap.Encrypted) {
          const snapId = snap.SnapshotId ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 5.5,
              title: `EBS snapshot ${snapId} is not encrypted`,
              resourceType: "AWS::EC2::Snapshot",
              resourceId: snapId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:snapshot/${snapId}`,
              region,
              description: `EBS snapshot "${snapId}" (volume: ${snap.VolumeId ?? "unknown"}) is not encrypted.`,
              impact:
                "Unencrypted snapshots can be copied or shared, exposing data without encryption protection.",
              remediationSteps: [
                "Copy the snapshot with encryption enabled.",
                "Delete the unencrypted snapshot after verifying the encrypted copy.",
              ],
            }),
          );
        }
      }

      // Check public snapshots — all owned snapshots with bounded concurrency
      await checkPublicSnapshots(
        client,
        snapshots,
        region,
        partition,
        accountId,
        findings,
        warnings,
      );

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

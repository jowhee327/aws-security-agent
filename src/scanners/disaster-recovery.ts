import {
  RDSClient,
  DescribeDBInstancesCommand,
  type DBInstance,
} from "@aws-sdk/client-rds";
import {
  EC2Client,
  DescribeVolumesCommand,
  DescribeSnapshotsCommand,
  type Volume,
  type Snapshot,
} from "@aws-sdk/client-ec2";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketVersioningCommand,
  GetBucketReplicationCommand,
} from "@aws-sdk/client-s3";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

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

export class DisasterRecoveryScanner implements Scanner {
  readonly moduleName = "disaster_recovery";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      let resourcesScanned = 0;

      // --- RDS checks ---
      const rdsClient = createClient(RDSClient, region, ctx.credentials);
      const instances: DBInstance[] = [];
      let marker: string | undefined;
      do {
        const resp = await rdsClient.send(
          new DescribeDBInstancesCommand({ Marker: marker }),
        );
        if (resp.DBInstances) instances.push(...resp.DBInstances);
        marker = resp.Marker;
      } while (marker);

      resourcesScanned += instances.length;

      for (const db of instances) {
        const dbId = db.DBInstanceIdentifier ?? "unknown";
        const dbArn =
          db.DBInstanceArn ??
          `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
        const engine = db.Engine ?? "unknown";

        // MultiAZ check
        if (!db.MultiAZ) {
          findings.push(
            makeFinding({
              riskScore: 6.0,
              title: `RDS instance ${dbId} is not Multi-AZ`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) does not have Multi-AZ deployment enabled.`,
              impact:
                "Single-AZ deployments have no automatic failover. An AZ outage will cause downtime and potential data loss.",
              remediationSteps: [
                "Enable Multi-AZ deployment for the RDS instance.",
                "This provides automatic failover to a standby in a different AZ.",
              ],
            }),
          );
        }

        // Backup retention check
        const retention = db.BackupRetentionPeriod ?? 0;
        if (retention === 0) {
          findings.push(
            makeFinding({
              riskScore: 5.5,
              title: `RDS instance ${dbId} has automated backups disabled`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has backup retention period set to 0 (disabled).`,
              impact:
                "No automated backups or point-in-time recovery. Data loss from failures or corruption is unrecoverable.",
              remediationSteps: [
                "Set the backup retention period to at least 7 days.",
                "Consider cross-region backup replication for critical databases.",
              ],
            }),
          );
        } else if (retention < 7) {
          findings.push(
            makeFinding({
              riskScore: 5.5,
              title: `RDS instance ${dbId} backup retention is only ${retention} day(s)`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has backup retention period of ${retention} day(s), below the recommended 7 days.`,
              impact:
                "Short retention windows limit point-in-time recovery options and may not meet compliance requirements.",
              remediationSteps: [
                "Increase the backup retention period to at least 7 days.",
                "For production databases, consider 14-35 days retention.",
              ],
            }),
          );
        }
      }

      // --- EBS snapshot checks ---
      const ec2Client = createClient(EC2Client, region, ctx.credentials);

      const volumes: Volume[] = [];
      let volToken: string | undefined;
      do {
        const resp = await ec2Client.send(
          new DescribeVolumesCommand({ NextToken: volToken }),
        );
        if (resp.Volumes) volumes.push(...resp.Volumes);
        volToken = resp.NextToken;
      } while (volToken);

      // Get all snapshots owned by this account
      const snapshots: Snapshot[] = [];
      let snapToken: string | undefined;
      do {
        const resp = await ec2Client.send(
          new DescribeSnapshotsCommand({
            OwnerIds: ["self"],
            NextToken: snapToken,
          }),
        );
        if (resp.Snapshots) snapshots.push(...resp.Snapshots);
        snapToken = resp.NextToken;
      } while (snapToken);

      // Build a map: volumeId -> most recent snapshot time
      const latestSnapshotByVolume = new Map<string, number>();
      for (const snap of snapshots) {
        if (!snap.VolumeId || snap.State !== "completed") continue;
        const snapTime = snap.StartTime?.getTime() ?? 0;
        const existing = latestSnapshotByVolume.get(snap.VolumeId) ?? 0;
        if (snapTime > existing) {
          latestSnapshotByVolume.set(snap.VolumeId, snapTime);
        }
      }

      // Only check in-use volumes for snapshot coverage
      const inUseVolumes = volumes.filter((v) => v.State === "in-use");
      resourcesScanned += inUseVolumes.length;
      const now = Date.now();

      for (const vol of inUseVolumes) {
        const volId = vol.VolumeId ?? "unknown";
        const volArn = `arn:${partition}:ec2:${region}:${accountId}:volume/${volId}`;
        const latestSnap = latestSnapshotByVolume.get(volId);

        if (latestSnap === undefined) {
          // No snapshots at all
          findings.push(
            makeFinding({
              riskScore: 7.0,
              title: `EBS volume ${volId} has no snapshots`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: volArn,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB, ${vol.VolumeType ?? "unknown"}) has no snapshots. Data cannot be recovered if the volume fails.`,
              impact:
                "Complete data loss if the volume becomes unavailable. No backup exists for disaster recovery.",
              remediationSteps: [
                "Create a snapshot of the volume immediately.",
                "Set up automated snapshots using AWS Backup or Amazon Data Lifecycle Manager.",
              ],
            }),
          );
        } else if (now - latestSnap > SEVEN_DAYS_MS) {
          const daysSince = Math.round((now - latestSnap) / (24 * 60 * 60 * 1000));
          findings.push(
            makeFinding({
              riskScore: 5.0,
              title: `EBS volume ${volId} has no recent snapshot (${daysSince} days old)`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: volArn,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB) most recent snapshot is ${daysSince} days old, exceeding the 7-day threshold.`,
              impact:
                "Recovery from the latest snapshot would lose up to ${daysSince} days of data.",
              remediationSteps: [
                "Create a fresh snapshot of the volume.",
                "Configure automated snapshot schedules using AWS Backup or Data Lifecycle Manager.",
              ],
            }),
          );
        }
      }

      // --- S3 checks ---
      const s3Client = createClient(S3Client, region, ctx.credentials);

      let bucketNames: string[] = [];
      try {
        const listResp = await s3Client.send(new ListBucketsCommand({}));
        bucketNames = (listResp.Buckets ?? []).map((b) => b.Name).filter((n): n is string => !!n);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 bucket list failed: ${msg}`);
      }

      resourcesScanned += bucketNames.length;

      for (const name of bucketNames) {
        const arn = `arn:${partition}:s3:::${name}`;

        // Versioning check
        try {
          const ver = await s3Client.send(
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
                region,
                description: `Bucket "${name}" versioning is ${ver.Status ?? "not set"}. Object deletion or overwrite is irreversible.`,
                impact:
                  "Accidental deletion or corruption of objects cannot be recovered without versioning.",
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

        // Cross-region replication check
        try {
          await s3Client.send(
            new GetBucketReplicationCommand({ Bucket: name }),
          );
          // If the call succeeds, replication is configured — no finding needed
        } catch (e: unknown) {
          if (
            e instanceof Error &&
            e.name === "ReplicationConfigurationNotFoundError"
          ) {
            findings.push(
              makeFinding({
                riskScore: 3.5,
                title: `S3 bucket ${name} has no cross-region replication`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region,
                description: `Bucket "${name}" does not have cross-region replication configured.`,
                impact:
                  "Data is stored in a single region. A regional outage could make the data unavailable.",
                remediationSteps: [
                  "Enable cross-region replication to a bucket in another region.",
                  "Ensure versioning is enabled (required for CRR).",
                  "Consider S3 Replication Time Control for critical data.",
                ],
              }),
            );
          } else {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name} replication check failed: ${msg}`);
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

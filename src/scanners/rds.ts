import {
  RDSClient,
  DescribeDBInstancesCommand,
  type DBInstance,
} from "@aws-sdk/client-rds";
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

export class RdsScanner implements Scanner {
  readonly moduleName = "rds";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];

    try {
      const client = createClient(RDSClient, region);

      const instances: DBInstance[] = [];
      let marker: string | undefined;
      do {
        const resp = await client.send(
          new DescribeDBInstancesCommand({ Marker: marker }),
        );
        if (resp.DBInstances) instances.push(...resp.DBInstances);
        marker = resp.Marker;
      } while (marker);

      for (const db of instances) {
        const dbId = db.DBInstanceIdentifier ?? "unknown";
        const dbArn =
          db.DBInstanceArn ??
          `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
        const engine = db.Engine ?? "unknown";

        // Publicly accessible
        if (db.PubliclyAccessible) {
          findings.push(
            makeFinding({
              riskScore: 8.0,
              title: `RDS instance ${dbId} is publicly accessible`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has PubliclyAccessible set to true.`,
              impact:
                "The database endpoint is resolvable to a public IP and may be accessible from the internet if security groups allow it.",
              remediationSteps: [
                "Modify the instance to set PubliclyAccessible to false.",
                "Ensure the instance is in a private subnet.",
                "Use a VPN or bastion host for database access.",
              ],
            }),
          );
        }

        // Not encrypted
        if (!db.StorageEncrypted) {
          findings.push(
            makeFinding({
              riskScore: 7.0,
              title: `RDS instance ${dbId} storage is not encrypted`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) does not have storage encryption enabled.`,
              impact:
                "Data at rest is not encrypted, increasing risk of data exposure from storage-level compromise.",
              remediationSteps: [
                "Create an encrypted snapshot of the instance.",
                "Restore a new instance from the encrypted snapshot.",
                "Enable encryption for all new RDS instances by default.",
              ],
            }),
          );
        }

        // No backups
        if ((db.BackupRetentionPeriod ?? 0) === 0) {
          findings.push(
            makeFinding({
              riskScore: 6.0,
              title: `RDS instance ${dbId} has no automated backups`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has backup retention period set to 0 (disabled).`,
              impact:
                "No point-in-time recovery is available. Data loss from accidental deletion or corruption is unrecoverable.",
              remediationSteps: [
                "Set the backup retention period to at least 7 days.",
                "Consider enabling cross-region backup replication for disaster recovery.",
              ],
            }),
          );
        }

        // No deletion protection
        if (!db.DeletionProtection) {
          findings.push(
            makeFinding({
              riskScore: 4.0,
              title: `RDS instance ${dbId} has no deletion protection`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) does not have deletion protection enabled.`,
              impact:
                "The instance can be accidentally deleted without safeguards, leading to potential data loss.",
              remediationSteps: [
                "Enable deletion protection on the instance.",
                "Use IAM policies to restrict who can modify deletion protection.",
              ],
            }),
          );
        }
      }

      return {
        module: this.moduleName,
        status: "success",
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
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

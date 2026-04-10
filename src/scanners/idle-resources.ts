import {
  EC2Client,
  DescribeVolumesCommand,
  DescribeAddressesCommand,
  DescribeInstancesCommand,
  DescribeNetworkInterfacesCommand,
  DescribeSecurityGroupsCommand,
  type Volume,
  type Address,
  type Instance,
  type SecurityGroup,
} from "@aws-sdk/client-ec2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

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

export class IdleResourcesScanner implements Scanner {
  readonly moduleName = "idle_resources";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region);
      let resourcesScanned = 0;

      // 1. Unattached EBS volumes (State = "available")
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
        if (vol.State === "available") {
          const volId = vol.VolumeId ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 3.0,
              title: `EBS volume ${volId} is unattached`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:volume/${volId}`,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB, ${vol.VolumeType ?? "unknown"}) is in "available" state with no attachments.`,
              impact:
                "Unattached volumes incur storage costs and may contain sensitive data that is no longer actively managed.",
              remediationSteps: [
                "Determine if the volume is still needed.",
                "If not needed, create a snapshot for archival and delete the volume.",
                "If needed, attach it to the appropriate instance.",
              ],
            }),
          );
        }
      }

      // 2. Unused Elastic IPs (not associated with any instance)
      let addresses: Address[] = [];
      try {
        const addrResp = await client.send(new DescribeAddressesCommand({}));
        addresses = addrResp.Addresses ?? [];
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`Elastic IP check failed: ${msg}`);
      }

      resourcesScanned += addresses.length;

      for (const addr of addresses) {
        if (!addr.AssociationId) {
          const allocId = addr.AllocationId ?? "unknown";
          const publicIp = addr.PublicIp ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 2.0,
              title: `Elastic IP ${publicIp} is not associated`,
              resourceType: "AWS::EC2::EIP",
              resourceId: allocId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:elastic-ip/${allocId}`,
              region,
              description: `Elastic IP ${publicIp} (${allocId}) is allocated but not associated with any instance or network interface.`,
              impact:
                "Unused Elastic IPs cost ~$3.60/month each and represent unnecessary spend.",
              remediationSteps: [
                "Associate the EIP with an instance or network interface if needed.",
                "Release the EIP if it is no longer required.",
              ],
            }),
          );
        }
      }

      // 3. Stopped EC2 instances (>30 days)
      const instances: Instance[] = [];
      let instToken: string | undefined;
      do {
        const instResp = await client.send(
          new DescribeInstancesCommand({ NextToken: instToken }),
        );
        for (const res of instResp.Reservations ?? []) {
          if (res.Instances) instances.push(...res.Instances);
        }
        instToken = instResp.NextToken;
      } while (instToken);

      resourcesScanned += instances.length;
      const now = Date.now();

      for (const inst of instances) {
        if (inst.State?.Name === "stopped") {
          const instId = inst.InstanceId ?? "unknown";
          const reason = inst.StateTransitionReason ?? "";
          const stoppedTime = reason ? parseStopTime(reason) : null;

          if (!stoppedTime) {
            warnings.push(
              `Could not determine stop date for instance ${instId}. StateTransitionReason: ${reason}`,
            );
            continue;
          }

          const stoppedDays = Math.round(
            (now - stoppedTime) / (24 * 60 * 60 * 1000),
          );

          if (stoppedDays > 30) {
            findings.push(
              makeFinding({
                riskScore: 3.0,
                title: `EC2 instance ${instId} has been stopped for ${stoppedDays} days`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`,
                region,
                description: `EC2 instance "${instId}" (${inst.InstanceType ?? "unknown"}) is in stopped state for ${stoppedDays} days. Attached EBS volumes continue to incur charges.`,
                impact:
                  "Stopped instances still incur EBS storage costs and may contain stale configurations or unpatched AMIs.",
                remediationSteps: [
                  "Determine if the instance is still needed.",
                  "If not needed, create an AMI for archival and terminate the instance.",
                  "If needed temporarily, consider using a launch template for on-demand recreation.",
                ],
              }),
            );
          }
        }
      }

      // 4. Unused Security Groups (not attached to any ENI)
      const securityGroups: SecurityGroup[] = [];
      let sgToken: string | undefined;
      do {
        const sgResp = await client.send(
          new DescribeSecurityGroupsCommand({ NextToken: sgToken }),
        );
        if (sgResp.SecurityGroups) securityGroups.push(...sgResp.SecurityGroups);
        sgToken = sgResp.NextToken;
      } while (sgToken);

      // Find all SGs referenced by ENIs
      const usedSgIds = new Set<string>();
      let eniToken: string | undefined;
      do {
        const eniResp = await client.send(
          new DescribeNetworkInterfacesCommand({ NextToken: eniToken }),
        );
        for (const eni of eniResp.NetworkInterfaces ?? []) {
          for (const group of eni.Groups ?? []) {
            if (group.GroupId) usedSgIds.add(group.GroupId);
          }
        }
        eniToken = eniResp.NextToken;
      } while (eniToken);

      resourcesScanned += securityGroups.length;

      for (const sg of securityGroups) {
        const sgId = sg.GroupId ?? "unknown";
        // Skip default security groups — they cannot be deleted
        if (sg.GroupName === "default") continue;

        if (!usedSgIds.has(sgId)) {
          findings.push(
            makeFinding({
              riskScore: 2.0,
              title: `Security group ${sgId} is not attached to any resource`,
              resourceType: "AWS::EC2::SecurityGroup",
              resourceId: sgId,
              resourceArn: `arn:${partition}:ec2:${region}:${sg.OwnerId ?? accountId}:security-group/${sgId}`,
              region,
              description: `Security group "${sg.GroupName}" (${sgId}) is not associated with any network interface.`,
              impact:
                "Unused security groups add clutter and may cause confusion during security reviews.",
              remediationSteps: [
                "Verify the security group is not referenced by other resources (e.g., launch templates).",
                "Delete the security group if it is no longer needed.",
              ],
            }),
          );
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

/**
 * Parse the stop time from EC2 StateTransitionReason.
 * Format: "User initiated (2024-01-15 08:30:00 GMT)"
 */
function parseStopTime(reason: string): number | null {
  const match = reason.match(/\((\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\w+)\)/);
  if (!match) return null;
  const parsed = Date.parse(match[1]);
  return isNaN(parsed) ? null : parsed;
}

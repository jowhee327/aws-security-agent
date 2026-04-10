import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  type SecurityGroup,
  type IpPermission,
} from "@aws-sdk/client-ec2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const HIGH_RISK_PORTS: Record<number, string> = {
  22: "SSH",
  3389: "RDP",
  3306: "MySQL",
  5432: "PostgreSQL",
  1433: "MSSQL",
  27017: "MongoDB",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
};

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

function isOpenToWorld(cidrIp?: string, cidrIpv6?: string): boolean {
  return cidrIp === "0.0.0.0/0" || cidrIpv6 === "::/0";
}

function permissionCoversPort(perm: IpPermission, port: number): boolean {
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  if (from === -1 && to === -1) return true; // all traffic
  return port >= from && port <= to;
}

function isAllPorts(perm: IpPermission): boolean {
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  return (from === -1 && to === -1) || (from === 0 && to === 65535);
}

export class SgScanner implements Scanner {
  readonly moduleName = "security_group";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region);

      // Paginate DescribeSecurityGroups
      const securityGroups: SecurityGroup[] = [];
      let nextToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeSecurityGroupsCommand({ NextToken: nextToken }),
        );
        if (resp.SecurityGroups) securityGroups.push(...resp.SecurityGroups);
        nextToken = resp.NextToken;
      } while (nextToken);

      // Get instances to assess impact per SG
      const sgInstanceCount = new Map<string, number>();
      let instToken: string | undefined;
      do {
        const instResp = await client.send(
          new DescribeInstancesCommand({ NextToken: instToken }),
        );
        for (const res of instResp.Reservations ?? []) {
          for (const inst of res.Instances ?? []) {
            for (const sg of inst.SecurityGroups ?? []) {
              if (sg.GroupId) {
                sgInstanceCount.set(
                  sg.GroupId,
                  (sgInstanceCount.get(sg.GroupId) ?? 0) + 1,
                );
              }
            }
          }
        }
        instToken = instResp.NextToken;
      } while (instToken);

      for (const sg of securityGroups) {
        const sgId = sg.GroupId ?? "unknown";
        const sgArn = `arn:${partition}:ec2:${region}:${sg.OwnerId}:security-group/${sgId}`;
        const instanceCount = sgInstanceCount.get(sgId) ?? 0;
        const impactSuffix =
          instanceCount > 0
            ? ` Affects ${instanceCount} instance(s).`
            : " No instances currently attached.";

        for (const perm of sg.IpPermissions ?? []) {
          const worldCidrs = [
            ...(perm.IpRanges ?? [])
              .filter((r) => isOpenToWorld(r.CidrIp))
              .map((r) => r.CidrIp!),
            ...(perm.Ipv6Ranges ?? [])
              .filter((r) => isOpenToWorld(undefined, r.CidrIpv6))
              .map((r) => r.CidrIpv6!),
          ];

          if (worldCidrs.length === 0) continue;

          const cidrStr = worldCidrs.join(", ");

          // Check all-ports open
          if (isAllPorts(perm)) {
            findings.push(
              makeFinding({
                riskScore: 9.5,
                title: `Security group ${sgId} allows all ports from ${cidrStr}`,
                resourceType: "AWS::EC2::SecurityGroup",
                resourceId: sgId,
                resourceArn: sgArn,
                region,
                description: `Security group "${sg.GroupName}" (${sgId}) has an inbound rule allowing all ports from ${cidrStr}.`,
                impact: `All services on associated instances are exposed to the internet.${impactSuffix}`,
                remediationSteps: [
                  "Remove the overly permissive inbound rule.",
                  "Create specific rules for only the required ports and source CIDRs.",
                  "Use VPN or bastion hosts for administrative access.",
                ],
              }),
            );
            continue;
          }

          // Check individual high-risk ports
          for (const [portNum, portName] of Object.entries(HIGH_RISK_PORTS)) {
            const port = Number(portNum);
            if (!permissionCoversPort(perm, port)) continue;

            const isSshRdp = port === 22 || port === 3389;
            const isDbPort = [3306, 5432, 1433, 27017].includes(port);
            const riskScore = isSshRdp ? 9.0 : isDbPort ? 8.0 : 7.5;

            findings.push(
              makeFinding({
                riskScore,
                title: `Security group ${sgId} allows ${portName} (${port}) from ${cidrStr}`,
                resourceType: "AWS::EC2::SecurityGroup",
                resourceId: sgId,
                resourceArn: sgArn,
                region,
                description: `Security group "${sg.GroupName}" (${sgId}) has an inbound rule allowing port ${port} (${portName}) from ${cidrStr}.`,
                impact: `${portName} service is exposed to the internet, enabling brute-force or exploitation attacks.${impactSuffix}`,
                remediationSteps: [
                  `Restrict port ${port} access to known IP ranges.`,
                  `Use AWS Systems Manager Session Manager or a bastion host instead of direct ${portName} access.`,
                  "Enable VPC Flow Logs to monitor connection attempts.",
                ],
              }),
            );
          }
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: securityGroups.length,
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

import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeAddressesCommand,
  type Instance,
  type SecurityGroup,
  type NetworkAcl,
  type IpPermission,
  type NetworkAclEntry,
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

function sgAllowsPort(sgs: SecurityGroup[], port: number): boolean {
  for (const sg of sgs) {
    for (const perm of sg.IpPermissions ?? []) {
      if (permissionAllowsWorldPort(perm, port)) return true;
    }
  }
  return false;
}

function sgAllowsAllPorts(sgs: SecurityGroup[]): boolean {
  for (const sg of sgs) {
    for (const perm of sg.IpPermissions ?? []) {
      if (isAllPorts(perm) && hasWorldCidr(perm)) return true;
    }
  }
  return false;
}

function permissionAllowsWorldPort(perm: IpPermission, port: number): boolean {
  if (!hasWorldCidr(perm)) return false;
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  if (from === -1 && to === -1) return true; // all traffic
  return port >= from && port <= to;
}

function hasWorldCidr(perm: IpPermission): boolean {
  const hasIpv4 = (perm.IpRanges ?? []).some((r) => r.CidrIp === "0.0.0.0/0");
  const hasIpv6 = (perm.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === "::/0");
  return hasIpv4 || hasIpv6;
}

function isAllPorts(perm: IpPermission): boolean {
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  return (from === -1 && to === -1) || (from === 0 && to === 65535);
}

function naclAllowsPort(nacl: NetworkAcl, port: number): boolean {
  // NACL rules are evaluated in order (lowest rule number first)
  // We check inbound rules only (Egress === false)
  const inboundRules = (nacl.Entries ?? [])
    .filter((e) => e.Egress === false)
    .sort((a, b) => (a.RuleNumber ?? 0) - (b.RuleNumber ?? 0));

  for (const rule of inboundRules) {
    if (naclRuleMatchesPort(rule, port) && naclRuleMatchesWorldCidr(rule)) {
      // RuleAction "allow" or "deny"
      return rule.RuleAction === "allow";
    }
  }
  // Default: deny
  return false;
}

function naclRuleMatchesPort(rule: NetworkAclEntry, port: number): boolean {
  // Protocol -1 means all traffic
  if (rule.Protocol === "-1") return true;
  // Protocol 6 = TCP, 17 = UDP
  if (rule.Protocol !== "6" && rule.Protocol !== "17") return false;
  const from = rule.PortRange?.From ?? 0;
  const to = rule.PortRange?.To ?? 65535;
  return port >= from && port <= to;
}

function naclRuleMatchesWorldCidr(rule: NetworkAclEntry): boolean {
  return rule.CidrBlock === "0.0.0.0/0" || rule.Ipv6CidrBlock === "::/0";
}

export class NetworkReachabilityScanner implements Scanner {
  readonly moduleName = "network_reachability";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region, ctx.credentials);

      // Get EIPs for lookup
      const eipMap = new Map<string, string>(); // instanceId -> EIP
      try {
        const eipResp = await client.send(new DescribeAddressesCommand({}));
        for (const addr of eipResp.Addresses ?? []) {
          if (addr.InstanceId && addr.PublicIp) {
            eipMap.set(addr.InstanceId, addr.PublicIp);
          }
        }
      } catch (e: unknown) {
        warnings.push(`Could not list Elastic IPs: ${e instanceof Error ? e.message : String(e)}`);
      }

      // Get instances
      const instances: Instance[] = [];
      let nextToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeInstancesCommand({ NextToken: nextToken }),
        );
        for (const res of resp.Reservations ?? []) {
          if (res.Instances) instances.push(...res.Instances);
        }
        nextToken = resp.NextToken;
      } while (nextToken);

      // Filter to instances with public IPs or EIPs
      const publicInstances = instances.filter((inst) => {
        const instId = inst.InstanceId ?? "";
        return inst.PublicIpAddress || eipMap.has(instId);
      });

      // Collect all SG IDs and subnet IDs
      const sgIds = new Set<string>();
      const subnetIds = new Set<string>();
      for (const inst of publicInstances) {
        for (const sg of inst.SecurityGroups ?? []) {
          if (sg.GroupId) sgIds.add(sg.GroupId);
        }
        if (inst.SubnetId) subnetIds.add(inst.SubnetId);
      }

      // Fetch all referenced SGs
      const sgMap = new Map<string, SecurityGroup>();
      if (sgIds.size > 0) {
        const sgResp = await client.send(
          new DescribeSecurityGroupsCommand({
            GroupIds: [...sgIds],
          }),
        );
        for (const sg of sgResp.SecurityGroups ?? []) {
          if (sg.GroupId) sgMap.set(sg.GroupId, sg);
        }
      }

      // Fetch NACLs for referenced subnets
      const subnetNaclMap = new Map<string, NetworkAcl>(); // subnetId -> NACL
      if (subnetIds.size > 0) {
        let naclToken: string | undefined;
        const allNacls: NetworkAcl[] = [];
        do {
          const naclResp = await client.send(
            new DescribeNetworkAclsCommand({
              Filters: [{ Name: "association.subnet-id", Values: [...subnetIds] }],
              NextToken: naclToken,
            }),
          );
          if (naclResp.NetworkAcls) allNacls.push(...naclResp.NetworkAcls);
          naclToken = naclResp.NextToken;
        } while (naclToken);

        for (const nacl of allNacls) {
          for (const assoc of nacl.Associations ?? []) {
            if (assoc.SubnetId) {
              subnetNaclMap.set(assoc.SubnetId, nacl);
            }
          }
        }
      }

      // Analyze each public instance
      for (const inst of publicInstances) {
        const instId = inst.InstanceId ?? "unknown";
        const instArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`;
        const publicIp = inst.PublicIpAddress ?? eipMap.get(instId) ?? "unknown";
        const subnetId = inst.SubnetId ?? "";

        // Get this instance's SGs
        const instSgs: SecurityGroup[] = [];
        for (const sg of inst.SecurityGroups ?? []) {
          if (sg.GroupId) {
            const fullSg = sgMap.get(sg.GroupId);
            if (fullSg) instSgs.push(fullSg);
          }
        }

        const nacl = subnetNaclMap.get(subnetId);

        // Check each high-risk port
        for (const [portStr, portName] of Object.entries(HIGH_RISK_PORTS)) {
          const port = Number(portStr);
          const sgAllows = sgAllowsPort(instSgs, port);
          const naclAllows = nacl ? naclAllowsPort(nacl, port) : true; // if no NACL info, assume allow

          if (sgAllows && naclAllows) {
            findings.push(
              makeFinding({
                riskScore: 9.5,
                title: `EC2 ${instId} (${publicIp}): ${portName} (${port}) reachable from internet`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" has public IP ${publicIp} and both its security group(s) and subnet NACL allow inbound ${portName} (port ${port}) from the internet.`,
                impact:
                  `${portName} is directly reachable from the internet, enabling brute-force, exploitation, or unauthorized access.`,
                remediationSteps: [
                  `Restrict security group inbound rules for port ${port} to specific IPs.`,
                  "Use Systems Manager Session Manager or a bastion host instead of direct access.",
                  "Add NACL deny rules for high-risk ports as an additional layer.",
                  "Enable VPC Flow Logs to monitor connection attempts.",
                ],
              }),
            );
          } else if (sgAllows && !naclAllows) {
            findings.push(
              makeFinding({
                riskScore: 2.0,
                title: `EC2 ${instId}: ${portName} (${port}) allowed by SG but blocked by NACL`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" (${publicIp}) has security group rules allowing ${portName} (port ${port}) from the internet, but the subnet NACL blocks it.`,
                impact:
                  "Currently protected by NACL, but the SG is overly permissive. NACL changes could expose the port.",
                remediationSteps: [
                  `Tighten the security group rules for port ${port} to match the intended access.`,
                  "Do not rely solely on NACLs for access control.",
                ],
              }),
            );
          }
        }

        // Check for all-ports open via SG + NACL
        if (sgAllowsAllPorts(instSgs)) {
          // Check if NACL is also wide open (allows common ports)
          const naclOpen = nacl ? naclAllowsPort(nacl, 80) : true; // proxy check with port 80
          if (naclOpen) {
            findings.push(
              makeFinding({
                riskScore: 8.0,
                title: `EC2 ${instId} (${publicIp}): all ports reachable from internet`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" has public IP ${publicIp} and its security group allows all ports from the internet with no NACL restriction.`,
                impact:
                  "All services on this instance are exposed to the internet, creating a large attack surface.",
                remediationSteps: [
                  "Replace the all-ports SG rule with specific port rules.",
                  "Implement NACL rules to restrict inbound traffic as defense in depth.",
                  "Audit all services running on the instance.",
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
        resourcesScanned: publicInstances.length,
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

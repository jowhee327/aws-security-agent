import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeInstancesCommand,
  DescribeFlowLogsCommand,
  DescribeSecurityGroupsCommand,
  type Vpc,
} from "@aws-sdk/client-ec2";
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

export class VpcScanner implements Scanner {
  readonly moduleName = "vpc";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(EC2Client, region);

      // Get all VPCs
      const vpcs: Vpc[] = [];
      let vpcToken: string | undefined;
      do {
        const resp = await client.send(
          new DescribeVpcsCommand({ NextToken: vpcToken }),
        );
        if (resp.Vpcs) vpcs.push(...resp.Vpcs);
        vpcToken = resp.NextToken;
      } while (vpcToken);

      for (const vpc of vpcs) {
        const vpcId = vpc.VpcId ?? "unknown";
        const vpcArn = `arn:${partition}:ec2:${region}:${vpc.OwnerId}:vpc/${vpcId}`;

        // Check default VPC for active instances
        if (vpc.IsDefault) {
          try {
            const instResp = await client.send(
              new DescribeInstancesCommand({
                Filters: [
                  { Name: "vpc-id", Values: [vpcId] },
                  {
                    Name: "instance-state-name",
                    Values: ["running", "stopped"],
                  },
                ],
              }),
            );

            let instanceCount = 0;
            for (const res of instResp.Reservations ?? []) {
              instanceCount += res.Instances?.length ?? 0;
            }

            if (instanceCount > 0) {
              findings.push(
                makeFinding({
                  riskScore: 7.0,
                  title: `Default VPC ${vpcId} has ${instanceCount} active instance(s)`,
                  resourceType: "AWS::EC2::VPC",
                  resourceId: vpcId,
                  resourceArn: vpcArn,
                  region,
                  description: `The default VPC "${vpcId}" in ${region} has ${instanceCount} running or stopped instance(s).`,
                  impact:
                    "Default VPCs have permissive networking defaults (public subnets, internet gateways) that may expose workloads unintentionally.",
                  remediationSteps: [
                    "Migrate instances to a custom VPC with properly configured subnets and security.",
                    "Delete the default VPC after migration if not needed.",
                    "If the default VPC must be retained, harden its security groups and NACLs.",
                  ],
                }),
              );
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Instance check failed for default VPC ${vpcId}: ${msg}`);
          }
        }

        // Check VPC Flow Logs
        try {
          const flowResp = await client.send(
            new DescribeFlowLogsCommand({
              Filter: [
                { Name: "resource-id", Values: [vpcId] },
              ],
            }),
          );

          if ((flowResp.FlowLogs ?? []).length === 0) {
            findings.push(
              makeFinding({
                riskScore: 7.0,
                title: `VPC ${vpcId} has no flow logs enabled`,
                resourceType: "AWS::EC2::VPC",
                resourceId: vpcId,
                resourceArn: vpcArn,
                region,
                description: `VPC "${vpcId}" in ${region} does not have VPC Flow Logs enabled.`,
                impact:
                  "Network traffic is not being logged. Suspicious connections, data exfiltration, or lateral movement cannot be detected.",
                remediationSteps: [
                  "Enable VPC Flow Logs for this VPC.",
                  "Send flow logs to CloudWatch Logs or S3 for analysis.",
                  "Consider using REJECT-only flow logs as a minimum for security monitoring.",
                ],
              }),
            );
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Flow log check failed for VPC ${vpcId}: ${msg}`);
        }

        // Check default security group for inbound rules
        try {
          const sgResp = await client.send(
            new DescribeSecurityGroupsCommand({
              Filters: [
                { Name: "vpc-id", Values: [vpcId] },
                { Name: "group-name", Values: ["default"] },
              ],
            }),
          );

          for (const sg of sgResp.SecurityGroups ?? []) {
            const inboundRules = sg.IpPermissions ?? [];
            // Filter out self-referencing rules (default SG default rule)
            const nonSelfRules = inboundRules.filter((perm) => {
              const hasNonSelfSource =
                (perm.IpRanges?.length ?? 0) > 0 ||
                (perm.Ipv6Ranges?.length ?? 0) > 0 ||
                (perm.PrefixListIds?.length ?? 0) > 0;

              const hasExternalSgRef = (perm.UserIdGroupPairs ?? []).some(
                (pair) => pair.GroupId !== sg.GroupId,
              );

              return hasNonSelfSource || hasExternalSgRef;
            });

            if (nonSelfRules.length > 0) {
              findings.push(
                makeFinding({
                  riskScore: 5.5,
                  title: `Default security group in VPC ${vpcId} has custom inbound rules`,
                  resourceType: "AWS::EC2::SecurityGroup",
                  resourceId: sg.GroupId ?? "unknown",
                  resourceArn: `arn:${partition}:ec2:${region}:${vpc.OwnerId}:security-group/${sg.GroupId}`,
                  region,
                  description: `The default security group in VPC "${vpcId}" has ${nonSelfRules.length} custom inbound rule(s) beyond the default self-referencing rule.`,
                  impact:
                    "Resources accidentally assigned to the default security group may have unintended network access.",
                  remediationSteps: [
                    "Remove all inbound and outbound rules from the default security group.",
                    "Create purpose-specific security groups for your workloads.",
                    "Use AWS Config rules to detect modifications to the default security group.",
                  ],
                }),
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Default SG check failed for VPC ${vpcId}: ${msg}`);
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: vpcs.length,
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

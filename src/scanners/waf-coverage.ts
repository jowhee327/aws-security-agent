import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  type LoadBalancer,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  WAFV2Client,
  GetWebACLForResourceCommand,
} from "@aws-sdk/client-wafv2";
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

export class WafCoverageScanner implements Scanner {
  readonly moduleName = "waf_coverage";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const elbClient = createClient(ElasticLoadBalancingV2Client, region, ctx.credentials);
      const wafClient = createClient(WAFV2Client, region, ctx.credentials);

      // List all ELBv2 load balancers
      const loadBalancers: LoadBalancer[] = [];
      let marker: string | undefined;
      do {
        const resp = await elbClient.send(
          new DescribeLoadBalancersCommand({ Marker: marker }),
        );
        if (resp.LoadBalancers) {
          loadBalancers.push(...resp.LoadBalancers);
        }
        marker = resp.NextMarker;
      } while (marker);

      // Filter to internet-facing only
      const internetFacing = loadBalancers.filter((lb) => lb.Scheme === "internet-facing");

      for (const lb of internetFacing) {
        const lbName = lb.LoadBalancerName ?? "unknown";
        const lbArn = lb.LoadBalancerArn ?? "unknown";
        const lbType = lb.Type ?? "unknown";

        // WAF only applies to ALB (application), not NLB (network) or GLB (gateway)
        if (lbType !== "application") {
          warnings.push(
            `Skipping ${lbType} load balancer "${lbName}" — WAF Web ACL association is only supported for ALBs.`,
          );
          continue;
        }

        try {
          const wafResp = await wafClient.send(
            new GetWebACLForResourceCommand({ ResourceArn: lbArn }),
          );

          if (!wafResp.WebACL) {
            findings.push(
              makeFinding({
                riskScore: 7.5,
                title: `Internet-facing ALB ${lbName} has no WAF protection`,
                resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
                resourceId: lbName,
                resourceArn: lbArn,
                region,
                description: `Internet-facing Application Load Balancer "${lbName}" does not have a WAF Web ACL associated. Traffic is not inspected for common web exploits.`,
                impact: "Without WAF, the ALB is exposed to SQL injection, XSS, and other OWASP Top 10 attacks",
                remediationSteps: [
                  "Create a WAFv2 Web ACL with managed rule groups (e.g., AWSManagedRulesCommonRuleSet).",
                  "Associate the Web ACL with the ALB using the REGIONAL scope.",
                  "Enable WAF logging for visibility into blocked requests.",
                  "Consider adding rate-based rules to mitigate DDoS at the application layer.",
                ],
              }),
            );
          }
        } catch (wafErr: unknown) {
          const errMsg = wafErr instanceof Error ? wafErr.message : String(wafErr);
          const errName = wafErr instanceof Error ? (wafErr as any).name ?? "" : "";

          // Handle WAFv2 not available or access denied gracefully
          if (errName === "WAFNonexistentItemException") {
            // No Web ACL associated — same as null response
            findings.push(
              makeFinding({
                riskScore: 7.5,
                title: `Internet-facing ALB ${lbName} has no WAF protection`,
                resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
                resourceId: lbName,
                resourceArn: lbArn,
                region,
                description: `Internet-facing Application Load Balancer "${lbName}" does not have a WAF Web ACL associated. Traffic is not inspected for common web exploits.`,
                impact: "Without WAF, the ALB is exposed to SQL injection, XSS, and other OWASP Top 10 attacks",
                remediationSteps: [
                  "Create a WAFv2 Web ACL with managed rule groups (e.g., AWSManagedRulesCommonRuleSet).",
                  "Associate the Web ACL with the ALB using the REGIONAL scope.",
                  "Enable WAF logging for visibility into blocked requests.",
                  "Consider adding rate-based rules to mitigate DDoS at the application layer.",
                ],
              }),
            );
          } else if (errName === "AccessDeniedException" || errName === "WAFInvalidParameterException") {
            warnings.push(
              `Could not check WAF for ALB "${lbName}": ${errMsg}. Ensure wafv2:GetWebACLForResource permission is granted.`,
            );
          } else {
            warnings.push(`Error checking WAF for ALB "${lbName}": ${errMsg}`);
          }
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: internetFacing.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const errName = err instanceof Error ? (err as any).name ?? "" : "";

      // If WAFv2 or ELBv2 is not available or access denied, return success with warning
      if (errName === "AccessDeniedException" || errName === "UnrecognizedClientException") {
        return {
          module: this.moduleName,
          status: "success",
          warnings: [`WAF coverage check skipped: ${errMsg}`],
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      return {
        module: this.moduleName,
        status: "error",
        error: errMsg,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

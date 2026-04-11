import {
  ConfigServiceClient,
  DescribeComplianceByConfigRuleCommand,
  GetComplianceDetailsByConfigRuleCommand,
  type ComplianceByConfigRule,
} from "@aws-sdk/client-config-service";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

/** Security-related Config rule name patterns that warrant HIGH severity */
const SECURITY_RULE_PATTERNS = [
  "securitygroup", "security-group",
  "encryption", "encrypted",
  "public", "unrestricted",
  "mfa", "password", "access-key",
  "root", "admin",
  "logging", "cloudtrail",
  "iam", "kms", "ssl", "tls",
  "vpc-flow", "guardduty", "securityhub",
];

function ruleIsSecurityRelated(ruleName: string): boolean {
  const lower = ruleName.toLowerCase();
  return SECURITY_RULE_PATTERNS.some((pat) => lower.includes(pat));
}

export class ConfigRulesFindingsScanner implements Scanner {
  readonly moduleName = "config_rules_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(ConfigServiceClient, region, ctx.credentials);

      // Step 1: Get all rules and their compliance status
      let nextToken: string | undefined;
      const nonCompliantRules: ComplianceByConfigRule[] = [];

      do {
        const resp = await client.send(
          new DescribeComplianceByConfigRuleCommand({ NextToken: nextToken }),
        );

        for (const rule of resp.ComplianceByConfigRules ?? []) {
          resourcesScanned++;
          if (rule.Compliance?.ComplianceType === "NON_COMPLIANT") {
            nonCompliantRules.push(rule);
          }
        }

        nextToken = resp.NextToken;
      } while (nextToken);

      if (resourcesScanned === 0) {
        warnings.push("AWS Config is not enabled in this region or no Config Rules are defined.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      // Step 2: For each non-compliant rule, get the non-compliant resources
      for (const rule of nonCompliantRules) {
        const ruleName = rule.ConfigRuleName ?? "unknown";

        try {
          let detailToken: string | undefined;
          do {
            const detailResp = await client.send(
              new GetComplianceDetailsByConfigRuleCommand({
                ConfigRuleName: ruleName,
                ComplianceTypes: ["NON_COMPLIANT"],
                NextToken: detailToken,
              }),
            );

            for (const evalResult of detailResp.EvaluationResults ?? []) {
              const qualifier = evalResult.EvaluationResultIdentifier?.EvaluationResultQualifier;
              const resourceType = qualifier?.ResourceType ?? "AWS::Unknown";
              const resourceId = qualifier?.ResourceId ?? "unknown";
              const annotation = evalResult.Annotation;

              const isSecurityRule = ruleIsSecurityRelated(ruleName);
              const riskScore = isSecurityRule ? 7.5 : 5.5;
              const severity = severityFromScore(riskScore);

              const descParts = [`Config Rule: ${ruleName}`, `Resource Type: ${resourceType}`];
              if (annotation) descParts.push(`Annotation: ${annotation}`);

              findings.push({
                severity,
                title: `${ruleName} - Non-Compliant`,
                resourceType,
                resourceId,
                resourceArn: `arn:${partition}:config:${region}:${accountId}:resource/${resourceType}/${resourceId}`,
                region,
                description: descParts.join(". "),
                impact: `Resource is non-compliant with Config Rule: ${ruleName}`,
                riskScore,
                remediationSteps: [
                  `Review the Config Rule "${ruleName}" in the AWS Config console.`,
                  `Check resource ${resourceId} for compliance violations.`,
                  "Follow the rule's remediation guidance to bring the resource into compliance.",
                ],
                priority: priorityFromSeverity(severity),
                module: this.moduleName,
                accountId,
              });
            }

            detailToken = detailResp.NextToken;
          } while (detailToken);
        } catch (detailErr) {
          const msg = detailErr instanceof Error ? detailErr.message : String(detailErr);
          warnings.push(`Failed to get details for rule ${ruleName}: ${msg}`);
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
      const msg = err instanceof Error ? err.message : String(err);

      // Config not enabled is a common case — return success with warning
      if (
        msg.includes("NoSuchConfigurationRecorder") ||
        msg.includes("InsufficientDeliveryPolicy") ||
        msg.includes("No Configuration Recorder")
      ) {
        warnings.push("AWS Config is not enabled in this region.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      return {
        module: this.moduleName,
        status: "error",
        error: `Config Rules scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

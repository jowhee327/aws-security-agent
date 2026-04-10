import {
  IAMClient,
  GetAccountPasswordPolicyCommand,
} from "@aws-sdk/client-iam";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient, getIamRegion } from "../utils/aws-client.js";
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

export class IamPasswordPolicyScanner implements Scanner {
  readonly moduleName = "iam_password_policy";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const iamRegion = getIamRegion(region);
      const client = createClient(IAMClient, iamRegion);
      const policyArn = `arn:${partition}:iam::${accountId}:account-password-policy`;

      let policy;
      try {
        const resp = await client.send(new GetAccountPasswordPolicyCommand({}));
        policy = resp.PasswordPolicy;
      } catch (e: unknown) {
        if (e instanceof Error && e.name === "NoSuchEntityException") {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: "No IAM password policy configured",
              resourceType: "AWS::IAM::AccountPasswordPolicy",
              resourceId: "account-password-policy",
              resourceArn: policyArn,
              region: iamRegion,
              description:
                "The AWS account does not have a custom password policy. The default policy has weak requirements.",
              impact:
                "Users can set weak passwords that are easily compromised via brute-force or credential stuffing attacks.",
              remediationSteps: [
                "Create an IAM password policy with minimum length >= 8.",
                "Require uppercase, lowercase, numbers, and symbols.",
                "Set maximum password age to 90 days or less.",
                "Set password reuse prevention to at least 5 previous passwords.",
              ],
            }),
          );

          return {
            module: this.moduleName,
            status: "success",
            warnings: warnings.length > 0 ? warnings : undefined,
            resourcesScanned: 1,
            findingsCount: findings.length,
            scanTimeMs: Date.now() - startMs,
            findings,
          };
        }
        throw e;
      }

      if (!policy) {
        warnings.push("Password policy response was empty.");
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

      // Check minimum password length
      if ((policy.MinimumPasswordLength ?? 0) < 8) {
        findings.push(
          makeFinding({
            riskScore: 7.0,
            title: "IAM password policy minimum length is too short",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            resourceId: "account-password-policy",
            resourceArn: policyArn,
            region: iamRegion,
            description: `Minimum password length is ${policy.MinimumPasswordLength ?? 0}, which is below the recommended minimum of 8 characters.`,
            impact:
              "Short passwords are more vulnerable to brute-force attacks.",
            remediationSteps: [
              "Update the password policy to require at least 8 characters.",
              "Consider requiring 14+ characters for stronger security.",
            ],
          }),
        );
      }

      // Check complexity requirements
      const complexityChecks = [
        { field: policy.RequireUppercaseCharacters, label: "uppercase characters" },
        { field: policy.RequireLowercaseCharacters, label: "lowercase characters" },
        { field: policy.RequireNumbers, label: "numbers" },
        { field: policy.RequireSymbols, label: "symbols" },
      ];

      const missing = complexityChecks
        .filter((c) => !c.field)
        .map((c) => c.label);

      if (missing.length > 0) {
        findings.push(
          makeFinding({
            riskScore: 6.0,
            title: "IAM password policy missing complexity requirements",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            resourceId: "account-password-policy",
            resourceArn: policyArn,
            region: iamRegion,
            description: `Password policy does not require: ${missing.join(", ")}.`,
            impact:
              "Passwords without complexity requirements are easier to guess or crack.",
            remediationSteps: [
              "Update the password policy to require uppercase, lowercase, numbers, and symbols.",
            ],
          }),
        );
      }

      // Check max password age
      if (!policy.MaxPasswordAge || policy.MaxPasswordAge === 0) {
        findings.push(
          makeFinding({
            riskScore: 5.5,
            title: "IAM password policy has no password expiry",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            resourceId: "account-password-policy",
            resourceArn: policyArn,
            region: iamRegion,
            description:
              "No maximum password age is set. Passwords never expire.",
            impact:
              "Compromised passwords remain valid indefinitely, increasing the window for unauthorized access.",
            remediationSteps: [
              "Set MaxPasswordAge to 90 days or less.",
              "Combine with MFA for defense in depth.",
            ],
          }),
        );
      }

      // Check password reuse prevention
      if (!policy.PasswordReusePrevention || policy.PasswordReusePrevention === 0) {
        findings.push(
          makeFinding({
            riskScore: 5.0,
            title: "IAM password policy has no reuse prevention",
            resourceType: "AWS::IAM::AccountPasswordPolicy",
            resourceId: "account-password-policy",
            resourceArn: policyArn,
            region: iamRegion,
            description:
              "No password reuse prevention is configured. Users can reuse previous passwords.",
            impact:
              "Users may cycle back to previously compromised passwords.",
            remediationSteps: [
              "Set PasswordReusePrevention to at least 5.",
              "This prevents reuse of the last 5 passwords.",
            ],
          }),
        );
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 1,
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

import {
  LambdaClient,
  ListFunctionsCommand,
  type FunctionConfiguration,
} from "@aws-sdk/client-lambda";
import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeInstanceAttributeCommand,
  type Instance,
} from "@aws-sdk/client-ec2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; matchType: "value" | "name" }> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/, matchType: "value" },
  { name: "Private Key", pattern: /-----BEGIN.*PRIVATE KEY-----/, matchType: "value" },
  { name: "Password in env var", pattern: /^(PASSWORD|PASSWD|DB_PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|AUTH_TOKEN)$/i, matchType: "name" },
];

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

export class SecretExposureScanner implements Scanner {
  readonly moduleName = "secret_exposure";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      // --- Lambda functions ---
      try {
        const lambda = createClient(LambdaClient, region);
        const functions: FunctionConfiguration[] = [];
        let marker: string | undefined;
        do {
          const resp = await lambda.send(
            new ListFunctionsCommand({ Marker: marker }),
          );
          if (resp.Functions) functions.push(...resp.Functions);
          marker = resp.NextMarker;
        } while (marker);

        resourcesScanned += functions.length;

        for (const fn of functions) {
          const fnName = fn.FunctionName ?? "unknown";
          const fnArn =
            fn.FunctionArn ??
            `arn:${partition}:lambda:${region}:${accountId}:function:${fnName}`;
          const envVars = fn.Environment?.Variables ?? {};

          for (const [varName, varValue] of Object.entries(envVars)) {
            for (const sp of SECRET_PATTERNS) {
              if (sp.matchType === "name") {
                if (sp.pattern.test(varName)) {
                  findings.push(
                    makeFinding({
                      riskScore: 7.5,
                      title: `Lambda ${fnName} has suspicious env var "${varName}"`,
                      resourceType: "AWS::Lambda::Function",
                      resourceId: fnName,
                      resourceArn: fnArn,
                      region,
                      description: `Lambda function "${fnName}" has an environment variable named "${varName}" which may contain a secret.`,
                      impact:
                        "Secrets in Lambda environment variables are visible to anyone with lambda:GetFunctionConfiguration permission and may leak through logs.",
                      remediationSteps: [
                        "Move the secret to AWS Secrets Manager or SSM Parameter Store (SecureString).",
                        "Update the Lambda function to fetch the secret at runtime.",
                        "Rotate the exposed credential immediately.",
                      ],
                    }),
                  );
                }
              } else {
                // match value
                if (sp.pattern.test(varValue)) {
                  const riskScore = sp.name === "AWS Access Key" ? 9.5 : 9.0;
                  findings.push(
                    makeFinding({
                      riskScore,
                      title: `Lambda ${fnName} env var contains ${sp.name}`,
                      resourceType: "AWS::Lambda::Function",
                      resourceId: fnName,
                      resourceArn: fnArn,
                      region,
                      description: `Lambda function "${fnName}" has an environment variable containing a ${sp.name} pattern.`,
                      impact:
                        "Hard-coded credentials in Lambda environment variables can be extracted by any principal with read access to the function configuration.",
                      remediationSteps: [
                        "Remove the hard-coded credential from environment variables.",
                        "Use AWS Secrets Manager or SSM Parameter Store (SecureString) instead.",
                        "Rotate the exposed credential immediately.",
                        "Review CloudTrail logs for unauthorized use of the credential.",
                      ],
                    }),
                  );
                }
              }
            }
          }
        }
      } catch (e: unknown) {
        warnings.push(`Lambda scan error: ${e instanceof Error ? e.message : String(e)}`);
      }

      // --- EC2 userData ---
      try {
        const ec2 = createClient(EC2Client, region);
        const instances: Instance[] = [];
        let nextToken: string | undefined;
        do {
          const resp = await ec2.send(
            new DescribeInstancesCommand({ NextToken: nextToken }),
          );
          for (const res of resp.Reservations ?? []) {
            if (res.Instances) instances.push(...res.Instances);
          }
          nextToken = resp.NextToken;
        } while (nextToken);

        resourcesScanned += instances.length;

        for (const inst of instances) {
          const instId = inst.InstanceId ?? "unknown";
          const instArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`;

          let userData: string | undefined;
          try {
            const attrResp = await ec2.send(
              new DescribeInstanceAttributeCommand({
                InstanceId: instId,
                Attribute: "userData",
              }),
            );
            const raw = attrResp.UserData?.Value;
            if (raw) {
              userData = Buffer.from(raw, "base64").toString("utf-8");
            }
          } catch (e: unknown) {
            warnings.push(`Could not read userData for ${instId}: ${e instanceof Error ? e.message : String(e)}`);
            continue;
          }

          if (!userData) continue;

          for (const sp of SECRET_PATTERNS) {
            if (sp.matchType === "name") continue; // name-matching doesn't apply to userData
            if (sp.pattern.test(userData)) {
              const riskScore = sp.name === "AWS Access Key" ? 9.5 : 8.0;
              findings.push(
                makeFinding({
                  riskScore,
                  title: `EC2 ${instId} userData contains ${sp.name}`,
                  resourceType: "AWS::EC2::Instance",
                  resourceId: instId,
                  resourceArn: instArn,
                  region,
                  description: `EC2 instance "${instId}" has user data containing a ${sp.name} pattern.`,
                  impact:
                    "Instance user data is accessible to anyone with ec2:DescribeInstanceAttribute permission and from the instance metadata service.",
                  remediationSteps: [
                    "Remove the secret from instance user data.",
                    "Use IAM instance profiles for AWS API access instead of embedding keys.",
                    "Use Secrets Manager or SSM Parameter Store for other secrets.",
                    "Rotate the exposed credential immediately.",
                  ],
                }),
              );
            }
          }
        }
      } catch (e: unknown) {
        warnings.push(`EC2 userData scan error: ${e instanceof Error ? e.message : String(e)}`);
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

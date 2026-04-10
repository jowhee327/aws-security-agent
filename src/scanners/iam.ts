import {
  IAMClient,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListAttachedUserPoliciesCommand,
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  type User,
} from "@aws-sdk/client-iam";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient, getIamRegion } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

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

function getOverPermissivePolicies(partition: string): string[] {
  return [
    `arn:${partition}:iam::aws:policy/AdministratorAccess`,
    `arn:${partition}:iam::aws:policy/PowerUserAccess`,
    `arn:${partition}:iam::aws:policy/IAMFullAccess`,
  ];
}

async function waitForCredentialReport(client: IAMClient): Promise<Uint8Array | undefined> {
  await client.send(new GenerateCredentialReportCommand({}));

  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const report = await client.send(new GetCredentialReportCommand({}));
      if (report.Content) return report.Content;
    } catch (e: unknown) {
      if (
        e instanceof Error &&
        (e.name === "ReportNotPresent" || e.name === "CredentialReportNotReadyException")
      ) {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
        continue;
      }
      throw e;
    }
  }
  return undefined;
}

export class IamScanner implements Scanner {
  readonly moduleName = "iam";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    const iamRegion = getIamRegion(region);

    try {
      const client = createClient(IAMClient, iamRegion);
      const overPermissivePolicies = getOverPermissivePolicies(partition);

      // GetAccountSummary works in all partitions (including China) and is needed
      // for user counts. Root-specific checks below are skipped in China regions
      // because China accounts have no root user.
      const summary = await client.send(new GetAccountSummaryCommand({}));
      const summaryMap = summary.SummaryMap ?? {};
      let resourcesScanned = 1; // account itself

      const rootArn = `arn:${partition}:iam::${accountId}:root`;
      const isChinaRegion = region.startsWith("cn-");

      // Root MFA check — skip in China (no root user)
      if (!isChinaRegion) {
        if (summaryMap["AccountMFAEnabled"] === 0) {
          findings.push(
            makeFinding({
              riskScore: 10.0,
              title: "Root account does not have MFA enabled",
              resourceType: "AWS::IAM::Root",
              resourceId: "root",
              resourceArn: rootArn,
              region: "global",
              description:
                "The AWS root account does not have multi-factor authentication enabled.",
              impact:
                "Compromised root credentials would grant unrestricted access to all AWS resources with no second factor of authentication.",
              remediationSteps: [
                "Enable MFA on the root account immediately using a hardware or virtual MFA device.",
                "Store the MFA device in a secure location.",
                "Avoid using the root account for daily operations.",
              ],
            }),
          );
        }
      } else {
        warnings.push("Root user checks skipped: AWS China regions use partner-managed accounts without root user.");
      }

      // Root access key check — skip in China (no root user)
      if (!isChinaRegion) {
        let rootHasAccessKey = false;
        try {
          const content = await waitForCredentialReport(client);
          if (content) {
            const csv = Buffer.from(content).toString("utf-8");
            const lines = csv.split("\n");
            const headers = lines[0]?.split(",") ?? [];
            const ak1Idx = headers.indexOf("access_key_1_active");
            const ak2Idx = headers.indexOf("access_key_2_active");
            if (lines.length > 1) {
              const rootRow = lines[1]?.split(",") ?? [];
              if (
                (ak1Idx >= 0 && rootRow[ak1Idx] === "true") ||
                (ak2Idx >= 0 && rootRow[ak2Idx] === "true")
              ) {
                rootHasAccessKey = true;
              }
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Credential report check failed: ${msg}`);
        }

        if (rootHasAccessKey) {
          findings.push(
            makeFinding({
              riskScore: 9.5,
              title: "Root account has active access keys",
              resourceType: "AWS::IAM::Root",
              resourceId: "root",
              resourceArn: rootArn,
              region: "global",
              description: "The root account has one or more active access keys.",
              impact:
                "Access keys for the root account provide unrestricted API access. If leaked, the entire account is compromised.",
              remediationSteps: [
                "Delete all root account access keys.",
                "Use IAM users or roles with least-privilege policies instead.",
              ],
            }),
          );
        }
      }

      // List all IAM users
      const users: User[] = [];
      let marker: string | undefined;
      do {
        const resp = await client.send(
          new ListUsersCommand({ Marker: marker }),
        );
        if (resp.Users) users.push(...resp.Users);
        marker = resp.IsTruncated ? resp.Marker : undefined;
      } while (marker);

      resourcesScanned += users.length;
      const now = Date.now();

      for (const user of users) {
        const userName = user.UserName ?? "unknown";
        const userArn = user.Arn ?? `arn:${partition}:iam::${accountId}:user/${userName}`;

        // List access keys for this user (needed for both age check and inactivity check)
        let activeKeys: Array<{
          keyId: string;
          createDate: number;
          lastUsed: number;
        }> = [];
        try {
          const keysResp = await client.send(
            new ListAccessKeysCommand({ UserName: userName }),
          );
          for (const key of keysResp.AccessKeyMetadata ?? []) {
            if (key.Status !== "Active") continue;
            const keyId = key.AccessKeyId ?? "unknown";
            const keyCreateDate = key.CreateDate?.getTime() ?? now;

            // Check last used time for each active key
            let lastUsedTime = 0;
            try {
              const lastUsedResp = await client.send(
                new GetAccessKeyLastUsedCommand({ AccessKeyId: keyId }),
              );
              lastUsedTime =
                lastUsedResp.AccessKeyLastUsed?.LastUsedDate?.getTime() ?? 0;
            } catch (e: unknown) {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(
                `Failed to get last used time for key ${keyId} of user ${userName}: ${msg}`,
              );
            }

            activeKeys.push({
              keyId,
              createDate: keyCreateDate,
              lastUsed: lastUsedTime,
            });

            // Check access key age
            const keyAge = now - keyCreateDate;
            if (keyAge > NINETY_DAYS_MS) {
              const ageDays = Math.round(keyAge / (24 * 60 * 60 * 1000));
              findings.push(
                makeFinding({
                  riskScore: 7.5,
                  title: `IAM user ${userName} has access key older than 90 days`,
                  resourceType: "AWS::IAM::AccessKey",
                  resourceId: keyId,
                  resourceArn: userArn,
                  region: "global",
                  description: `Access key ${keyId} for user "${userName}" is ${ageDays} days old.`,
                  impact:
                    "Old access keys are more likely to have been exposed or leaked over time.",
                  remediationSteps: [
                    "Rotate the access key by creating a new key and deleting the old one.",
                    "Implement an access key rotation policy (maximum 90 days).",
                    "Consider using IAM roles or temporary credentials instead.",
                  ],
                }),
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Access key check failed for user ${userName}: ${msg}`);
        }

        // Check inactive users: both console AND API access must be inactive >90 days
        const passwordLastUsed = user.PasswordLastUsed?.getTime() ?? 0;
        const createTime = user.CreateDate?.getTime() ?? 0;
        const latestKeyUsed = activeKeys.reduce(
          (max, k) => Math.max(max, k.lastUsed),
          0,
        );
        const latestActivity = Math.max(passwordLastUsed, createTime, latestKeyUsed);
        const daysSinceActivity =
          (now - latestActivity) / (24 * 60 * 60 * 1000);
        if (daysSinceActivity > 90) {
          findings.push(
            makeFinding({
              riskScore: 5.0,
              title: `IAM user ${userName} inactive for over 90 days`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has not logged in or used credentials for ${Math.round(daysSinceActivity)} days.`,
              impact:
                "Inactive accounts increase attack surface without providing operational value.",
              remediationSteps: [
                "Verify if the user account is still needed.",
                "Disable or delete the user if no longer required.",
                "Remove access keys and console access for dormant accounts.",
              ],
            }),
          );
        }

        // Check over-permissive policies
        try {
          const policiesResp = await client.send(
            new ListAttachedUserPoliciesCommand({ UserName: userName }),
          );
          for (const policy of policiesResp.AttachedPolicies ?? []) {
            const policyArn = policy.PolicyArn ?? "";
            if (overPermissivePolicies.includes(policyArn)) {
              findings.push(
                makeFinding({
                  riskScore: 7.0,
                  title: `IAM user ${userName} has ${policy.PolicyName} attached`,
                  resourceType: "AWS::IAM::User",
                  resourceId: userName,
                  resourceArn: userArn,
                  region: "global",
                  description: `User "${userName}" has the over-permissive managed policy "${policy.PolicyName}" (${policyArn}) directly attached.`,
                  impact:
                    "The user has far more permissions than likely needed, violating least-privilege principle.",
                  remediationSteps: [
                    `Remove the ${policy.PolicyName} policy from user "${userName}".`,
                    "Create a custom policy granting only the specific permissions required.",
                    "Use IAM Access Analyzer to identify actually used permissions.",
                  ],
                }),
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Policy check failed for user ${userName}: ${msg}`);
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

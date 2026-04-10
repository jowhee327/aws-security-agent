import {
  IAMClient,
  ListUsersCommand,
  ListMFADevicesCommand,
  GetLoginProfileCommand,
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

export class IamMfaAuditScanner implements Scanner {
  readonly moduleName = "iam_mfa_audit";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const iamRegion = getIamRegion(region);
      const client = createClient(IAMClient, iamRegion);

      // List all IAM users
      const users: Array<{ UserName: string; Arn: string }> = [];
      let marker: string | undefined;
      do {
        const resp = await client.send(new ListUsersCommand({ Marker: marker }));
        if (resp.Users) {
          for (const u of resp.Users) {
            users.push({
              UserName: u.UserName ?? "unknown",
              Arn: u.Arn ?? `arn:${partition}:iam::${accountId}:user/${u.UserName ?? "unknown"}`,
            });
          }
        }
        marker = resp.IsTruncated ? resp.Marker : undefined;
      } while (marker);

      if (users.length === 0) {
        return {
          module: this.moduleName,
          status: "success",
          warnings: warnings.length > 0 ? warnings : undefined,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings,
        };
      }

      let usersWithConsole = 0;
      let usersWithMfa = 0;
      let totalChecked = 0;

      for (const user of users) {
        // Check if user has console access
        let hasConsole = false;
        try {
          await client.send(new GetLoginProfileCommand({ UserName: user.UserName }));
          hasConsole = true;
          usersWithConsole++;
        } catch (e: unknown) {
          if (e instanceof Error && e.name === "NoSuchEntityException") {
            // No console access — skip MFA check for this user
            continue;
          }
          // Other errors: warn but assume console access for safety
          warnings.push(`Could not check login profile for ${user.UserName}: ${e instanceof Error ? e.message : String(e)}`);
          hasConsole = true;
          usersWithConsole++;
        }

        totalChecked++;

        // Check MFA devices
        const mfaResp = await client.send(
          new ListMFADevicesCommand({ UserName: user.UserName }),
        );
        const mfaDevices = mfaResp.MFADevices ?? [];

        if (mfaDevices.length > 0) {
          usersWithMfa++;
        } else if (hasConsole) {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: `IAM user ${user.UserName} has console access without MFA`,
              resourceType: "AWS::IAM::User",
              resourceId: user.UserName,
              resourceArn: user.Arn,
              region: iamRegion,
              description: `User "${user.UserName}" has console login enabled but no MFA device configured.`,
              impact:
                "Account is vulnerable to credential theft. If the password is compromised, there is no second factor to prevent unauthorized access.",
              remediationSteps: [
                `Enable MFA for user ${user.UserName}.`,
                "Use a virtual MFA device (e.g., Google Authenticator) or a hardware security key.",
                "Consider enforcing MFA via IAM policy conditions.",
              ],
            }),
          );
        }
      }

      // Overall MFA adoption finding
      if (usersWithConsole > 0 && usersWithMfa < usersWithConsole) {
        const adoptionPercent = Math.round((usersWithMfa / usersWithConsole) * 100);
        findings.push(
          makeFinding({
            riskScore: 6.0,
            title: "MFA adoption is not 100% for console users",
            resourceType: "AWS::IAM::Account",
            resourceId: "mfa-adoption",
            resourceArn: `arn:${partition}:iam::${accountId}:root`,
            region: iamRegion,
            description: `MFA is enabled for ${usersWithMfa}/${usersWithConsole} console users (${adoptionPercent}% adoption).`,
            impact:
              "Users without MFA present a higher risk of account compromise.",
            remediationSteps: [
              "Enable MFA for all IAM users with console access.",
              "Use an SCP or IAM policy to deny actions without MFA.",
              "Consider using AWS SSO with mandatory MFA for centralized access.",
            ],
          }),
        );
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: users.length,
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

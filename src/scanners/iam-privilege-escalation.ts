import {
  IAMClient,
  ListUsersCommand,
  ListAttachedUserPoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
  type User,
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

interface PolicyStatement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
}

function extractActions(doc: unknown): string[] {
  const actions: string[] = [];
  if (!doc || typeof doc !== "object") return actions;
  const policy = doc as { Statement?: PolicyStatement | PolicyStatement[] };
  const stmts = Array.isArray(policy.Statement)
    ? policy.Statement
    : policy.Statement
      ? [policy.Statement]
      : [];

  for (const stmt of stmts) {
    if (stmt.Effect !== "Allow") continue;
    const acts = Array.isArray(stmt.Action)
      ? stmt.Action
      : stmt.Action
        ? [stmt.Action]
        : [];
    actions.push(...acts);
  }
  return actions.map((a) => a.toLowerCase());
}

function hasAction(actions: string[], pattern: string): boolean {
  const pat = pattern.toLowerCase();
  return actions.some((a) => {
    if (a === "*") return true;
    if (a === pat) return true;
    // Wildcard match: "iam:*" matches "iam:createrole"
    if (a.endsWith("*")) {
      const prefix = a.slice(0, -1);
      if (pat.startsWith(prefix)) return true;
    }
    return false;
  });
}

export class IamPrivilegeEscalationScanner implements Scanner {
  readonly moduleName = "iam_privilege_escalation";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    const iamRegion = getIamRegion(region);

    warnings.push(
      "Note: This scanner currently checks IAM users only. Role and group policy analysis will be added in a future version.",
    );

    try {
      const client = createClient(IAMClient, iamRegion);

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

      for (const user of users) {
        const userName = user.UserName ?? "unknown";
        const userArn =
          user.Arn ??
          `arn:${partition}:iam::${accountId}:user/${userName}`;

        // Collect all allowed actions from both managed and inline policies
        const allActions: string[] = [];

        // 1. Check attached (managed) policies
        try {
          const attachedResp = await client.send(
            new ListAttachedUserPoliciesCommand({ UserName: userName }),
          );
          for (const policy of attachedResp.AttachedPolicies ?? []) {
            const policyArn = policy.PolicyArn;
            if (!policyArn) continue;
            try {
              const policyResp = await client.send(
                new GetPolicyCommand({ PolicyArn: policyArn }),
              );
              const versionId =
                policyResp.Policy?.DefaultVersionId ?? "v1";
              const versionResp = await client.send(
                new GetPolicyVersionCommand({
                  PolicyArn: policyArn,
                  VersionId: versionId,
                }),
              );
              const doc = versionResp.PolicyVersion?.Document;
              if (doc) {
                const parsed = JSON.parse(decodeURIComponent(doc));
                allActions.push(...extractActions(parsed));
              }
            } catch (e: unknown) {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(
                `Could not read policy ${policyArn} for user ${userName}: ${msg}`,
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(
            `Could not list attached policies for user ${userName}: ${msg}`,
          );
        }

        // 2. Check inline policies
        try {
          const inlineResp = await client.send(
            new ListUserPoliciesCommand({ UserName: userName }),
          );
          for (const policyName of inlineResp.PolicyNames ?? []) {
            try {
              const inlinePolicyResp = await client.send(
                new GetUserPolicyCommand({
                  UserName: userName,
                  PolicyName: policyName,
                }),
              );
              const doc = inlinePolicyResp.PolicyDocument;
              if (doc) {
                const parsed = JSON.parse(decodeURIComponent(doc));
                allActions.push(...extractActions(parsed));
              }
            } catch (e: unknown) {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(
                `Could not read inline policy ${policyName} for user ${userName}: ${msg}`,
              );
            }
          }
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(
            `Could not list inline policies for user ${userName}: ${msg}`,
          );
        }

        if (allActions.length === 0) continue;

        // Check for wildcard iam:* or full wildcard *
        if (
          hasAction(allActions, "iam:*") ||
          allActions.includes("*")
        ) {
          findings.push(
            makeFinding({
              riskScore: 9.0,
              title: `IAM user ${userName} has iam:* wildcard permissions`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has wildcard IAM permissions (iam:* or *), granting full control over identity and access management.`,
              impact:
                "The user can create, modify, or delete any IAM resource including creating admin users, modifying policies, and escalating privileges without restriction.",
              remediationSteps: [
                `Remove wildcard IAM permissions from user "${userName}".`,
                "Replace with specific, least-privilege IAM permissions.",
                "Use IAM Access Analyzer to identify actually used permissions.",
              ],
            }),
          );
          // Skip further checks — wildcard already covers everything
          continue;
        }

        // Self-grant admin: iam:PutUserPolicy or iam:AttachUserPolicy
        if (
          hasAction(allActions, "iam:putuserpolicy") ||
          hasAction(allActions, "iam:attachuserpolicy")
        ) {
          findings.push(
            makeFinding({
              riskScore: 9.5,
              title: `IAM user ${userName} can self-grant admin via policy attachment`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:PutUserPolicy or iam:AttachUserPolicy, allowing them to attach AdministratorAccess or any policy to themselves.`,
              impact:
                "The user can escalate to full administrator access by attaching an admin policy to their own account.",
              remediationSteps: [
                `Remove iam:PutUserPolicy and iam:AttachUserPolicy from user "${userName}".`,
                "Use permission boundaries to restrict policy attachment scope.",
                "Require MFA for sensitive IAM operations via condition keys.",
              ],
            }),
          );
        }

        // Create admin roles: iam:CreateRole + iam:AttachRolePolicy
        if (
          hasAction(allActions, "iam:createrole") &&
          hasAction(allActions, "iam:attachrolepolicy")
        ) {
          findings.push(
            makeFinding({
              riskScore: 8.0,
              title: `IAM user ${userName} can create admin roles`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has both iam:CreateRole and iam:AttachRolePolicy, allowing creation of new roles with admin policies.`,
              impact:
                "The user can create a new IAM role with AdministratorAccess and assume it to gain full account access.",
              remediationSteps: [
                `Restrict iam:CreateRole and iam:AttachRolePolicy with resource conditions for user "${userName}".`,
                "Use permission boundaries on all created roles.",
                "Monitor IAM role creation via CloudTrail alerts.",
              ],
            }),
          );
        }

        // PassRole + Lambda escalation: iam:PassRole + lambda:CreateFunction
        if (
          hasAction(allActions, "iam:passrole") &&
          hasAction(allActions, "lambda:createfunction")
        ) {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: `IAM user ${userName} can escalate via Lambda role passing`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:PassRole and lambda:CreateFunction, allowing them to create a Lambda function with an admin role.`,
              impact:
                "The user can pass a high-privilege role to a Lambda function and invoke it to execute actions beyond their own permissions.",
              remediationSteps: [
                `Restrict iam:PassRole to specific role ARNs for user "${userName}".`,
                "Use condition keys to limit which roles can be passed to Lambda.",
                "Implement SCP guardrails for privilege escalation paths.",
              ],
            }),
          );
        }

        // Create access keys for other users: iam:CreateAccessKey
        if (hasAction(allActions, "iam:createaccesskey")) {
          findings.push(
            makeFinding({
              riskScore: 8.0,
              title: `IAM user ${userName} can create access keys for other users`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:CreateAccessKey, which allows creating access keys for any IAM user unless restricted by resource conditions.`,
              impact:
                "The user can impersonate other IAM users (including admins) by generating access keys on their behalf.",
              remediationSteps: [
                `Restrict iam:CreateAccessKey to the user's own ARN using a resource condition.`,
                "Implement SCP to prevent cross-user key creation.",
                "Monitor CreateAccessKey events in CloudTrail.",
              ],
            }),
          );
        }

        // STS AssumeRole on admin roles
        if (hasAction(allActions, "sts:assumerole")) {
          findings.push(
            makeFinding({
              riskScore: 8.0,
              title: `IAM user ${userName} can assume roles (potential admin escalation)`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has sts:AssumeRole, which may allow assuming high-privilege or admin roles if not restricted by resource ARN.`,
              impact:
                "The user can escalate privileges by assuming roles with higher permissions than their own.",
              remediationSteps: [
                `Restrict sts:AssumeRole to specific role ARNs for user "${userName}".`,
                "Require MFA for assuming sensitive roles via role trust policy conditions.",
                "Audit which roles this user can assume and their permission levels.",
              ],
            }),
          );
        }
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

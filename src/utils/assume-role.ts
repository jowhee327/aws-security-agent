import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

export async function getCurrentAccountId(region: string): Promise<string> {
  const sts = new STSClient({ region });
  const result = await sts.send(new GetCallerIdentityCommand({}));
  return result.Account!;
}

export const DEFAULT_EXTERNAL_ID = "aws-security-mcp-audit";

export async function assumeRole(roleArn: string, region: string, options?: {
  sessionName?: string;
  externalId?: string;
}): Promise<{
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}> {
  const sessionName = options?.sessionName ?? "aws-security-mcp";
  const externalId = options?.externalId ?? DEFAULT_EXTERNAL_ID;
  const sts = new STSClient({ region });
  const result = await sts.send(new AssumeRoleCommand({
    RoleArn: roleArn,
    RoleSessionName: sessionName,
    ExternalId: externalId,
    DurationSeconds: 3600,
  }));
  return {
    accessKeyId: result.Credentials!.AccessKeyId!,
    secretAccessKey: result.Credentials!.SecretAccessKey!,
    sessionToken: result.Credentials!.SessionToken!,
  };
}

export function buildRoleArn(accountId: string, roleName: string, partition = "aws"): string {
  return `arn:${partition}:iam::${accountId}:role/${roleName}`;
}

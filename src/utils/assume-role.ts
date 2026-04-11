import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

export async function getCurrentAccountId(region: string): Promise<string> {
  const sts = new STSClient({ region });
  const result = await sts.send(new GetCallerIdentityCommand({}));
  return result.Account!;
}

export async function assumeRole(roleArn: string, region: string, sessionName = "aws-security-mcp"): Promise<{
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}> {
  const sts = new STSClient({ region });
  const result = await sts.send(new AssumeRoleCommand({
    RoleArn: roleArn,
    RoleSessionName: sessionName,
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

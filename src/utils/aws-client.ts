import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { isAwsCredentials, type CloudCredentials } from "../types.js";

let cachedAccountId: string | undefined;

export function getPartition(region: string): string {
  if (region.startsWith("cn-")) return "aws-cn";
  if (region.startsWith("us-gov-")) return "aws-us-gov";
  return "aws";
}

export function getIamRegion(region: string): string {
  // IAM is global in standard AWS (us-east-1) but regional in China
  if (region.startsWith("cn-")) return region;
  return "us-east-1";
}

export async function getAccountId(region?: string): Promise<string> {
  if (cachedAccountId) return cachedAccountId;

  const stsRegion = region ?? "us-east-1";
  const sts = new STSClient({ region: stsRegion });
  const response = await sts.send(new GetCallerIdentityCommand({}));
  cachedAccountId = response.Account ?? "unknown";
  return cachedAccountId;
}

export function createClient<T>(
  ClientClass: new (config: any) => T,
  region?: string,
  credentials?: CloudCredentials,
): T {
  const config: any = { region: region ?? "us-east-1" };
  // Only AWS-shaped credentials are meaningful for AWS SDK clients.
  if (isAwsCredentials(credentials)) config.credentials = credentials;
  return new ClientClass(config);
}

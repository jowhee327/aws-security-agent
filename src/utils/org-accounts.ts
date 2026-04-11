import { OrganizationsClient, ListAccountsCommand } from "@aws-sdk/client-organizations";

export interface OrgAccount {
  id: string;
  name: string;
  email: string;
  status: string;
}

export async function listOrgAccounts(region: string): Promise<OrgAccount[]> {
  // Organizations API must use specific endpoints
  // Global: us-east-1, China: cn-northwest-1
  const orgRegion = region.startsWith("cn-") ? "cn-northwest-1" : "us-east-1";
  const client = new OrganizationsClient({ region: orgRegion });
  const accounts: OrgAccount[] = [];
  let nextToken: string | undefined;

  do {
    const result = await client.send(new ListAccountsCommand({ NextToken: nextToken }));
    for (const acct of result.Accounts || []) {
      if (acct.Status === "ACTIVE") {
        accounts.push({
          id: acct.Id!,
          name: acct.Name || "",
          email: acct.Email || "",
          status: acct.Status!,
        });
      }
    }
    nextToken = result.NextToken;
  } while (nextToken);

  return accounts;
}

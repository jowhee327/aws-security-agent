import { describe, it, expect, vi, beforeEach } from "vitest";

const mockSend = vi.fn();

vi.mock("@aws-sdk/client-organizations", () => ({
  OrganizationsClient: vi.fn().mockImplementation(() => ({ send: mockSend })),
  ListAccountsCommand: vi.fn().mockImplementation((input: unknown) => ({
    ...input,
    constructor: { name: "ListAccountsCommand" },
  })),
}));

import { listOrgAccounts } from "../../src/utils/org-accounts.js";

describe("listOrgAccounts", () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns active accounts from Organizations", async () => {
    mockSend.mockResolvedValueOnce({
      Accounts: [
        { Id: "111111111111", Name: "Management", Email: "mgmt@example.com", Status: "ACTIVE" },
        { Id: "222222222222", Name: "Production", Email: "prod@example.com", Status: "ACTIVE" },
        { Id: "333333333333", Name: "Suspended", Email: "old@example.com", Status: "SUSPENDED" },
      ],
      NextToken: undefined,
    });

    const accounts = await listOrgAccounts("us-east-1");
    expect(accounts).toHaveLength(2);
    expect(accounts[0].id).toBe("111111111111");
    expect(accounts[0].name).toBe("Management");
    expect(accounts[1].id).toBe("222222222222");
  });

  it("paginates through multiple pages", async () => {
    mockSend
      .mockResolvedValueOnce({
        Accounts: [
          { Id: "111111111111", Name: "Acct1", Email: "a1@example.com", Status: "ACTIVE" },
        ],
        NextToken: "page2",
      })
      .mockResolvedValueOnce({
        Accounts: [
          { Id: "222222222222", Name: "Acct2", Email: "a2@example.com", Status: "ACTIVE" },
        ],
        NextToken: undefined,
      });

    const accounts = await listOrgAccounts("us-east-1");
    expect(accounts).toHaveLength(2);
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it("returns empty array when no accounts", async () => {
    mockSend.mockResolvedValueOnce({
      Accounts: [],
      NextToken: undefined,
    });

    const accounts = await listOrgAccounts("us-east-1");
    expect(accounts).toHaveLength(0);
  });

  it("throws when Organizations API fails", async () => {
    mockSend.mockRejectedValueOnce(new Error("Not authorized"));
    await expect(listOrgAccounts("us-east-1")).rejects.toThrow("Not authorized");
  });
});

/**
 * HuaweiRmsComplianceScanner (Huawei Cloud rms_compliance_findings) — SDK
 * client factory + SDK package are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listPolicyStatesByDomainId, listPolicyAssignments, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } =
  vi.hoisted(() => ({
    listPolicyStatesByDomainId: vi.fn(),
    listPolicyAssignments: vi.fn(),
    hwClientMock: vi.fn(),
    loadHuaweiCredentialsMock: vi.fn(),
    resolveRegionScopeMock: vi.fn(),
  }));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  hwObsClient: vi.fn(),
  silenceSdkLogging: vi.fn(),
}));
// The SDK package must never be loaded in unit tests (heavy + configures log4js).
vi.mock("@huaweicloud/huaweicloud-sdk-config", () => ({
  ConfigClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiRmsComplianceScanner,
  RMS_POLICY_STATES_PAGE_SIZE,
  RMS_POLICY_ASSIGNMENTS_PAGE_SIZE,
  RMS_MAX_POLICY_STATES,
  RMS_NOT_ENABLED_WARNING,
  RMS_HIGH_SEVERITY_KEYWORDS,
  rmsPolicyRiskScore,
  policyStateToFinding,
  isNonCompliant,
  normalizeRmsRegion,
  type LoosePolicyState,
} from "../../../../src/providers/huaweicloud/scanners/rms-compliance.js";
import { createHuaweiCredentials, HuaweiCredentialsNotFoundError } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext } from "../../../../src/types.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const DOMAIN = "0123456789abcdef0123456789abcdef";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;

const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });

const ctx: ScanContext = {
  region: "cn-north-4",
  partition: "huaweicloud",
  accountId: DOMAIN,
  provider: "huaweicloud",
  projectId: "p-north4",
  domainId: DOMAIN,
  credentials: creds,
};

function state(over: Partial<LoosePolicyState> & { resource_id: string }): LoosePolicyState {
  return {
    domain_id: DOMAIN,
    region_id: "cn-north-4",
    resource_name: over.resource_id,
    resource_provider: "ecs",
    resource_type: "cloudservers",
    trigger_type: "resource",
    compliance_state: "NonCompliant",
    policy_assignment_id: "pa-generic",
    policy_assignment_name: "ecs-instance-in-vpc",
    policy_definition_id: "ecs-instance-in-vpc",
    evaluation_time: "2026-09-13T01:02:03Z",
    ...over,
  };
}

const ASSIGNMENTS = {
  value: [
    { id: "pa-mfa", name: "Org-iam-user-mfa-enabled", policy_assignment_type: "builtin", policy_definition_id: "iam-user-mfa-enabled", description: "IAM users must have MFA enabled.", state: "Enabled" },
    { id: "pa-tag", name: "Org-required-tag-check", policy_assignment_type: "builtin", policy_definition_id: "required-tag-check", description: "Resources must carry the required tags.", state: "Enabled" },
    { id: "pa-generic", name: "ecs-instance-in-vpc", policy_assignment_type: "builtin", policy_definition_id: "ecs-instance-in-vpc", state: "Enabled" },
  ],
  page_info: { current_count: 3 },
};

/** Capture anything that could reach the MCP stdio channel or a terminal. */
const captured: string[] = [];
const spies: Array<ReturnType<typeof vi.spyOn>> = [];
beforeAll(() => {
  spies.push(vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  spies.push(vi.spyOn(process.stderr, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    spies.push(vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" "));
    }));
  }
});
afterAll(() => { for (const s of spies) s.mockRestore(); });
afterEach(() => {
  const all = captured.join("\n");
  expect(all, "no output may contain the Authorization header or key material").not.toContain("Authorization");
  expect(all).not.toContain(FAKE_AK);
  expect(all).not.toContain(FAKE_SK);
  captured.length = 0;
});

describe("HuaweiRmsComplianceScanner (rms_compliance_findings)", () => {
  const scanner = new HuaweiRmsComplianceScanner();

  beforeEach(() => {
    listPolicyStatesByDomainId.mockReset();
    listPolicyAssignments.mockReset();
    hwClientMock.mockReset();
    hwClientMock.mockResolvedValue({ listPolicyStatesByDomainId, listPolicyAssignments });
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
    listPolicyAssignments.mockResolvedValue(ASSIGNMENTS);
  });

  it("is registered on the huaweicloud provider under a new module name", () => {
    expect(scanner.moduleName).toBe("rms_compliance_findings");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("rms_compliance_findings");
  });

  it("maps NonCompliant states across 2 pages to findings, filters Compliant ones client-side, builds URNs and uplifts severity", async () => {
    const page1 = [
      state({ resource_id: "srv-1", policy_assignment_id: "pa-mfa", policy_assignment_name: "Org-iam-user-mfa-enabled", policy_definition_id: "iam-user-mfa-enabled", resource_provider: "iam", resource_type: "users", region_id: "global", resource_name: "alice" }),
      state({ resource_id: "srv-2", compliance_state: "Compliant" }), // server ignored the filter → dropped client-side
      state({ resource_id: "srv-3", policy_assignment_id: "pa-tag", policy_assignment_name: "Org-required-tag-check", policy_definition_id: "required-tag-check", enterprise_project_id: "ep-1" }),
    ];
    const page2 = [
      state({ resource_id: "vol-9", resource_provider: "evs", resource_type: "volumes", policy_assignment_id: "pa-enc", policy_assignment_name: undefined, policy_definition_id: "volumes-encrypted-check", region_id: "cn-east-3" }),
      state({ resource_id: "srv-4", compliance_state: "compliant" }),
      state({ resource_id: "sg-7", resource_provider: "vpc", resource_type: "securityGroups", policy_assignment_id: "pa-sg", policy_assignment_name: "vpc-sg-ports-check", policy_definition_id: "vpc-sg-ports-check" }),
    ];
    listPolicyStatesByDomainId
      .mockResolvedValueOnce({ value: page1, page_info: { current_count: 3, next_marker: "m-1" } })
      .mockResolvedValueOnce({ value: page2, page_info: { current_count: 3 } });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.resourcesScanned).toBe(6);
    expect(result.findingsCount).toBe(4);
    expect(result.findings).toHaveLength(4);

    // Pagination: first call without marker, second with the returned next_marker; compliance filter always sent.
    expect(listPolicyStatesByDomainId).toHaveBeenCalledTimes(2);
    expect(listPolicyStatesByDomainId.mock.calls[0][0]).toEqual({ domainId: DOMAIN, compliance_state: "NonCompliant", limit: RMS_POLICY_STATES_PAGE_SIZE });
    expect(listPolicyStatesByDomainId.mock.calls[1][0]).toEqual({ domainId: DOMAIN, compliance_state: "NonCompliant", limit: RMS_POLICY_STATES_PAGE_SIZE, marker: "m-1" });
    expect(listPolicyAssignments).toHaveBeenCalledTimes(1);
    expect(listPolicyAssignments.mock.calls[0][0]).toEqual({ limit: RMS_POLICY_ASSIGNMENTS_PAGE_SIZE });

    // Global RMS client with the account domain ID; credential chain not consulted.
    expect(hwClientMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0][1]).toBe("rms");
    expect(hwClientMock.mock.calls[0][2]).toBe(creds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();

    const byId = new Map(result.findings.map((f) => [f.resourceId, f]));
    expect(byId.has("srv-2")).toBe(false);
    expect(byId.has("srv-4")).toBe(false);

    // Global IAM resource, HIGH via "mfa", enriched with the assignment description.
    const mfa = byId.get("srv-1")!;
    expect(mfa).toMatchObject({
      severity: "HIGH",
      priority: "P1",
      riskScore: 7.5,
      resourceType: "iam:users",
      region: "global",
      resourceArn: `hws:global:${DOMAIN}:iam:users:srv-1`,
      source: "RMS",
      provider: "huaweicloud",
      module: "rms_compliance_findings",
      accountId: DOMAIN,
    });
    expect(mfa.title).toBe("RMS policy non-compliance: Org-iam-user-mfa-enabled");
    expect(mfa.impact).toBe("Source: RMS (iam-user-mfa-enabled)");
    expect(mfa.description).toContain("srv-1 (alice)");
    expect(mfa.description).toContain("IAM users must have MFA enabled.");
    expect(mfa.description).toContain("Last evaluated: 2026-09-13T01:02:03Z");
    expect(mfa.remediationSteps.join("\n")).toContain("iam-user-mfa-enabled");
    expect(mfa.enterpriseProjectId).toBeUndefined();

    // Default MEDIUM, enterprise project attached.
    const tag = byId.get("srv-3")!;
    expect(tag).toMatchObject({ severity: "MEDIUM", priority: "P2", riskScore: 5.0, resourceType: "ecs:cloudservers", enterpriseProjectId: "ep-1", region: "cn-north-4" });
    expect(tag.resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:ecs:cloudservers:srv-3`);

    // Other region kept (regionScope=all), Finding.region reflects the resource's region; HIGH via "encrypt" on the definition id
    // even though the state has no assignment name and the assignment is unknown to listPolicyAssignments.
    const vol = byId.get("vol-9")!;
    expect(vol).toMatchObject({ severity: "HIGH", riskScore: 7.5, region: "cn-east-3", resourceType: "evs:volumes" });
    expect(vol.resourceArn).toBe(`hws:cn-east-3:${DOMAIN}:evs:volumes:vol-9`);
    expect(vol.title).toBe("RMS policy non-compliance: volumes-encrypted-check");

    // HIGH via "sg-ports".
    expect(byId.get("sg-7")).toMatchObject({ severity: "HIGH", resourceType: "vpc:securityGroups" });

    // Cross-region informational warning only.
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("1 RMS compliance finding(s) belong to regions other than cn-north-4");

    // Serialized result never carries key material.
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(FAKE_AK);
    expect(serialized).not.toContain(FAKE_SK);
  });

  it("regionScope=context drops other-region states but keeps global ones, with a warning", async () => {
    const scoped = new HuaweiRmsComplianceScanner({ regionScope: "context" });
    listPolicyStatesByDomainId.mockResolvedValueOnce({
      value: [
        state({ resource_id: "a", region_id: "cn-north-4" }),
        state({ resource_id: "b", region_id: "cn-east-3" }),
        state({ resource_id: "c", region_id: "global", resource_provider: "iam", resource_type: "users" }),
        state({ resource_id: "d", region_id: "ap-southeast-1" }),
      ],
      page_info: { current_count: 4 },
    });

    const result = await scoped.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(4);
    expect(result.findings.map((f) => f.resourceId).sort()).toEqual(["a", "c"]);
    expect(result.warnings).toEqual(["2 RMS compliance finding(s) from other regions were skipped (regionScope=context)."]);
  });

  it("returns 0 findings and no warnings when everything is compliant (empty page)", async () => {
    listPolicyStatesByDomainId.mockResolvedValueOnce({ value: [], page_info: { current_count: 0 } });

    const result = await scanner.scan(ctx);

    expect(result).toMatchObject({ module: "rms_compliance_findings", status: "success", resourcesScanned: 0, findingsCount: 0, findings: [] });
    expect(result.warnings).toBeUndefined();
    expect(typeof result.scanTimeMs).toBe("number");
  });

  it("tolerates a 403 on listPolicyAssignments (warning) and still produces findings from the states", async () => {
    listPolicyAssignments.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "IAM.0002", errorMsg: "You have no permission to perform this action.", requestId: "req-pa" });
    listPolicyStatesByDomainId.mockResolvedValueOnce({
      value: [state({ resource_id: "srv-1", policy_assignment_id: "pa-x", policy_assignment_name: "obs-bucket-public-read-policy-check", policy_definition_id: "obs-bucket-public-read-policy-check", resource_provider: "obs", resource_type: "buckets" })],
      page_info: { current_count: 1 },
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0]).toMatchObject({ severity: "HIGH", resourceType: "obs:buckets", source: "RMS" });
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("could not list policy assignments");
    expect(result.warnings![0]).toContain("IAM.0002");
  });

  it("skipAssignmentLookup / client without listPolicyAssignments never calls it", async () => {
    hwClientMock.mockResolvedValue({ listPolicyStatesByDomainId });
    listPolicyStatesByDomainId.mockResolvedValueOnce({ value: [state({ resource_id: "srv-1" })], page_info: {} });

    const result = await new HuaweiRmsComplianceScanner({ skipAssignmentLookup: true }).scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(listPolicyAssignments).not.toHaveBeenCalled();
    expect(result.warnings).toBeUndefined();
  });

  it("caps at RMS_MAX_POLICY_STATES with a truncation warning", async () => {
    const big = Array.from({ length: RMS_POLICY_STATES_PAGE_SIZE }, (_, i) => state({ resource_id: `r-${i}` }));
    listPolicyStatesByDomainId.mockImplementation(async (req: { marker?: string }) => ({
      value: big,
      page_info: { current_count: big.length, next_marker: `m-${req.marker ?? "0"}` },
    }));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(RMS_MAX_POLICY_STATES);
    expect(result.findingsCount).toBe(RMS_MAX_POLICY_STATES);
    expect(listPolicyStatesByDomainId).toHaveBeenCalledTimes(RMS_MAX_POLICY_STATES / RMS_POLICY_STATES_PAGE_SIZE + 1);
    expect(result.warnings!.some((w) => w.includes("truncated"))).toBe(true);
  });

  it("degrades gracefully on 403 IAM.0002 (success, access-denied warning, 0 findings)", async () => {
    listPolicyStatesByDomainId.mockRejectedValueOnce({
      httpStatusCode: 403,
      errorCode: "IAM.0002",
      errorMsg: "You have no permission to perform this action.",
      requestId: "req-403",
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toEqual([
      "RMS: insufficient permissions (HTTP 403 | IAM.0002 | You have no permission to perform this action. | requestId=req-403); skipped",
    ]);
  });

  it("reports RMS not enabled on 404 with status success", async () => {
    listPolicyStatesByDomainId.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "RMS.0002", errorMsg: "The tracker config does not exist.", requestId: "req-404" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain(RMS_NOT_ENABLED_WARNING);
    expect(result.warnings![0]).toContain("RMS.0002");
  });

  it("never surfaces the signed Authorization header from a raw SDK error", async () => {
    listPolicyStatesByDomainId.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" },
      message: "Request failed with status code 401",
      config: { url: `https://rms.myhuaweicloud.com/v1/resource-manager/domains/${DOMAIN}/policy-states`, headers: { Authorization: FAKE_AUTH_HEADER } },
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success"); // 401 = access denied → graceful
    const serialized = JSON.stringify(result);
    expect(serialized).toContain("APIGW.0301");
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
    expect(serialized).not.toContain(FAKE_SK);
  });

  it("returns status error (without credentials) on unexpected failures", async () => {
    listPolicyStatesByDomainId.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "RMS.9999", errorMsg: "internal error" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toBe("RMS compliance findings scan failed: HTTP 500 | RMS.9999 | internal error");
    expect(result.findingsCount).toBe(0);
    expect(JSON.stringify(result)).not.toContain(FAKE_AK);

    listPolicyStatesByDomainId.mockRejectedValueOnce(new Error("connect ETIMEDOUT 1.2.3.4:443"));
    const net = await scanner.scan(ctx);
    expect(net.status).toBe("error");
    expect(net.error).toContain("ETIMEDOUT");
  });

  it("falls back to the credential chain and resolves the domain ID via IAM when needed", async () => {
    const chainCreds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });
    loadHuaweiCredentialsMock.mockReturnValueOnce({ basic: chainCreds, global: chainCreds, source: "env" });
    listPolicyStatesByDomainId.mockResolvedValueOnce({ value: [], page_info: {} });

    const viaChain = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });
    expect(viaChain.status).toBe("success");
    expect(loadHuaweiCredentialsMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0][2]).toBe(chainCreds);

    const noDomain = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: "p-north4", domainId: DOMAIN });
    listPolicyStatesByDomainId.mockResolvedValueOnce({ value: [], page_info: {} });

    const viaIam = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: "", credentials: noDomain });
    expect(viaIam.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noDomain, "cn-north-4");
    expect(hwClientMock.mock.calls[1][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
  });

  it("returns status error when no credentials are configured anywhere", async () => {
    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new HuaweiCredentialsNotFoundError("/nonexistent/credentials"); });

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });

    expect(result.status).toBe("error");
    expect(result.error).toContain("Huawei Cloud credentials not found");
    expect(hwClientMock).not.toHaveBeenCalled();
  });
});

describe("rms-compliance pure helpers", () => {
  it("rmsPolicyRiskScore uplifts only the explicit keyword table", () => {
    expect(RMS_HIGH_SEVERITY_KEYWORDS).toEqual(["mfa", "public", "encrypt", "sg-ports", "security-group", "root", "access-key"]);
    expect(rmsPolicyRiskScore("iam-user-mfa-enabled", undefined)).toBe(7.5);
    expect(rmsPolicyRiskScore("Org-IAM-Root-Access-Key-Check", undefined)).toBe(7.5);
    expect(rmsPolicyRiskScore(undefined, "obs-bucket-public-read-policy-check")).toBe(7.5);
    expect(rmsPolicyRiskScore("custom", "volumes-encrypted-check")).toBe(7.5);
    expect(rmsPolicyRiskScore("vpc-security-group-open", undefined)).toBe(7.5);
    expect(rmsPolicyRiskScore("access-keys-rotated", undefined)).toBe(7.5);
    expect(rmsPolicyRiskScore("required-tag-check", "required-tag-check")).toBe(5.0);
    expect(rmsPolicyRiskScore(undefined, undefined)).toBe(5.0);
  });

  it("isNonCompliant / normalizeRmsRegion are tolerant of casing and separators", () => {
    expect(isNonCompliant({ compliance_state: "NonCompliant" })).toBe(true);
    expect(isNonCompliant({ complianceState: "non_compliant" })).toBe(true);
    expect(isNonCompliant({ compliance_state: "Compliant" })).toBe(false);
    expect(isNonCompliant({})).toBe(false);
    expect(normalizeRmsRegion("cn-north-4")).toBe("cn-north-4");
    expect(normalizeRmsRegion("Global")).toBe("global");
    expect(normalizeRmsRegion("")).toBe("global");
    expect(normalizeRmsRegion(undefined)).toBe("global");
  });

  it("policyStateToFinding falls back to the definition id, then assignment id, then a generic label", () => {
    const base = { domainId: DOMAIN, module: "rms_compliance_findings" };
    const byDef = policyStateToFinding({ resource_id: "r1", resource_provider: "ecs", resource_type: "cloudservers", policy_definition_id: "def-1" }, base);
    expect(byDef.title).toBe("RMS policy non-compliance: def-1");
    expect(byDef.region).toBe("global");
    expect(byDef.resourceArn).toBe(`hws:global:${DOMAIN}:ecs:cloudservers:r1`);
    expect(byDef.accountId).toBe(DOMAIN);

    const byAssignment = policyStateToFinding({ resource_id: "r2", policy_assignment_id: "pa-1" }, base, { id: "pa-1", name: "from-map", policyDefinitionId: "def-map", description: "desc-map" });
    expect(byAssignment.title).toBe("RMS policy non-compliance: from-map");
    expect(byAssignment.impact).toBe("Source: RMS (def-map)");
    expect(byAssignment.description).toContain("desc-map");
    expect(byAssignment.resourceType).toBe("unknown:resource");

    const generic = policyStateToFinding({ resource_id: "r3" }, base);
    expect(generic.title).toBe("RMS policy non-compliance: unknown policy");
    expect(generic.impact).toBe("Source: RMS (custom)");
  });
});

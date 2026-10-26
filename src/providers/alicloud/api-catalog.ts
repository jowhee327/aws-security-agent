/**
 * Alibaba Cloud API catalog (plan §3.5, Appendix A).
 *
 * Every RPC / ROA call made by the alicloud provider MUST reference one of these
 * constants — scanners never inline `{ action, version, ... }` (enforced by a test that
 * greps `src/providers/alicloud/scanners/**`). The orchestrator's offline API-existence
 * probe (plan §7) iterates {@link ALI_API_CATALOG} with a fake AK: a gateway answer of
 * `InvalidAction.NotFound` / `InvalidVersion` / `UnsupportedHTTPMethod` means a bug here.
 *
 * action / version / method / style / pathname are copied from the per-service SDK
 * definitions (`new $OpenApiUtil.Params({...})` in `@alicloud/<pkg>/dist/client.js`,
 * extracted 2026-10-26). NOTE the per-API method: Config `GetCompliancePackReport` is
 * GET-only (POST → UnsupportedHTTPMethod). IMS APIs are not in the locally installed
 * SDK; their existence was verified with a live fake-AK probe.
 *
 * EXPERIMENTAL: not yet validated against a live account.
 */

export type AliService =
  | "ecs"
  | "vpc"
  | "slb"
  | "rds"
  | "ram"
  | "ims"
  | "sts"
  | "actiontrail"
  | "config"
  | "sas"
  | "kms"
  | "waf"
  | "cas"
  | "resourcemanager"
  | "fc"
  | "alidns";

export interface AliApiSpec {
  readonly service: AliService;
  readonly action: string;
  readonly version: string;
  readonly method: "GET" | "POST";
  readonly style: "RPC" | "ROA";
  /** ROA only (e.g. FC3 `/2023-03-30/functions`); RPC calls always use `/`. */
  readonly pathname?: string;
  /** Reserved for Phase 3 (dns_dangling / disaster_recovery / waf_coverage / multi-account); listed for the probe. */
  readonly phase3?: true;
}

/** API version per service (one version per service in this phase). */
export const ALI_API_VERSIONS: Readonly<Record<AliService, string>> = {
  ecs: "2014-05-26",
  vpc: "2016-04-28",
  slb: "2014-05-15",
  rds: "2014-08-15",
  ram: "2015-05-01",
  ims: "2019-08-15",
  sts: "2015-04-01",
  actiontrail: "2020-07-06",
  config: "2020-09-07",
  sas: "2018-12-03",
  kms: "2016-01-20",
  waf: "2021-10-01",
  cas: "2020-04-07",
  resourcemanager: "2020-03-31",
  fc: "2023-03-30",
  alidns: "2015-01-09",
};

function rpc(service: AliService, action: string, method: "GET" | "POST" = "POST", phase3 = false): AliApiSpec {
  return Object.freeze({
    service,
    action,
    version: ALI_API_VERSIONS[service],
    method,
    style: "RPC" as const,
    ...(phase3 ? { phase3: true as const } : {}),
  });
}

function roa(service: AliService, action: string, method: "GET" | "POST", pathname: string): AliApiSpec {
  return Object.freeze({ service, action, version: ALI_API_VERSIONS[service], method, style: "ROA" as const, pathname });
}

/** API specs grouped by service: `ALI_API.ecs.DescribeInstances`. */
export const ALI_API = Object.freeze({
  sts: Object.freeze({
    GetCallerIdentity: rpc("sts", "GetCallerIdentity"),
    AssumeRole: rpc("sts", "AssumeRole", "POST", true),
  }),
  ecs: Object.freeze({
    DescribeRegions: rpc("ecs", "DescribeRegions"),
    DescribeInstances: rpc("ecs", "DescribeInstances"),
    DescribeUserData: rpc("ecs", "DescribeUserData"),
    DescribeDisks: rpc("ecs", "DescribeDisks"),
    DescribeSecurityGroups: rpc("ecs", "DescribeSecurityGroups"),
    DescribeSecurityGroupAttribute: rpc("ecs", "DescribeSecurityGroupAttribute"),
    DescribeNetworkInterfaces: rpc("ecs", "DescribeNetworkInterfaces"),
    DescribeAutoSnapshotPolicyEx: rpc("ecs", "DescribeAutoSnapshotPolicyEx", "POST", true),
  }),
  vpc: Object.freeze({
    DescribeEipAddresses: rpc("vpc", "DescribeEipAddresses"),
  }),
  slb: Object.freeze({
    DescribeLoadBalancers: rpc("slb", "DescribeLoadBalancers"),
    DescribeLoadBalancerAttribute: rpc("slb", "DescribeLoadBalancerAttribute", "POST", true),
  }),
  rds: Object.freeze({
    DescribeDBInstances: rpc("rds", "DescribeDBInstances"),
    DescribeDBInstanceNetInfo: rpc("rds", "DescribeDBInstanceNetInfo"),
    DescribeDBInstanceIPArrayList: rpc("rds", "DescribeDBInstanceIPArrayList"),
    DescribeTags: rpc("rds", "DescribeTags"),
    DescribeBackupPolicy: rpc("rds", "DescribeBackupPolicy", "POST", true),
  }),
  ram: Object.freeze({
    ListUsers: rpc("ram", "ListUsers"),
    ListPoliciesForUser: rpc("ram", "ListPoliciesForUser"),
    ListGroupsForUser: rpc("ram", "ListGroupsForUser"),
    ListPoliciesForGroup: rpc("ram", "ListPoliciesForGroup"),
    ListRoles: rpc("ram", "ListRoles"),
    ListPoliciesForRole: rpc("ram", "ListPoliciesForRole"),
    ListPolicies: rpc("ram", "ListPolicies"),
    GetPolicy: rpc("ram", "GetPolicy"),
    GetPolicyVersion: rpc("ram", "GetPolicyVersion"),
    GetRole: rpc("ram", "GetRole"),
    ListAccessKeys: rpc("ram", "ListAccessKeys"),
  }),
  ims: Object.freeze({
    GetPasswordPolicy: rpc("ims", "GetPasswordPolicy"),
    GetAccountSecurityPracticeReport: rpc("ims", "GetAccountSecurityPracticeReport"),
    ListVirtualMFADevices: rpc("ims", "ListVirtualMFADevices"),
    GetUserMFAInfo: rpc("ims", "GetUserMFAInfo"),
    GetLoginProfile: rpc("ims", "GetLoginProfile"),
    GetAccountSummary: rpc("ims", "GetAccountSummary"),
    GetSecurityPreference: rpc("ims", "GetSecurityPreference"),
  }),
  actiontrail: Object.freeze({
    DescribeTrails: rpc("actiontrail", "DescribeTrails"),
    GetTrailStatus: rpc("actiontrail", "GetTrailStatus"),
  }),
  config: Object.freeze({
    GetConfigurationRecorder: rpc("config", "GetConfigurationRecorder"),
    ListConfigRules: rpc("config", "ListConfigRules"),
    ListConfigRuleEvaluationResults: rpc("config", "ListConfigRuleEvaluationResults"),
    ListCompliancePacks: rpc("config", "ListCompliancePacks"),
    ListCompliancePackTemplates: rpc("config", "ListCompliancePackTemplates"),
    GetCompliancePackReport: rpc("config", "GetCompliancePackReport", "GET"), // GET-only (plan §6.1)
    ListManagedRules: rpc("config", "ListManagedRules"),
  }),
  sas: Object.freeze({
    DescribeVersionConfig: rpc("sas", "DescribeVersionConfig"),
    DescribeSuspEvents: rpc("sas", "DescribeSuspEvents"),
    DescribeVulList: rpc("sas", "DescribeVulList"),
    DescribeCloudCenterInstances: rpc("sas", "DescribeCloudCenterInstances"),
  }),
  kms: Object.freeze({
    ListKmsInstances: rpc("kms", "ListKmsInstances"),
    ListKeys: rpc("kms", "ListKeys"),
    DescribeKey: rpc("kms", "DescribeKey"),
  }),
  waf: Object.freeze({
    DescribeInstance: rpc("waf", "DescribeInstance"),
    DescribeDefenseResources: rpc("waf", "DescribeDefenseResources", "POST", true),
    DescribeCloudResources: rpc("waf", "DescribeCloudResources", "POST", true),
  }),
  cas: Object.freeze({
    ListUserCertificateOrder: rpc("cas", "ListUserCertificateOrder"),
    ListCertificates: rpc("cas", "ListCertificates"),
  }),
  resourcemanager: Object.freeze({
    GetResourceDirectory: rpc("resourcemanager", "GetResourceDirectory", "POST", true),
    ListAccounts: rpc("resourcemanager", "ListAccounts", "POST", true),
  }),
  fc: Object.freeze({
    ListFunctions: roa("fc", "ListFunctions", "GET", "/2023-03-30/functions"),
  }),
  alidns: Object.freeze({
    DescribeDomains: rpc("alidns", "DescribeDomains", "POST", true),
    DescribeDomainRecords: rpc("alidns", "DescribeDomainRecords", "POST", true),
  }),
} satisfies Record<AliService, Record<string, AliApiSpec>>);

/** Every API spec known to the provider (flat list for the offline existence probe). */
export const ALI_API_CATALOG: readonly AliApiSpec[] = Object.freeze(
  Object.values(ALI_API).flatMap((svc) => Object.values(svc) as AliApiSpec[]),
);

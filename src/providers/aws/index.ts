import type { Scanner } from "../../scanners/base.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";
import { getAccountId, getPartition } from "../../utils/aws-client.js";
import { listOrgAccounts } from "../../utils/org-accounts.js";
import { assumeRole, buildRoleArn } from "../../utils/assume-role.js";

import { ServiceDetectionScanner } from "../../scanners/service-detection.js";
import { SecretExposureScanner } from "../../scanners/secret-exposure.js";
import { SslCertificateScanner } from "../../scanners/ssl-certificate.js";
import { DnsDanglingScanner } from "../../scanners/dns-dangling.js";
import { NetworkReachabilityScanner } from "../../scanners/network-reachability.js";
import { IamPrivilegeEscalationScanner } from "../../scanners/iam-privilege-escalation.js";
import { PublicAccessVerifyScanner } from "../../scanners/public-access-verify.js";
import { TagComplianceScanner } from "../../scanners/tag-compliance.js";
import { IdleResourcesScanner } from "../../scanners/idle-resources.js";
import { DisasterRecoveryScanner } from "../../scanners/disaster-recovery.js";
import { SecurityHubFindingsScanner } from "../../scanners/security-hub-findings.js";
import { GuardDutyFindingsScanner } from "../../scanners/guardduty-findings.js";
import { InspectorFindingsScanner } from "../../scanners/inspector-findings.js";
import { TrustedAdvisorFindingsScanner } from "../../scanners/trusted-advisor-findings.js";
import { ConfigRulesFindingsScanner } from "../../scanners/config-rules-findings.js";
import { AccessAnalyzerFindingsScanner } from "../../scanners/access-analyzer-findings.js";
import { PatchComplianceFindingsScanner } from "../../scanners/patch-compliance-findings.js";
import { Imdsv2EnforcementScanner } from "../../scanners/imdsv2-enforcement.js";
import { WafCoverageScanner } from "../../scanners/waf-coverage.js";

const DEFAULT_AWS_REGION = "us-east-1";
const DEFAULT_ROLE_NAME = "SecurityAuditRole";

/**
 * AWS provider: thin wrapper over the existing STS / Organizations / assume-role
 * utilities and the 19 detection scanners. Behaviour is identical to the
 * pre-provider code paths; `runner.ts` keeps using the utilities directly.
 *
 * The ECR image CVE scanner is intentionally excluded here: `index.ts`
 * constructs it with tool-specific repository caps.
 */
export const awsProvider: CloudProvider = {
  id: "aws",

  async getAccountId(scope: RegionScope): Promise<string> {
    return getAccountId(scope.region);
  },

  async listRegions(_creds?: CloudCredentials, defaultRegion?: string): Promise<RegionScope[]> {
    const region = defaultRegion ?? DEFAULT_AWS_REGION;
    return [{ region, partition: getPartition(region) }];
  },

  async listAccounts(scope: RegionScope): Promise<AccountRef[]> {
    const accounts = await listOrgAccounts(scope.region);
    return accounts.map((a) => ({ id: a.id, name: a.name }));
  },

  async assumeCrossAccount(
    target: AccountRef,
    scope: RegionScope,
    opts?: AssumeCrossAccountOptions,
  ): Promise<CloudCredentials> {
    const partition = scope.partition ?? getPartition(scope.region);
    const roleArn = buildRoleArn(target.id, opts?.roleName ?? DEFAULT_ROLE_NAME, partition);
    return assumeRole(roleArn, scope.region, {
      sessionName: opts?.sessionName,
      externalId: opts?.externalId,
    });
  },

  scanners(): Scanner[] {
    return [
      new ServiceDetectionScanner(),
      new SecretExposureScanner(),
      new SslCertificateScanner(),
      new DnsDanglingScanner(),
      new NetworkReachabilityScanner(),
      new IamPrivilegeEscalationScanner(),
      new PublicAccessVerifyScanner(),
      new TagComplianceScanner(),
      new IdleResourcesScanner(),
      new DisasterRecoveryScanner(),
      new SecurityHubFindingsScanner(),
      new GuardDutyFindingsScanner(),
      new InspectorFindingsScanner(),
      new TrustedAdvisorFindingsScanner(),
      new ConfigRulesFindingsScanner(),
      new AccessAnalyzerFindingsScanner(),
      new PatchComplianceFindingsScanner(),
      new Imdsv2EnforcementScanner(),
      new WafCoverageScanner(),
    ];
  },

  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string {
    const partition = scope.partition ?? getPartition(scope.region);
    const [service, ...rest] = resourceType.split(":");
    const typePrefix = rest.length > 0 ? `${rest.join(":")}/` : "";
    return `arn:${partition}:${service}:${scope.region}:${accountId}:${typePrefix}${resourceId}`;
  },
};

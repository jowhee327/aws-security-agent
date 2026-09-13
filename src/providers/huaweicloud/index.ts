/**
 * Huawei Cloud provider (Phase 1 skeleton).
 *
 * Scanners live in ./scanners/* and are registered in {@link huaweiCloudProvider.scanners}.
 * Each scanner imports its SDK package lazily so the default AWS path never loads Huawei SDKs.
 * Multi-account (Organizations listAccounts + STS assumeAgency) is reserved for
 * Phase 2: the interface methods exist but throw a clear "not implemented" error.
 */
import type { Scanner } from "../../scanners/base.js";
import type { HuaweiCloudCredentials } from "../../types.js";
import { isHuaweiCloudCredentials } from "../../types.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";
import { loadHuaweiCredentials, resolveProjects, resolveRegionScope } from "./credentials.js";
import { toResourceUrn as toHwsUrn } from "./urn.js";
import { RmsTrackerScanner } from "./scanners/rms-tracker.js";
import { ObsPublicAccessScanner } from "./scanners/obs-public-access.js";
import { HuaweiSecretExposureScanner } from "./scanners/secret-exposure.js";
import { HuaweiSslCertificateScanner } from "./scanners/ssl-certificate.js";
import { HuaweiIdleResourcesScanner } from "./scanners/idle-resources.js";
import { HuaweiTagComplianceScanner } from "./scanners/tag-compliance.js";
// Importing client.ts silences log4js at provider load (P0 mitigation, see client.ts).
import "./client.js";

export const HUAWEI_PARTITION = "huaweicloud";
export const DEFAULT_HUAWEI_REGION = "cn-north-4";

/** Resolve the global credentials to use: explicit HW creds on the call, else the credential chain. */
function globalCreds(creds?: CloudCredentials): HuaweiCloudCredentials {
  if (isHuaweiCloudCredentials(creds)) return creds;
  return loadHuaweiCredentials().global;
}

export const huaweiCloudProvider: CloudProvider = {
  id: "huaweicloud",

  /** Account identifier = IAM domain ID (from credentials or IAM project listing). */
  async getAccountId(scope: RegionScope, creds?: CloudCredentials): Promise<string> {
    if (scope.domainId) return scope.domainId;
    const c = globalCreds(creds);
    if (c.domainId) return c.domainId;
    const resolved = await resolveRegionScope(c, scope.region);
    return resolved.domainId ?? "unknown";
  },

  /** One RegionScope per top-level region project returned by IAM. */
  async listRegions(creds?: CloudCredentials, defaultRegion?: string): Promise<RegionScope[]> {
    const c = globalCreds(creds);
    const projects = await resolveProjects(c);
    const scopes: RegionScope[] = [];
    for (const p of projects.values()) {
      // resolveProjects() already filtered to valid region IDs (no sub-projects / MOS).
      scopes.push({ region: p.region, projectId: p.projectId, domainId: p.domainId });
    }
    scopes.sort((a, b) => (a.region < b.region ? -1 : a.region > b.region ? 1 : 0)); // code-point order, locale-independent
    if (defaultRegion) {
      // Put the requested region first when present.
      const idx = scopes.findIndex((s) => s.region === defaultRegion);
      if (idx > 0) scopes.unshift(...scopes.splice(idx, 1));
    }
    return scopes;
  },

  // TODO(Phase 2): Organizations `listAccounts` (global endpoint, GlobalCredentials).
  async listAccounts(_scope: RegionScope, _creds?: CloudCredentials): Promise<AccountRef[]> {
    throw new Error("Huawei Cloud multi-account discovery (Organizations listAccounts) is not implemented in Phase 1");
  },

  // TODO(Phase 2): STS `assumeAgency` via regional STS endpoint; `roleName` maps to the agency name.
  async assumeCrossAccount(
    _target: AccountRef,
    _scope: RegionScope,
    _opts?: AssumeCrossAccountOptions,
  ): Promise<CloudCredentials> {
    throw new Error("Huawei Cloud cross-account access (STS assumeAgency) is not implemented in Phase 1");
  },

  scanners(): Scanner[] {
    return [
      new RmsTrackerScanner(), // config_rules_findings (T2)
      new ObsPublicAccessScanner(), // public_access_verify (T3)
      new HuaweiSecretExposureScanner(), // secret_exposure (T4)
      new HuaweiSslCertificateScanner(), // ssl_certificate (T5)
      new HuaweiIdleResourcesScanner(), // idle_resources (T5)
      new HuaweiTagComplianceScanner(), // tag_compliance (T5)
    ];
  },

  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string {
    const [svc, ...rest] = resourceType.split(":");
    const type = rest.length > 0 ? rest.join(":") : "resource";
    return toHwsUrn(svc, type, resourceId, scope.region, scope.domainId ?? accountId);
  },
};

export { toResourceUrn, parseResourceUrn } from "./urn.js";
export * from "./errors.js";
export {
  parseHuaweiCredentialsIni,
  loadHuaweiCredentials,
  createHuaweiCredentials,
  redactHuaweiCredentials,
  resolveProjects,
  resolveRegionScope,
  clearHuaweiProjectCache,
  type HuaweiCredentialSet,
} from "./credentials.js";
export { hwClient, hwObsClient, hwEndpoint, isGlobalService, silenceSdkLogging, type HwService } from "./client.js";
export { RmsTrackerScanner, RMS_TRACKER_NOT_ENABLED_WARNING, rmsTrackerUrn } from "./scanners/rms-tracker.js";
export { ObsPublicAccessScanner, evaluateObsAcl, evaluateObsPolicy, pabBlocksAll, obsCall, ObsHttpError } from "./scanners/obs-public-access.js";
export { HuaweiSecretExposureScanner, HUAWEI_SECRET_PATTERNS, HUAWEI_EXTRA_SECRET_PATTERNS } from "./scanners/secret-exposure.js";
export { HuaweiSslCertificateScanner, evaluateCertificate } from "./scanners/ssl-certificate.js";
export { HuaweiIdleResourcesScanner, stoppedDays } from "./scanners/idle-resources.js";
export { HuaweiTagComplianceScanner, HW_TAG_RESOURCE_TYPES, getMissingRmsTags } from "./scanners/tag-compliance.js";

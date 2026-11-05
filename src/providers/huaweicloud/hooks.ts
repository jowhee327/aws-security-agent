/**
 * Huawei Cloud orchestration hooks (see `CloudProviderHooks`).
 *
 * Kept in a dependency-light module (no SDK / scanner imports) so that
 * `scanners/runner.ts` and `index.ts` can fall back to these values when the
 * registered provider object does not carry the hooks itself (e.g. test doubles).
 * The values reproduce the pre-generalisation hard-coded runner behaviour exactly.
 */
import type { CloudProviderHooks, RegionScope } from "../types.js";
import type { ScanContext } from "../../types.js";
import { redactHwDiagnostic } from "./errors.js";

export const HUAWEI_PARTITION = "huaweicloud";
export const DEFAULT_HUAWEI_REGION = "cn-north-4";

/**
 * Huawei Cloud modules backed by account-wide (global) services — RMS tracker and
 * RMS compliance states aggregate every region — so in multi-region mode they run
 * once instead of once per region (mirrors AGGREGATION_MODULES for AWS org mode).
 */
export const HUAWEI_GLOBAL_MODULES = new Set([
  "config_rules_findings",
  "rms_compliance_findings",
]);

export const HUAWEI_MULTI_ACCOUNT_WARNING =
  "org_mode requested but multi-account scanning (Organizations listAccounts + STS assumeAgency) is not yet supported for huaweicloud (Phase 1). Scanning the current account only.";

/** Region project → projectId; account → domainId (falls back to the resolved account ID). */
function huaweiContextFor(scope: RegionScope, accountId: string): Partial<ScanContext> {
  const domainId = scope.domainId ?? (accountId !== "unknown" ? accountId : undefined);
  const extra: Partial<ScanContext> = {};
  if (scope.projectId) extra.projectId = scope.projectId;
  if (domainId) extra.domainId = domainId;
  return extra;
}

export const huaweiCloudHooks: CloudProviderHooks = {
  displayName: "Huawei Cloud",
  partitionFor: () => HUAWEI_PARTITION,
  defaultRegion: DEFAULT_HUAWEI_REGION,
  globalModules: HUAWEI_GLOBAL_MODULES,
  redactDiagnostic: redactHwDiagnostic,
  contextFor: huaweiContextFor,
  supportsMultiAccount: false,
  regionalMessages: {
    noRegions: (fallback) => `Huawei Cloud region discovery returned no region projects; scanning ${fallback} only.`,
    unknownRegion: (requested, known) =>
      `Huawei Cloud region "${requested}" is not among this account's IAM region projects (known: ${known}); scanning it anyway.`,
    discoveryFailed: (reason, fallback) => `Huawei Cloud region discovery failed: ${reason}. Scanning ${fallback} only.`,
    multiAccountUnsupported: HUAWEI_MULTI_ACCOUNT_WARNING,
  },
};

/**
 * Alibaba Cloud OS patch compliance scanner (moduleName `patch_compliance_findings`,
 * plan §4.1 P2 / T7). EXPERIMENTAL — not yet validated against a live account.
 *
 * SSM Patch Manager counterpart (mirrors the Huawei HSS scanner `hss-patch-compliance.ts`).
 * Alibaba Cloud has no Patch Manager; OS patch status is derived from Security Center:
 *
 *  1. {@link checkSasEdition} (`DescribeVersionConfig`): not purchased / Free Edition /
 *     value-added only → 0 findings + "not enabled / insufficient edition" warning (status
 *     success).
 *  2. `DescribeVulList` (centralised tds endpoint, `CurrentPage` / `PageSize`, `Dealed=n`)
 *     for {@link SAS_PATCH_VUL_TYPES} — `sys` (Windows system patches) and `cve` (Linux
 *     software vulnerabilities, i.e. missing package updates).
 *  3. Records (vulnerability × host) are aggregated per host (`Uuid`, else `InstanceId`) as
 *     Huawei `summarizeHostVuls` does: one Finding per host with unhandled vulnerabilities.
 *     riskScore mirrors the AWS thresholds: any asap (high-priority) item → 7.5 (HIGH,
 *     "security patches missing"), later / unrated → 5.5 (MEDIUM), only nntf → 3.0 (LOW).
 *     Hosts are sorted by risk / high-priority count / total and capped at
 *     {@link SAS_PATCH_MAX_HOST_FINDINGS} with an overflow warning.
 *
 * Every server-sourced string (host IDs / names / IPs, OS, vulnerability names) passes
 * through redactAliDiagnostic. Errors: auth_failed / api_misuse → module `status: "error"`;
 * access denied / not enabled / throttled / network → warning + degrade.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { toAliUrn } from "../urn.js";
import { checkSasEdition, listSasVulRecords, sasNecessity, SAS_NECESSITY_RANK, type SasVulRecord } from "./sas-shared.js";
import { aliErrorResult, aliSafeFinding, aliScanEnv, aliUntrusted, emptyScanResult } from "./shared.js";

/** `sys` = Windows system patches, `cve` = Linux software vulnerabilities. */
export const SAS_PATCH_VUL_TYPES: readonly string[] = ["sys", "cve"];
/** Hosts reported as individual findings. */
export const SAS_PATCH_MAX_HOST_FINDINGS = 100;

const WHAT = "OS patch compliance data";

export interface SasHostPatchState {
  /** Aggregation key (Uuid, else InstanceId), redacted. */
  key: string;
  uuid?: string;
  instanceId?: string;
  instanceName?: string;
  ip?: string;
  regionId?: string;
  os?: string;
  total: number;
  asap: number;
  later: number;
  nntf: number;
  unknown: number;
  /** Windows system patch (`sys`) vs Linux software (`cve`) item counts. */
  sys: number;
  cve: number;
  /** Most urgent vulnerability names (for the description). */
  sample: string[];
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

/** Aggregate unhandled `sys` / `cve` records per host (pure); items are de-duplicated per host by Type + Name. */
export function summarizeSasHostVuls(records: SasVulRecord[]): SasHostPatchState[] {
  const hosts = new Map<string, { state: SasHostPatchState; seen: Set<string>; ranked: Array<{ rank: number; name: string }> }>();
  for (const { type, rec } of records) {
    const uuid = aliUntrusted(rec.Uuid);
    const instanceId = aliUntrusted(rec.InstanceId);
    const key = uuid ?? instanceId;
    if (!key) continue;
    let entry = hosts.get(key);
    if (!entry) {
      const instanceName = aliUntrusted(rec.InstanceName);
      const ip = aliUntrusted(rec.InternetIp) ?? aliUntrusted(rec.IntranetIp);
      const regionId = aliUntrusted(rec.RegionId);
      const os = aliUntrusted(rec.OsName) ?? aliUntrusted(rec.OsVersion);
      entry = {
        state: {
          key,
          ...(uuid ? { uuid } : {}),
          ...(instanceId ? { instanceId } : {}),
          ...(instanceName ? { instanceName } : {}),
          ...(ip ? { ip } : {}),
          ...(regionId ? { regionId } : {}),
          ...(os ? { os } : {}),
          total: 0,
          asap: 0,
          later: 0,
          nntf: 0,
          unknown: 0,
          sys: 0,
          cve: 0,
          sample: [],
        },
        seen: new Set(),
        ranked: [],
      };
      hosts.set(key, entry);
    }
    const name = aliUntrusted(rec.AliasName) ?? aliUntrusted(rec.Name) ?? "unnamed vulnerability";
    const itemKey = `${type}|${aliUntrusted(rec.Name) ?? name}`;
    if (entry.seen.has(itemKey)) continue;
    entry.seen.add(itemKey);
    const s = entry.state;
    const necessity = sasNecessity(rec);
    s.total++;
    s[necessity]++;
    if (type === "sys") s.sys++;
    else s.cve++;
    entry.ranked.push({ rank: SAS_NECESSITY_RANK[necessity], name });
  }
  return [...hosts.values()].map(({ state, ranked }) => {
    ranked.sort((a, b) => a.rank - b.rank || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return { ...state, sample: ranked.slice(0, 5).map((r) => r.name) };
  });
}

/** riskScore mirroring the AWS patch scanner: high-priority items → 7.5, later / unrated → 5.5, only nntf → 3.0. */
export function sasPatchRiskScore(state: Pick<SasHostPatchState, "asap" | "later" | "unknown">): number {
  if (state.asap > 0) return 7.5;
  if (state.later > 0 || state.unknown > 0) return 5.5;
  return 3.0;
}

/** Highest risk first, then most high-priority items, then most items, then key. */
export function sortSasHostStates(list: SasHostPatchState[]): SasHostPatchState[] {
  return [...list].sort((a, b) => {
    const ra = sasPatchRiskScore(a);
    const rb = sasPatchRiskScore(b);
    if (ra !== rb) return rb - ra;
    if (a.asap !== b.asap) return b.asap - a.asap;
    if (a.total !== b.total) return b.total - a.total;
    return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  });
}

export class AliSasPatchScanner implements Scanner {
  readonly moduleName = "patch_compliance_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);

      const edition = await checkSasEdition(env, WHAT);
      if (edition.kind === "stop") return emptyScanResult(this.moduleName, startMs, { warnings: [edition.warning] });
      if (edition.warning) warnings.push(edition.warning);

      const listing = await listSasVulRecords(env, SAS_PATCH_VUL_TYPES, WHAT);
      warnings.push(...listing.warnings);

      const hosts = sortSasHostStates(summarizeSasHostVuls(listing.records)).filter((h) => h.total > 0);
      for (const h of hosts.slice(0, SAS_PATCH_MAX_HOST_FINDINGS)) findings.push(this.hostFinding(h, env.accountId));

      if (hosts.length > SAS_PATCH_MAX_HOST_FINDINGS) {
        const high = hosts.filter((h) => h.asap > 0).length;
        warnings.push(
          `SAS: ${hosts.length} host(s) with unhandled OS vulnerabilities (${high} with high-priority items); only the top ${SAS_PATCH_MAX_HOST_FINDINGS} (by risk and missing patch count) are reported as findings. Review the rest in the Security Center console.`,
        );
      }

      return {
        ...emptyScanResult(this.moduleName, startMs, { warnings }),
        resourcesScanned: hosts.length,
        findingsCount: findings.length,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "SAS patch compliance scan failed", err, warnings);
    }
  }

  private hostFinding(h: SasHostPatchState, accountId: string): Finding {
    const id = h.instanceId ?? h.key;
    const label = h.instanceName && h.instanceName !== id ? `${id} (${h.instanceName})` : id;
    const riskScore = sasPatchRiskScore(h);

    const titleParts: string[] = [];
    if (h.asap > 0) titleParts.push(`${h.asap} high-priority`);
    if (h.later > 0) titleParts.push(`${h.later} medium-priority`);
    if (h.nntf > 0) titleParts.push(`${h.nntf} low-priority`);
    if (h.unknown > 0) titleParts.push(`${h.unknown} unrated`);

    const descParts = [
      `Host: ${label}`,
      h.uuid && h.uuid !== id ? `Security Center UUID: ${h.uuid}` : undefined,
      h.os ? `OS: ${h.os}` : undefined,
      h.ip ? `IP: ${h.ip}` : undefined,
      `Unhandled vulnerabilities: ${h.total} (Windows system patches: ${h.sys}, Linux software: ${h.cve})`,
      `High-priority (asap): ${h.asap}`,
      `Medium-priority (later): ${h.later}`,
      `Low-priority (nntf): ${h.nntf}`,
      h.sample.length > 0 ? `Examples: ${h.sample.join(", ")}` : undefined,
    ].filter((p): p is string => Boolean(p));

    const resourceArn =
      h.instanceId && h.regionId ? toAliUrn("ecs", "instance", h.instanceId, h.regionId, accountId) : toAliUrn("sas", "host", h.key, "", accountId);

    return makeFinding({
      riskScore,
      title: `Host ${label} has ${h.total} unpatched OS vulnerabilities (${titleParts.join(", ")})`,
      resourceType: "ACS::ECS::Instance",
      resourceId: id,
      resourceArn,
      region: h.regionId ?? "global",
      description: descParts.join(". ") + ".",
      impact: `Host has ${h.total} unhandled operating system / package vulnerabilities${h.asap > 0 ? ` including ${h.asap} high-priority` : ""} — potential security vulnerabilities.`,
      remediationSteps: [
        `Review the host in the Security Center console → Assets → Servers → ${label} → Vulnerabilities.`,
        "Fix high-priority (asap) items first (Security Center one-click fix, Windows Update or the package manager), then reboot if required.",
        "Verify the fix with a Security Center re-scan; ignore only vulnerabilities that are confirmed not applicable.",
        "Establish a regular OS patch cadence (e.g. scheduled vulnerability scans + maintenance windows).",
      ],
      accountId,
      module: this.moduleName,
    });
  }
}

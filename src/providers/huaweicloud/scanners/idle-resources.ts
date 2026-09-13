/**
 * Huawei Cloud idle resources scanner (moduleName `idle_resources`).
 *
 * Mirrors `src/scanners/idle-resources.ts` (EC2) per resource class:
 *  1. EVS volumes with `status === "available"` (unattached)         → 3.0
 *  2. EIPs with `status === "DOWN"` (allocated but unbound)          → 2.0
 *  3. ECS servers `SHUTOFF` for more than 30 days                    → 3.0
 *     (Huawei exposes no stop timestamp; the server's `updated` time —
 *     the last state change — is used as the stop time proxy. Servers
 *     without a parseable `updated` produce a warning, as on AWS.)
 *  4. VPC security groups not referenced by any ECS server           → 2.0
 *     (skipped when the ECS listing failed, to avoid false positives;
 *     the `default` group is never reported.)
 *
 * Pagination: EVS `offset`/`limit` (+ `count`), EIP `marker`(= last id)/`limit`,
 * ECS `offset`(page)/`limit` (+ `count`), VPC `marker`(= last id)/`limit`.
 *
 * Graceful degradation: 403 / not enabled per service → warning, continue.
 * Any other failure → status "error" (as the AWS scanner).
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwRegionScopeFromContext, parseHwTimestamp } from "./shared.js";

export const EVS_PAGE_SIZE = 100;
export const EVS_MAX_VOLUMES = 2000;
export const EIP_PAGE_SIZE = 100;
export const EIP_MAX_ADDRESSES = 2000;
export const ECS_PAGE_SIZE = 100;
export const ECS_MAX_SERVERS = 1000;
export const SG_PAGE_SIZE = 100;
export const SG_MAX_GROUPS = 2000;
export const STOPPED_DAYS_THRESHOLD = 30;
const MAX_PAGES = 100;

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

interface LooseVolume {
  id?: string;
  name?: string;
  status?: string;
  size?: number;
  volume_type?: string;
  volumeType?: string;
  attachments?: unknown[];
}
interface LooseListVolumesResponse {
  volumes?: LooseVolume[];
  count?: number;
}

interface LoosePublicip {
  id?: string;
  status?: string;
  public_ip_address?: string;
  publicIpAddress?: string;
  port_id?: string;
  portId?: string;
  alias?: string;
  bandwidth_size?: number;
  bandwidthSize?: number;
}
interface LooseListPublicipsResponse {
  publicips?: LoosePublicip[];
}

interface LooseServerSecurityGroup {
  id?: string;
  name?: string;
}
interface LooseServer {
  id?: string;
  name?: string;
  status?: string;
  updated?: string;
  flavor?: { id?: string; name?: string };
  security_groups?: LooseServerSecurityGroup[];
  securityGroups?: LooseServerSecurityGroup[];
}
interface LooseListServersResponse {
  servers?: LooseServer[];
  count?: number;
}

interface LooseSecurityGroup {
  id?: string;
  name?: string;
  description?: string;
  vpc_id?: string;
  vpcId?: string;
}
interface LooseListSecurityGroupsResponse {
  security_groups?: LooseSecurityGroup[];
  securityGroups?: LooseSecurityGroup[];
}

/** Minimal client surfaces (tests inject fakes). */
export interface EvsLikeClient {
  listVolumes(req?: unknown): Promise<unknown>;
}
export interface EipLikeClient {
  listPublicips(req?: unknown): Promise<unknown>;
}
export interface EcsLikeClient {
  listServersDetails(req?: unknown): Promise<unknown>;
}
export interface VpcLikeClient {
  listSecurityGroups(req?: unknown): Promise<unknown>;
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: {
  riskScore: number;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  remediationSteps: string[];
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "huaweicloud" };
}

/** Whole days a SHUTOFF server has been stopped, using `updated` as the stop-time proxy; undefined when unknown. */
export function stoppedDays(server: { updated?: string }, nowMs: number = Date.now()): number | undefined {
  const t = parseHwTimestamp(server.updated);
  if (t === undefined) return undefined;
  return Math.round((nowMs - t) / (24 * 60 * 60 * 1000));
}

/**
 * Generic marker pagination for list calls whose response carries no page
 * info (EIP v2, VPC v2): the marker is the last item's `id`.
 */
async function listByIdMarker<T extends { id?: string }>(
  call: (req: Record<string, unknown>) => Promise<unknown>,
  pick: (resp: unknown) => T[] | undefined,
  pageSize: number,
  max: number,
): Promise<{ items: T[]; truncated: boolean }> {
  const items: T[] = [];
  let marker: string | undefined;
  let truncated = false;
  for (let page = 0; page < MAX_PAGES; page++) {
    const req: Record<string, unknown> = { limit: pageSize };
    if (marker !== undefined) req.marker = marker;
    const batch = pick(await call(req)) ?? [];
    items.push(...batch);
    if (items.length >= max) {
      truncated = items.length > max || batch.length === pageSize;
      items.length = Math.min(items.length, max);
      break;
    }
    if (batch.length === 0 || batch.length < pageSize) break;
    const last = batch[batch.length - 1]?.id;
    if (!last || last === marker) break;
    marker = last;
  }
  return { items, truncated };
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiIdleResourcesScanner implements Scanner {
  readonly moduleName = "idle_resources";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const creds = hwCredentialsFromContext(ctx, "basic");
      const scope = await hwRegionScopeFromContext(ctx, creds);
      const { region } = scope;
      const domainId = scope.domainId || ctx.accountId;
      const now = Date.now();

      // 1. Unattached EVS volumes (status = "available")
      try {
        const { EvsClient } = await import("@huaweicloud/huaweicloud-sdk-evs");
        const evs = (await hwClient(EvsClient, "evs", creds, scope)) as unknown as EvsLikeClient;

        const volumes: LooseVolume[] = [];
        let truncated = false;
        for (let page = 0; page < MAX_PAGES; page++) {
          const resp = (await evs.listVolumes({ limit: EVS_PAGE_SIZE, offset: page * EVS_PAGE_SIZE })) as LooseListVolumesResponse | undefined;
          const batch = Array.isArray(resp?.volumes) ? resp!.volumes! : [];
          volumes.push(...batch);
          if (volumes.length >= EVS_MAX_VOLUMES) {
            truncated = volumes.length > EVS_MAX_VOLUMES || batch.length === EVS_PAGE_SIZE;
            volumes.length = Math.min(volumes.length, EVS_MAX_VOLUMES);
            break;
          }
          const count = typeof resp?.count === "number" ? resp.count : undefined;
          if (batch.length === 0 || batch.length < EVS_PAGE_SIZE || (count !== undefined && volumes.length >= count)) break;
        }
        if (truncated) warnings.push(`EVS: more than ${EVS_MAX_VOLUMES} volumes; only the first ${EVS_MAX_VOLUMES} were checked.`);

        resourcesScanned += volumes.length;

        for (const vol of volumes) {
          if ((vol.status ?? "").toLowerCase() !== "available") continue;
          const volId = vol.id ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 3.0,
              title: `EVS volume ${volId} is unattached`,
              resourceType: "HuaweiCloud::EVS::Volume",
              resourceId: volId,
              resourceArn: toResourceUrn("evs", "volume", volId, region, domainId),
              region,
              description: `EVS volume "${volId}"${vol.name ? ` (${vol.name})` : ""} (${vol.size ?? "?"}GB, ${vol.volume_type ?? vol.volumeType ?? "unknown"}) is in "available" state with no attachments.`,
              impact:
                "Unattached volumes incur storage costs and may contain sensitive data that is no longer actively managed.",
              remediationSteps: [
                "Determine if the volume is still needed.",
                "If not needed, create a snapshot (or CBR backup) for archival and delete the volume.",
                "If needed, attach it to the appropriate ECS server.",
              ],
            }),
          );
        }
      } catch (err) {
        const degraded = degradeHwError("EVS", err);
        if (!degraded) throw err;
        warnings.push(degraded);
      }

      // 2. Unbound EIPs (status = "DOWN")
      try {
        const { EipClient } = await import("@huaweicloud/huaweicloud-sdk-eip/v2/EipClient.js");
        const eip = (await hwClient(EipClient, "eip", creds, scope)) as unknown as EipLikeClient;

        const { items: publicips, truncated } = await listByIdMarker<LoosePublicip>(
          (req) => eip.listPublicips(req),
          (resp) => (Array.isArray((resp as LooseListPublicipsResponse | undefined)?.publicips) ? (resp as LooseListPublicipsResponse).publicips : undefined),
          EIP_PAGE_SIZE,
          EIP_MAX_ADDRESSES,
        );
        if (truncated) warnings.push(`EIP: more than ${EIP_MAX_ADDRESSES} public IPs; only the first ${EIP_MAX_ADDRESSES} were checked.`);

        resourcesScanned += publicips.length;

        for (const ip of publicips) {
          if ((ip.status ?? "").toUpperCase() !== "DOWN") continue;
          const id = ip.id ?? "unknown";
          const address = ip.public_ip_address ?? ip.publicIpAddress ?? "unknown";
          findings.push(
            makeFinding({
              riskScore: 2.0,
              title: `Elastic IP ${address} is not bound`,
              resourceType: "HuaweiCloud::EIP::PublicIp",
              resourceId: id,
              resourceArn: toResourceUrn("eip", "publicip", id, region, domainId),
              region,
              description: `Elastic IP ${address} (${id}${ip.alias ? `, ${ip.alias}` : ""}) is allocated but not bound to any ECS server, NAT gateway or load balancer (status DOWN).`,
              impact: "Unbound EIPs are billed while idle and represent unnecessary spend.",
              remediationSteps: [
                "Bind the EIP to an ECS server, NAT gateway or load balancer if needed.",
                "Release the EIP if it is no longer required.",
              ],
            }),
          );
        }
      } catch (err) {
        const degraded = degradeHwError("EIP", err);
        if (!degraded) throw err;
        warnings.push(degraded);
      }

      // 3. Stopped ECS servers (SHUTOFF > 30 days)
      let servers: LooseServer[] | undefined;
      try {
        const { EcsClient } = await import("@huaweicloud/huaweicloud-sdk-ecs");
        const ecs = (await hwClient(EcsClient, "ecs", creds, scope)) as unknown as EcsLikeClient;

        const list: LooseServer[] = [];
        let truncated = false;
        for (let page = 1; page <= MAX_PAGES; page++) {
          const resp = (await ecs.listServersDetails({ offset: page, limit: ECS_PAGE_SIZE })) as LooseListServersResponse | undefined;
          const batch = Array.isArray(resp?.servers) ? resp!.servers! : [];
          list.push(...batch);
          if (list.length >= ECS_MAX_SERVERS) {
            truncated = list.length > ECS_MAX_SERVERS || batch.length === ECS_PAGE_SIZE;
            list.length = Math.min(list.length, ECS_MAX_SERVERS);
            break;
          }
          const count = typeof resp?.count === "number" ? resp.count : undefined;
          if (batch.length === 0 || batch.length < ECS_PAGE_SIZE || (count !== undefined && list.length >= count)) break;
        }
        if (truncated) warnings.push(`ECS: more than ${ECS_MAX_SERVERS} servers; only the first ${ECS_MAX_SERVERS} were checked (security group usage may be incomplete).`);
        servers = list;

        resourcesScanned += list.length;

        for (const srv of list) {
          if ((srv.status ?? "").toUpperCase() !== "SHUTOFF") continue;
          const id = srv.id ?? "unknown";
          const days = stoppedDays(srv, now);
          if (days === undefined) {
            warnings.push(`Could not determine stop date for ECS server ${id} (no parseable "updated" timestamp).`);
            continue;
          }
          if (days <= STOPPED_DAYS_THRESHOLD) continue;
          findings.push(
            makeFinding({
              riskScore: 3.0,
              title: `ECS server ${id} has been stopped for ${days} days`,
              resourceType: "HuaweiCloud::ECS::CloudServer",
              resourceId: id,
              resourceArn: toResourceUrn("ecs", "server", id, region, domainId),
              region,
              description: `ECS server "${id}"${srv.name ? ` (${srv.name})` : ""} (${srv.flavor?.id ?? srv.flavor?.name ?? "unknown"}) has been in SHUTOFF state for about ${days} days (last state change ${srv.updated}). Attached EVS disks continue to incur charges.`,
              impact:
                "Stopped servers still incur EVS storage costs and may contain stale configurations or unpatched images.",
              remediationSteps: [
                "Determine if the server is still needed.",
                "If not needed, create an image (IMS) for archival and delete the server.",
                "If needed temporarily, consider stopping with billing suspension (\"stop-charging\") or recreating it on demand from an image.",
              ],
            }),
          );
        }
      } catch (err) {
        const degraded = degradeHwError("ECS", err);
        if (!degraded) throw err;
        warnings.push(degraded);
      }

      // 4. Security groups not referenced by any ECS server
      if (servers === undefined) {
        warnings.push("VPC: security group usage check skipped because the ECS server listing was unavailable.");
      } else {
        try {
          const { VpcClient } = await import("@huaweicloud/huaweicloud-sdk-vpc");
          const vpc = (await hwClient(VpcClient, "vpc", creds, scope)) as unknown as VpcLikeClient;

          const { items: groups, truncated } = await listByIdMarker<LooseSecurityGroup>(
            (req) => vpc.listSecurityGroups(req),
            (resp) => {
              const r = resp as LooseListSecurityGroupsResponse | undefined;
              const list = r?.security_groups ?? r?.securityGroups;
              return Array.isArray(list) ? list : undefined;
            },
            SG_PAGE_SIZE,
            SG_MAX_GROUPS,
          );
          if (truncated) warnings.push(`VPC: more than ${SG_MAX_GROUPS} security groups; only the first ${SG_MAX_GROUPS} were checked.`);

          const usedSgIds = new Set<string>();
          for (const srv of servers) {
            for (const g of srv.security_groups ?? srv.securityGroups ?? []) {
              if (g?.id) usedSgIds.add(g.id);
            }
          }

          resourcesScanned += groups.length;

          for (const sg of groups) {
            const sgId = sg.id ?? "unknown";
            // The default security group cannot be deleted — skip it, as on AWS.
            if (sg.name === "default") continue;
            if (usedSgIds.has(sgId)) continue;
            findings.push(
              makeFinding({
                riskScore: 2.0,
                title: `Security group ${sgId} is not attached to any ECS server`,
                resourceType: "HuaweiCloud::VPC::SecurityGroup",
                resourceId: sgId,
                resourceArn: toResourceUrn("vpc", "security-group", sgId, region, domainId),
                region,
                description: `Security group "${sg.name ?? "unknown"}" (${sgId}) is not associated with any ECS server in this region.`,
                impact: "Unused security groups add clutter and may cause confusion during security reviews.",
                remediationSteps: [
                  "Verify the security group is not referenced by other resources (e.g., RDS instances, ELB, ENIs/ports, CCE nodes).",
                  "Delete the security group if it is no longer needed.",
                ],
              }),
            );
          }
        } catch (err) {
          const degraded = degradeHwError("VPC", err);
          if (!degraded) throw err;
          warnings.push(degraded);
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud idle resources scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

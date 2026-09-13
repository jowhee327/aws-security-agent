/**
 * Huawei Cloud ECS metadata-service token enforcement (moduleName `imdsv2_enforcement`, plan T9).
 *
 * Mirrors `src/scanners/imdsv2-enforcement.ts` (EC2 HttpTokens):
 *
 *  1. `listServersDetails({status:"ACTIVE", offset:<page>, limit})` — running
 *     servers only, as the AWS scanner filters `instance-state-name=running`
 *     (drop the `status` filter to include stopped servers). Paginated, cap
 *     {@link IMDS_MAX_SERVERS} with a truncation warning.
 *  2. Per server (N+1 — ECS does not return metadata options in the list, so
 *     bounded concurrency {@link IMDS_CONCURRENCY}): `showMetadataOptions({server_id})`
 *     → `{ http_endpoint: enabled|disabled, http_tokens: optional|required }`.
 *     - `http_endpoint === "disabled"` → metadata service off → no finding.
 *     - `http_tokens !== "required"` → Finding, riskScore 7.5 (same as AWS
 *       "does not enforce IMDSv2"). A missing `http_tokens` value counts as
 *       not enforced, as on AWS (`?? "unknown"`).
 *
 * Graceful degradation: 403 / not enabled on the server listing → warning +
 * status success; per-server 403 / 404 are aggregated into ONE warning (count
 * + first redacted diagnostic) and the scan continues; other per-server
 * failures are aggregated the same way. Unexpected failures of the server
 * listing → status "error".
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { classifyHwError, degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwRegionScopeFromContext } from "./shared.js";

export const IMDS_PAGE_SIZE = 100;
export const IMDS_MAX_SERVERS = 500;
export const IMDS_CONCURRENCY = 5;
/** Server states evaluated (AWS parity: running instances only). */
export const IMDS_SERVER_STATUS = "ACTIVE";
const MAX_PAGES = 100;

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

export interface LooseEcsServer {
  id?: string;
  name?: string;
  status?: string;
  flavor?: { id?: string; name?: string };
  metadata?: Record<string, unknown>;
}
interface LooseListServersResponse {
  servers?: LooseEcsServer[];
  count?: number;
}
export interface LooseMetadataOptions {
  http_endpoint?: string;
  httpEndpoint?: string;
  http_tokens?: string;
  httpTokens?: string;
}

/** Minimal client surface (tests inject fakes). */
export interface EcsMetadataClient {
  listServersDetails(req?: unknown): Promise<unknown>;
  showMetadataOptions(req?: unknown): Promise<unknown>;
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
  accountId: string;
  module: string;
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "huaweicloud" };
}

export type MetadataVerdict = "enforced" | "not_enforced" | "endpoint_disabled";

/** Pure evaluation of a metadata-options response (AWS semantics: anything but "required" is not enforced). */
export function evaluateMetadataOptions(opts: LooseMetadataOptions | undefined): { verdict: MetadataVerdict; httpTokens: string; httpEndpoint: string } {
  const httpEndpoint = (opts?.http_endpoint ?? opts?.httpEndpoint ?? "enabled").toString().toLowerCase();
  const httpTokens = (opts?.http_tokens ?? opts?.httpTokens ?? "unknown").toString().toLowerCase();
  if (httpEndpoint === "disabled") return { verdict: "endpoint_disabled", httpTokens, httpEndpoint };
  return { verdict: httpTokens === "required" ? "enforced" : "not_enforced", httpTokens, httpEndpoint };
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

type ServerOutcome =
  | { kind: "ok"; server: LooseEcsServer; options: LooseMetadataOptions | undefined }
  | { kind: "failed"; server: LooseEcsServer; err: unknown };

export class HuaweiEcsImdsv2Scanner implements Scanner {
  readonly moduleName = "imdsv2_enforcement";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const creds = hwCredentialsFromContext(ctx, "basic");
      const scope = await hwRegionScopeFromContext(ctx, creds);
      const { region } = scope;
      const domainId = scope.domainId || ctx.accountId;

      const { EcsClient } = await import("@huaweicloud/huaweicloud-sdk-ecs");
      const ecs = (await hwClient(EcsClient, "ecs", creds, scope)) as unknown as EcsMetadataClient;

      // 1. Running servers (paginated: offset = page number starting at 1, capped).
      const servers: LooseEcsServer[] = [];
      try {
        let truncated = false;
        for (let page = 1; page <= MAX_PAGES; page++) {
          const resp = (await ecs.listServersDetails({ status: IMDS_SERVER_STATUS, offset: page, limit: IMDS_PAGE_SIZE })) as
            | LooseListServersResponse
            | undefined;
          const batch = Array.isArray(resp?.servers) ? resp!.servers! : [];
          servers.push(...batch);
          if (servers.length >= IMDS_MAX_SERVERS) {
            truncated = servers.length > IMDS_MAX_SERVERS || batch.length === IMDS_PAGE_SIZE;
            servers.length = Math.min(servers.length, IMDS_MAX_SERVERS);
            break;
          }
          const count = typeof resp?.count === "number" ? resp.count : undefined;
          if (batch.length === 0 || batch.length < IMDS_PAGE_SIZE || (count !== undefined && servers.length >= count)) break;
        }
        if (truncated) warnings.push(`ECS: more than ${IMDS_MAX_SERVERS} running servers; only the first ${IMDS_MAX_SERVERS} were checked.`);
      } catch (err) {
        const degraded = degradeHwError("ECS", err);
        if (!degraded) throw err;
        warnings.push(degraded);
        return this.result(startMs, 0, findings, warnings);
      }

      // 2. Metadata options per server (N+1, bounded).
      const tasks = servers.map((server) => async (): Promise<ServerOutcome> => {
        if (!server.id) return { kind: "failed", server, err: new Error("server has no id") };
        try {
          const options = (await ecs.showMetadataOptions({ server_id: server.id })) as LooseMetadataOptions | undefined;
          return { kind: "ok", server, options };
        } catch (err) {
          return { kind: "failed", server, err };
        }
      });
      const settled = await runWithConcurrency(tasks, IMDS_CONCURRENCY);

      const unavailable: { count: number; first?: unknown } = { count: 0 };
      const failed: { count: number; first?: unknown } = { count: 0 };

      for (const r of settled) {
        if (r.status === "rejected") {
          failed.count++;
          failed.first ??= r.reason;
          continue;
        }
        const outcome = r.value;
        if (outcome.kind === "failed") {
          const { kind } = classifyHwError(outcome.err);
          const bucket = kind === "access_denied" || kind === "not_found" || kind === "not_enabled" ? unavailable : failed;
          bucket.count++;
          bucket.first ??= outcome.err;
          continue;
        }
        const { server, options } = outcome;
        const { verdict, httpTokens, httpEndpoint } = evaluateMetadataOptions(options);
        if (verdict !== "not_enforced") continue;

        const serverId = server.id ?? "unknown";
        const flavor = server.flavor?.id ?? server.flavor?.name ?? "unknown";
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: `ECS server ${serverId} does not enforce metadata service tokens (IMDSv2)`,
            resourceType: "HuaweiCloud::ECS::CloudServer",
            resourceId: serverId,
            resourceArn: toResourceUrn("ecs", "server", serverId, region, domainId),
            region,
            description: [
              `ECS server ${serverId}${server.name ? ` (${server.name})` : ""} (flavor: ${flavor}, state: ${server.status ?? "unknown"}) has http_tokens set to "${httpTokens}" (http_endpoint: ${httpEndpoint}).`,
              "The metadata service accepts unauthenticated (token-less) requests, allowing IMDSv1-style access.",
            ].join(" "),
            impact: "Token-less metadata access lets attackers steal the server's IAM agency temporary credentials via SSRF attacks",
            remediationSteps: [
              'Enforce token-based metadata access by setting http_tokens to "required" (ECS console → server → Metadata options, or the ECS API UpdateMetadataOptions).',
              "Update applications on the server to use the token-based metadata workflow (PUT /openstack/latest/api/token, then requests with X-Metadata-Token).",
              "Bake the setting into images / launch templates and Auto Scaling configurations so new servers enforce it.",
              'If the server does not need the metadata service at all, set http_endpoint to "disabled".',
            ],
            accountId: domainId,
            module: this.moduleName,
          }),
        );
      }

      if (unavailable.count > 0) {
        warnings.push(
          `ECS: metadata options unavailable for ${unavailable.count} server(s) (insufficient permissions or not found — ${describeHwError(unavailable.first)}); those servers were not evaluated.`,
        );
      }
      if (failed.count > 0) {
        warnings.push(`ECS: metadata options lookup failed for ${failed.count} server(s) (${describeHwError(failed.first)}); those servers were not evaluated.`);
      }

      return this.result(startMs, servers.length, findings, warnings);
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud ECS metadata options scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }

  private result(startMs: number, resourcesScanned: number, findings: Finding[], warnings: string[]): ScanResult {
    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : undefined,
      resourcesScanned,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }
}

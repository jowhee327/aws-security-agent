/**
 * Detection-only scanner: checks whether the Huawei Cloud RMS (Config)
 * resource recorder ("tracker") is enabled for the account.
 *
 * Mirrors `src/scanners/config-rules-findings.ts` (AWS Config recorder check):
 * same moduleName so reports / i18n reuse, 0 findings, a warning when the
 * recorder is missing, graceful degradation on 403, `status: "error"` only for
 * genuine failures. Compliance findings themselves come from the RMS
 * compliance aggregation scanner (plan T6).
 *
 * RMS is a global service: endpoint `rms.myhuaweicloud.com`, GlobalCredentials
 * with the account domain ID (fills the `{domain_id}` path parameter).
 */
import type { Scanner } from "../../../scanners/base.js";
import type { ScanContext, ScanResult } from "../../../types.js";
import { hwClient } from "../client.js";
import { classifyHwError, degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { emptyScanResult, hwCredentialsFromContext, hwDomainIdFromContext } from "./shared.js";

export const RMS_TRACKER_NOT_ENABLED_WARNING =
  "Huawei Cloud RMS (Config) resource recorder is not enabled for this account.";

/** Logical URN of the (single, account-level) RMS tracker. */
export function rmsTrackerUrn(domainId: string): string {
  return toResourceUrn("rms", "tracker", "default", "global", domainId);
}

/** Minimal surface of ConfigClient used here (lets tests inject fakes). */
export interface RmsTrackerClient {
  showTrackerConfig(req?: unknown): Promise<unknown>;
}

/**
 * Loose runtime shape of ShowTrackerConfigResponse. The SDK deserializes JSON
 * into plain objects, so wire keys (`retention_period_in_days`, `frozen_status`)
 * are what exist at runtime; camelCase accessors are accepted for model
 * instances / fakes.
 */
interface LooseTrackerConfig {
  channel?: unknown;
  selector?: unknown;
  agency_name?: string;
  agencyName?: string;
  retention_period_in_days?: number;
  retentionPeriodInDays?: number;
  frozen_status?: { is_frozen?: boolean; frozen_scene?: string[]; isFrozen?: boolean; frozenScene?: string[] };
  frozenStatus?: { is_frozen?: boolean; frozen_scene?: string[]; isFrozen?: boolean; frozenScene?: string[] };
}

export function isTrackerConfigured(resp: unknown): boolean {
  if (!resp || typeof resp !== "object") return false;
  const r = resp as LooseTrackerConfig;
  return (
    r.channel !== undefined ||
    r.selector !== undefined ||
    r.agency_name !== undefined ||
    r.agencyName !== undefined ||
    r.retention_period_in_days !== undefined ||
    r.retentionPeriodInDays !== undefined
  );
}

function frozenScenes(resp: unknown): string[] | undefined {
  const r = resp as LooseTrackerConfig;
  const fs = r.frozen_status ?? r.frozenStatus;
  if (!fs) return undefined;
  const frozen = fs.is_frozen ?? fs.isFrozen;
  if (!frozen) return undefined;
  return fs.frozen_scene ?? fs.frozenScene ?? [];
}

export class RmsTrackerScanner implements Scanner {
  readonly moduleName = "config_rules_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const creds = hwCredentialsFromContext(ctx, "global");
      const domainId = await hwDomainIdFromContext(ctx, creds);
      const { ConfigClient } = await import("@huaweicloud/huaweicloud-sdk-config");
      const client = (await hwClient(ConfigClient, "rms", creds, {
        region: ctx.region,
        domainId,
      })) as unknown as RmsTrackerClient;

      // The SDK binds `{domain_id}` from GlobalCredentials; the request body is empty.
      const resp = await client.showTrackerConfig({ domainId });

      if (!isTrackerConfigured(resp)) {
        warnings.push(RMS_TRACKER_NOT_ENABLED_WARNING);
      } else {
        const scenes = frozenScenes(resp);
        if (scenes) {
          warnings.push(
            `Huawei Cloud RMS (Config) resource recorder ${rmsTrackerUrn(domainId)} is frozen` +
              (scenes.length > 0 ? ` (${scenes.join(", ")})` : "") +
              "; resource changes are not being recorded.",
          );
        }
      }

      return emptyScanResult(this.moduleName, startMs, { warnings });
    } catch (err) {
      const { kind } = classifyHwError(err);

      if (kind === "not_found" || kind === "not_enabled") {
        warnings.push(`${RMS_TRACKER_NOT_ENABLED_WARNING} (${describeHwError(err)})`);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }

      if (kind === "access_denied") {
        warnings.push(degradeHwError("RMS", err) ?? `RMS: insufficient permissions (${describeHwError(err)}); skipped`);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }

      return emptyScanResult(this.moduleName, startMs, {
        status: "error",
        error: `RMS tracker detection check failed: ${describeHwError(err)}`,
      });
    }
  }
}

/**
 * Detection-only scanner: checks whether the Alibaba Cloud Config resource recorder is
 * enabled for the account (moduleName `config_rules_findings`, plan §4.1 / T2).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/config-rules-findings.ts` (AWS Config recorder check) and the
 * Huawei RMS tracker scanner: same moduleName so reports / i18n reuse, 0 findings, a
 * warning when the recorder is missing / not REGISTERED, graceful degradation on
 * access denied. Compliance findings come from `config_compliance_findings`.
 *
 * API: Config `GetConfigurationRecorder` (2020-09-07) on the centralised, site-dependent
 * endpoint (`config.cn-shanghai.aliyuncs.com` cn / `config.ap-southeast-1.aliyuncs.com`
 * intl). Response: `ConfigurationRecorder.ConfigurationRecorderStatus` ∈
 * REGISTRABLE | BUILDING | REGISTERED | REBUILDING | UNREGISTERED (+ `ResourceTypes`).
 *
 * Errors: auth_failed / api_misuse / other → `status: "error"` (an authentication failure
 * is NEVER reported as "not enabled", plan §6.1); not_enabled / not_found → warning;
 * access_denied / throttled / network → degraded warning.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { ScanContext, ScanResult } from "../../../types.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliEndpoint, type AliSite } from "../client.js";
import { classifyAliError, degradeAliError, describeAliError } from "../errors.js";
import { toAliUrn } from "../urn.js";
import { aliCallCtx, aliErrorResult, aliField, aliScanEnv, aliString, emptyScanResult } from "./shared.js";

export const ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING =
  "Alibaba Cloud Config resource recorder is not enabled for this account.";

export const ALI_CONFIG_RECORDER_REGISTERED = "REGISTERED";

/** Logical URN of the (single, account-level) Config recorder. */
export function aliConfigRecorderUrn(accountId: string): string {
  return toAliUrn("config", "recorder", "default", "", accountId);
}

/** `ConfigurationRecorder.ConfigurationRecorderStatus` (upper-cased), undefined when absent. */
export function configRecorderStatus(body: unknown): string | undefined {
  const status = aliString(aliField(aliField(body, "ConfigurationRecorder"), "ConfigurationRecorderStatus"));
  return status?.toUpperCase();
}

/** Number of resource types the recorder monitors (undefined when not reported). */
export function configRecorderResourceTypeCount(body: unknown): number | undefined {
  const types = aliField(aliField(body, "ConfigurationRecorder"), "ResourceTypes");
  return Array.isArray(types) ? types.length : undefined;
}

export function configEndpointNote(site: AliSite): string {
  return `endpoint ${aliEndpoint("config", undefined, site)}, site ${site}`;
}

export class AliConfigRecorderScanner implements Scanner {
  readonly moduleName = "config_rules_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    let site: AliSite | undefined;

    try {
      const env = aliScanEnv(ctx);
      site = env.site;
      const body = await aliCall(ALI_API.config.GetConfigurationRecorder, aliCallCtx(env));
      const status = configRecorderStatus(body);

      if (status !== ALI_CONFIG_RECORDER_REGISTERED) {
        warnings.push(
          `${ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING} (ConfigurationRecorderStatus=${status ?? "absent"}; ${configEndpointNote(env.site)})`,
        );
      } else if (configRecorderResourceTypeCount(body) === 0) {
        warnings.push(
          `Alibaba Cloud Config resource recorder ${aliConfigRecorderUrn(env.accountId)} is registered but monitors no resource types.`,
        );
      }
      return emptyScanResult(this.moduleName, startMs, { warnings });
    } catch (err) {
      const { kind } = classifyAliError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        const where = site ? `; ${configEndpointNote(site)}` : "";
        warnings.push(`${ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING} (${describeAliError(err)}${where})`);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }
      const degraded = degradeAliError("Config", err);
      if (degraded) {
        warnings.push(degraded);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }
      return aliErrorResult(this.moduleName, startMs, "Config recorder detection check failed", err);
    }
  }
}

/**
 * Huawei Cloud secret exposure scanner (moduleName `secret_exposure`).
 *
 * Mirrors `src/scanners/secret-exposure.ts` (Lambda env vars + EC2 user data):
 *  - FunctionGraph: `listFunctions` (marker pagination) → per function
 *    `showFunctionConfig` → scan `user_data` (JSON string of env vars).
 *    `encrypted_user_data` is fine (encrypted at rest) and never inspected.
 *  - ECS: `listServersDetails` (offset/limit pagination) → decode
 *    `OS-EXT-SRV-ATTR:user_data` (base64) → scan.
 *
 * Detectors reuse the AWS `SECRET_PATTERNS` plus Huawei-specific ones (see
 * {@link HUAWEI_SECRET_PATTERNS}). Findings never contain the matched value —
 * only the detector name and, for name matches, the env-var name.
 *
 * Graceful degradation: 403 per service → warning, continue; both denied →
 * status success + warnings. Bounded concurrency and caps protect large tenants.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { SECRET_PATTERNS, type SecretPattern } from "../../../scanners/secret-exposure.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { hwClient } from "../client.js";
import { classifyHwError, degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwRegionScopeFromContext, MarkerGuard, repeatedMarkerWarning } from "./shared.js";

export const FG_MAX_FUNCTIONS = 500;
export const FG_PAGE_SIZE = 200;
export const FG_CONFIG_CONCURRENCY = 5;
export const ECS_MAX_SERVERS = 1000;
export const ECS_PAGE_SIZE = 100;
const MAX_PAGES = 50;

/**
 * Huawei-specific detectors layered on top of the shared AWS patterns. A bare
 * Huawei AK (20 upper-case alphanumerics) is too generic to match on its own,
 * so the value detector requires an assignment context (`ak=`, `access_key_id:`,
 * `HUAWEICLOUD_SDK_AK=` …) followed by a 20-char upper-case token.
 */
export const HUAWEI_EXTRA_SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: "Huawei Cloud Access Key",
    pattern:
      /\b(?:HUAWEICLOUD_SDK_AK|huaweicloud_sdk_ak|OBS_ACCESS_KEY_ID|obs_access_key_id|ACCESS_KEY_ID|access_key_id|accessKeyId|AccessKeyId|ACCESS_KEY|access_key|HW_AK|hw_ak|AK|ak)\b\s*[=:]\s*["']?[A-Z0-9]{20}(?![A-Za-z0-9])/,
    matchType: "value",
  },
  {
    name: "Huawei Cloud credential in env var",
    pattern: /^(HUAWEICLOUD_SDK_AK|HUAWEICLOUD_SDK_SK|HUAWEICLOUD_SDK_SECURITY_TOKEN|OBS_ACCESS_KEY_ID|OBS_SECRET_ACCESS_KEY|ACCESS_KEY|ACCESS_KEY_ID|SECRET_KEY|SECRET_ACCESS_KEY|HW_AK|HW_SK)$/i,
    matchType: "name",
  },
];

export const HUAWEI_SECRET_PATTERNS: readonly SecretPattern[] = [...SECRET_PATTERNS, ...HUAWEI_EXTRA_SECRET_PATTERNS];

function isAccessKeyPattern(sp: SecretPattern): boolean {
  return /Access Key/i.test(sp.name);
}

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

interface LooseFunction {
  func_urn?: string;
  funcUrn?: string;
  func_name?: string;
  funcName?: string;
  user_data?: string;
  userData?: string;
  encrypted_user_data?: string;
}

interface LooseListFunctionsResponse {
  functions?: LooseFunction[];
  next_marker?: number | string;
  nextMarker?: number | string;
  count?: number;
}

interface LooseServer {
  id?: string;
  name?: string;
  "OS-EXT-SRV-ATTR:user_data"?: string;
  osExtSrvAttrUserData?: string;
}

interface LooseListServersResponse {
  servers?: LooseServer[];
  count?: number;
}

/** Minimal client surfaces (tests inject fakes). */
export interface FunctionGraphLikeClient {
  listFunctions(req?: unknown): Promise<unknown>;
  showFunctionConfig(req?: unknown): Promise<unknown>;
}
export interface EcsLikeClient {
  listServersDetails(req?: unknown): Promise<unknown>;
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Parse FunctionGraph `user_data` (a JSON object of env vars serialized as a
 * string). Non-JSON input is returned as a single unnamed value so value
 * detectors still run over it.
 */
export function parseFunctionUserData(userData: unknown): Array<[name: string | undefined, value: string]> {
  if (userData === undefined || userData === null || userData === "") return [];
  let obj: unknown = userData;
  if (typeof userData === "string") {
    try {
      obj = JSON.parse(userData);
    } catch {
      return [[undefined, userData]];
    }
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return [[undefined, typeof userData === "string" ? userData : JSON.stringify(userData)]];
  }
  return Object.entries(obj as Record<string, unknown>).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v ?? "")]);
}

/** Decode ECS user data (base64). Never throws; falls back to the raw text when it is not valid base64. */
export function decodeEcsUserData(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length === 0) return undefined;
  const trimmed = raw.trim();
  try {
    if (/^[A-Za-z0-9+/=\s]+$/.test(trimmed)) {
      const decoded = Buffer.from(trimmed, "base64").toString("utf-8");
      if (decoded.length > 0 && !/�/.test(decoded)) return decoded;
    }
  } catch {
    // fall through to raw text
  }
  return trimmed;
}

/** Run value detectors over `text`; returns matched detectors (deduplicated by name). */
export function matchValuePatterns(text: string, patterns: readonly SecretPattern[] = HUAWEI_SECRET_PATTERNS): SecretPattern[] {
  const out: SecretPattern[] = [];
  for (const sp of patterns) {
    if (sp.matchType !== "value") continue;
    if (sp.pattern.test(text)) out.push(sp);
  }
  return out;
}

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

function toMarkerNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiSecretExposureScanner implements Scanner {
  readonly moduleName = "secret_exposure";

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

      // --- FunctionGraph ---
      try {
        const { FunctionGraphClient } = await import("@huaweicloud/huaweicloud-sdk-functiongraph");
        const fg = (await hwClient(FunctionGraphClient, "functiongraph", creds, scope)) as unknown as FunctionGraphLikeClient;

        const functions: LooseFunction[] = [];
        let marker: number | undefined;
        let truncated = false;
        const markers = new MarkerGuard();
        for (let page = 0; page < MAX_PAGES; page++) {
          const req: Record<string, string> = { maxitems: String(FG_PAGE_SIZE) };
          if (marker !== undefined) req.marker = String(marker);
          const resp = (await fg.listFunctions(req)) as LooseListFunctionsResponse | undefined;
          const batch = Array.isArray(resp?.functions) ? resp!.functions! : [];
          functions.push(...batch);
          if (functions.length >= FG_MAX_FUNCTIONS) {
            truncated = functions.length > FG_MAX_FUNCTIONS || batch.length === FG_PAGE_SIZE;
            functions.length = Math.min(functions.length, FG_MAX_FUNCTIONS);
            break;
          }
          const next = toMarkerNumber(resp?.next_marker ?? resp?.nextMarker);
          const count = typeof resp?.count === "number" ? resp.count : undefined;
          if (batch.length === 0 || next === undefined || next === marker || (count !== undefined && next >= count)) break;
          if (!markers.accept(next)) {
            warnings.push(repeatedMarkerWarning("FunctionGraph", "functions"));
            break;
          }
          marker = next;
        }
        if (truncated) warnings.push(`FunctionGraph: more than ${FG_MAX_FUNCTIONS} functions; only the first ${FG_MAX_FUNCTIONS} were checked.`);

        resourcesScanned += functions.length;

        const tasks = functions.map((fn) => async () => {
          const urn = fn.func_urn ?? fn.funcUrn;
          if (!urn) return { fn, config: fn as LooseFunction, fallback: false };
          try {
            const cfg = (await fg.showFunctionConfig({ function_urn: urn })) as LooseFunction | undefined;
            return { fn, config: cfg ?? fn, fallback: false };
          } catch (err) {
            return { fn, config: fn, fallback: true, err };
          }
        });
        const settled = await runWithConcurrency(tasks, FG_CONFIG_CONCURRENCY);

        for (const r of settled) {
          if (r.status === "rejected") {
            warnings.push(`FunctionGraph: could not read function configuration: ${describeHwError(r.reason)}`);
            continue;
          }
          const { fn, config, fallback, err } = r.value as { fn: LooseFunction; config: LooseFunction; fallback: boolean; err?: unknown };
          const fnName = fn.func_name ?? fn.funcName ?? config.func_name ?? config.funcName ?? "unknown";
          const fnUrn = fn.func_urn ?? fn.funcUrn ?? config.func_urn ?? config.funcUrn ?? fnName;
          const resourceArn = toResourceUrn("functiongraph", "function", fnUrn, region, domainId);
          if (fallback) {
            warnings.push(`FunctionGraph: showFunctionConfig failed for ${fnName} (${describeHwError(err)}); used list data.`);
          }

          const envEntries = parseFunctionUserData(config.user_data ?? config.userData ?? fn.user_data ?? fn.userData);
          for (const [varName, varValue] of envEntries) {
            for (const sp of HUAWEI_SECRET_PATTERNS) {
              if (sp.matchType === "name") {
                if (varName !== undefined && sp.pattern.test(varName)) {
                  findings.push(
                    makeFinding({
                      riskScore: 7.5,
                      title: `FunctionGraph ${fnName} has suspicious env var "${varName}"`,
                      resourceType: "HuaweiCloud::FunctionGraph::Function",
                      resourceId: fnName,
                      resourceArn,
                      region,
                      description: `FunctionGraph function "${fnName}" has an environment variable named "${varName}" which may contain a secret.`,
                      impact:
                        "Secrets in FunctionGraph environment variables are visible to anyone with functiongraph:function:getConfig permission and may leak through logs.",
                      remediationSteps: [
                        "Move the secret to encrypted environment variables (encrypted_user_data with KMS) or to CSMS (Cloud Secret Management Service).",
                        "Update the function to fetch the secret at runtime.",
                        "Rotate the exposed credential immediately.",
                      ],
                    }),
                  );
                }
              } else if (sp.pattern.test(varValue)) {
                findings.push(
                  makeFinding({
                    riskScore: isAccessKeyPattern(sp) ? 9.5 : 9.0,
                    title: `FunctionGraph ${fnName} env var contains ${sp.name}`,
                    resourceType: "HuaweiCloud::FunctionGraph::Function",
                    resourceId: fnName,
                    resourceArn,
                    region,
                    description: `FunctionGraph function "${fnName}" has an environment variable${varName ? ` "${varName}"` : ""} containing a ${sp.name} pattern.`,
                    impact:
                      "Hard-coded credentials in function environment variables can be extracted by any principal with read access to the function configuration.",
                    remediationSteps: [
                      "Remove the hard-coded credential from environment variables.",
                      "Use encrypted environment variables (KMS) or CSMS, or grant the function an IAM agency instead of embedding AK/SK.",
                      "Rotate the exposed credential immediately.",
                      "Review CTS (Cloud Trace Service) logs for unauthorized use of the credential.",
                    ],
                  }),
                );
              }
            }
          }
        }
      } catch (err) {
        const degraded = degradeHwError("FunctionGraph", err);
        warnings.push(degraded ?? `FunctionGraph scan error: ${describeHwError(err)}`);
      }

      // --- ECS user data ---
      try {
        const { EcsClient } = await import("@huaweicloud/huaweicloud-sdk-ecs");
        const ecs = (await hwClient(EcsClient, "ecs", creds, scope)) as unknown as EcsLikeClient;

        const servers: LooseServer[] = [];
        let truncated = false;
        for (let page = 1; page <= MAX_PAGES; page++) {
          const resp = (await ecs.listServersDetails({ offset: page, limit: ECS_PAGE_SIZE })) as LooseListServersResponse | undefined;
          const batch = Array.isArray(resp?.servers) ? resp!.servers! : [];
          servers.push(...batch);
          if (servers.length >= ECS_MAX_SERVERS) {
            truncated = servers.length > ECS_MAX_SERVERS || batch.length === ECS_PAGE_SIZE;
            servers.length = Math.min(servers.length, ECS_MAX_SERVERS);
            break;
          }
          const count = typeof resp?.count === "number" ? resp.count : undefined;
          if (batch.length === 0 || batch.length < ECS_PAGE_SIZE || (count !== undefined && servers.length >= count)) break;
        }
        if (truncated) warnings.push(`ECS: more than ${ECS_MAX_SERVERS} servers; only the first ${ECS_MAX_SERVERS} were checked.`);

        resourcesScanned += servers.length;

        for (const srv of servers) {
          const id = srv.id ?? "unknown";
          const resourceArn = toResourceUrn("ecs", "server", id, region, domainId);
          const userData = decodeEcsUserData(srv["OS-EXT-SRV-ATTR:user_data"] ?? srv.osExtSrvAttrUserData);
          if (!userData) continue;

          for (const sp of matchValuePatterns(userData)) {
            findings.push(
              makeFinding({
                riskScore: isAccessKeyPattern(sp) ? 9.5 : 8.0,
                title: `ECS ${id} user data contains ${sp.name}`,
                resourceType: "HuaweiCloud::ECS::CloudServer",
                resourceId: id,
                resourceArn,
                region,
                description: `ECS server "${id}"${srv.name ? ` (${srv.name})` : ""} has user data containing a ${sp.name} pattern.`,
                impact:
                  "Instance user data is readable by anyone with ecs:cloudServers:list permission and from the instance metadata service.",
                remediationSteps: [
                  "Remove the secret from the server user data (re-create or re-inject user data without secrets).",
                  "Use an IAM agency bound to the ECS instance for Huawei Cloud API access instead of embedding AK/SK.",
                  "Use CSMS (Cloud Secret Management Service) or KMS-encrypted parameters for other secrets.",
                  "Rotate the exposed credential immediately.",
                ],
              }),
            );
          }
        }
      } catch (err) {
        const degraded = degradeHwError("ECS", err);
        warnings.push(degraded ?? `ECS user data scan error: ${describeHwError(err)}`);
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
      classifyHwError(err); // normalise; never stringify raw SDK errors
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud secret exposure scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

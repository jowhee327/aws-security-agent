/**
 * Alibaba Cloud secret exposure scanner (moduleName `secret_exposure`, plan §4.1 P0 / T4).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/secret-exposure.ts` (Lambda env vars + EC2 user data):
 *  - ECS: `DescribeInstances` (PageNumber / PageSize) → per instance `DescribeUserData`
 *    (concurrency {@link ECS_USERDATA_CONCURRENCY}, cap {@link ECS_MAX_USERDATA} with a
 *    warning) → base64-decode `UserData` (never throws; invalid base64 / binary payloads
 *    are scanned as raw text) → value detectors.
 *  - Function Compute 3.0: `ListFunctions` (ROA GET `/2023-03-30/functions` on
 *    `fcv3.<region>.aliyuncs.com`, `nextToken` / `limit` pagination) → `environmentVariables`
 *    names (name detectors) and values (value detectors).
 *
 * Detectors are the AWS `SECRET_PATTERNS` plus {@link ALI_EXTRA_SECRET_PATTERNS} (AccessKey
 * ID `LTAI…` and Alibaba credential env-var names). riskScores follow the AWS scanner:
 * function env value 9.0 (Access Key 9.5), env var name 7.5, user data 8.0 (Access Key 9.5).
 * Findings NEVER contain the matched value — only the detector name and the location
 * (instance ID / function name / env-var key name).
 *
 * Errors: access denied / not enabled / throttled / network on a sub-service → warning and
 * skip; **auth_failed or api_misuse anywhere → module `status: "error"`**. Every error text
 * goes through describeAliError / redactAliDiagnostic.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { SECRET_PATTERNS, type SecretPattern } from "../../../scanners/secret-exposure.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { AliCloudError, classifyAliError, degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliSafeFinding,
  aliSafeWarnings,
  aliScanEnv,
  aliString,
  aliUntrusted,
  isAliFatal,
  listAliEcsInstances,
  type AliScanEnv,
} from "./shared.js";

export const ECS_MAX_USERDATA = 500;
export const ECS_USERDATA_CONCURRENCY = 5;
/** FC3 ListFunctions page size (`limit`, maximum 100) and function cap. */
export const FC_PAGE_SIZE = 100;
export const FC_MAX_FUNCTIONS = 1000;

/**
 * Alibaba-specific detectors layered on top of the shared AWS patterns. The AccessKey ID
 * pattern is the one the error redactor uses (`LTAI` + 12–30 alphanumerics).
 */
export const ALI_EXTRA_SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: "Alibaba Cloud Access Key", pattern: /LTAI[0-9A-Za-z]{12,30}/, matchType: "value" },
  {
    name: "Alibaba Cloud credential in env var",
    pattern:
      /^(ALIBABA_CLOUD_ACCESS_KEY_ID|ALIBABA_CLOUD_ACCESS_KEY_SECRET|ALIBABA_CLOUD_SECURITY_TOKEN|ALICLOUD_ACCESS_KEY|ALICLOUD_SECRET_KEY|ALICLOUD_SECURITY_TOKEN|ACCESS_KEY_ID|ACCESS_KEY_SECRET|ACCESS_KEY|SECRET_KEY|OSS_ACCESS_KEY_ID|OSS_ACCESS_KEY_SECRET)$/i,
    matchType: "name",
  },
];

export const ALI_SECRET_PATTERNS: readonly SecretPattern[] = [...SECRET_PATTERNS, ...ALI_EXTRA_SECRET_PATTERNS];

function isAccessKeyPattern(sp: SecretPattern): boolean {
  return /Access Key/i.test(sp.name);
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

/**
 * Decode ECS `UserData` (base64). Never throws: input that is not well-formed base64, or
 * whose decoded bytes are not valid UTF-8 text (e.g. gzip), is returned as the raw text so
 * the value detectors still run over it. Empty input → undefined.
 */
export function decodeAliUserData(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    const compact = trimmed.replace(/\s+/g, "");
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(compact) && compact.length % 4 !== 1) {
      const decoded = Buffer.from(compact, "base64").toString("utf-8");
      if (decoded.length > 0 && !decoded.includes("\uFFFD")) return decoded;
    }
  } catch {
    // fall through to the raw text
  }
  return trimmed;
}

/** Value detectors matching `text` (each detector at most once). */
export function matchAliValuePatterns(text: string, patterns: readonly SecretPattern[] = ALI_SECRET_PATTERNS): SecretPattern[] {
  return patterns.filter((sp) => sp.matchType === "value" && sp.pattern.test(text));
}

/** Name detectors matching an env-var name. */
export function matchAliNamePatterns(name: string, patterns: readonly SecretPattern[] = ALI_SECRET_PATTERNS): SecretPattern[] {
  return patterns.filter((sp) => sp.matchType === "name" && sp.pattern.test(name));
}

/** Re-wrap any error as a redacted AliCloudError — never keep the raw object. */
function toAliError(err: unknown, api: string): AliCloudError {
  return err instanceof AliCloudError ? err : new AliCloudError(classifyAliError(err), api);
}

/** Warning for a non-fatal sub-service failure (degradeAliError, or a generic redacted line). */
function softWarning(service: string, err: unknown): string {
  return degradeAliError(service, err) ?? redactAliDiagnostic(`${service}: failed (${describeAliError(err)}); skipped`);
}

interface SubResult {
  findings: Finding[];
  warnings: string[];
  resourcesScanned: number;
  /** auth_failed / api_misuse → module error. */
  fatal?: AliCloudError;
}

/* ------------------------------------------------------------------------ */
/* ECS user data                                                            */
/* ------------------------------------------------------------------------ */

const ECS_REMEDIATION = [
  "Remove the secret from the instance user data (ECS console → Instance → Set User Data, or recreate the instance).",
  "Attach a RAM role to the ECS instance for Alibaba Cloud API access instead of embedding an AccessKey pair.",
  "Use KMS Secrets Manager or OOS encrypted parameters for other secrets.",
  "Rotate the exposed credential immediately.",
];

async function scanEcsUserData(ctx: ScanContext, env: AliScanEnv): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  const region = ctx.region;

  let ids: string[];
  try {
    const list = await listAliEcsInstances(env, region);
    r.warnings.push(...list.warnings);
    ids = list.instances.flatMap((i) => {
      const id = aliString(i.InstanceId);
      return id ? [id] : [];
    });
  } catch (err) {
    if (isAliFatal(err)) return { ...r, fatal: toAliError(err, "ecs:DescribeInstances") };
    r.warnings.push(softWarning("ECS DescribeInstances", err));
    return r;
  }

  if (ids.length > ECS_MAX_USERDATA) {
    r.warnings.push(`ECS: ${ids.length} instances in ${region}; user data was checked for the first ${ECS_MAX_USERDATA} only.`);
    ids = ids.slice(0, ECS_MAX_USERDATA);
  }

  const settled = await runWithConcurrency(
    ids.map((id) => () => aliCall(ALI_API.ecs.DescribeUserData, aliCallCtx(env, region), { RegionId: region, InstanceId: id })),
    ECS_USERDATA_CONCURRENCY,
  );

  let failed = 0;
  let firstFailure: string | undefined;
  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    // Raw id was only used for the DescribeUserData call; only the redacted form is emitted.
    const id = aliUntrusted(ids[i]) ?? "unknown";
    if (s.status === "rejected") {
      if (isAliFatal(s.reason)) return { ...r, fatal: toAliError(s.reason, "ecs:DescribeUserData") };
      if (classifyAliError(s.reason).kind === "not_found") continue; // instance released meanwhile
      failed++;
      firstFailure ??= softWarning(`ECS ${id} DescribeUserData`, s.reason);
      continue;
    }
    r.resourcesScanned++;
    const userData = decodeAliUserData(aliField(s.value, "UserData"));
    if (!userData) continue;

    for (const sp of matchAliValuePatterns(userData)) {
      r.findings.push(
        makeFinding({
          riskScore: isAccessKeyPattern(sp) ? 9.5 : 8.0,
          title: `ECS ${id} user data contains ${sp.name}`,
          resourceType: "ACS::ECS::Instance",
          resourceId: id,
          resourceArn: toAliUrn("ecs", "instance", id, region, env.accountId),
          region,
          description: `ECS instance "${id}" (${region}) has user data containing a ${sp.name} pattern. The matched value is not included in this report.`,
          impact:
            "Instance user data is readable by anyone with ecs:DescribeUserData permission and from inside the instance via the metadata service (100.100.100.200).",
          remediationSteps: ECS_REMEDIATION,
        }),
      );
    }
  }
  if (failed > 0) {
    r.warnings.push(failed === 1 ? firstFailure! : `ECS DescribeUserData failed for ${failed} instance(s) in ${region}; first: ${firstFailure}`);
  }
  return r;
}

/* ------------------------------------------------------------------------ */
/* Function Compute 3.0                                                     */
/* ------------------------------------------------------------------------ */

/** `environmentVariables` → [name, value] pairs (non-string values are stringified safely). */
export function fcEnvEntries(fn: unknown): Array<[string, string]> {
  const vars = aliField(fn, "environmentVariables");
  if (!vars || typeof vars !== "object" || Array.isArray(vars)) return [];
  return Object.entries(vars as Record<string, unknown>).map(([k, v]) => [
    k,
    typeof v === "string" ? v : v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v),
  ]);
}

async function scanFunctionCompute(ctx: ScanContext, env: AliScanEnv): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  const region = ctx.region;

  let functions: unknown[];
  try {
    const page = await aliPaginate<unknown, unknown>({
      style: "token",
      label: "FC ListFunctions",
      pageSize: FC_PAGE_SIZE,
      maxItems: FC_MAX_FUNCTIONS,
      sizeParam: "limit",
      tokenParam: "nextToken",
      fetch: (q) => aliCall(ALI_API.fc.ListFunctions, aliCallCtx(env, region), q),
      items: (body) => aliArray(aliField(body, "functions")),
      nextToken: (body) => aliString(aliField(body, "nextToken")),
    });
    r.warnings.push(...page.warnings);
    functions = page.items;
  } catch (err) {
    if (isAliFatal(err)) return { ...r, fatal: toAliError(err, "fc:ListFunctions") };
    r.warnings.push(softWarning("Function Compute ListFunctions", err));
    return r;
  }

  for (const fn of functions) {
    // Function / env var names are server-sourced: only redacted forms are emitted.
    // (Env var VALUES are only pattern-matched, never emitted.)
    const name = aliUntrusted(aliField(fn, "functionName"));
    if (!name) continue;
    r.resourcesScanned++;
    const resourceArn = toAliUrn("fc", "function", name, region, env.accountId);

    for (const [rawVarName, varValue] of fcEnvEntries(fn)) {
      const varName = aliUntrusted(rawVarName) ?? "";
      for (const sp of matchAliNamePatterns(rawVarName)) {
        r.findings.push(
          makeFinding({
            riskScore: 7.5,
            title: `Function Compute ${name} has suspicious env var "${varName}"`,
            resourceType: "ACS::FC::Function",
            resourceId: name,
            resourceArn,
            region,
            description: `Function Compute function "${name}" (${region}) has an environment variable named "${varName}" (${sp.name}) which may contain a secret.`,
            impact:
              "Secrets in function environment variables are visible to anyone with fc:GetFunction / fc:ListFunctions permission and may leak through logs.",
            remediationSteps: [
              "Move the secret to KMS Secrets Manager and fetch it at runtime.",
              "Grant the function a RAM role (and use the temporary credentials FC injects) instead of an AccessKey pair.",
              "Rotate the exposed credential immediately.",
            ],
          }),
        );
      }
      for (const sp of matchAliValuePatterns(varValue)) {
        r.findings.push(
          makeFinding({
            riskScore: isAccessKeyPattern(sp) ? 9.5 : 9.0,
            title: `Function Compute ${name} env var contains ${sp.name}`,
            resourceType: "ACS::FC::Function",
            resourceId: name,
            resourceArn,
            region,
            description: `Function Compute function "${name}" (${region}) has environment variable "${varName}" containing a ${sp.name} pattern. The matched value is not included in this report.`,
            impact:
              "Hard-coded credentials in function environment variables can be extracted by any principal with read access to the function configuration.",
            remediationSteps: [
              "Remove the hard-coded credential from the environment variables.",
              "Use KMS Secrets Manager, or a RAM role attached to the function, instead of embedding an AccessKey pair.",
              "Rotate the exposed credential immediately.",
              "Review ActionTrail logs for unauthorized use of the credential.",
            ],
          }),
        );
      }
    }
  }
  return r;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliSecretExposureScanner implements Scanner {
  readonly moduleName = "secret_exposure";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];
    let resourcesScanned = 0;

    try {
      const env = aliScanEnv(ctx);

      for (const [label, run] of [
        ["Function Compute secret scan failed", scanFunctionCompute],
        ["ECS user data secret scan failed", scanEcsUserData],
      ] as const) {
        const sub = await run(ctx, env);
        warnings.push(...sub.warnings);
        if (sub.fatal) return aliErrorResult(this.moduleName, startMs, label, sub.fatal, warnings);
        findings.push(...sub.findings);
        resourcesScanned += sub.resourcesScanned;
      }

      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings: aliSafeWarnings(warnings) } : {}),
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "Secret exposure scan failed", err, warnings);
    }
  }
}

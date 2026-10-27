/**
 * Azure secret exposure scanner (moduleName `secret_exposure`, plan §4.1 P1 / T4).
 * EXPERIMENTAL — not yet validated against a live account; field names follow the
 * `@azure/arm-appservice` 19.x / `@azure/arm-compute` 25.x d.ts.
 *
 * Azure analog of `src/scanners/secret-exposure.ts` (Lambda env vars + EC2 user data) and
 * the Alibaba / Huawei scanners. Two independent sub-services:
 *
 * App Service (web apps + function apps): `WebSiteManagementClient.webApps.list()` (paged,
 * capped at {@link AZURE_WEBAPP_MAX_APPS}) → per app (N+1, concurrency
 * {@link AZURE_SECRET_CONCURRENCY}, cap {@link AZURE_SECRET_MAX_APPS} with a warning)
 * `listApplicationSettings` (name + value detectors) and `listConnectionStrings` (value
 * detectors). Both are POST `…/config/appsettings/list` / `…/config/connectionstrings/list`
 * actions that need `Microsoft.Web/sites/config/list/action` — NOT part of the built-in Reader role, so a
 * Reader-only principal gets an access-denied warning for this sub-service. Values that are
 * Key Vault / App Configuration references (`@Microsoft.KeyVault(…)`,
 * `@Microsoft.AppConfiguration(…)`) are the recommended pattern and are skipped.
 * Deployment slots are not scanned (production slot only).
 *
 * Virtual machines: `ComputeManagementClient.virtualMachines.listAll()` (paged, capped at
 * {@link AZURE_VM_MAX_VMS}). What is visible to a read-only principal:
 *  - `osProfile.customData` is write-only: ARM does not return it from GET / list (the d.ts
 *    still declares the field). It is decoded and scanned if a response ever carries it.
 *  - `userData` is only returned by `virtualMachines.get(…, { expand: "userData" })`; it is
 *    NOT scanned (extra per-VM call, see the T4 open questions).
 *  - Custom Script extensions (`CustomScript` / `CustomScriptExtension` /
 *    `CustomScriptForLinux`): per VM (concurrency {@link AZURE_SECRET_CONCURRENCY}, cap
 *    {@link AZURE_SECRET_MAX_VMS}) `virtualMachineExtensions.list(rg, vm)`; the PUBLIC
 *    `settings` (`commandToExecute`, `fileUris`, base64 `script`, …) are scanned.
 *    `protectedSettings` is never read (ARM does not return it either).
 *
 * Detectors are the AWS `SECRET_PATTERNS` plus {@link AZURE_EXTRA_SECRET_PATTERNS}
 * (storage account / shared access keys, SAS signatures, passwords inside connection
 * strings, Azure credential setting names). riskScores follow the AWS scanner: app setting /
 * connection string value 9.0 (cloud access keys 9.5), setting name 7.5, VM custom data /
 * extension settings 8.0 (cloud access keys 9.5). Findings NEVER contain the matched value —
 * only the detector name and the location (app / VM name + setting / extension NAME).
 *
 * Errors: access denied / not enabled / throttled / network on a sub-service (or on the
 * per-resource calls, aggregated into one warning) → warning and skip; **auth_failed or
 * api_misuse anywhere → module `status: "error"`**. Raw SDK errors (holding the Bearer
 * token) never reach the result.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { SECRET_PATTERNS, type SecretPattern } from "../../../scanners/secret-exposure.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { classifyAzureError } from "../errors.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureEmptyResult,
  azureErrorResult,
  azureNoSubscriptionWarning,
  azureSafeFinding,
  azureSafeWarnings,
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

/** Listing caps (items consumed from the paged list). */
export const AZURE_WEBAPP_MAX_APPS = 5000;
export const AZURE_VM_MAX_VMS = 5000;
/** Per-resource (N+1) call caps and concurrency. */
export const AZURE_SECRET_MAX_APPS = 500;
export const AZURE_SECRET_MAX_VMS = 500;
export const AZURE_SECRET_CONCURRENCY = 5;
/** Longest settings / custom data text that is pattern-matched (bytes beyond are ignored). */
export const AZURE_SECRET_MAX_TEXT = 256 * 1024;

/**
 * Azure-specific detectors layered on top of the shared AWS patterns. Only the detector
 * NAME is ever emitted.
 */
export const AZURE_EXTRA_SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: "Azure Storage account key", pattern: /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/i, matchType: "value" },
  { name: "Azure shared access key", pattern: /SharedAccessKey=[A-Za-z0-9+/]{40,}={0,2}/i, matchType: "value" },
  { name: "Azure SAS token", pattern: /(?:^|[?&;\s"'])sig=[A-Za-z0-9%+/=]{20,}/i, matchType: "value" },
  { name: "Password in connection string", pattern: /(?:^|;)\s*(?:password|pwd)\s*=\s*[^;\s'"]+/i, matchType: "value" },
  {
    name: "Azure credential in app setting",
    pattern:
      /^(AZURE_CLIENT_SECRET|AZURE_STORAGE_KEY|AZURE_STORAGE_ACCOUNT_KEY|AZURE_STORAGE_ACCESS_KEY|STORAGE_ACCOUNT_KEY|CLIENT_SECRET|SAS_TOKEN|AZURE_SAS_TOKEN)$/i,
    matchType: "name",
  },
];

export const AZURE_SECRET_PATTERNS: readonly SecretPattern[] = [...SECRET_PATTERNS, ...AZURE_EXTRA_SECRET_PATTERNS];

const WEB_APP_TYPE = "Microsoft.Web/sites";
const VM_TYPE = "Microsoft.Compute/virtualMachines";
const WEBAPP_LIST_SERVICE = "App Service webApps.list";
const VM_LIST_SERVICE = "Compute virtualMachines.listAll";

/** Custom Script extension handler types (Windows / Linux v2 / legacy Linux). */
const CUSTOM_SCRIPT_TYPES = new Set(["customscript", "customscriptextension", "customscriptforlinux"]);

/** Key Vault / App Configuration reference values (the recommended way to hold secrets). */
const SECRET_REFERENCE_RE = /^\s*@Microsoft\.(?:KeyVault|AppConfiguration)\(/i;

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function isCloudKeyPattern(sp: SecretPattern): boolean {
  return /Access Key|account key|shared access key/i.test(sp.name);
}

/** Value detectors matching `text` (each detector at most once). */
export function matchAzureValuePatterns(text: string, patterns: readonly SecretPattern[] = AZURE_SECRET_PATTERNS): SecretPattern[] {
  const capped = text.length > AZURE_SECRET_MAX_TEXT ? text.slice(0, AZURE_SECRET_MAX_TEXT) : text;
  return patterns.filter((sp) => sp.matchType === "value" && sp.pattern.test(capped));
}

/** Name detectors matching a setting name. */
export function matchAzureNamePatterns(name: string, patterns: readonly SecretPattern[] = AZURE_SECRET_PATTERNS): SecretPattern[] {
  return patterns.filter((sp) => sp.matchType === "name" && sp.pattern.test(name));
}

/** `@Microsoft.KeyVault(…)` / `@Microsoft.AppConfiguration(…)` reference value. */
export function isAzureSecretReference(value: string): boolean {
  return SECRET_REFERENCE_RE.test(value);
}

/**
 * Decode base64 custom data / a Custom Script `script`. Never throws: input that is not
 * well-formed base64, or whose decoded bytes are not valid UTF-8 text (e.g. gzip), is
 * returned as the raw text so the value detectors still run over it. Empty → undefined.
 */
export function decodeAzureBase64Text(raw: unknown): string | undefined {
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

/** Text of an arbitrary settings value (strings as-is, objects JSON-encoded; never throws). */
function settingsText(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === undefined || v === null) return "";
  try {
    return typeof v === "object" ? JSON.stringify(v) ?? "" : String(v);
  } catch {
    return "";
  }
}

/** `{ properties: { name: value } }` (StringDictionary) → [name, value] pairs. */
export function azureAppSettingEntries(dict: unknown): Array<[string, string]> {
  const props = azField(dict, "properties");
  if (!props || typeof props !== "object" || Array.isArray(props)) return [];
  return Object.entries(props as Record<string, unknown>).map(([k, v]) => [k, settingsText(v)]);
}

/** `{ properties: { name: { value, type } } }` (ConnectionStringDictionary) → [name, value] pairs. */
export function azureConnectionStringEntries(dict: unknown): Array<[string, string]> {
  const props = azField(dict, "properties");
  if (!props || typeof props !== "object" || Array.isArray(props)) return [];
  return Object.entries(props as Record<string, unknown>).map(([k, v]) => [
    k,
    v && typeof v === "object" ? settingsText(azField(v, "value")) : settingsText(v),
  ]);
}

/** Extension handler type: flattened `typePropertiesType` (TypeSpec SDK) or raw `properties.type`. */
function extensionHandlerType(ext: unknown): string | undefined {
  return azString(azField(ext, "typePropertiesType")) ?? azString(azField(azField(ext, "properties"), "type"));
}

/** Public `settings` of an extension (flattened or nested). `protectedSettings` is never read. */
function extensionSettings(ext: unknown): unknown {
  const direct = azField(ext, "settings");
  return direct !== undefined ? direct : azField(azField(ext, "properties"), "settings");
}

export function isAzureCustomScriptExtension(ext: unknown): boolean {
  const t = extensionHandlerType(ext);
  return t !== undefined && CUSTOM_SCRIPT_TYPES.has(t.toLowerCase());
}

/** Text scanned for a Custom Script extension: the JSON settings plus the decoded base64 `script`. */
export function azureCustomScriptText(ext: unknown): string {
  const settings = extensionSettings(ext);
  const parts = [settingsText(settings)];
  const script = decodeAzureBase64Text(azField(settings, "script"));
  if (script) parts.push(script);
  return parts.join("\n");
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/** Identity of a listed resource; every emitted string is redacted, raw parts kept for SDK calls. */
interface ResourceRef {
  name: string;
  arn: string;
  region: string;
  resourceGroup?: string;
  rawName?: string;
  rawResourceGroup?: string;
}

function resourceRef(resource: unknown, resourceType: string, env: AzureScanEnv): ResourceRef {
  const rawId = azString(azField(resource, "id"));
  const parsed = rawId ? parseAzureResourceId(rawId) : undefined;
  const rawName = azString(azField(resource, "name")) ?? parsed?.name;
  const rawResourceGroup = parsed?.resourceGroup ?? azString(azField(resource, "resourceGroup"));
  return {
    name: aztUntrustedOpt(rawName) ?? "unknown",
    arn: toAzureUrn({ id: rawId, subscriptionId: env.subscriptionId, resourceGroup: rawResourceGroup, resourceType, name: rawName ?? "unknown" }),
    region: aztUntrustedOpt(azField(resource, "location")) ?? "global",
    resourceGroup: aztUntrustedOpt(rawResourceGroup),
    rawName,
    rawResourceGroup,
  };
}

function where(ref: ResourceRef, env: AzureScanEnv): string {
  return `${ref.resourceGroup ? `resource group ${ref.resourceGroup}, ` : ""}subscription ${aztUntrusted(env.subscriptionId)}`;
}

interface SubResult {
  findings: Finding[];
  warnings: string[];
  resourcesScanned: number;
  /** auth_failed / api_misuse → module error. */
  fatal?: unknown;
}

/** Aggregates non-fatal per-resource call failures into one warning line. */
class FailureTally {
  private count = 0;
  private first?: string;
  private denied = false;

  constructor(private readonly label: string, private readonly deniedHint?: string) {}

  add(service: string, err: unknown): void {
    this.count++;
    if (classifyAzureError(err).kind === "access_denied") this.denied = true;
    this.first ??= azureSoftWarning(service, err);
  }

  warning(): string | undefined {
    if (this.count === 0) return undefined;
    const hint = this.denied && this.deniedHint ? ` ${this.deniedHint}` : "";
    return this.count === 1 ? `${this.first}${hint}` : `${this.label} failed for ${this.count} resource(s); first: ${this.first}${hint}`;
  }
}

/* ------------------------------------------------------------------------ */
/* App Service                                                              */
/* ------------------------------------------------------------------------ */

const APP_SETTINGS_DENIED_HINT =
  "(reading app settings / connection strings requires Microsoft.Web/sites/config/list/action, which the Reader role does not include)";

const APP_REMEDIATION = [
  "Move the secret to Azure Key Vault and reference it from the app setting (@Microsoft.KeyVault(SecretUri=…)) using the app's managed identity.",
  "Prefer managed identity / Entra ID authentication to storage, SQL and other Azure services instead of keys and passwords.",
  "Rotate the exposed credential immediately.",
  "Restrict who holds Microsoft.Web/sites/config/list/action (Contributor / Website Contributor) on the app.",
];

async function scanAppService(env: AzureScanEnv, module: string): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  let apps: unknown[];
  let client: {
    webApps: {
      listApplicationSettings: (rg: string, name: string) => Promise<unknown>;
      listConnectionStrings: (rg: string, name: string) => Promise<unknown>;
    };
  };
  try {
    const { WebSiteManagementClient } = await import("@azure/arm-appservice");
    const sdk = await armClient(WebSiteManagementClient, env.credentials, env.subscriptionId);
    client = sdk as unknown as typeof client;
    const page = await azurePaginate(sdk.webApps.list(), { max: AZURE_WEBAPP_MAX_APPS });
    apps = page.items;
    if (page.truncated) r.warnings.push(azureTruncationWarning(WEBAPP_LIST_SERVICE, AZURE_WEBAPP_MAX_APPS));
  } catch (err) {
    if (isAzureFatal(err)) return { ...r, fatal: err };
    r.warnings.push(`${azureSoftWarning(WEBAPP_LIST_SERVICE, err)} — app settings / connection strings not checked for secrets.`);
    return r;
  }

  const refs = apps.map((a) => resourceRef(a, WEB_APP_TYPE, env)).filter((ref) => ref.rawName && ref.rawResourceGroup);
  let targets = refs;
  if (targets.length > AZURE_SECRET_MAX_APPS) {
    r.warnings.push(
      `App Service: ${targets.length} apps in subscription ${aztUntrusted(env.subscriptionId)}; app settings were checked for the first ${AZURE_SECRET_MAX_APPS} only.`,
    );
    targets = targets.slice(0, AZURE_SECRET_MAX_APPS);
  }

  const tasks: Array<() => Promise<unknown>> = [];
  for (const ref of targets) {
    tasks.push(async () => client.webApps.listApplicationSettings(ref.rawResourceGroup!, ref.rawName!));
    tasks.push(async () => client.webApps.listConnectionStrings(ref.rawResourceGroup!, ref.rawName!));
  }
  const settled = await runWithConcurrency(tasks, AZURE_SECRET_CONCURRENCY);

  const tally = new FailureTally("App Service listApplicationSettings / listConnectionStrings", APP_SETTINGS_DENIED_HINT);
  for (let i = 0; i < targets.length; i++) {
    const ref = targets[i];
    let read = false;
    for (const [j, kind] of [
      [2 * i, "settings"],
      [2 * i + 1, "connectionStrings"],
    ] as const) {
      const s = settled[j];
      const api = kind === "settings" ? "listApplicationSettings" : "listConnectionStrings";
      if (s.status === "rejected") {
        if (isAzureFatal(s.reason)) return { ...r, fatal: s.reason };
        if (classifyAzureError(s.reason).kind === "not_found") continue; // app deleted meanwhile
        tally.add(`App Service ${ref.name} ${api}`, s.reason);
        continue;
      }
      read = true;
      if (kind === "settings") r.findings.push(...appSettingFindings(ref, env, module, azureAppSettingEntries(s.value)));
      else r.findings.push(...connectionStringFindings(ref, env, module, azureConnectionStringEntries(s.value)));
    }
    if (read) r.resourcesScanned++;
  }
  const w = tally.warning();
  if (w) r.warnings.push(w);
  return r;
}

function appSettingFindings(ref: ResourceRef, env: AzureScanEnv, module: string, entries: Array<[string, string]>): Finding[] {
  const out: Finding[] = [];
  for (const [rawName, value] of entries) {
    if (!value.trim() || isAzureSecretReference(value)) continue;
    // Setting names are server-sourced: only redacted forms are emitted. Values are only
    // pattern-matched, never emitted.
    const settingName = aztUntrusted(rawName);
    for (const sp of matchAzureNamePatterns(rawName)) {
      out.push(
        makeFinding({
          riskScore: 7.5,
          title: `App Service ${ref.name} has suspicious app setting "${settingName}"`,
          resourceType: WEB_APP_TYPE,
          resourceId: ref.name,
          resourceArn: ref.arn,
          region: ref.region,
          description: `App Service app "${ref.name}" (${where(ref, env)}) has an app setting named "${settingName}" (${sp.name}) holding a plain value (not a Key Vault reference), which may be a secret. The value is not included in this report.`,
          impact:
            "App settings are exposed to the app as environment variables and readable by any principal with Microsoft.Web/sites/config/list/action (e.g. Contributor), the Kudu console and deployment tooling.",
          remediationSteps: APP_REMEDIATION,
          accountId: env.tenantId,
          module,
        }),
      );
    }
    for (const sp of matchAzureValuePatterns(value)) {
      out.push(
        makeFinding({
          riskScore: isCloudKeyPattern(sp) ? 9.5 : 9.0,
          title: `App Service ${ref.name} app setting contains ${sp.name}`,
          resourceType: WEB_APP_TYPE,
          resourceId: ref.name,
          resourceArn: ref.arn,
          region: ref.region,
          description: `App Service app "${ref.name}" (${where(ref, env)}) has app setting "${settingName}" containing a ${sp.name} pattern. The matched value is not included in this report.`,
          impact:
            "Hard-coded credentials in app settings can be extracted by any principal with read access to the app configuration and leak through deployment tooling and diagnostics.",
          remediationSteps: APP_REMEDIATION,
          accountId: env.tenantId,
          module,
        }),
      );
    }
  }
  return out;
}

function connectionStringFindings(ref: ResourceRef, env: AzureScanEnv, module: string, entries: Array<[string, string]>): Finding[] {
  const out: Finding[] = [];
  for (const [rawName, value] of entries) {
    if (!value.trim() || isAzureSecretReference(value)) continue;
    const csName = aztUntrusted(rawName);
    for (const sp of matchAzureValuePatterns(value)) {
      out.push(
        makeFinding({
          riskScore: isCloudKeyPattern(sp) ? 9.5 : 9.0,
          title: `App Service ${ref.name} connection string contains ${sp.name}`,
          resourceType: WEB_APP_TYPE,
          resourceId: ref.name,
          resourceArn: ref.arn,
          region: ref.region,
          description: `App Service app "${ref.name}" (${where(ref, env)}) has connection string "${csName}" containing a ${sp.name} pattern. The matched value is not included in this report.`,
          impact:
            "Credentials embedded in connection strings can be read by any principal with Microsoft.Web/sites/config/list/action and give direct access to the backing database / storage / messaging service.",
          remediationSteps: APP_REMEDIATION,
          accountId: env.tenantId,
          module,
        }),
      );
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Virtual machines                                                         */
/* ------------------------------------------------------------------------ */

const VM_REMEDIATION = [
  "Remove the secret from the VM custom data / Custom Script extension public settings (use protectedSettings, which are encrypted and never returned by the API).",
  "Give the VM a managed identity and fetch secrets from Azure Key Vault at runtime instead of embedding them.",
  "Rotate the exposed credential immediately.",
];

async function scanVirtualMachines(env: AzureScanEnv, module: string): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  let vms: unknown[];
  let client: { virtualMachineExtensions: { list: (rg: string, vm: string) => Promise<unknown> } };
  try {
    const { ComputeManagementClient } = await import("@azure/arm-compute");
    const sdk = await armClient(ComputeManagementClient, env.credentials, env.subscriptionId);
    client = sdk as unknown as typeof client;
    const page = await azurePaginate(sdk.virtualMachines.listAll(), { max: AZURE_VM_MAX_VMS });
    vms = page.items;
    if (page.truncated) r.warnings.push(azureTruncationWarning(VM_LIST_SERVICE, AZURE_VM_MAX_VMS));
  } catch (err) {
    if (isAzureFatal(err)) return { ...r, fatal: err };
    r.warnings.push(`${azureSoftWarning(VM_LIST_SERVICE, err)} — VM custom data / Custom Script extensions not checked for secrets.`);
    return r;
  }

  const refs = vms.map((vm) => ({ vm, ref: resourceRef(vm, VM_TYPE, env) }));
  r.resourcesScanned = refs.length;

  // customData (normally absent: write-only in ARM).
  for (const { vm, ref } of refs) {
    const customData = decodeAzureBase64Text(azField(azField(vm, "osProfile"), "customData"));
    if (!customData) continue;
    for (const sp of matchAzureValuePatterns(customData)) {
      r.findings.push(
        makeFinding({
          riskScore: isCloudKeyPattern(sp) ? 9.5 : 8.0,
          title: `VM ${ref.name} custom data contains ${sp.name}`,
          resourceType: VM_TYPE,
          resourceId: ref.name,
          resourceArn: ref.arn,
          region: ref.region,
          description: `Virtual machine "${ref.name}" (${where(ref, env)}) has custom data containing a ${sp.name} pattern. The matched value is not included in this report.`,
          impact: "Custom data is saved as a file on the VM and readable by any process / user on the instance.",
          remediationSteps: VM_REMEDIATION,
          accountId: env.tenantId,
          module,
        }),
      );
    }
  }

  // Custom Script extension public settings (N+1).
  let targets = refs.filter(({ ref }) => ref.rawName && ref.rawResourceGroup);
  if (targets.length > AZURE_SECRET_MAX_VMS) {
    r.warnings.push(
      `Compute: ${targets.length} VMs in subscription ${aztUntrusted(env.subscriptionId)}; VM extensions were checked for the first ${AZURE_SECRET_MAX_VMS} only.`,
    );
    targets = targets.slice(0, AZURE_SECRET_MAX_VMS);
  }
  const settled = await runWithConcurrency(
    targets.map(({ ref }) => async () => client.virtualMachineExtensions.list(ref.rawResourceGroup!, ref.rawName!)),
    AZURE_SECRET_CONCURRENCY,
  );
  const tally = new FailureTally("Compute virtualMachineExtensions.list");
  for (let i = 0; i < targets.length; i++) {
    const { ref } = targets[i];
    const s = settled[i];
    if (s.status === "rejected") {
      if (isAzureFatal(s.reason)) return { ...r, fatal: s.reason };
      if (classifyAzureError(s.reason).kind === "not_found") continue; // VM deleted meanwhile
      tally.add(`Compute VM ${ref.name} virtualMachineExtensions.list`, s.reason);
      continue;
    }
    for (const ext of azArray(azField(s.value, "value"))) {
      if (!isAzureCustomScriptExtension(ext)) continue;
      const extName = aztUntrustedOpt(azField(ext, "name")) ?? "unknown";
      for (const sp of matchAzureValuePatterns(azureCustomScriptText(ext))) {
        r.findings.push(
          makeFinding({
            riskScore: isCloudKeyPattern(sp) ? 9.5 : 8.0,
            title: `VM ${ref.name} Custom Script extension settings contain ${sp.name}`,
            resourceType: VM_TYPE,
            resourceId: ref.name,
            resourceArn: ref.arn,
            region: ref.region,
            description: `Virtual machine "${ref.name}" (${where(ref, env)}) has Custom Script extension "${extName}" whose public settings contain a ${sp.name} pattern. The matched value is not included in this report.`,
            impact:
              "Extension public settings are stored in plain text, returned by the ARM API to any principal with Microsoft.Compute/virtualMachines/extensions/read (including Reader) and written to the VM's extension status files.",
            remediationSteps: VM_REMEDIATION,
            accountId: env.tenantId,
            module,
          }),
        );
      }
    }
  }
  const w = tally.warning();
  if (w) r.warnings.push(w);
  return r;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AzureSecretExposureScanner implements Scanner {
  readonly moduleName = "secret_exposure";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure secret exposure scan failed", err);
    }
    if (!env) return azureEmptyResult(this.moduleName, startMs, { warnings: [azureNoSubscriptionWarning(this.moduleName)] });

    const warnings: string[] = [];
    const findings: Finding[] = [];
    let resourcesScanned = 0;
    // Sequential so the per-resource concurrency limit holds for the whole module.
    for (const [label, run] of [
      ["App Service secret scan failed", scanAppService],
      ["VM secret scan failed", scanVirtualMachines],
    ] as const) {
      const sub = await run(env, this.moduleName);
      warnings.push(...sub.warnings);
      if (sub.fatal !== undefined) return azureErrorResult(this.moduleName, startMs, label, sub.fatal, warnings);
      findings.push(...sub.findings);
      resourcesScanned += sub.resourcesScanned;
    }

    return {
      module: this.moduleName,
      status: "success",
      ...(warnings.length > 0 ? { warnings: azureSafeWarnings(warnings) } : {}),
      resourcesScanned,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }
}

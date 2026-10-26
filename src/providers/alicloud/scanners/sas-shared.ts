/**
 * Helpers shared by the Security Center (SAS) scanners — `guardduty_findings`
 * (sas-alerts.ts), `inspector_findings` (sas-vulns.ts) and `patch_compliance_findings`
 * (sas-patch.ts). EXPERIMENTAL — not yet validated against a live account.
 *
 * SAS is centralised (`tds.aliyuncs.com` / intl `tds.ap-southeast-1.aliyuncs.com`, API
 * 2018-12-03), so every call goes through {@link aliCallCtx} without a region.
 *
 *  - {@link checkSasEdition}: `DescribeVersionConfig.Version` — absent (not purchased),
 *    1 (Free Edition) or 10 (value-added services only) → "not enabled / insufficient
 *    edition" (0 findings + warning, module status success), unless the account uses the
 *    pay-as-you-go edition (`IsPostpay` / `PostPayStatus=1`; to be confirmed on a live account).
 *  - {@link listSasVulRecords}: `DescribeVulList` per `Type` (CurrentPage / PageSize,
 *    `Dealed=n` = unhandled), records already fixed / ignored are dropped.
 *  - {@link sasNecessity}: `Necessity` asap / later / nntf (fallback `Level`).
 *
 * Fatal errors (auth_failed / api_misuse) are re-thrown for the scanner to report as
 * `status: "error"`; everything else becomes a redacted warning.
 */
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { classifyAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { ALI_SAS_EDITIONS, ALI_SAS_LOW_MATURITY_VERSIONS } from "./service-detection.js";
import { aliArray, aliCallCtx, aliField, aliNumber, aliSoftWarning, aliString, isAliFatal, type AliScanEnv } from "./shared.js";

/** Prefix of every "SAS not enabled / insufficient edition" warning. */
export const SAS_NOT_ENABLED_WARNING = "Security Center (SAS) is not enabled or runs an insufficient edition";

/** DescribeVulList page size and per-Type record cap (records are per vulnerability × host). */
export const SAS_VUL_PAGE_SIZE = 50;
export const SAS_MAX_VUL_RECORDS_PER_TYPE = 1000;

/** `DescribeVulList` record `Status` values that are no longer actionable: fixed / ignored / not found / expired. */
export const SAS_VUL_CLOSED_STATUSES: ReadonlySet<number> = new Set([7, 10, 12, 20]);

/** Human label per `DescribeVulList` Type. */
export const SAS_VUL_TYPE_LABELS: Readonly<Record<string, string>> = {
  cve: "Linux software (CVE)",
  sys: "Windows system",
  cms: "Web-CMS",
  app: "application",
  emg: "emergency",
  sca: "software component",
};

function truthy(v: unknown): boolean {
  return v === true || v === 1 || (typeof v === "string" && ["true", "1"].includes(v.trim().toLowerCase()));
}

/** Standard not-enabled warning: `<prefix> (<detail>); <what> not available. …` (redacted). */
export function sasNotEnabledWarning(what: string, detail: string): string {
  return redactAliDiagnostic(
    `${SAS_NOT_ENABLED_WARNING} (${detail}); ${what} not available. Upgrade Security Center to a paid edition (or enable pay-as-you-go) and bind it to your servers.`,
  );
}

export type SasEditionCheck =
  /** Paid edition (or edition unknown after a transient failure): run the listing. */
  | { kind: "enabled"; edition?: string; warning?: string }
  /** Not purchased / free / insufficient edition / no permission: 0 findings + warning. */
  | { kind: "stop"; warning: string };

/**
 * DescribeVersionConfig gate. not_enabled / free edition → stop with the not-enabled
 * warning; access denied → stop with a permission warning; throttled / network / other →
 * warning and continue (the listing decides). Throws auth_failed / api_misuse.
 */
export async function checkSasEdition(env: AliScanEnv, what: string): Promise<SasEditionCheck> {
  let body: unknown;
  try {
    body = await aliCall(ALI_API.sas.DescribeVersionConfig, aliCallCtx(env));
  } catch (err) {
    if (isAliFatal(err)) throw err;
    const kind = classifyAliError(err).kind;
    if (kind === "not_enabled") return { kind: "stop", warning: sasNotEnabledWarning(what, describeAliError(err)) };
    if (kind === "access_denied") return { kind: "stop", warning: aliSoftWarning("SAS DescribeVersionConfig", err) };
    return {
      kind: "enabled",
      warning: redactAliDiagnostic(`SAS DescribeVersionConfig: edition check failed (${describeAliError(err)}); continuing without the edition check`),
    };
  }
  const postpay = truthy(aliField(body, "IsPostpay")) || aliNumber(aliField(body, "PostPayStatus")) === 1;
  const version = aliNumber(aliField(body, "Version"));
  if (version === undefined) {
    if (postpay) return { kind: "enabled", edition: "pay-as-you-go" };
    return { kind: "stop", warning: sasNotEnabledWarning(what, "Security Center edition not reported: not purchased") };
  }
  const edition = ALI_SAS_EDITIONS[version] ?? `edition ${version}`;
  if (ALI_SAS_LOW_MATURITY_VERSIONS.has(version) && !postpay) {
    return { kind: "stop", warning: sasNotEnabledWarning(what, edition) };
  }
  return { kind: "enabled", edition: postpay && ALI_SAS_LOW_MATURITY_VERSIONS.has(version) ? "pay-as-you-go" : edition };
}

/**
 * Warning + whether to stop further queries of the same API for a non-fatal listing
 * failure. not_enabled → the standard not-enabled warning; access denied / not enabled
 * stop (same permission / edition for every query). Caller re-throws fatal errors first.
 */
export function sasListFailure(label: string, what: string, err: unknown): { warning: string; stop: boolean } {
  const kind = classifyAliError(err).kind;
  if (kind === "not_enabled") return { warning: sasNotEnabledWarning(what, `${label}: ${describeAliError(err)}`), stop: true };
  return { warning: aliSoftWarning(label, err), stop: kind === "access_denied" };
}

/* ------------------------------------------------------------------------ */
/* Necessity                                                                 */
/* ------------------------------------------------------------------------ */

export type SasNecessity = "asap" | "later" | "nntf" | "unknown";

/** Ranking (most urgent first). */
export const SAS_NECESSITY_RANK: Readonly<Record<SasNecessity, number>> = { asap: 0, later: 1, nntf: 2, unknown: 3 };

/** riskScore per necessity: asap → HIGH 8.0, later → MEDIUM 5.5, nntf → LOW 3.0, unrated → MEDIUM 5.5. */
export const SAS_NECESSITY_RISK: Readonly<Record<SasNecessity, number>> = { asap: 8.0, later: 5.5, nntf: 3.0, unknown: 5.5 };

/** Display label per necessity. */
export const SAS_NECESSITY_LABELS: Readonly<Record<SasNecessity, string>> = {
  asap: "high-priority (asap)",
  later: "medium-priority (later)",
  nntf: "low-priority (nntf)",
  unknown: "unrated",
};

/** `Necessity` (asap / later / nntf; case-insensitive), falling back to `Level` (serious|critical|high / medium / low). */
export function sasNecessity(rec: unknown): SasNecessity {
  const n = aliString(aliField(rec, "Necessity"))?.toLowerCase();
  if (n === "asap" || n === "later" || n === "nntf") return n;
  const level = aliString(aliField(rec, "Level"))?.toLowerCase();
  if (level === "serious" || level === "critical" || level === "high") return "asap";
  if (level === "medium") return "later";
  if (level === "low") return "nntf";
  return "unknown";
}

/** The more urgent of two necessities. */
export function sasMoreUrgent(a: SasNecessity, b: SasNecessity): SasNecessity {
  return SAS_NECESSITY_RANK[a] <= SAS_NECESSITY_RANK[b] ? a : b;
}

/* ------------------------------------------------------------------------ */
/* DescribeVulList                                                           */
/* ------------------------------------------------------------------------ */

export interface SasVulRecord {
  /** Queried `Type` (record `Type` when present). */
  type: string;
  rec: Record<string, unknown>;
}

export interface SasVulListing {
  records: SasVulRecord[];
  warnings: string[];
  /** True when a query hit the not-enabled / permission condition (remaining types skipped). */
  stopped: boolean;
  /** Number of types queried successfully. */
  queried: number;
}

/** Record still actionable (unhandled): `Status` absent or not fixed / ignored / not found / expired. */
export function sasVulOpen(rec: unknown): boolean {
  const status = aliNumber(aliField(rec, "Status"));
  return status === undefined || !SAS_VUL_CLOSED_STATUSES.has(status);
}

/**
 * Unhandled `DescribeVulList` records for each type (in order). Non-fatal failures become
 * warnings; access denied / not enabled stop the remaining types. Throws auth_failed /
 * api_misuse.
 */
export async function listSasVulRecords(
  env: AliScanEnv,
  types: readonly string[],
  what: string,
  maxPerType: number = SAS_MAX_VUL_RECORDS_PER_TYPE,
): Promise<SasVulListing> {
  const records: SasVulRecord[] = [];
  const warnings: string[] = [];
  let stopped = false;
  let queried = 0;
  for (const type of types) {
    const label = `SAS DescribeVulList (Type=${type})`;
    try {
      const page = await aliPaginate<unknown, Record<string, unknown>>({
        style: "page",
        label,
        pageSize: SAS_VUL_PAGE_SIZE,
        maxItems: maxPerType,
        pageParam: "CurrentPage",
        fetch: (q) => aliCall(ALI_API.sas.DescribeVulList, aliCallCtx(env), { Type: type, Dealed: "n", Lang: "en", ...q }),
        items: (body) => aliArray<Record<string, unknown>>(aliField(body, "VulRecords")).filter((r) => r && typeof r === "object"),
        totalCount: (body) => aliNumber(aliField(body, "TotalCount")),
      });
      queried++;
      warnings.push(...page.warnings.map(redactAliDiagnostic));
      for (const rec of page.items) {
        if (!sasVulOpen(rec)) continue;
        records.push({ type: aliString(rec.Type)?.toLowerCase() ?? type, rec });
      }
    } catch (err) {
      if (isAliFatal(err)) throw err;
      const f = sasListFailure(label, what, err);
      warnings.push(f.warning);
      if (f.stop) {
        stopped = true;
        break;
      }
    }
  }
  return { records, warnings, stopped, queried };
}

/** CVE IDs from `Related` (comma-separated) and `ExtendContentJson.cveList`, de-duplicated, redacted. */
export function sasVulCves(rec: unknown): string[] {
  const out = new Set<string>();
  const related = aliString(aliField(rec, "Related"));
  if (related) for (const c of related.split(/[,\s]+/)) if (c) out.add(redactAliDiagnostic(c));
  for (const c of aliArray(aliField(aliField(rec, "ExtendContentJson"), "cveList"))) {
    const s = aliString(c);
    if (s) out.add(redactAliDiagnostic(s));
  }
  return [...out];
}

/** Truncate long free text for descriptions. */
export function sasTruncate(s: string | undefined, max = 200): string | undefined {
  if (!s) return undefined;
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

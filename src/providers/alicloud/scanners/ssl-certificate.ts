/**
 * Alibaba Cloud SSL certificate scanner (moduleName `ssl_certificate`, plan §4.1 P1 / T4).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/ssl-certificate.ts` (ACM). Certificate Management Service (CAS,
 * centralised `cas.aliyuncs.com` / intl `cas.ap-southeast-1.aliyuncs.com`)
 * `ListUserCertificateOrder` with `CurrentPage` / `ShowSize` pagination (`TotalCount`):
 *  - queried for `OrderType=CERT` (issued + uploaded) and `OrderType=UPLOAD` (uploaded), each
 *    once with an empty `Status` (the API then returns only valid certificates: ISSUED +
 *    WILLEXPIRED) and once with `Status=EXPIRED` (otherwise expired certificates are never
 *    returned). Entries are de-duplicated by `CertificateId`.
 *  - remaining days from `CertEndTime` (epoch ms) or `EndDate` (`yyyy-MM-dd`, UTC), floored
 *    like the AWS scanner.
 *
 * Thresholds / riskScore are the AWS ones: expired 8.0 (also when `Expired=true` or
 * `Status=EXPIRED` without a parseable date), < 30 days 6.0, < 90 days 4.0; abnormal status
 * (`CHECKED_FAIL` = ACM FAILED, `REVOKED`) 7.5. Pending orders (PAYED / CHECKING /
 * NOTACTIVATED) produce nothing. resourceArn `acs:cas::<uid>:certificate/<certId>` (global).
 *
 * Errors: auth_failed / api_misuse → module `status: "error"`; access denied / not
 * enabled / throttled / network → warning + degrade.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { classifyAliError, degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliSafeFinding,
  aliSafeWarnings,
  aliScanEnv,
  aliString,
  aliUntrusted,
  isAliFatal,
} from "./shared.js";

export const CAS_PAGE_SIZE = 50;
/** Per-query certificate cap. */
export const CAS_MAX_CERTIFICATES = 1000;

/** `OrderType` values queried (CERT = issued + uploaded, UPLOAD = uploaded only). */
export const CAS_ORDER_TYPES = ["CERT", "UPLOAD"] as const;
/** `Status` filters per OrderType: "" = default (ISSUED + WILLEXPIRED), EXPIRED = expired only. */
export const CAS_STATUS_FILTERS = ["", "EXPIRED"] as const;

/** Statuses meaning the certificate cannot be used (ACM "FAILED" equivalent). */
export const CAS_ABNORMAL_STATUSES: ReadonlySet<string> = new Set(["CHECKED_FAIL", "REVOKED"]);
/** Order statuses that are not (yet) a certificate — no evaluation. */
export const CAS_PENDING_STATUSES: ReadonlySet<string> = new Set(["PAYED", "CHECKING", "NOTACTIVATED"]);

export const CAS_EXPIRED_RISK = 8.0;
export const CAS_EXPIRES_30_RISK = 6.0;
export const CAS_EXPIRES_90_RISK = 4.0;
export const CAS_ABNORMAL_RISK = 7.5;

const DAY_MS = 24 * 60 * 60 * 1000;

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

function truthy(v: unknown): boolean {
  return v === true || (typeof v === "string" && v.trim().toLowerCase() === "true");
}

/** Expiry instant (epoch ms) from `CertEndTime` (ms; seconds accepted) or `EndDate` (`yyyy-MM-dd`, UTC). */
export function casCertEndMs(cert: unknown): number | undefined {
  const ms = aliNumber(aliField(cert, "CertEndTime"));
  if (ms !== undefined && ms > 0) return ms < 1e12 ? ms * 1000 : ms;
  const end = aliString(aliField(cert, "EndDate"));
  if (!end) return undefined;
  const m = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?/.exec(end);
  const t = m ? Date.parse(`${m[1]}T${m[2] ?? "00:00:00"}Z`) : Date.parse(end);
  return Number.isNaN(t) ? undefined : t;
}

/** Whole days until `endMs` (negative when past); Math.floor as the AWS scanner. */
export function casDaysUntil(endMs: number, nowMs: number = Date.now()): number {
  return Math.floor((endMs - nowMs) / DAY_MS);
}

export type CasVerdict =
  | { kind: "abnormal"; status: string }
  | { kind: "expired"; days?: number }
  | { kind: "expires_30"; days: number }
  | { kind: "expires_90"; days: number }
  | { kind: "ok" };

/** Classify one `CertificateOrderList` entry. */
export function evaluateCasCertificate(cert: unknown, nowMs: number = Date.now()): CasVerdict {
  const status = (aliString(aliField(cert, "Status")) ?? "").toUpperCase();
  if (CAS_ABNORMAL_STATUSES.has(status)) return { kind: "abnormal", status };
  if (CAS_PENDING_STATUSES.has(status)) return { kind: "ok" };
  const endMs = casCertEndMs(cert);
  const days = endMs !== undefined ? casDaysUntil(endMs, nowMs) : undefined;
  if ((days !== undefined && days < 0) || status === "EXPIRED" || truthy(aliField(cert, "Expired"))) {
    return { kind: "expired", ...(days !== undefined && days < 0 ? { days } : {}) };
  }
  if (days === undefined) return { kind: "ok" };
  if (days < 30) return { kind: "expires_30", days };
  if (days < 90) return { kind: "expires_90", days };
  return { kind: "ok" };
}

/** Certificate ID (CertificateId; InstanceId / OrderId as fallbacks). */
function casCertId(cert: unknown): string | undefined {
  return aliString(aliField(cert, "CertificateId")) ?? aliString(aliField(cert, "InstanceId")) ?? aliString(aliField(cert, "OrderId"));
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliSslCertificateScanner implements Scanner {
  readonly moduleName = "ssl_certificate";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);
      const certs = new Map<string, Record<string, unknown>>();

      queries: for (const orderType of CAS_ORDER_TYPES) {
        for (const status of CAS_STATUS_FILTERS) {
          const label = `CAS ListUserCertificateOrder (OrderType=${orderType}${status ? `, Status=${status}` : ""})`;
          try {
            const page = await aliPaginate<unknown, Record<string, unknown>>({
              style: "page",
              label,
              pageSize: CAS_PAGE_SIZE,
              maxItems: CAS_MAX_CERTIFICATES,
              pageParam: "CurrentPage",
              sizeParam: "ShowSize",
              fetch: (q) => aliCall(ALI_API.cas.ListUserCertificateOrder, aliCallCtx(env), { OrderType: orderType, ...(status ? { Status: status } : {}), ...q }),
              items: (body) =>
                aliArray<Record<string, unknown>>(aliField(body, "CertificateOrderList")).filter((c) => c && typeof c === "object"),
              totalCount: (body) => aliNumber(aliField(body, "TotalCount")),
            });
            warnings.push(...page.warnings);
            for (const c of page.items) {
              const id = casCertId(c);
              if (id && !certs.has(id)) certs.set(id, c);
            }
          } catch (err) {
            if (isAliFatal(err)) return aliErrorResult(this.moduleName, startMs, "SSL certificate check failed", err, warnings);
            warnings.push(degradeAliError(label, err) ?? redactAliDiagnostic(`${label}: failed (${describeAliError(err)}); skipped`));
            // Same API and permission for every query: stop on a permission / enablement problem.
            const kind = classifyAliError(err).kind;
            if (kind === "access_denied" || kind === "not_enabled") break queries;
          }
        }
      }

      const nowMs = Date.now();
      for (const [rawCertId, cert] of certs) {
        // Raw id is only the dedup map key; every emitted certificate field is redacted.
        const certId = aliUntrusted(rawCertId) ?? "unknown";
        const domain = aliUntrusted(cert.Domain) ?? aliUntrusted(cert.CommonName) ?? aliUntrusted(cert.Name) ?? certId;
        const name = aliUntrusted(cert.Name);
        const sans = aliUntrusted(cert.Sans);
        const source = truthy(cert.Upload) || aliString(cert.SourceType)?.toLowerCase() === "upload" ? " (uploaded)" : "";
        const label = `CAS certificate ${certId}${name && name !== domain ? ` "${name}"` : ""}${source} for "${domain}"${sans && sans !== domain ? ` (SANs: ${sans})` : ""}`;
        const base = {
          resourceType: "ACS::CAS::Certificate",
          resourceId: domain,
          resourceArn: toAliUrn("cas", "certificate", certId, "", env.accountId),
          region: "global",
        };
        const endMs = casCertEndMs(cert);
        const endDay = endMs !== undefined ? new Date(endMs).toISOString().split("T")[0] : undefined;
        const v = evaluateCasCertificate(cert, nowMs);

        switch (v.kind) {
          case "abnormal":
            findings.push(
              makeFinding({
                ...base,
                riskScore: CAS_ABNORMAL_RISK,
                title: `Certificate for ${domain} is in ${v.status} status`,
                description: `${label} has status ${v.status}.`,
                impact:
                  v.status === "REVOKED"
                    ? "The certificate has been revoked and will be rejected by clients. Services relying on it may lose HTTPS protection."
                    : "The certificate failed review and cannot be used for TLS termination. Services relying on it may lose HTTPS protection.",
                remediationSteps: [
                  "Check the order / certificate status in the Certificate Management Service console.",
                  "Apply for (or upload) a new certificate with correct domain validation.",
                  "If using DNS validation, ensure the validation records are correctly configured.",
                ],
              }),
            );
            break;
          case "expired":
            findings.push(
              makeFinding({
                ...base,
                riskScore: CAS_EXPIRED_RISK,
                title: `Certificate for ${domain} has expired`,
                description: `${label} ${v.days !== undefined ? `expired ${Math.abs(v.days)} days ago` : "has expired"}${endDay ? ` (${endDay})` : ""}.`,
                impact: "Expired certificates cause TLS errors for end users. Browsers will display security warnings and block access.",
                remediationSteps: [
                  "Renew or replace the certificate immediately and redeploy it to SLB / CDN / WAF / OSS.",
                  "Enable automatic renewal / hosting (trustee) for purchased certificates.",
                  "Remove the expired certificate once no resource references it.",
                ],
              }),
            );
            break;
          case "expires_30":
            findings.push(
              makeFinding({
                ...base,
                riskScore: CAS_EXPIRES_30_RISK,
                title: `Certificate for ${domain} expires in ${v.days} days`,
                description: `${label} expires in ${v.days} days${endDay ? ` (${endDay})` : ""}.`,
                impact: "Certificate will expire soon. If not renewed, services will experience TLS errors.",
                remediationSteps: [
                  "Renew the certificate (or verify automatic renewal / hosting is active).",
                  "If uploaded, obtain and upload the renewed certificate, then redeploy it.",
                  "Set up CloudMonitor / CAS expiry notifications.",
                ],
              }),
            );
            break;
          case "expires_90":
            findings.push(
              makeFinding({
                ...base,
                riskScore: CAS_EXPIRES_90_RISK,
                title: `Certificate for ${domain} expires in ${v.days} days`,
                description: `${label} expires in ${v.days} days${endDay ? ` (${endDay})` : ""}.`,
                impact: "Certificate is approaching expiry. Plan renewal to avoid service disruption.",
                remediationSteps: [
                  "Verify automatic renewal / hosting is configured for purchased certificates.",
                  "If uploaded, begin the renewal process.",
                  "Consider setting up monitoring for certificate expiry dates.",
                ],
              }),
            );
            break;
          case "ok":
            break;
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings: aliSafeWarnings(warnings) } : {}),
        resourcesScanned: certs.size,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "SSL certificate check failed", err, warnings);
    }
  }
}

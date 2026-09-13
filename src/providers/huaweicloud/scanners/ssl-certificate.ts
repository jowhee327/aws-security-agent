/**
 * Huawei Cloud SSL certificate scanner (moduleName `ssl_certificate`).
 *
 * Mirrors `src/scanners/ssl-certificate.ts` (ACM):
 *  - SCM (Cloud Certificate Manager, regional) `listCertificates` with
 *    `limit`/`offset` pagination (`total_count`) → `expire_time` + `status`.
 *  - ELB v3 `listCertificates` (marker pagination via `page_info.next_marker`)
 *    supplements certificates uploaded directly to ELB; entries that reference
 *    an SCM certificate (`scm_certificate_id`) or share domain + expiry day with
 *    an SCM certificate are de-duplicated.
 *
 * Thresholds / riskScore are the AWS ones: expired 8.0, < 30 days 6.0,
 * < 90 days 4.0; unusable certificate (SCM `UNPASSED` = ACM FAILED, `REVOKED`)
 * 7.5. SCM `EXPIRED` status is reported as expired even without a parseable
 * `expire_time`. Pending states (CHECKING*, ISSUING, PAID, …) produce nothing.
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
import { daysUntil, hwCredentialsFromContext, hwRegionScopeFromContext, parseHwTimestamp, MarkerGuard, repeatedMarkerWarning } from "./shared.js";

export const SCM_PAGE_SIZE = 50;
export const SCM_MAX_CERTIFICATES = 1000;
export const ELB_CERT_PAGE_SIZE = 100;
export const ELB_MAX_CERTIFICATES = 1000;
const MAX_PAGES = 100;

/** SCM statuses that mean the certificate cannot be used (ACM "FAILED" equivalent). */
export const SCM_FAILED_STATUSES: ReadonlySet<string> = new Set(["UNPASSED", "REVOKED"]);
/** SCM statuses that are transitional / not yet issued — no expiry evaluation. */
export const SCM_PENDING_STATUSES: ReadonlySet<string> = new Set([
  "PAID",
  "CHECKING",
  "CHECKING_ORG",
  "ISSUING",
  "SUPPLEMENTCHECKING",
  "CANCELCHECKING",
  "CANCELING",
  "CANCELED",
  "REVOKING",
]);

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

interface LooseScmCertificate {
  id?: string;
  name?: string;
  domain?: string;
  status?: string;
  type?: string;
  expire_time?: string;
  expireTime?: string;
}

interface LooseScmListResponse {
  certificates?: LooseScmCertificate[];
  total_count?: number;
  totalCount?: number;
}

interface LooseElbCertificate {
  id?: string;
  name?: string;
  domain?: string;
  type?: string;
  expire_time?: string;
  expireTime?: string;
  scm_certificate_id?: string;
  scmCertificateId?: string;
}

interface LooseElbListResponse {
  certificates?: LooseElbCertificate[];
  page_info?: { next_marker?: string; nextMarker?: string };
  pageInfo?: { next_marker?: string; nextMarker?: string };
}

/** Minimal client surfaces (tests inject fakes). */
export interface ScmLikeClient {
  listCertificates(req?: unknown): Promise<unknown>;
}
export interface ElbLikeClient {
  listCertificates(req?: unknown): Promise<unknown>;
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

export type CertificateVerdict =
  | { kind: "failed"; status: string }
  | { kind: "expired"; daysAgo: number; expiryIso?: string }
  | { kind: "expiring"; days: number; riskScore: 6.0 | 4.0; expiryIso?: string }
  | { kind: "ok" };

/**
 * Evaluate a certificate (SCM or ELB) into a verdict using the AWS thresholds.
 * `status` is optional (ELB certificates carry none).
 */
export function evaluateCertificate(status: string | undefined, expireTime: unknown, nowMs: number = Date.now()): CertificateVerdict {
  const st = (status ?? "").toUpperCase();
  if (SCM_FAILED_STATUSES.has(st)) return { kind: "failed", status: st };

  const expiryMs = parseHwTimestamp(expireTime);
  if (st === "EXPIRED") {
    const daysAgo = expiryMs !== undefined ? Math.max(0, -daysUntil(expiryMs, nowMs)) : 0;
    return { kind: "expired", daysAgo, expiryIso: expiryMs !== undefined ? new Date(expiryMs).toISOString().split("T")[0] : undefined };
  }
  if (SCM_PENDING_STATUSES.has(st)) return { kind: "ok" };
  if (expiryMs === undefined) return { kind: "ok" };

  const days = daysUntil(expiryMs, nowMs);
  const expiryIso = new Date(expiryMs).toISOString().split("T")[0];
  if (days < 0) return { kind: "expired", daysAgo: Math.abs(days), expiryIso };
  if (days < 30) return { kind: "expiring", days, riskScore: 6.0, expiryIso };
  if (days < 90) return { kind: "expiring", days, riskScore: 4.0, expiryIso };
  return { kind: "ok" };
}

function certLabel(c: { domain?: string; name?: string; id?: string }): string {
  return c.domain || c.name || c.id || "unknown";
}

/** De-duplication key shared by SCM and ELB entries: lower-cased domain + expiry day. */
function domainExpiryKey(domain: string | undefined, expireTime: unknown): string | undefined {
  if (!domain) return undefined;
  const ms = parseHwTimestamp(expireTime);
  if (ms === undefined) return undefined;
  return `${domain.toLowerCase()}|${new Date(ms).toISOString().split("T")[0]}`;
}

function toVerdictFindings(opts: {
  verdict: CertificateVerdict;
  label: string;
  service: "SCM" | "ELB";
  resourceType: string;
  resourceArn: string;
  region: string;
}): Finding | undefined {
  const { verdict, label, service, resourceType, resourceArn, region } = opts;
  const svcName = service === "SCM" ? "SCM (Cloud Certificate Manager)" : "ELB";
  const base = { resourceType, resourceId: label, resourceArn, region };

  switch (verdict.kind) {
    case "failed":
      return makeFinding({
        ...base,
        riskScore: 7.5,
        title: `Certificate for ${label} is in ${verdict.status} status`,
        description: `${svcName} certificate for "${label}" has status ${verdict.status} and cannot be used for TLS termination.`,
        impact:
          "The certificate failed validation or was revoked and cannot be used for TLS termination. Services relying on it may lose HTTPS protection.",
        remediationSteps: [
          "Check the failure / revocation reason in the SCM console.",
          "Request or upload a new certificate with correct domain validation.",
          "If using DNS validation, ensure the required DNS records are correctly configured.",
        ],
      });
    case "expired":
      return makeFinding({
        ...base,
        riskScore: 8.0,
        title: `Certificate for ${label} has expired`,
        description: `${svcName} certificate for "${label}" expired ${verdict.daysAgo} days ago${verdict.expiryIso ? ` (${verdict.expiryIso})` : ""}.`,
        impact:
          "Expired certificates cause TLS errors for end users. Browsers will display security warnings and block access.",
        remediationSteps: [
          "Renew or replace the certificate immediately.",
          "If the certificate was bought through SCM, check why renewal did not happen and re-issue it.",
          "Re-bind the renewed certificate to ELB listeners / WAF / CDN domains that use it.",
        ],
      });
    case "expiring":
      return makeFinding({
        ...base,
        riskScore: verdict.riskScore,
        title: `Certificate for ${label} expires in ${verdict.days} days`,
        description: `${svcName} certificate for "${label}" expires in ${verdict.days} days${verdict.expiryIso ? ` (${verdict.expiryIso})` : ""}.`,
        impact:
          verdict.riskScore === 6.0
            ? "Certificate will expire soon. If not renewed, services will experience TLS errors."
            : "Certificate is approaching expiry. Plan renewal to avoid service disruption.",
        remediationSteps:
          verdict.riskScore === 6.0
            ? [
                "Renew the certificate in SCM (or upload the renewed certificate) now.",
                "Re-bind the renewed certificate to the ELB listeners / WAF / CDN domains that use it.",
                "Set up CES (Cloud Eye) alarms or SCM expiry notifications for certificate expiry.",
              ]
            : [
                "Plan the certificate renewal in SCM (or prepare the renewed certificate for upload).",
                "Verify which ELB listeners / WAF / CDN domains use the certificate so they can be updated.",
                "Consider enabling SCM expiry notifications for certificate expiry dates.",
              ],
      });
    default:
      return undefined;
  }
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiSslCertificateScanner implements Scanner {
  readonly moduleName = "ssl_certificate";

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

      const scmIds = new Set<string>();
      const scmDomainKeys = new Set<string>();

      // --- SCM ---
      try {
        const { ScmClient } = await import("@huaweicloud/huaweicloud-sdk-scm");
        const scm = (await hwClient(ScmClient, "scm", creds, scope)) as unknown as ScmLikeClient;

        const certs: LooseScmCertificate[] = [];
        let truncated = false;
        for (let page = 0; page < MAX_PAGES; page++) {
          const resp = (await scm.listCertificates({ limit: SCM_PAGE_SIZE, offset: page * SCM_PAGE_SIZE })) as LooseScmListResponse | undefined;
          const batch = Array.isArray(resp?.certificates) ? resp!.certificates! : [];
          certs.push(...batch);
          if (certs.length >= SCM_MAX_CERTIFICATES) {
            truncated = certs.length > SCM_MAX_CERTIFICATES || batch.length === SCM_PAGE_SIZE;
            certs.length = Math.min(certs.length, SCM_MAX_CERTIFICATES);
            break;
          }
          const total = typeof resp?.total_count === "number" ? resp.total_count : typeof resp?.totalCount === "number" ? resp.totalCount : undefined;
          if (batch.length === 0 || batch.length < SCM_PAGE_SIZE || (total !== undefined && certs.length >= total)) break;
        }
        if (truncated) warnings.push(`SCM: more than ${SCM_MAX_CERTIFICATES} certificates; only the first ${SCM_MAX_CERTIFICATES} were checked.`);

        resourcesScanned += certs.length;

        for (const cert of certs) {
          const id = cert.id ?? "unknown";
          if (cert.id) scmIds.add(cert.id);
          const expireTime = cert.expire_time ?? cert.expireTime;
          const key = domainExpiryKey(cert.domain, expireTime);
          if (key) scmDomainKeys.add(key);

          const verdict = evaluateCertificate(cert.status, expireTime, now);
          const finding = toVerdictFindings({
            verdict,
            label: certLabel(cert),
            service: "SCM",
            resourceType: "HuaweiCloud::SCM::Certificate",
            resourceArn: toResourceUrn("scm", "certificate", id, region, domainId),
            region,
          });
          if (finding) findings.push(finding);
        }
      } catch (err) {
        const degraded = degradeHwError("SCM", err);
        if (!degraded) throw err;
        warnings.push(degraded);
      }

      // --- ELB (certificates uploaded directly to ELB) ---
      try {
        const { ElbClient } = await import("@huaweicloud/huaweicloud-sdk-elb/v3/ElbClient.js");
        const elb = (await hwClient(ElbClient, "elb", creds, scope)) as unknown as ElbLikeClient;

        const certs: LooseElbCertificate[] = [];
        let marker: string | undefined;
        let truncated = false;
        const markers = new MarkerGuard();
        for (let page = 0; page < MAX_PAGES; page++) {
          const req: Record<string, unknown> = { limit: ELB_CERT_PAGE_SIZE };
          if (marker !== undefined) req.marker = marker;
          const resp = (await elb.listCertificates(req)) as LooseElbListResponse | undefined;
          const batch = Array.isArray(resp?.certificates) ? resp!.certificates! : [];
          certs.push(...batch);
          if (certs.length >= ELB_MAX_CERTIFICATES) {
            truncated = certs.length > ELB_MAX_CERTIFICATES || batch.length === ELB_CERT_PAGE_SIZE;
            certs.length = Math.min(certs.length, ELB_MAX_CERTIFICATES);
            break;
          }
          const pageInfo = resp?.page_info ?? resp?.pageInfo;
          const next = pageInfo?.next_marker ?? pageInfo?.nextMarker;
          if (batch.length === 0 || !next || next === marker) break;
          if (!markers.accept(next)) {
            warnings.push(repeatedMarkerWarning("ELB", "certificates"));
            break;
          }
          marker = next;
        }
        if (truncated) warnings.push(`ELB: more than ${ELB_MAX_CERTIFICATES} certificates; only the first ${ELB_MAX_CERTIFICATES} were checked.`);

        for (const cert of certs) {
          const scmRef = cert.scm_certificate_id ?? cert.scmCertificateId;
          const expireTime = cert.expire_time ?? cert.expireTime;
          const key = domainExpiryKey(cert.domain, expireTime);
          // Already covered by the SCM listing → skip (de-duplicate by SCM id, then by domain + expiry day).
          if ((scmRef && scmIds.has(scmRef)) || (key && scmDomainKeys.has(key))) continue;

          resourcesScanned += 1;
          const id = cert.id ?? "unknown";
          const verdict = evaluateCertificate(undefined, expireTime, now);
          const finding = toVerdictFindings({
            verdict,
            label: certLabel(cert),
            service: "ELB",
            resourceType: "HuaweiCloud::ELB::Certificate",
            resourceArn: toResourceUrn("elb", "certificate", id, region, domainId),
            region,
          });
          if (finding) findings.push(finding);
        }
      } catch (err) {
        const degraded = degradeHwError("ELB", err);
        if (!degraded) throw err;
        warnings.push(degraded);
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
        error: `Huawei Cloud SSL certificate scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

/**
 * Alibaba Cloud Security Center (SAS) alert scanner (moduleName `guardduty_findings`,
 * plan §4.1 P2 / T7). EXPERIMENTAL — not yet validated against a live account.
 *
 * GuardDuty counterpart: SAS security alerts (intrusions, brute force, web shells,
 * malicious processes, anomalous logins, …).
 *
 *  1. {@link checkSasEdition} (`DescribeVersionConfig`): not purchased / Free Edition /
 *     value-added only → 0 findings + "not enabled / insufficient edition" warning (status
 *     success; `service_detection` already reports the missing edition as a Finding).
 *  2. `DescribeSuspEvents` (centralised tds endpoint, `CurrentPage` / `PageSize` ≤ 100,
 *     `Dealed=N` = unhandled, `Levels=serious,suspicious,remind`), capped at
 *     {@link SAS_MAX_ALERTS} listed alerts.
 *  3. One Finding per unhandled alert — `Level` serious → HIGH 8.0, suspicious → MEDIUM 6.0,
 *     remind → LOW 3.0 (unknown → 6.0) — most severe / most recent first, capped at
 *     {@link SAS_MAX_ALERT_FINDINGS} with an overflow warning carrying the per-level counts.
 *
 * Every server-sourced string (event name / type / description, instance name / ID, IPs)
 * passes through redactAliDiagnostic. Errors: auth_failed / api_misuse → module
 * `status: "error"`; access denied / not enabled / throttled / network → warning + degrade.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import { checkSasEdition, sasListFailure, sasTruncate } from "./sas-shared.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliSafeFinding,
  aliScanEnv,
  aliUntrusted,
  emptyScanResult,
  isAliFatal,
} from "./shared.js";

export const SAS_ALERT_PAGE_SIZE = 100;
/** Alerts listed per scan. */
export const SAS_MAX_ALERTS = 1000;
/** Alerts reported as individual findings. */
export const SAS_MAX_ALERT_FINDINGS = 100;

export type SasAlertLevel = "serious" | "suspicious" | "remind" | "unknown";

/** riskScore per alert `Level`. */
export const SAS_ALERT_RISK: Readonly<Record<SasAlertLevel, number>> = { serious: 8.0, suspicious: 6.0, remind: 3.0, unknown: 6.0 };
const LEVEL_RANK: Readonly<Record<SasAlertLevel, number>> = { serious: 0, suspicious: 1, remind: 2, unknown: 3 };
const LEVEL_LABELS: Readonly<Record<SasAlertLevel, string>> = { serious: "urgent", suspicious: "suspicious", remind: "reminder", unknown: "unrated" };

const WHAT = "security alert (threat detection) data";

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

/** Normalise `Level` (case-insensitive). */
export function sasAlertLevel(rec: unknown): SasAlertLevel {
  const l = aliUntrusted(aliField(rec, "Level"))?.toLowerCase();
  return l === "serious" || l === "suspicious" || l === "remind" ? l : "unknown";
}

function lastSeenMs(rec: unknown): number {
  const ts = aliNumber(aliField(rec, "LastTimeStamp")) ?? aliNumber(aliField(rec, "OccurrenceTimeStamp"));
  return ts !== undefined ? ts : 0;
}

/** Most severe first, then most recent, then by ID for stability. */
export function sortSasAlerts<T>(alerts: T[]): T[] {
  return [...alerts].sort((a, b) => {
    const la = LEVEL_RANK[sasAlertLevel(a)];
    const lb = LEVEL_RANK[sasAlertLevel(b)];
    if (la !== lb) return la - lb;
    const ta = lastSeenMs(a);
    const tb = lastSeenMs(b);
    if (ta !== tb) return tb - ta;
    const ia = String(aliField(a, "Id") ?? "");
    const ib = String(aliField(b, "Id") ?? "");
    return ia < ib ? -1 : ia > ib ? 1 : 0;
  });
}

export class AliSasAlertsScanner implements Scanner {
  readonly moduleName = "guardduty_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);

      const edition = await checkSasEdition(env, WHAT);
      if (edition.kind === "stop") return emptyScanResult(this.moduleName, startMs, { warnings: [edition.warning] });
      if (edition.warning) warnings.push(edition.warning);

      const label = "SAS DescribeSuspEvents";
      let alerts: Record<string, unknown>[];
      try {
        const page = await aliPaginate<unknown, Record<string, unknown>>({
          style: "page",
          label,
          pageSize: SAS_ALERT_PAGE_SIZE,
          maxItems: SAS_MAX_ALERTS,
          pageParam: "CurrentPage",
          fetch: (q) =>
            aliCall(ALI_API.sas.DescribeSuspEvents, aliCallCtx(env), {
              From: "sas",
              Lang: "en",
              Dealed: "N",
              Levels: "serious,suspicious,remind",
              ...q,
            }),
          items: (body) => aliArray<Record<string, unknown>>(aliField(body, "SuspEvents")).filter((e) => e && typeof e === "object"),
          totalCount: (body) => aliNumber(aliField(body, "TotalCount")),
        });
        warnings.push(...page.warnings.map(redactAliDiagnostic));
        alerts = page.items;
      } catch (err) {
        if (isAliFatal(err)) return aliErrorResult(this.moduleName, startMs, "SAS alert scan failed", err, warnings);
        warnings.push(sasListFailure(label, WHAT, err).warning);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }

      const counts: Record<SasAlertLevel, number> = { serious: 0, suspicious: 0, remind: 0, unknown: 0 };
      for (const a of alerts) counts[sasAlertLevel(a)]++;
      const sorted = sortSasAlerts(alerts);
      for (const a of sorted.slice(0, SAS_MAX_ALERT_FINDINGS)) findings.push(this.alertFinding(a, env.accountId));

      if (sorted.length > SAS_MAX_ALERT_FINDINGS) {
        warnings.push(
          `SAS: ${sorted.length} unhandled alerts (serious ${counts.serious}, suspicious ${counts.suspicious}, remind ${counts.remind}${counts.unknown ? `, unrated ${counts.unknown}` : ""}); only the top ${SAS_MAX_ALERT_FINDINGS} (by level and recency) are reported as findings. Review the rest in the Security Center console.`,
        );
      }

      return {
        ...emptyScanResult(this.moduleName, startMs, { warnings }),
        resourcesScanned: alerts.length,
        findingsCount: findings.length,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "SAS alert scan failed", err, warnings);
    }
  }

  private alertFinding(a: Record<string, unknown>, accountId: string): Finding {
    const level = sasAlertLevel(a);
    const id = aliUntrusted(a.Id) ?? aliUntrusted(a.UniqueInfo) ?? "unknown";
    const name =
      aliUntrusted(a.AlarmEventNameDisplay) ?? aliUntrusted(a.Name) ?? aliUntrusted(a.AlarmEventName) ?? "Security Center alert";
    const type = aliUntrusted(a.AlarmEventTypeDisplay) ?? aliUntrusted(a.AlarmEventType) ?? aliUntrusted(a.EventSubType);
    const instanceId = aliUntrusted(a.InstanceId);
    const instanceName = aliUntrusted(a.InstanceName);
    const ip = aliUntrusted(a.InternetIp) ?? aliUntrusted(a.IntranetIp);
    const uuid = aliUntrusted(a.Uuid);
    const asset = instanceId ? `${instanceId}${instanceName && instanceName !== instanceId ? ` (${instanceName})` : ""}` : instanceName ?? ip ?? uuid ?? "unknown asset";
    const first = aliUntrusted(a.OccurrenceTime);
    const last = aliUntrusted(a.LastTime);
    const desc = sasTruncate(aliUntrusted(a.Desc));

    const descParts = [
      `Security Center ${LEVEL_LABELS[level]} alert "${name}"${type ? ` (type: ${type})` : ""} is unhandled on ${asset}`,
      ip && ip !== asset ? `IP: ${ip}` : undefined,
      first ? `First seen: ${first}` : undefined,
      last ? `Last seen: ${last}` : undefined,
      desc ? `Details: ${desc}` : undefined,
      `Alert ID: ${id}`,
    ].filter((p): p is string => Boolean(p));

    return makeFinding({
      riskScore: SAS_ALERT_RISK[level],
      title: `SAS ${LEVEL_LABELS[level]} alert: ${name} on ${asset}`,
      resourceType: "ACS::SAS::Alert",
      resourceId: instanceId ?? uuid ?? id,
      resourceArn: toAliUrn("sas", "alert", id, "", accountId),
      region: "global",
      description: descParts.join(". ") + ".",
      impact:
        level === "serious"
          ? "Urgent Security Center alerts indicate likely compromise (intrusion, malware, web shell, reverse shell or credential abuse) that needs immediate response."
          : level === "remind"
            ? "Reminder-level alerts indicate low-risk anomalies that may precede an attack if left uninvestigated."
            : "Suspicious activity was detected on the asset; if malicious, it may lead to compromise or data exfiltration.",
      remediationSteps: [
        `Open the Security Center console → Alerts and locate the alert "${name}" (ID ${id}).`,
        "Investigate the alert details (process, file, source IP, login records) and the attack timeline.",
        "Contain the threat (isolate the host, kill the process, quarantine the file, block the source IP) and remediate the root cause.",
        "Mark the alert as handled (or whitelist it if confirmed benign) and configure alert notifications.",
      ],
      accountId,
      module: this.moduleName,
    });
  }
}

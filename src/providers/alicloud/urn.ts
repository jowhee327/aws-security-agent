/**
 * Alibaba Cloud resource URN, aligned with the official ARN layout (plan §3.4):
 *   `acs:<svc>:<region>:<uid>:<type>/<id>`
 * Global resources (RAM, CAS, Config, SAS, …) use an EMPTY region segment, as in the
 * official form `acs:ram::1234567890123456:user/alice`.
 *
 * Deliberate deviation: OSS buckets use `acs:oss:<region>:<uid>:bucket/<name>` (the
 * official OSS ARN is `acs:oss:*:<uid>:<bucket>`) so every URN has `<type>/<id>`.
 */
import { redactAliDiagnostic } from "./errors.js";

export const ACS_URN_PREFIX = "acs";

/**
 * Services whose resources are account-level: the URN region segment is empty even
 * when the scan context carries a region.
 */
export const ALI_GLOBAL_URN_SERVICES: ReadonlySet<string> = new Set([
  "ram",
  "ims",
  "sts",
  "cas",
  "config",
  "sas",
  "resourcemanager",
  "alidns",
]);

export function toAliUrn(svc: string, type: string, id: string, region: string | undefined, uid: string): string {
  const r = region ? region.trim() : "";
  // id / region / uid are usually server-sourced: redact so a hostile value cannot smuggle
  // credential material through the URN (ordinary IDs are unchanged).
  return `${ACS_URN_PREFIX}:${svc}:${redactAliDiagnostic(r)}:${redactAliDiagnostic(uid)}:${type}/${redactAliDiagnostic(id)}`;
}

export interface ParsedAliUrn {
  svc: string;
  /** Empty string for global resources. */
  region: string;
  uid: string;
  type: string;
  id: string;
}

/**
 * Parse an `acs:` URN produced by {@link toAliUrn}; returns undefined for other formats.
 * `type` is everything before the FIRST `/` of the resource part; `/` and `:` inside the
 * id are preserved. A resource part without `/` (official OSS form) yields `type: ""`.
 */
export function parseAliUrn(urn: string): ParsedAliUrn | undefined {
  if (typeof urn !== "string" || !urn.startsWith(`${ACS_URN_PREFIX}:`)) return undefined;
  const parts = urn.split(":");
  if (parts.length < 5) return undefined;
  const [, svc, region, uid, ...rest] = parts;
  const resource = rest.join(":");
  if (!svc || !resource) return undefined;
  const slash = resource.indexOf("/");
  if (slash < 0) return { svc, region, uid, type: "", id: resource };
  return { svc, region, uid, type: resource.slice(0, slash), id: resource.slice(slash + 1) };
}

/**
 * Huawei Cloud resource URN.
 * Format: `hws:<region>:<domainId>:<svc>:<type>:<id>` (decided in plan §6.4 Q5).
 * Global resources (IAM, RMS, Organizations, ...) use the logical region
 * {@link HWS_GLOBAL_REGION}; an empty/undefined region is coerced to it so a
 * URN never contains an empty segment (`hws::...`).
 */
export const HWS_URN_PREFIX = "hws";
export const HWS_GLOBAL_REGION = "global";

export function toResourceUrn(
  svc: string,
  type: string,
  id: string,
  region: string | undefined,
  domainId: string,
): string {
  const r = region && region.trim() ? region.trim() : HWS_GLOBAL_REGION;
  return `${HWS_URN_PREFIX}:${r}:${domainId}:${svc}:${type}:${id}`;
}

export interface ParsedHwsUrn {
  region: string;
  domainId: string;
  svc: string;
  type: string;
  id: string;
}

/** Parse a `hws:` URN produced by {@link toResourceUrn}; returns undefined for other formats. */
export function parseResourceUrn(urn: string): ParsedHwsUrn | undefined {
  if (!urn.startsWith(`${HWS_URN_PREFIX}:`)) return undefined;
  const parts = urn.split(":");
  if (parts.length < 6) return undefined;
  const [, region, domainId, svc, type, ...rest] = parts;
  return { region, domainId, svc, type, id: rest.join(":") };
}

/**
 * Huawei Cloud resource URN.
 * Format: `hws:<region>:<domainId>:<svc>:<type>:<id>` (decided in plan §6.4 Q5).
 * Global resources (IAM, OBS bucket names, ...) use an empty or logical region.
 */
export const HWS_URN_PREFIX = "hws";

export function toResourceUrn(
  svc: string,
  type: string,
  id: string,
  region: string,
  domainId: string,
): string {
  return `${HWS_URN_PREFIX}:${region}:${domainId}:${svc}:${type}:${id}`;
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

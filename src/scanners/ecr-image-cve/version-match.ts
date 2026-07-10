import type { Advisory, VersionRange } from "./types.js";

/**
 * Version handling for non-semver forms:
 *  - Alpine package revisions: `1.26.3-r0` (revision compared after upstream version)
 *  - OpenSSL letter suffixes: `1.0.2k` (letter compared as an extra segment)
 *  - plain semver: `1.27.4`
 * The original string must be kept by callers; only comparison uses the normalized form.
 */

interface ParsedVersion {
  /** numeric-or-letter segments, e.g. 1.0.2k → [1, 0, 2, 11] */
  segments: number[];
  /** Alpine -rN revision, -1 when absent */
  revision: number;
}

export function parseVersion(version: string): ParsedVersion {
  let v = version.trim();

  // Strip epoch (dpkg `1:1.26.3-1`) — epochs are rare in our component table
  const epochIdx = v.indexOf(":");
  if (epochIdx > 0 && /^\d+$/.test(v.slice(0, epochIdx))) {
    v = v.slice(epochIdx + 1);
  }

  // Alpine -rN package revision
  let revision = -1;
  const revMatch = v.match(/-r(\d+)$/);
  if (revMatch) {
    revision = parseInt(revMatch[1], 10);
    v = v.slice(0, revMatch.index);
  }

  // Cut distro suffixes like `-1ubuntu2`, `+deb12u1`, `~alpha` — keep the upstream part
  const upstream = v.split(/[-+~]/)[0];

  const segments: number[] = [];
  // Match runs of digits or single trailing letters (openssl 1.0.2k style)
  const re = /(\d+)|([a-zA-Z]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(upstream)) !== null) {
    if (m[1] !== undefined) {
      segments.push(parseInt(m[1], 10));
    } else {
      // letter suffix: 'a' → 1 ... 'z' → 26 (only first letter matters for openssl-style)
      segments.push(m[2].toLowerCase().charCodeAt(0) - 96);
    }
  }

  return { segments, revision };
}

function compareParsed(pa: ParsedVersion, pb: ParsedVersion, compareRevisions: boolean): number {
  const len = Math.max(pa.segments.length, pb.segments.length);
  for (let i = 0; i < len; i++) {
    const sa = pa.segments[i] ?? 0;
    const sb = pb.segments[i] ?? 0;
    if (sa !== sb) return sa < sb ? -1 : 1;
  }
  if (compareRevisions && pa.revision !== pb.revision) return pa.revision < pb.revision ? -1 : 1;
  return 0;
}

/** Standard -1/0/1 comparison on normalized versions. */
export function compareVersions(a: string, b: string): number {
  return compareParsed(parseVersion(a), parseVersion(b), true);
}

/**
 * Advisory ranges are upstream ranges: when a bound carries no distro `-rN`
 * revision, the package's revision is ignored, so `1.30.0-r0` is inside an
 * inclusive max of `1.30.0`. A bound that does carry a revision (distro-level
 * advisory) is compared revision-and-all.
 */
export function versionInRange(version: string, range: VersionRange): boolean {
  const pv = parseVersion(version);
  if (range.min !== undefined) {
    const pmin = parseVersion(range.min);
    const cmp = compareParsed(pv, pmin, pmin.revision >= 0);
    if (range.minInclusive === false ? cmp <= 0 : cmp < 0) return false;
  }
  if (range.max !== undefined) {
    const pmax = parseVersion(range.max);
    const cmp = compareParsed(pv, pmax, pmax.revision >= 0);
    if (range.maxInclusive === false ? cmp >= 0 : cmp > 0) return false;
  }
  return true;
}

export function advisoryMatches(advisory: Advisory, component: string, version: string): boolean {
  if (advisory.component !== component) return false;
  return advisory.affectedRanges.some((r) => versionInRange(version, r));
}

import type {
  Advisory,
  ComponentName,
  ComponentRecord,
  ConfirmedFinding,
  CveMatch,
  GapFinding,
  GapReason,
  ImageInventory,
  OfficialFinding,
  ReverseGapFinding,
  SuppressedFinding,
  Suppression,
} from "./types.js";
import type { Severity } from "../../types.js";
import { advisoryMatches, compareVersions } from "./version-match.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export function meetsMinSeverity(severity: Severity, minSeverity: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minSeverity];
}

/** Map a package/binary name (apk, dpkg, or official-finding name) to a canonical component. */
export function normalizeComponentName(name: string): ComponentName | undefined {
  const n = name.toLowerCase().trim();
  if (n === "nginx" || n.startsWith("nginx-")) return "nginx";
  if (n === "openssl" || n.startsWith("openssl") || n.startsWith("libssl") || n.startsWith("libcrypto")) return "openssl";
  if (n === "curl" || n.startsWith("libcurl")) return "curl";
  if (n === "redis" || n === "redis-server" || n.startsWith("redis")) return "redis";
  if (n === "node" || n === "nodejs" || n.startsWith("nodejs")) return "node";
  if (n === "httpd" || n === "apache2" || n.startsWith("apache2")) return "httpd";
  if (n === "haproxy") return "haproxy";
  if (n === "php" || /^php\d/.test(n) || n.startsWith("php-") || n.startsWith("php8") || n.startsWith("php7")) return "php";
  if (n === "python3" || n === "python" || /^python3(\.\d+)?$/.test(n)) return "python3";
  if (n.startsWith("openjdk") || n.startsWith("java-") || n === "java") return "java";
  if (n === "envoy") return "envoy";
  return undefined;
}

/** Upstream portion of a version (drops Alpine `-rN` and distro suffixes) for cross-channel comparison. */
function upstreamVersion(version: string): string {
  let v = version;
  const epochIdx = v.indexOf(":");
  if (epochIdx > 0 && /^\d+$/.test(v.slice(0, epochIdx))) v = v.slice(epochIdx + 1);
  return v.split(/[-+~]/)[0];
}

/**
 * Merge Channel A (packages) and Channel B (binaries) into unified component
 * records with provenance. A binary is `package-managed` only when the same
 * component appears in Channel A with a matching upstream version; otherwise
 * it is flagged `unmanaged-binary` (the Lilly case).
 */
export function buildComponentRecords(inventory: ImageInventory): ComponentRecord[] {
  const records: ComponentRecord[] = [];

  const packagesByComponent = new Map<ComponentName, { name: string; version: string }[]>();
  for (const pkg of inventory.packages) {
    const component = normalizeComponentName(pkg.name) ?? (pkg.sourcePackage ? normalizeComponentName(pkg.sourcePackage) : undefined);
    if (!component) continue;
    const list = packagesByComponent.get(component) ?? [];
    list.push({ name: pkg.name, version: pkg.version });
    packagesByComponent.set(component, list);
    records.push({
      component,
      version: pkg.version,
      channel: "package",
      provenance: "package-managed",
      evidence: pkg.name,
    });
  }

  const seenBinary = new Set<string>();
  for (const bin of inventory.binaries) {
    const key = `${bin.component}@${bin.version}`;
    if (seenBinary.has(key)) continue;
    seenBinary.add(key);

    const pkgs = packagesByComponent.get(bin.component) ?? [];
    const managed = pkgs.some((p) => compareVersions(upstreamVersion(p.version), bin.version) === 0);
    records.push({
      component: bin.component,
      version: bin.version,
      channel: "binary",
      provenance: managed ? "package-managed" : "unmanaged-binary",
      evidence: bin.filePath,
      signatureId: bin.signatureId,
      layerDigest: bin.layerDigest,
    });
  }

  return records;
}

/** Match component records against the advisory table, filtered by minimum severity. */
export function matchCves(
  components: ComponentRecord[],
  advisories: Advisory[],
  minSeverity: Severity,
): CveMatch[] {
  const matches: CveMatch[] = [];
  const seen = new Set<string>();

  for (const comp of components) {
    for (const adv of advisories) {
      if (!meetsMinSeverity(adv.severity, minSeverity)) continue;
      if (!advisoryMatches(adv, comp.component, comp.version)) continue;
      // Prefer the binary-channel record when both channels match the same CVE+component;
      // unmanaged-binary provenance must win so the gap reason is correct.
      const key = `${adv.cveId}|${comp.component}`;
      if (seen.has(key)) {
        const existing = matches.find((m) => `${m.cveId}|${m.component}` === key);
        if (existing && existing.provenance === "package-managed" && comp.provenance === "unmanaged-binary") {
          existing.provenance = "unmanaged-binary";
          existing.channel = comp.channel;
          existing.version = comp.version;
          existing.evidence = comp.evidence;
        }
        continue;
      }
      seen.add(key);
      matches.push({
        cveId: adv.cveId,
        component: comp.component,
        version: comp.version,
        severity: adv.severity,
        cvss: adv.cvss,
        fixedIn: adv.fixedIn,
        provenance: comp.provenance,
        channel: comp.channel,
        evidence: comp.evidence,
        advisorySource: adv.source,
        summary: adv.summary,
      });
    }
  }

  return matches;
}

/** Distro releases past upstream security support (kept deliberately coarse). */
const EOL_OS: Array<{ id: string; maxEolVersion: string }> = [
  { id: "alpine", maxEolVersion: "3.17" },
  { id: "debian", maxEolVersion: "10" },
  { id: "ubuntu", maxEolVersion: "18.04" },
  { id: "centos", maxEolVersion: "8" },
];

const SUPPORTED_OS_IDS = new Set(["alpine", "debian", "ubuntu"]);

export function classifyGapReason(match: CveMatch, inventory: ImageInventory): GapReason {
  if (match.provenance === "unmanaged-binary") return "unmanaged-binary";

  const osId = inventory.os.id?.toLowerCase();
  const osVersion = inventory.os.versionId;

  if (osId && osVersion) {
    const eol = EOL_OS.find((e) => e.id === osId);
    if (eol && compareVersions(osVersion, eol.maxEolVersion) <= 0) return "eol-os";
  }

  if (osId && SUPPORTED_OS_IDS.has(osId)) {
    // Package-managed on a supported, non-EOL distro and official scanners missed it:
    // the distro security feed has no entry for this CVE on this branch.
    return "distro-secdb-no-entry";
  }

  if (!osId || !SUPPORTED_OS_IDS.has(osId)) {
    return inventory.rpmDbPresent || osId ? "unsupported-os" : "unknown";
  }

  return "unknown";
}

export interface DiffInput {
  imageDigest: string;
  repository: string;
  ourMatches: CveMatch[];
  officialFindings: OfficialFinding[];
  inventory: ImageInventory;
  minSeverity: Severity;
}

export interface DiffOutput {
  gaps: GapFinding[];
  confirmed: ConfirmedFinding[];
  reverseGaps: ReverseGapFinding[];
}

export function normalizeOfficialSeverity(sev: string | undefined): Severity | undefined {
  const s = sev?.toUpperCase();
  if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") return s;
  return undefined;
}

/**
 * Whether an official finding's severity clears the reporting threshold.
 * Policy for non-standard Inspector severities:
 *  - INFORMATIONAL ranks below LOW ⇒ never clears a threshold of LOW or above.
 *  - UNTRIAGED / anything else unrecognized is unranked; it is only surfaced in
 *    report-everything mode (minSeverity=LOW) so it cannot flood reverse-gaps
 *    by bypassing the filter entirely, but is still visible if the user asks
 *    for everything.
 */
export function officialSeverityMeetsMin(sev: string | undefined, minSeverity: Severity): boolean {
  const normalized = normalizeOfficialSeverity(sev);
  if (normalized) return meetsMinSeverity(normalized, minSeverity);
  const s = sev?.toUpperCase();
  if (s === "INFORMATIONAL" || s === "NONE") return false;
  // UNTRIAGED / unknown: only in report-everything mode.
  return minSeverity === "LOW";
}

/**
 * Diff our matches against official (ECR basic / Inspector enhanced) findings.
 * Dedup key: imageDigest + cveId + normalized component name. An official
 * finding whose component is missing or unrecognized never confirms one of
 * our matches; it stays a reverse-gap/self-audit row so real gaps are not
 * hidden behind a CVE-ID-only coincidence.
 */
export function diffWithOfficial(input: DiffInput): DiffOutput {
  const { imageDigest, repository, ourMatches, officialFindings, inventory, minSeverity } = input;

  const gaps: GapFinding[] = [];
  const confirmed: ConfirmedFinding[] = [];
  const matchedOfficial = new Set<OfficialFinding>();

  for (const match of ourMatches) {
    const hits = officialFindings.filter((of) => {
      if (of.cveId !== match.cveId) return false;
      if (!of.component) return false;
      return normalizeComponentName(of.component) === match.component;
    });

    if (hits.length > 0) {
      for (const h of hits) matchedOfficial.add(h);
      const sources = [...new Set(hits.map((h) => h.source))];
      confirmed.push({ ...match, imageDigest, repository, confirmedBy: sources });
    } else {
      gaps.push({ ...match, imageDigest, repository, reason: classifyGapReason(match, inventory) });
    }
  }

  const reverseGaps: ReverseGapFinding[] = [];
  const seenReverse = new Set<string>();
  for (const of of officialFindings) {
    if (matchedOfficial.has(of)) continue;
    // Unknown/non-standard severities (UNTRIAGED, INFORMATIONAL) must not bypass
    // the minSeverity filter and flood reverse-gaps — see officialSeverityMeetsMin.
    if (!officialSeverityMeetsMin(of.severity, minSeverity)) continue;
    const key = `${of.cveId}|${of.component ?? ""}`;
    if (seenReverse.has(key)) continue;
    seenReverse.add(key);
    reverseGaps.push({
      imageDigest,
      repository,
      cveId: of.cveId,
      component: of.component,
      severity: of.severity,
      source: of.source,
    });
  }

  return { gaps, confirmed, reverseGaps };
}

/** Split gap findings into kept vs suppressed. Suppressed findings are never silently dropped. */
export function applySuppressions(
  gaps: GapFinding[],
  suppressions: Suppression[],
): { kept: GapFinding[]; suppressed: SuppressedFinding[] } {
  if (suppressions.length === 0) return { kept: gaps, suppressed: [] };

  const kept: GapFinding[] = [];
  const suppressed: SuppressedFinding[] = [];

  for (const gap of gaps) {
    const rule = suppressions.find((s) => {
      if (s.cveId !== gap.cveId) return false;
      if (s.imageDigestPrefix && !gap.imageDigest.startsWith(s.imageDigestPrefix)) return false;
      if (s.component && normalizeComponentName(s.component) !== gap.component) return false;
      return true;
    });
    if (rule) {
      suppressed.push({ ...gap, suppressionReason: rule.reason });
    } else {
      kept.push(gap);
    }
  }

  return { kept, suppressed };
}

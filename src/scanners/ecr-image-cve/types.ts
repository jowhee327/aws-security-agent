import type { Severity } from "../../types.js";

/** Canonical component keys tracked by the Channel-B binary detector and the advisory table. */
export type ComponentName =
  | "nginx"
  | "openssl"
  | "curl"
  | "redis"
  | "node"
  | "httpd"
  | "haproxy"
  | "php"
  | "python3"
  | "java"
  | "envoy";

/** Channel A — a package installed via the image's package manager. */
export interface PackageRecord {
  name: string;
  version: string;
  /** Source/origin package when the metadata provides one (apk `o:`, dpkg `Source:`). */
  sourcePackage?: string;
  manager: "apk" | "dpkg";
}

/** Channel B — a well-known server binary detected inside a layer tar. */
export interface BinaryRecord {
  component: ComponentName;
  version: string;
  filePath: string;
  signatureId: string;
  layerDigest: string;
}

export interface OsInfo {
  /** os-release ID (alpine, debian, ubuntu, ...) */
  id?: string;
  /** os-release VERSION_ID (3.21, 12, 22.04, ...) */
  versionId?: string;
  prettyName?: string;
  /** Content of /etc/alpine-release when present. */
  alpineRelease?: string;
}

export type Provenance = "package-managed" | "unmanaged-binary";

/** Unified component record fed into CVE matching (from either channel). */
export interface ComponentRecord {
  component: ComponentName;
  version: string;
  channel: "package" | "binary";
  provenance: Provenance;
  /** Original package name or binary file path, for evidence. */
  evidence: string;
  signatureId?: string;
  layerDigest?: string;
}

/**
 * v1 simplification: layers are scanned additively with last-writer-wins for
 * file inventory; OCI whiteout semantics are NOT applied, so a file deleted in
 * a later layer may still be reported.
 */
export interface ImageInventory {
  packages: PackageRecord[];
  binaries: BinaryRecord[];
  os: OsInfo;
  /** An rpmdb was seen but rpm parsing is unsupported in v1. */
  rpmDbPresent: boolean;
}

export interface VersionRange {
  min?: string;
  max?: string;
  minInclusive?: boolean;
  maxInclusive?: boolean;
}

export interface Advisory {
  cveId: string;
  component: ComponentName;
  affectedRanges: VersionRange[];
  fixedIn: string[];
  severity: Severity;
  cvss: number;
  summary: string;
  source: string;
}

/** A CVE we matched against the image inventory (before diffing with official results). */
export interface CveMatch {
  cveId: string;
  component: ComponentName;
  /** Original version string as found (e.g. `1.26.3-r0`). */
  version: string;
  severity: Severity;
  cvss: number;
  fixedIn: string[];
  provenance: Provenance;
  channel: "package" | "binary";
  evidence: string;
  advisorySource: string;
  summary: string;
}

/** A finding reported by ECR Basic Scanning or Inspector Enhanced Scanning. */
export interface OfficialFinding {
  cveId: string;
  /** Normalized component/package name when the official finding names one. */
  component?: string;
  severity?: string;
  source: "basic" | "enhanced";
}

export type GapReason =
  | "unmanaged-binary"
  | "distro-secdb-no-entry"
  | "eol-os"
  | "unsupported-os"
  | "unknown";

export interface GapFinding extends CveMatch {
  imageDigest: string;
  repository: string;
  reason: GapReason;
}

export interface ConfirmedFinding extends CveMatch {
  imageDigest: string;
  repository: string;
  confirmedBy: Array<"basic" | "enhanced">;
}

export interface ReverseGapFinding {
  imageDigest: string;
  repository: string;
  cveId: string;
  component?: string;
  severity?: string;
  source: "basic" | "enhanced";
}

export interface Suppression {
  cveId: string;
  imageDigestPrefix?: string;
  component?: string;
  reason: string;
}

export interface SuppressedFinding extends GapFinding {
  suppressionReason: string;
}

export interface ImageBaseline {
  imageDigest: string;
  /**
   * Digest of the platform manifest actually scanned. Differs from
   * imageDigest for manifest-list (multi-arch) images; official findings are
   * queried under both digests.
   */
  resolvedDigest: string;
  repository: string;
  /** availability of official scan channels for this image */
  basicScan: "available" | "no-official-scan" | "error";
  enhancedScan: "available" | "not-enabled" | "error";
  baseline: "basic+enhanced" | "basic-only" | "enhanced-only" | "none";
}

export interface SkippedImage {
  imageDigest: string;
  repository: string;
  reason: string;
}

export interface EcrImageCveReport {
  summary: {
    repositoriesScanned: number;
    imagesScanned: number;
    imagesSkipped: number;
    gapCount: number;
    gapCritical: number;
    gapHigh: number;
    confirmedCount: number;
    reverseGapCount: number;
    suppressedCount: number;
    /** confirmed / (confirmed + gap + reverse-gap); 1.0 means we fully agree with official scans. */
    coverageConsistencyRatio: number | null;
  };
  gapFindings: GapFinding[];
  reverseGapFindings: ReverseGapFinding[];
  confirmedCount: number;
  /** Detail rows only when includeConfirmed=true. */
  confirmedFindings?: ConfirmedFinding[];
  suppressed: SuppressedFinding[];
  skippedImages: SkippedImage[];
  baselinePerImage: ImageBaseline[];
}

export interface EcrImageCveOptions {
  /** Glob filter on repository names (e.g. `prod-*`). */
  repositoryFilter?: string;
  /** Latest-pushed N images per repo (plus any image tagged `latest`). Default 3. */
  maxImagesPerRepo?: number;
  /** Minimum severity to report. Default "high" (i.e. HIGH + CRITICAL). */
  minSeverity?: "critical" | "high" | "medium" | "low";
  /** Enable NVD API 2.0 online lookup (Tier 2). Default false. */
  onlineCveLookup?: boolean;
  /** Include confirmed finding detail rows in the report. Default false. */
  includeConfirmed?: boolean;
  suppressions?: Suppression[];
  /** Platform preference for manifest lists. Default ["linux/amd64", "linux/arm64"]. */
  platformPreference?: string[];
  /** Whole image is skipped (not just the layer) if any layer exceeds this many compressed bytes. Default 512 MB. */
  maxLayerBytes?: number;
  /** Skip images whose compressed layers total more than this. Default 2 GB. */
  maxImageBytes?: number;
  /** Cap on decompressed bytes stream-scanned per candidate binary. Default 64 MB. */
  maxBinaryScanBytes?: number;
  /**
   * Maximum number of repositories to scan; remaining repos are recorded in
   * warnings and skipped. Default 50 (a small cap of 10 is used under scan_all).
   */
  maxRepositories?: number;
  /**
   * Cumulative cap on compressed layer bytes downloaded across the whole scan.
   * Once exceeded, remaining images are skipped with a recorded reason. Default 20 GB.
   */
  maxTotalBytes?: number;
}

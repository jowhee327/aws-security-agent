import { ECRClient } from "@aws-sdk/client-ecr";
import { Inspector2Client } from "@aws-sdk/client-inspector2";
import { Scanner } from "../base.js";
import { ScanResult, ScanContext, Finding, Severity } from "../../types.js";
import { createClient } from "../../utils/aws-client.js";
import { priorityFromSeverity } from "../../utils/risk-scoring.js";
import { OFFLINE_ADVISORIES } from "./advisories.js";
import {
  getBasicScanFindings,
  getEnhancedFindings,
  getManifestLayers,
  InspectorCoverageCache,
  listImages,
  listRepositories,
  openLayerStream,
  type ImageRef,
} from "./ecr-client.js";
import {
  applySuppressions,
  buildComponentRecords,
  diffWithOfficial,
  matchCves,
} from "./engine.js";
import { InventoryCollector, scanLayerStream, layerCompression } from "./layer-scan.js";
import { fetchNvdAdvisoriesResult } from "./nvd-lookup.js";
import type {
  Advisory,
  ComponentName,
  ConfirmedFinding,
  EcrImageCveOptions,
  EcrImageCveReport,
  GapFinding,
  ImageBaseline,
  OfficialFinding,
  ReverseGapFinding,
  SkippedImage,
  SuppressedFinding,
} from "./types.js";

const DEFAULT_MAX_IMAGES_PER_REPO = 3;
const DEFAULT_MAX_LAYER_BYTES = 512 * 1024 * 1024; // 512 MB compressed
const DEFAULT_MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB compressed total
const DEFAULT_MAX_REPOSITORIES = 50;
const DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024 * 1024; // 20 GB compressed across the whole scan
/** Conservative repo cap applied when the scanner runs as part of scan_all / scan_group. */
export const SCAN_ALL_MAX_REPOSITORIES = 10;
const DEFAULT_PLATFORMS = ["linux/amd64", "linux/arm64"];

const GAP_REASON_LABELS: Record<string, string> = {
  "unmanaged-binary": "binary is not explainable by any installed package (edge/community pkg, vendor repo, or source-compiled)",
  "distro-secdb-no-entry": "distro security feed has no secfixes entry for this CVE on this release branch",
  "eol-os": "OS release is end-of-life; distro no longer publishes advisories",
  "unsupported-os": "OS/package-manager is not covered by official scanners (rpm parsing unsupported in v1)",
  unknown: "cause could not be classified automatically",
};

function minSeverityToEnum(min: EcrImageCveOptions["minSeverity"]): Severity {
  switch (min) {
    case "critical": return "CRITICAL";
    case "medium": return "MEDIUM";
    case "low": return "LOW";
    case "high":
    default: return "HIGH";
  }
}

/**
 * Whether the image's official-scan baseline actually verifies the "official
 * scans did not report this CVE" claim. When both channels errored (throttling,
 * access denied) the absence is unverifiable and the finding must not assert it.
 */
function baselineVerifiesAbsence(baseline: ImageBaseline | undefined): boolean {
  if (!baseline) return false;
  // At least one channel produced an authoritative negative (scan present /
  // enabled, or definitively not-scanned/not-enabled — not an error).
  const basicOk = baseline.basicScan === "available" || baseline.basicScan === "no-official-scan";
  const enhancedOk = baseline.enhancedScan === "available" || baseline.enhancedScan === "not-enabled";
  return basicOk || enhancedOk;
}

function gapToFinding(
  gap: GapFinding,
  region: string,
  partition: string,
  accountId: string,
  baseline?: ImageBaseline,
): Finding {
  const severity = gap.severity;
  const shortDigest = gap.imageDigest.replace("sha256:", "").slice(0, 12);
  const verified = baselineVerifiesAbsence(baseline);
  const officialClause = verified
    ? "Official ECR Basic/Inspector Enhanced scans did not report this CVE."
    : "Official ECR Basic/Inspector Enhanced scan results were unavailable for this image (scan errored/throttled), so this CVE's absence from official findings could not be verified — treat as a candidate gap pending a re-scan.";
  return {
    severity,
    title: `${gap.cveId} in ${gap.component} ${gap.version} ${verified ? "missed by" : "not confirmed against"} official ECR/Inspector scans (${gap.repository}@${shortDigest})`,
    resourceType: "AWS::ECR::Image",
    resourceId: `${gap.repository}@${gap.imageDigest}`,
    resourceArn: `arn:${partition}:ecr:${region}:${accountId}:repository/${gap.repository}`,
    region,
    description:
      `${gap.summary} Detected via ${gap.channel === "binary" ? "binary version signature" : "package metadata"} ` +
      `(${gap.evidence}, provenance: ${gap.provenance}). ${officialClause} ` +
      `Gap reason: ${gap.reason} — ${GAP_REASON_LABELS[gap.reason]}.`,
    impact: `CVSS ${gap.cvss} ${gap.severity} vulnerability is running undetected by AWS-native scanning; advisory: ${gap.advisorySource}`,
    riskScore: gap.cvss,
    remediationSteps: [
      gap.fixedIn.length > 0
        ? `Upgrade ${gap.component} to ${gap.fixedIn.join(" or ")} and rebuild the image.`
        : `Rebuild the image with a patched ${gap.component} build.`,
      gap.reason === "unmanaged-binary"
        ? `Replace the unmanaged ${gap.component} binary (${gap.evidence}) with a distro-packaged version so official scanners can track it.`
        : "Move to a supported, non-EOL base image so distro advisories cover this component.",
      "Re-scan the image after rebuild and verify the CVE no longer matches.",
      `If this is a confirmed false positive, add a suppression entry for ${gap.cveId} with a documented reason.`,
    ],
    priority: priorityFromSeverity(severity),
  };
}

/**
 * Merge official-findings results queried under multiple digests (manifest-list
 * parent + resolved child). Findings are deduped by cveId + component + source;
 * one available channel makes the merged channel available, otherwise an error
 * on any digest is surfaced over a plain not-found/not-enabled status.
 */
export function mergeOfficialResults<S extends string>(
  results: Array<{ findings: OfficialFinding[]; status: S }>,
): { findings: OfficialFinding[]; status: S } {
  const findings: OfficialFinding[] = [];
  const seen = new Set<string>();
  for (const r of results) {
    for (const f of r.findings) {
      const key = `${f.cveId}|${f.component ?? ""}|${f.source}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(f);
    }
  }
  const status =
    results.find((r) => r.status === "available")?.status
    ?? results.find((r) => r.status === "error")?.status
    ?? results[0].status;
  return { findings, status };
}

export class EcrImageCveScanner implements Scanner {
  readonly moduleName = "ecr_image_cve";

  constructor(private readonly options: EcrImageCveOptions = {}) {}

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];
    const opts = this.options;

    const maxImagesPerRepo = opts.maxImagesPerRepo ?? DEFAULT_MAX_IMAGES_PER_REPO;
    const minSeverity = minSeverityToEnum(opts.minSeverity);
    const platforms = opts.platformPreference ?? DEFAULT_PLATFORMS;
    const maxLayerBytes = opts.maxLayerBytes ?? DEFAULT_MAX_LAYER_BYTES;
    const maxImageBytes = opts.maxImageBytes ?? DEFAULT_MAX_IMAGE_BYTES;
    const maxRepositories = opts.maxRepositories ?? DEFAULT_MAX_REPOSITORIES;
    const maxTotalBytes = opts.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;

    try {
      const ecr = createClient(ECRClient, region, ctx.credentials);
      const inspector = createClient(Inspector2Client, region, ctx.credentials);

      const allRepos = await listRepositories(ecr, opts.repositoryFilter);
      if (allRepos.length === 0) {
        warnings.push(
          opts.repositoryFilter
            ? `No ECR repositories match filter "${opts.repositoryFilter}" in ${region}.`
            : `No ECR repositories found in ${region}.`,
        );
      }

      // Bound the number of repositories scanned; a huge account otherwise turns
      // this into an unbounded, multi-gigabyte download inside one tool call.
      const repos = allRepos.slice(0, maxRepositories);
      if (allRepos.length > repos.length) {
        warnings.push(
          `Repository cap reached: scanned ${repos.length} of ${allRepos.length} repositories (maxRepositories=${maxRepositories}); ${allRepos.length - repos.length} skipped. Narrow repositoryFilter or raise the cap.`,
        );
      }

      const allGaps: GapFinding[] = [];
      const allConfirmed: ConfirmedFinding[] = [];
      const allReverseGaps: ReverseGapFinding[] = [];
      const skippedImages: SkippedImage[] = [];
      const baselinePerImage: ImageBaseline[] = [];
      let imagesScanned = 0;
      let totalBytesDownloaded = 0;
      let budgetExhausted = false;
      // NVD truncation warnings are deduped across images (the feed is per-component).
      const nvdWarnings = new Set<string>();

      // Cache Inspector ECR coverage once per scan — it is an account-global
      // answer, so querying it per image is redundant.
      const coverageCache = new InspectorCoverageCache(inspector);

      for (const repo of repos) {
        const repoName = repo.repositoryName!;
        let images: ImageRef[];
        try {
          images = await listImages(ecr, repoName, maxImagesPerRepo);
        } catch (err) {
          warnings.push(`Failed to list images in ${repoName}: ${err instanceof Error ? err.message : String(err)}`);
          continue;
        }

        for (const image of images) {
          if (budgetExhausted) {
            skippedImages.push({
              imageDigest: image.imageDigest,
              repository: repoName,
              reason: `total download budget ${maxTotalBytes} bytes reached before this image; skipped to keep the scan bounded`,
            });
            continue;
          }
          try {
            const { layers, resolvedDigest } = await getManifestLayers(ecr, repoName, image.imageDigest, platforms);

            const totalBytes = layers.reduce((sum, l) => sum + (l.size ?? 0), 0);
            if (totalBytes > maxImageBytes) {
              skippedImages.push({
                imageDigest: image.imageDigest,
                repository: repoName,
                reason: `total compressed size ${totalBytes} exceeds limit ${maxImageBytes}`,
              });
              continue;
            }

            // Overall download budget: skip this image (and all later ones) once
            // downloading it would push cumulative bytes past the cap.
            if (totalBytesDownloaded + totalBytes > maxTotalBytes) {
              budgetExhausted = true;
              skippedImages.push({
                imageDigest: image.imageDigest,
                repository: repoName,
                reason: `total download budget ${maxTotalBytes} bytes would be exceeded (already downloaded ${totalBytesDownloaded}, image needs ${totalBytes}); skipped to keep the scan bounded`,
              });
              continue;
            }

            // A layer we cannot scan means the inventory would be incomplete; a
            // clean result from a partial layer set is not authoritative, so the
            // whole image is skipped rather than silently under-reported.
            const oversized = layers.find((l) => (l.size ?? 0) > maxLayerBytes);
            if (oversized) {
              skippedImages.push({
                imageDigest: image.imageDigest,
                repository: repoName,
                reason: `layer ${oversized.digest} compressed size ${oversized.size} exceeds limit ${maxLayerBytes}; inventory would be incomplete`,
              });
              continue;
            }

            // zstd layers cannot be decompressed with zlib; a partial inventory
            // is not authoritative, so skip the whole image with a clear reason.
            const zstdLayer = layers.find((l) => layerCompression(l.mediaType) === "zstd");
            if (zstdLayer) {
              skippedImages.push({
                imageDigest: image.imageDigest,
                repository: repoName,
                reason: `unsupported layer compression zstd (layer ${zstdLayer.digest}); inventory would be incomplete`,
              });
              continue;
            }

            const collector = new InventoryCollector();
            for (const layer of layers) {
              const stream = await openLayerStream(ecr, repo.registryId, repoName, layer.digest);
              await scanLayerStream(stream, layer.digest, layer.mediaType, collector, { maxBinaryScanBytes: opts.maxBinaryScanBytes });
            }
            totalBytesDownloaded += totalBytes;

            const inventory = collector.build();
            if (inventory.rpmDbPresent) {
              warnings.push(`${repoName}@${image.imageDigest}: rpm database detected — rpm: unsupported-v1, package channel incomplete for this image.`);
            }

            const components = buildComponentRecords(inventory);

            let advisories: Advisory[] = OFFLINE_ADVISORIES;
            if (opts.onlineCveLookup) {
              const uniqueComponents = [...new Set(components.map((c) => c.component))] as ComponentName[];
              const online = await Promise.all(uniqueComponents.map((c) => fetchNvdAdvisoriesResult(c)));
              const offlineIds = new Set(OFFLINE_ADVISORIES.map((a) => a.cveId));
              advisories = [
                ...OFFLINE_ADVISORIES,
                ...online.flatMap((r) => r.advisories).filter((a) => !offlineIds.has(a.cveId)),
              ];
              for (const r of online) {
                if (r.warning && !nvdWarnings.has(r.warning)) nvdWarnings.add(r.warning);
              }
            }

            const ourMatches = matchCves(components, advisories, minSeverity);

            // Multi-arch images: official findings may be keyed to the parent
            // (manifest list) digest OR the resolved child platform digest, so
            // query both and merge to avoid reporting false gaps.
            const digests = image.imageDigest === resolvedDigest
              ? [image.imageDigest]
              : [image.imageDigest, resolvedDigest];
            const basic = mergeOfficialResults(
              await Promise.all(digests.map((d) => getBasicScanFindings(ecr, repoName, d))),
            );
            // Resolve Inspector coverage once per repository (cached) and pass it
            // in so getEnhancedFindings does not re-query ListCoverage per digest.
            const covered = await coverageCache.isRepositoryCovered(repoName);
            const enhanced = mergeOfficialResults(
              await Promise.all(
                digests.map((d) =>
                  covered === false
                    ? Promise.resolve({ findings: [], status: "not-enabled" as const })
                    : getEnhancedFindings(inspector, d, repoName, repo.registryId, covered),
                ),
              ),
            );
            const baseline: ImageBaseline = {
              imageDigest: image.imageDigest,
              resolvedDigest,
              repository: repoName,
              basicScan: basic.status,
              enhancedScan: enhanced.status,
              baseline:
                basic.status === "available" && enhanced.status === "available" ? "basic+enhanced"
                : basic.status === "available" ? "basic-only"
                : enhanced.status === "available" ? "enhanced-only"
                : "none",
            };
            baselinePerImage.push(baseline);

            const diff = diffWithOfficial({
              imageDigest: image.imageDigest,
              repository: repoName,
              ourMatches,
              officialFindings: [...basic.findings, ...enhanced.findings],
              inventory,
              minSeverity,
            });

            allGaps.push(...diff.gaps);
            allConfirmed.push(...diff.confirmed);
            allReverseGaps.push(...diff.reverseGaps);
            imagesScanned++;
          } catch (err) {
            skippedImages.push({
              imageDigest: image.imageDigest,
              repository: repoName,
              reason: err instanceof Error ? err.message : String(err),
            });
          }
        }
      }

      warnings.push(...nvdWarnings);

      const { kept: gapFindings, suppressed } = applySuppressions(allGaps, opts.suppressions ?? []);

      const report = buildReport({
        repositoriesScanned: repos.length,
        imagesScanned,
        gapFindings,
        suppressed,
        confirmed: allConfirmed,
        reverseGaps: allReverseGaps,
        skippedImages,
        baselinePerImage,
        includeConfirmed: opts.includeConfirmed ?? false,
      });

      // Baseline is keyed per image (parent digest); used to qualify the gap
      // description when official scan results were unverifiable.
      const baselineByDigest = new Map(baselinePerImage.map((b) => [b.imageDigest, b]));
      const findings = gapFindings.map((g) =>
        gapToFinding(g, region, partition, accountId, baselineByDigest.get(g.imageDigest)),
      );

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: imagesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
        ...({ ecrImageCve: report } as Record<string, unknown>),
      } as ScanResult & { ecrImageCve: EcrImageCveReport };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

function buildReport(input: {
  repositoriesScanned: number;
  imagesScanned: number;
  gapFindings: GapFinding[];
  suppressed: SuppressedFinding[];
  confirmed: ConfirmedFinding[];
  reverseGaps: ReverseGapFinding[];
  skippedImages: SkippedImage[];
  baselinePerImage: ImageBaseline[];
  includeConfirmed: boolean;
}): EcrImageCveReport {
  const { gapFindings, suppressed, confirmed, reverseGaps } = input;
  const total = confirmed.length + gapFindings.length + reverseGaps.length;
  return {
    summary: {
      repositoriesScanned: input.repositoriesScanned,
      imagesScanned: input.imagesScanned,
      imagesSkipped: input.skippedImages.length,
      gapCount: gapFindings.length,
      gapCritical: gapFindings.filter((g) => g.severity === "CRITICAL").length,
      gapHigh: gapFindings.filter((g) => g.severity === "HIGH").length,
      confirmedCount: confirmed.length,
      reverseGapCount: reverseGaps.length,
      suppressedCount: suppressed.length,
      coverageConsistencyRatio: total > 0 ? Math.round((confirmed.length / total) * 1000) / 1000 : null,
    },
    gapFindings,
    reverseGapFindings: reverseGaps,
    confirmedCount: confirmed.length,
    ...(input.includeConfirmed ? { confirmedFindings: confirmed } : {}),
    suppressed,
    skippedImages: input.skippedImages,
    baselinePerImage: input.baselinePerImage,
  };
}

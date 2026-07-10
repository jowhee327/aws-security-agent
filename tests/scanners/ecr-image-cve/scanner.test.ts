import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { gzipSync } from "node:zlib";
import { pack } from "tar-stream";

vi.mock("../../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { EcrImageCveScanner } from "../../../src/scanners/ecr-image-cve/index.js";
import { mergeOfficialResults } from "../../../src/scanners/ecr-image-cve/scanner.js";
import type { EcrImageCveReport, OfficialFinding } from "../../../src/scanners/ecr-image-cve/types.js";
import type { ScanContext, ScanResult } from "../../../src/types.js";

const ctx: ScanContext = {
  region: "cn-northwest-1",
  partition: "aws-cn",
  accountId: "123456789012",
};

function fakeElf(embedded: string): Buffer {
  return Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    Buffer.alloc(16, 0),
    Buffer.from(embedded, "latin1"),
  ]);
}

async function makeLayer(entries: Array<{ name: string; content: Buffer | string }>): Promise<Buffer> {
  const p = pack();
  for (const e of entries) p.entry({ name: e.name }, e.content);
  p.finalize();
  const chunks: Buffer[] = [];
  for await (const chunk of p) chunks.push(chunk as Buffer);
  return gzipSync(Buffer.concat(chunks));
}

const MANIFEST = {
  schemaVersion: 2,
  mediaType: "application/vnd.docker.distribution.manifest.v2+json",
  layers: [
    { mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", digest: "sha256:layer1", size: 1024 },
  ],
};

type ResultWithReport = ScanResult & { ecrImageCve: EcrImageCveReport };

describe("mergeOfficialResults status precedence (finding: missing test)", () => {
  const f = (cveId: string, component: string, source: "basic" | "enhanced"): OfficialFinding => ({
    cveId,
    component,
    severity: "CRITICAL",
    source,
  });

  it("prefers 'available' over any other status", () => {
    const merged = mergeOfficialResults([
      { findings: [], status: "error" },
      { findings: [f("CVE-1", "nginx", "basic")], status: "available" },
      { findings: [], status: "no-official-scan" },
    ]);
    expect(merged.status).toBe("available");
  });

  it("prefers 'error' over a plain not-found/not-enabled when no channel is available", () => {
    const merged = mergeOfficialResults([
      { findings: [], status: "no-official-scan" },
      { findings: [], status: "error" },
    ]);
    expect(merged.status).toBe("error");
  });

  it("falls back to the first status when neither available nor error is present", () => {
    const merged = mergeOfficialResults([
      { findings: [], status: "no-official-scan" },
      { findings: [], status: "not-enabled" },
    ]);
    expect(merged.status).toBe("no-official-scan");
  });

  it("dedupes findings by cveId + component + source across digests", () => {
    const merged = mergeOfficialResults([
      { findings: [f("CVE-1", "nginx", "basic"), f("CVE-1", "nginx", "basic")], status: "available" },
      { findings: [f("CVE-1", "nginx", "basic"), f("CVE-2", "curl", "enhanced")], status: "available" },
    ]);
    expect(merged.findings).toHaveLength(2);
    expect(merged.findings.map((x) => x.cveId).sort()).toEqual(["CVE-1", "CVE-2"]);
  });
});

describe("EcrImageCveScanner", () => {
  let layerBlob: Buffer;
  const originalFetch = globalThis.fetch;

  beforeEach(async () => {
    mockSend.mockReset();
    layerBlob = await makeLayer([
      { name: "etc/os-release", content: 'ID=alpine\nVERSION_ID=3.21.0\n' },
      { name: "etc/alpine-release", content: "3.21.0\n" },
      { name: "lib/apk/db/installed", content: "P:musl\nV:1.2.5-r8\no:musl\n" },
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);
    globalThis.fetch = vi.fn(async () => new Response(new Uint8Array(layerBlob))) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function mockAws(opts: { basicFindings?: any; basicError?: Error; coverage?: any[] } = {}) {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      switch (cmd.constructor.name) {
        case "DescribeRepositoriesCommand":
          return { repositories: [{ repositoryName: "prod-nginx", registryId: "123456789012" }] };
        case "DescribeImagesCommand":
          return {
            imageDetails: [
              { imageDigest: "sha256:abc123", imageTags: ["latest"], imagePushedAt: new Date("2026-06-01"), imageSizeInBytes: 1024 },
            ],
          };
        case "BatchGetImageCommand":
          return {
            images: [{
              imageManifest: JSON.stringify(MANIFEST),
              imageManifestMediaType: MANIFEST.mediaType,
            }],
          };
        case "GetDownloadUrlForLayerCommand":
          return { downloadUrl: "https://example.com/layer" };
        case "DescribeImageScanFindingsCommand":
          if (opts.basicError) throw opts.basicError;
          return { imageScanFindings: { findings: opts.basicFindings ?? [] } };
        case "ListCoverageCommand":
          return { coveredResources: opts.coverage ?? [] };
        case "ListFindingsCommand":
          return { findings: [] };
        default:
          return {};
      }
    });
  }

  it("reports the Lilly-case gap when official scans are silent", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    mockAws({ basicError: scanNotFound, coverage: [] });

    const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(1);
    expect(result.findingsCount).toBeGreaterThanOrEqual(1);

    const finding = result.findings.find((f) => f.title.includes("CVE-2026-42945"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.riskScore).toBe(9.2);
    expect(finding!.priority).toBe("P0");
    expect(finding!.resourceType).toBe("AWS::ECR::Image");
    expect(finding!.resourceArn).toBe("arn:aws-cn:ecr:cn-northwest-1:123456789012:repository/prod-nginx");
    expect(finding!.description).toContain("unmanaged-binary");

    const report = result.ecrImageCve;
    expect(report.summary.gapCount).toBeGreaterThanOrEqual(1);
    expect(report.gapFindings[0].reason).toBe("unmanaged-binary");
    expect(report.baselinePerImage).toEqual([
      expect.objectContaining({
        imageDigest: "sha256:abc123",
        basicScan: "no-official-scan",
        enhancedScan: "not-enabled",
        baseline: "none",
      }),
    ]);
  });

  it("classifies as confirmed when the official basic scan reports the same CVE", async () => {
    mockAws({
      basicFindings: [
        {
          name: "CVE-2026-42945",
          severity: "CRITICAL",
          attributes: [{ key: "package_name", value: "nginx" }],
        },
      ],
      coverage: [],
    });

    const result = (await new EcrImageCveScanner({ includeConfirmed: true }).scan(ctx)) as ResultWithReport;

    expect(result.status).toBe("success");
    const report = result.ecrImageCve;
    expect(report.confirmedCount).toBe(1);
    expect(report.confirmedFindings).toHaveLength(1);
    expect(report.gapFindings.find((g) => g.cveId === "CVE-2026-42945")).toBeUndefined();
    expect(result.findings.find((f) => f.title.includes("CVE-2026-42945"))).toBeUndefined();
    expect(report.summary.coverageConsistencyRatio).toBe(1);
  });

  it("routes suppressed CVEs to the suppressed section instead of findings", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    mockAws({ basicError: scanNotFound });

    const scanner = new EcrImageCveScanner({
      suppressions: [{ cveId: "CVE-2026-42945", reason: "accepted risk" }],
    });
    const result = (await scanner.scan(ctx)) as ResultWithReport;

    const report = result.ecrImageCve;
    expect(report.suppressed).toHaveLength(1);
    expect(report.suppressed[0].suppressionReason).toBe("accepted risk");
    expect(report.gapFindings.find((g) => g.cveId === "CVE-2026-42945")).toBeUndefined();
    expect(result.findings.find((f) => f.title.includes("CVE-2026-42945"))).toBeUndefined();
  });

  it("warns when no repositories match the filter", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "DescribeRepositoriesCommand") {
        return { repositories: [{ repositoryName: "staging-app" }] };
      }
      return {};
    });

    const result = await new EcrImageCveScanner({ repositoryFilter: "prod-*" }).scan(ctx);
    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.warnings?.[0]).toContain('No ECR repositories match filter "prod-*"');
  });

  it("returns error status when repository listing fails", async () => {
    mockSend.mockRejectedValue(new Error("ECR access denied"));

    const result = await new EcrImageCveScanner().scan(ctx);
    expect(result.status).toBe("error");
    expect(result.error).toContain("access denied");
    expect(result.findings).toEqual([]);
  });

  it("skips the whole image (not just the layer) when a layer exceeds maxLayerBytes", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    mockAws({ basicError: scanNotFound });

    const result = (await new EcrImageCveScanner({ maxLayerBytes: 512 }).scan(ctx)) as ResultWithReport;

    expect(result.status).toBe("success");
    // An incomplete layer set must not be treated as an authoritative clean scan
    expect(result.resourcesScanned).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.ecrImageCve.skippedImages).toHaveLength(1);
    expect(result.ecrImageCve.skippedImages[0]).toMatchObject({
      imageDigest: "sha256:abc123",
      repository: "prod-nginx",
    });
    expect(result.ecrImageCve.skippedImages[0].reason).toContain("exceeds limit");
    expect(result.ecrImageCve.summary.imagesSkipped).toBe(1);
  });

  describe("manifest-list (multi-arch) official-findings digest handling", () => {
    const PARENT_DIGEST = "sha256:abc123";
    const CHILD_DIGEST = "sha256:child456";
    const MANIFEST_LIST = {
      schemaVersion: 2,
      mediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
      manifests: [
        { digest: CHILD_DIGEST, platform: { os: "linux", architecture: "amd64" } },
      ],
    };

    function mockMultiArchAws(opts: {
      basicFindingsByDigest?: Record<string, any[]>;
      enhancedFindingsByDigest?: Record<string, any[]>;
    } = {}) {
      mockSend.mockImplementation((cmd: { constructor: { name: string }; input?: any }) => {
        const input = (cmd as { input?: any }).input ?? {};
        switch (cmd.constructor.name) {
          case "DescribeRepositoriesCommand":
            return { repositories: [{ repositoryName: "prod-nginx", registryId: "123456789012" }] };
          case "DescribeImagesCommand":
            return {
              imageDetails: [
                { imageDigest: PARENT_DIGEST, imageTags: ["latest"], imagePushedAt: new Date("2026-06-01"), imageSizeInBytes: 1024 },
              ],
            };
          case "BatchGetImageCommand": {
            const requested = input.imageIds?.[0]?.imageDigest;
            const manifest = requested === CHILD_DIGEST ? MANIFEST : MANIFEST_LIST;
            return {
              images: [{
                imageManifest: JSON.stringify(manifest),
                imageManifestMediaType: manifest.mediaType,
              }],
            };
          }
          case "GetDownloadUrlForLayerCommand":
            return { downloadUrl: "https://example.com/layer" };
          case "DescribeImageScanFindingsCommand": {
            const digest = input.imageId?.imageDigest;
            const findings = opts.basicFindingsByDigest?.[digest];
            if (!findings) {
              const err = new Error("scan not found");
              err.name = "ScanNotFoundException";
              throw err;
            }
            return { imageScanFindings: { findings } };
          }
          case "ListCoverageCommand":
            return { coveredResources: opts.enhancedFindingsByDigest ? [{ resourceId: "x" }] : [] };
          case "ListFindingsCommand": {
            const digest = input.filterCriteria?.ecrImageHash?.[0]?.value;
            return { findings: opts.enhancedFindingsByDigest?.[digest] ?? [] };
          }
          default:
            return {};
        }
      });
    }

    it("records both parent and resolved digests in the baseline entry", async () => {
      mockMultiArchAws();

      const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;

      expect(result.status).toBe("success");
      expect(result.ecrImageCve.baselinePerImage).toEqual([
        expect.objectContaining({
          imageDigest: PARENT_DIGEST,
          resolvedDigest: CHILD_DIGEST,
        }),
      ]);
    });

    it("confirms (not gaps) a CVE that basic scanning reports only under the resolved child digest", async () => {
      mockMultiArchAws({
        basicFindingsByDigest: {
          [CHILD_DIGEST]: [
            {
              name: "CVE-2026-42945",
              severity: "CRITICAL",
              attributes: [{ key: "package_name", value: "nginx" }],
            },
          ],
        },
      });

      const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;

      expect(result.status).toBe("success");
      const report = result.ecrImageCve;
      expect(report.confirmedCount).toBe(1);
      expect(report.gapFindings.find((g) => g.cveId === "CVE-2026-42945")).toBeUndefined();
      expect(report.baselinePerImage[0].basicScan).toBe("available");
    });

    it("confirms a CVE that Inspector reports only under the resolved child digest, deduping across digests", async () => {
      const enhancedFinding = {
        packageVulnerabilityDetails: {
          vulnerabilityId: "CVE-2026-42945",
          vulnerablePackages: [{ name: "nginx" }],
        },
        severity: "CRITICAL",
        resources: [
          {
            type: "AWS_ECR_CONTAINER_IMAGE",
            details: { awsEcrContainerImage: { repositoryName: "prod-nginx", registry: "123456789012" } },
          },
        ],
      };
      mockMultiArchAws({
        enhancedFindingsByDigest: {
          [PARENT_DIGEST]: [enhancedFinding],
          [CHILD_DIGEST]: [enhancedFinding],
        },
      });

      const result = (await new EcrImageCveScanner({ includeConfirmed: true }).scan(ctx)) as ResultWithReport;

      expect(result.status).toBe("success");
      const report = result.ecrImageCve;
      // Reported under both digests → merged + deduped into one confirmation
      expect(report.confirmedCount).toBe(1);
      expect(report.gapFindings.find((g) => g.cveId === "CVE-2026-42945")).toBeUndefined();
      expect(report.reverseGapFindings).toEqual([]);
      expect(report.baselinePerImage[0].enhancedScan).toBe("available");
    });

    it("queries official findings with both the parent and resolved digests", async () => {
      mockMultiArchAws({ enhancedFindingsByDigest: {} });

      await new EcrImageCveScanner().scan(ctx);

      const basicDigests = mockSend.mock.calls
        .filter((c) => (c[0] as { constructor: { name: string } }).constructor.name === "DescribeImageScanFindingsCommand")
        .map((c) => (c[0] as { input: any }).input.imageId?.imageDigest);
      expect(basicDigests).toContain(PARENT_DIGEST);
      expect(basicDigests).toContain(CHILD_DIGEST);

      const enhancedDigests = mockSend.mock.calls
        .filter((c) => (c[0] as { constructor: { name: string } }).constructor.name === "ListFindingsCommand")
        .map((c) => (c[0] as { input: any }).input.filterCriteria?.ecrImageHash?.[0]?.value);
      expect(enhancedDigests).toContain(PARENT_DIGEST);
      expect(enhancedDigests).toContain(CHILD_DIGEST);
    });
  });

  it("skips the whole image when total compressed size exceeds maxImageBytes", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    mockAws({ basicError: scanNotFound });

    // MANIFEST's single layer declares size 1024; cap below that skips the image.
    const result = (await new EcrImageCveScanner({ maxImageBytes: 512 }).scan(ctx)) as ResultWithReport;

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.ecrImageCve.skippedImages).toHaveLength(1);
    expect(result.ecrImageCve.skippedImages[0].reason).toContain("total compressed size");
    expect(result.ecrImageCve.summary.imagesSkipped).toBe(1);
  });

  describe("maxTotalBytes download budget (finding N4)", () => {
    // Three single-layer images (1024 declared bytes each), newest first, so the
    // scanner processes d1, d2, d3 in that order.
    function mockThreeImages() {
      const scanNotFound = new Error("scan not found");
      scanNotFound.name = "ScanNotFoundException";
      mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
        switch (cmd.constructor.name) {
          case "DescribeRepositoriesCommand":
            return { repositories: [{ repositoryName: "prod-nginx", registryId: "123456789012" }] };
          case "DescribeImagesCommand":
            return {
              imageDetails: [
                { imageDigest: "sha256:d1", imageTags: ["v3"], imagePushedAt: new Date("2026-06-03"), imageSizeInBytes: 1024 },
                { imageDigest: "sha256:d2", imageTags: ["v2"], imagePushedAt: new Date("2026-06-02"), imageSizeInBytes: 1024 },
                { imageDigest: "sha256:d3", imageTags: ["v1"], imagePushedAt: new Date("2026-06-01"), imageSizeInBytes: 1024 },
              ],
            };
          case "BatchGetImageCommand":
            return { images: [{ imageManifest: JSON.stringify(MANIFEST), imageManifestMediaType: MANIFEST.mediaType }] };
          case "GetDownloadUrlForLayerCommand":
            return { downloadUrl: "https://example.com/layer" };
          case "DescribeImageScanFindingsCommand":
            throw scanNotFound;
          case "ListCoverageCommand":
            return { coveredResources: [] };
          case "ListFindingsCommand":
            return { findings: [] };
          default:
            return {};
        }
      });
    }

    it("skips remaining images once the budget is exhausted, with distinct reasons for the tripping image and later ones", async () => {
      mockThreeImages();

      // Budget covers exactly one 1024-byte image: d1 scans, d2 trips the
      // budget, d3 is skipped because the budget was already exhausted.
      const result = (await new EcrImageCveScanner({ maxTotalBytes: 1024 }).scan(ctx)) as ResultWithReport;

      expect(result.status).toBe("success");
      expect(result.resourcesScanned).toBe(1);
      expect(result.ecrImageCve.skippedImages).toHaveLength(2);
      expect(result.ecrImageCve.summary.imagesSkipped).toBe(2);

      const skippedByDigest = new Map(result.ecrImageCve.skippedImages.map((s) => [s.imageDigest, s]));
      expect(skippedByDigest.get("sha256:d2")).toMatchObject({ repository: "prod-nginx" });
      expect(skippedByDigest.get("sha256:d2")!.reason).toBe(
        "total download budget 1024 bytes would be exceeded (already downloaded 1024, image needs 1024); skipped to keep the scan bounded",
      );
      expect(skippedByDigest.get("sha256:d3")!.reason).toBe(
        "total download budget 1024 bytes reached before this image; skipped to keep the scan bounded",
      );
    });

    it("allows cumulative bytes exactly equal to the budget (boundary: == passes, > skips)", async () => {
      mockThreeImages();

      // 3 × 1024 = 3072 == budget: all three images must scan, none skipped.
      const atBudget = (await new EcrImageCveScanner({ maxTotalBytes: 3072 }).scan(ctx)) as ResultWithReport;
      expect(atBudget.status).toBe("success");
      expect(atBudget.resourcesScanned).toBe(3);
      expect(atBudget.ecrImageCve.skippedImages).toEqual([]);

      mockThreeImages();

      // One byte under: the third image would push past the budget and is skipped.
      const underBudget = (await new EcrImageCveScanner({ maxTotalBytes: 3071 }).scan(ctx)) as ResultWithReport;
      expect(underBudget.status).toBe("success");
      expect(underBudget.resourcesScanned).toBe(2);
      expect(underBudget.ecrImageCve.skippedImages).toHaveLength(1);
      expect(underBudget.ecrImageCve.skippedImages[0]).toMatchObject({ imageDigest: "sha256:d3" });
      expect(underBudget.ecrImageCve.skippedImages[0].reason).toContain("would be exceeded (already downloaded 2048, image needs 1024)");
    });
  });

  it("skips an image whose layer uses unsupported zstd compression with an explicit reason (finding 2)", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    const zstdManifest = {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      layers: [
        { mediaType: "application/vnd.oci.image.layer.v1.tar+zstd", digest: "sha256:zstd1", size: 1024 },
      ],
    };
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      switch (cmd.constructor.name) {
        case "DescribeRepositoriesCommand":
          return { repositories: [{ repositoryName: "prod-nginx", registryId: "123456789012" }] };
        case "DescribeImagesCommand":
          return { imageDetails: [{ imageDigest: "sha256:abc123", imageTags: ["latest"], imagePushedAt: new Date("2026-06-01"), imageSizeInBytes: 1024 }] };
        case "BatchGetImageCommand":
          return { images: [{ imageManifest: JSON.stringify(zstdManifest), imageManifestMediaType: zstdManifest.mediaType }] };
        case "DescribeImageScanFindingsCommand":
          throw scanNotFound;
        case "ListCoverageCommand":
          return { coveredResources: [] };
        default:
          return {};
      }
    });

    const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;
    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.ecrImageCve.skippedImages).toHaveLength(1);
    expect(result.ecrImageCve.skippedImages[0].reason).toContain("unsupported layer compression zstd");
  });

  it("caps the number of repositories scanned and warns about the remainder (finding 3)", async () => {
    const scanNotFound = new Error("scan not found");
    scanNotFound.name = "ScanNotFoundException";
    mockSend.mockImplementation((cmd: { constructor: { name: string }; input?: any }) => {
      switch (cmd.constructor.name) {
        case "DescribeRepositoriesCommand":
          return {
            repositories: [
              { repositoryName: "prod-a", registryId: "123456789012" },
              { repositoryName: "prod-b", registryId: "123456789012" },
              { repositoryName: "prod-c", registryId: "123456789012" },
            ],
          };
        case "DescribeImagesCommand":
          return { imageDetails: [] }; // no images, we only care about the repo cap
        case "ListCoverageCommand":
          return { coveredResources: [] };
        default:
          return {};
      }
    });

    const result = (await new EcrImageCveScanner({ maxRepositories: 1 }).scan(ctx)) as ResultWithReport;
    expect(result.status).toBe("success");
    expect(result.ecrImageCve.summary.repositoriesScanned).toBe(1);
    expect(result.warnings?.some((w) => w.includes("Repository cap reached"))).toBe(true);
  });

  it("qualifies the gap description when both official channels errored (finding 7)", async () => {
    // Basic scan and Inspector coverage both throw ⇒ baseline error/unverifiable.
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      switch (cmd.constructor.name) {
        case "DescribeRepositoriesCommand":
          return { repositories: [{ repositoryName: "prod-nginx", registryId: "123456789012" }] };
        case "DescribeImagesCommand":
          return { imageDetails: [{ imageDigest: "sha256:abc123", imageTags: ["latest"], imagePushedAt: new Date("2026-06-01"), imageSizeInBytes: 1024 }] };
        case "BatchGetImageCommand":
          return { images: [{ imageManifest: JSON.stringify(MANIFEST), imageManifestMediaType: MANIFEST.mediaType }] };
        case "GetDownloadUrlForLayerCommand":
          return { downloadUrl: "https://example.com/layer" };
        case "DescribeImageScanFindingsCommand":
          throw new Error("ThrottlingException");
        case "ListCoverageCommand":
          throw new Error("ThrottlingException");
        default:
          return {};
      }
    });

    const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;
    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("CVE-2026-42945"));
    expect(finding).toBeDefined();
    expect(finding!.description).toContain("could not be verified");
    expect(finding!.title).toContain("not confirmed against");
    expect(result.ecrImageCve.baselinePerImage[0].basicScan).toBe("error");
    expect(result.ecrImageCve.baselinePerImage[0].enhancedScan).toBe("error");
  });

  it("records skipped images when the manifest cannot be fetched", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      switch (cmd.constructor.name) {
        case "DescribeRepositoriesCommand":
          return { repositories: [{ repositoryName: "prod-nginx" }] };
        case "DescribeImagesCommand":
          return { imageDetails: [{ imageDigest: "sha256:abc123", imagePushedAt: new Date("2026-06-01") }] };
        case "BatchGetImageCommand":
          return { images: [], failures: [{ failureReason: "ImageNotFound" }] };
        default:
          return {};
      }
    });

    const result = (await new EcrImageCveScanner().scan(ctx)) as ResultWithReport;
    expect(result.status).toBe("success");
    expect(result.ecrImageCve.skippedImages).toHaveLength(1);
    expect(result.ecrImageCve.skippedImages[0].reason).toContain("ImageNotFound");
  });
});

import {
  ECRClient,
  DescribeRepositoriesCommand,
  DescribeImagesCommand,
  BatchGetImageCommand,
  GetDownloadUrlForLayerCommand,
  DescribeImageScanFindingsCommand,
  type ImageDetail,
  type Repository,
} from "@aws-sdk/client-ecr";
import {
  Inspector2Client,
  ListFindingsCommand,
  ListCoverageCommand,
} from "@aws-sdk/client-inspector2";
import type { OfficialFinding } from "./types.js";

export interface ImageRef {
  repositoryName: string;
  imageDigest: string;
  imageTags: string[];
  imagePushedAt?: Date;
  imageSizeBytes?: number;
}

export interface ManifestLayer {
  digest: string;
  mediaType?: string;
  size?: number;
}

/** Convert a repo-name glob (`prod-*`) into a RegExp. */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

/**
 * Select images to scan per repo: latest-pushed N plus any image tagged `latest`,
 * deduplicated by digest (digest is the identity key; tags drift).
 */
export function selectImages(details: ImageDetail[], repositoryName: string, maxPerRepo: number): ImageRef[] {
  const withDigest = details.filter((d) => d.imageDigest);
  const sorted = [...withDigest].sort(
    (a, b) => (b.imagePushedAt?.getTime() ?? 0) - (a.imagePushedAt?.getTime() ?? 0),
  );

  const picked = new Map<string, ImageDetail>();
  for (const d of sorted.slice(0, maxPerRepo)) picked.set(d.imageDigest!, d);
  for (const d of withDigest) {
    if (d.imageTags?.includes("latest")) picked.set(d.imageDigest!, d);
  }

  return [...picked.values()].map((d) => ({
    repositoryName,
    imageDigest: d.imageDigest!,
    imageTags: d.imageTags ?? [],
    imagePushedAt: d.imagePushedAt,
    imageSizeBytes: d.imageSizeInBytes,
  }));
}

export async function listRepositories(client: ECRClient, filter?: string): Promise<Repository[]> {
  const repos: Repository[] = [];
  let nextToken: string | undefined;
  do {
    const resp = await client.send(new DescribeRepositoriesCommand({ nextToken, maxResults: 100 }));
    repos.push(...(resp.repositories ?? []));
    nextToken = resp.nextToken;
  } while (nextToken);

  if (!filter) return repos;
  const re = globToRegExp(filter);
  return repos.filter((r) => r.repositoryName && re.test(r.repositoryName));
}

export async function listImages(client: ECRClient, repositoryName: string, maxPerRepo: number): Promise<ImageRef[]> {
  const details: ImageDetail[] = [];
  let nextToken: string | undefined;
  do {
    const resp = await client.send(
      new DescribeImagesCommand({ repositoryName, nextToken, maxResults: 100 }),
    );
    details.push(...(resp.imageDetails ?? []));
    nextToken = resp.nextToken;
  } while (nextToken);
  return selectImages(details, repositoryName, maxPerRepo);
}

const MANIFEST_MEDIA_TYPES = [
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.index.v1+json",
];

interface ManifestListEntry {
  digest: string;
  platform?: { os?: string; architecture?: string };
}

/**
 * Fetch the image manifest via BatchGetImage; resolve manifest lists (multi-arch)
 * by platform preference. Returns the layer list of the resolved single-arch manifest.
 */
export async function getManifestLayers(
  client: ECRClient,
  repositoryName: string,
  imageDigest: string,
  platformPreference: string[],
): Promise<{ layers: ManifestLayer[]; resolvedDigest: string }> {
  const fetchManifest = async (digest: string): Promise<{ mediaType?: string; body: any }> => {
    const resp = await client.send(
      new BatchGetImageCommand({
        repositoryName,
        imageIds: [{ imageDigest: digest }],
        acceptedMediaTypes: MANIFEST_MEDIA_TYPES,
      }),
    );
    const image = resp.images?.[0];
    if (!image?.imageManifest) {
      const failure = resp.failures?.[0];
      throw new Error(`BatchGetImage failed for ${repositoryName}@${digest}: ${failure?.failureReason ?? "no manifest returned"}`);
    }
    const body = JSON.parse(image.imageManifest);
    return { mediaType: image.imageManifestMediaType ?? body.mediaType, body };
  };

  let { mediaType, body } = await fetchManifest(imageDigest);
  let resolvedDigest = imageDigest;

  const isList = mediaType?.includes("manifest.list") || mediaType?.includes("image.index") || Array.isArray(body.manifests);
  if (isList) {
    const entries: ManifestListEntry[] = body.manifests ?? [];
    let chosen: ManifestListEntry | undefined;
    for (const pref of platformPreference) {
      const [os, arch] = pref.split("/");
      chosen = entries.find((e) => e.platform?.os === os && e.platform?.architecture === arch);
      if (chosen) break;
    }
    chosen = chosen ?? entries[0];
    if (!chosen) throw new Error(`Manifest list for ${repositoryName}@${imageDigest} has no platform entries`);
    resolvedDigest = chosen.digest;
    ({ body } = await fetchManifest(resolvedDigest));
  }

  const layers: ManifestLayer[] = (body.layers ?? []).map((l: any) => ({
    digest: l.digest,
    mediaType: l.mediaType,
    size: l.size,
  }));
  return { layers, resolvedDigest };
}

/** Overall timeout for a single layer blob download; a stalled S3 fetch must not hang the tool. */
const LAYER_DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

/** Get a pre-signed download URL for a layer blob and open it as a Node stream. */
export async function openLayerStream(
  client: ECRClient,
  registryId: string | undefined,
  repositoryName: string,
  layerDigest: string,
  timeoutMs: number = LAYER_DOWNLOAD_TIMEOUT_MS,
): Promise<NodeJS.ReadableStream> {
  const resp = await client.send(
    new GetDownloadUrlForLayerCommand({ registryId, repositoryName, layerDigest }),
  );
  if (!resp.downloadUrl) throw new Error(`No download URL for layer ${layerDigest}`);

  // A stalled S3 download must not hang the layer loop / image / whole tool call.
  const httpResp = await fetch(resp.downloadUrl, { signal: AbortSignal.timeout(timeoutMs) });
  if (!httpResp.ok || !httpResp.body) {
    // Release the connection if we got a response body we won't consume.
    try {
      await httpResp.body?.cancel();
    } catch {
      // best-effort
    }
    throw new Error(`Layer download failed for ${layerDigest}: HTTP ${httpResp.status}`);
  }
  const { Readable } = await import("node:stream");
  return Readable.fromWeb(httpResp.body as import("node:stream/web").ReadableStream);
}

export interface OfficialScanResult {
  findings: OfficialFinding[];
  basicScan: "available" | "no-official-scan" | "error";
  enhancedScan: "available" | "not-enabled" | "error";
}

/** Fetch ECR basic scan findings; ScanNotFoundException → no-official-scan. */
export async function getBasicScanFindings(
  client: ECRClient,
  repositoryName: string,
  imageDigest: string,
): Promise<{ findings: OfficialFinding[]; status: "available" | "no-official-scan" | "error" }> {
  const findings: OfficialFinding[] = [];
  try {
    let nextToken: string | undefined;
    do {
      const resp = await client.send(
        new DescribeImageScanFindingsCommand({
          repositoryName,
          imageId: { imageDigest },
          nextToken,
          maxResults: 1000,
        }),
      );
      for (const f of resp.imageScanFindings?.findings ?? []) {
        if (!f.name?.startsWith("CVE-")) continue;
        const pkgName = f.attributes?.find((a) => a.key === "package_name")?.value;
        findings.push({ cveId: f.name, component: pkgName, severity: f.severity, source: "basic" });
      }
      // Enhanced findings can also surface here when Inspector owns the repo scan
      for (const f of resp.imageScanFindings?.enhancedFindings ?? []) {
        const cveId = f.packageVulnerabilityDetails?.vulnerabilityId;
        if (!cveId?.startsWith("CVE-")) continue;
        const pkgName = f.packageVulnerabilityDetails?.vulnerablePackages?.[0]?.name;
        findings.push({ cveId, component: pkgName, severity: f.severity, source: "basic" });
      }
      nextToken = resp.nextToken;
    } while (nextToken);
    return { findings, status: "available" };
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    if (name === "ScanNotFoundException") return { findings: [], status: "no-official-scan" };
    return { findings: [], status: "error" };
  }
}

/**
 * Caches Inspector ECR coverage per scan. Coverage is queried once per
 * repository (rather than once per image digest, which returns the same answer)
 * and filtered by repository name so the result is per-repository precise:
 * an account with Inspector enabled but *this* repository uncovered
 * (unsupported base OS, etc.) reports not-enabled for that repo's images.
 */
export class InspectorCoverageCache {
  private byRepository = new Map<string, boolean>();

  constructor(private readonly client: Inspector2Client) {}

  /**
   * Whether Inspector is actively scanning ECR images in this repository.
   * Returns undefined on a coverage API error so the caller can distinguish
   * "not enabled" from "could not determine".
   */
  async isRepositoryCovered(repositoryName: string): Promise<boolean | undefined> {
    const cached = this.byRepository.get(repositoryName);
    if (cached !== undefined) return cached;
    try {
      const coverage = await this.client.send(
        new ListCoverageCommand({
          filterCriteria: {
            resourceType: [{ comparison: "EQUALS", value: "AWS_ECR_CONTAINER_IMAGE" }],
            ecrRepositoryName: [{ comparison: "EQUALS", value: repositoryName }],
          },
          maxResults: 1,
        }),
      );
      const covered = (coverage.coveredResources?.length ?? 0) > 0;
      this.byRepository.set(repositoryName, covered);
      return covered;
    } catch {
      return undefined;
    }
  }
}

/**
 * Fetch Inspector enhanced findings for one ECR image. Coverage is decided by
 * the caller (via InspectorCoverageCache) so it is not re-queried per digest.
 * The same digest can be pushed to multiple repositories/registries, so the
 * query is scoped by repository name and registry (account) in addition to the
 * digest, and each finding's resource details are re-checked before acceptance.
 */
export async function getEnhancedFindings(
  client: Inspector2Client,
  imageDigest: string,
  repositoryName: string,
  registryId?: string,
  coverageOverride?: boolean,
): Promise<{ findings: OfficialFinding[]; status: "available" | "not-enabled" | "error" }> {
  try {
    // Empty coverage for ECR ⇒ Inspector ECR scanning is not active (baseline = basic-only).
    // When the caller supplies a cached coverage decision, use it instead of re-querying.
    const covered =
      coverageOverride ??
      (await client
        .send(
          new ListCoverageCommand({
            filterCriteria: {
              resourceType: [{ comparison: "EQUALS", value: "AWS_ECR_CONTAINER_IMAGE" }],
              ecrRepositoryName: [{ comparison: "EQUALS", value: repositoryName }],
            },
            maxResults: 1,
          }),
        )
        .then((c) => (c.coveredResources?.length ?? 0) > 0));
    if (!covered) return { findings: [], status: "not-enabled" };

    const findings: OfficialFinding[] = [];
    let nextToken: string | undefined;
    do {
      const resp = await client.send(
        new ListFindingsCommand({
          filterCriteria: {
            ecrImageHash: [{ comparison: "EQUALS", value: imageDigest }],
            ecrImageRepositoryName: [{ comparison: "EQUALS", value: repositoryName }],
            ...(registryId ? { ecrImageRegistry: [{ comparison: "EQUALS", value: registryId }] } : {}),
          },
          nextToken,
          maxResults: 100,
        }),
      );
      for (const f of resp.findings ?? []) {
        const cveId = f.packageVulnerabilityDetails?.vulnerabilityId;
        if (!cveId?.startsWith("CVE-")) continue;
        const image = f.resources?.find((r) => r.type === "AWS_ECR_CONTAINER_IMAGE")?.details?.awsEcrContainerImage;
        if (image) {
          if (image.imageHash && image.imageHash !== imageDigest) continue;
          if (image.repositoryName && image.repositoryName !== repositoryName) continue;
          if (registryId && image.registry && image.registry !== registryId) continue;
        }
        const pkgName = f.packageVulnerabilityDetails?.vulnerablePackages?.[0]?.name;
        findings.push({ cveId, component: pkgName, severity: f.severity, source: "enhanced" });
      }
      nextToken = resp.nextToken;
    } while (nextToken);
    return { findings, status: "available" };
  } catch {
    return { findings: [], status: "error" };
  }
}

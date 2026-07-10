import { describe, it, expect, vi } from "vitest";
import { getEnhancedFindings, globToRegExp, selectImages } from "../../../src/scanners/ecr-image-cve/ecr-client.js";
import type { ImageDetail } from "@aws-sdk/client-ecr";
import type { Inspector2Client } from "@aws-sdk/client-inspector2";

describe("globToRegExp", () => {
  it("matches simple globs", () => {
    const re = globToRegExp("prod-*");
    expect(re.test("prod-nginx")).toBe(true);
    expect(re.test("prod-")).toBe(true);
    expect(re.test("staging-nginx")).toBe(false);
    expect(re.test("xprod-nginx")).toBe(false);
  });

  it("escapes regex metacharacters and supports ?", () => {
    expect(globToRegExp("app.v?").test("app.v1")).toBe(true);
    expect(globToRegExp("app.v?").test("appxv1")).toBe(false);
  });
});

describe("selectImages", () => {
  const img = (digest: string, pushedAt: string, tags?: string[]): ImageDetail => ({
    imageDigest: digest,
    imagePushedAt: new Date(pushedAt),
    imageTags: tags,
  });

  it("keeps the latest-pushed N images identified by digest", () => {
    const details = [
      img("sha256:a", "2026-01-01T00:00:00Z", ["v1"]),
      img("sha256:b", "2026-03-01T00:00:00Z", ["v3"]),
      img("sha256:c", "2026-02-01T00:00:00Z", ["v2"]),
      img("sha256:d", "2026-04-01T00:00:00Z", ["v4"]),
    ];
    const selected = selectImages(details, "repo", 2);
    const digests = selected.map((s) => s.imageDigest);
    expect(digests).toContain("sha256:d");
    expect(digests).toContain("sha256:b");
    expect(digests).toHaveLength(2);
  });

  it("always includes any image tagged 'latest' beyond the N cap", () => {
    const details = [
      img("sha256:a", "2026-01-01T00:00:00Z", ["latest"]),
      img("sha256:b", "2026-03-01T00:00:00Z", ["v3"]),
      img("sha256:c", "2026-02-01T00:00:00Z", ["v2"]),
    ];
    const selected = selectImages(details, "repo", 1);
    const digests = selected.map((s) => s.imageDigest);
    expect(digests).toContain("sha256:b");
    expect(digests).toContain("sha256:a");
    expect(digests).toHaveLength(2);
  });

  it("dedupes by digest when the latest-pushed image is also tagged 'latest'", () => {
    const details = [
      img("sha256:a", "2026-03-01T00:00:00Z", ["latest", "v3"]),
      img("sha256:b", "2026-01-01T00:00:00Z", ["v1"]),
    ];
    const selected = selectImages(details, "repo", 1);
    expect(selected).toHaveLength(1);
    expect(selected[0].imageDigest).toBe("sha256:a");
    expect(selected[0].repositoryName).toBe("repo");
  });

  it("ignores entries without a digest", () => {
    const selected = selectImages([{ imagePushedAt: new Date() }], "repo", 3);
    expect(selected).toEqual([]);
  });
});

describe("getEnhancedFindings repository scoping", () => {
  const DIGEST = "sha256:abc123";

  function inspectorMock(findings: unknown[]) {
    const send = vi.fn(async (cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "ListCoverageCommand") {
        return { coveredResources: [{ resourceId: "x" }] };
      }
      return { findings };
    });
    return { client: { send } as unknown as Inspector2Client, send };
  }

  const finding = (repositoryName: string, imageHash = DIGEST, registry = "123456789012") => ({
    packageVulnerabilityDetails: {
      vulnerabilityId: "CVE-2026-42945",
      vulnerablePackages: [{ name: "nginx" }],
    },
    severity: "CRITICAL",
    resources: [
      {
        type: "AWS_ECR_CONTAINER_IMAGE",
        id: `arn:aws:ecr:us-east-1:${registry}:repository/${repositoryName}/sha256:x`,
        details: { awsEcrContainerImage: { repositoryName, imageHash, registry } },
      },
    ],
  });

  it("passes digest + repository + registry filter criteria to ListFindings", async () => {
    const { client, send } = inspectorMock([]);
    await getEnhancedFindings(client, DIGEST, "prod-nginx", "123456789012");

    const listFindingsCall = send.mock.calls.find(
      (c) => (c[0] as { constructor: { name: string } }).constructor.name === "ListFindingsCommand",
    );
    expect(listFindingsCall).toBeDefined();
    const criteria = (listFindingsCall![0] as { input: { filterCriteria: Record<string, unknown> } }).input.filterCriteria;
    expect(criteria.ecrImageHash).toEqual([{ comparison: "EQUALS", value: DIGEST }]);
    expect(criteria.ecrImageRepositoryName).toEqual([{ comparison: "EQUALS", value: "prod-nginx" }]);
    expect(criteria.ecrImageRegistry).toEqual([{ comparison: "EQUALS", value: "123456789012" }]);
  });

  it("drops findings for the same digest that live in another repository", async () => {
    const { client } = inspectorMock([finding("other-repo")]);
    const result = await getEnhancedFindings(client, DIGEST, "prod-nginx", "123456789012");
    expect(result.status).toBe("available");
    expect(result.findings).toEqual([]);
  });

  it("drops findings for the same digest in another registry account", async () => {
    const { client } = inspectorMock([finding("prod-nginx", DIGEST, "999999999999")]);
    const result = await getEnhancedFindings(client, DIGEST, "prod-nginx", "123456789012");
    expect(result.findings).toEqual([]);
  });

  it("keeps findings that match digest, repository, and registry", async () => {
    const { client } = inspectorMock([finding("prod-nginx")]);
    const result = await getEnhancedFindings(client, DIGEST, "prod-nginx", "123456789012");
    expect(result.findings).toEqual([
      { cveId: "CVE-2026-42945", component: "nginx", severity: "CRITICAL", source: "enhanced" },
    ]);
  });
});

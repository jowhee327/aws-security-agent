import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "fs";
import { join } from "path";

import { getProvider, listProviderIds, isProviderId, DEFAULT_PROVIDER_ID } from "../../src/providers/registry.js";

/** Derive the expected module set from src/scanners/*.ts (excluding framework files and ecr-image-cve/). */
function expectedAwsModuleNames(): Set<string> {
  const dir = join(__dirname, "..", "..", "src", "scanners");
  const names = new Set<string>();
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".ts") || f === "base.ts" || f === "runner.ts") continue;
    const src = readFileSync(join(dir, f), "utf8");
    const m = /readonly moduleName = "([a-z0-9_]+)"/.exec(src);
    if (m) names.add(m[1]);
  }
  return names;
}

describe("provider registry", () => {
  it("defaults to aws", () => {
    expect(DEFAULT_PROVIDER_ID).toBe("aws");
    expect(getProvider().id).toBe("aws");
    expect(getProvider("aws").id).toBe("aws");
  });

  it("registers aws and huaweicloud", () => {
    expect(listProviderIds().sort()).toEqual(["aws", "huaweicloud"]);
    expect(isProviderId("aws")).toBe(true);
    expect(isProviderId("huaweicloud")).toBe(true);
    expect(isProviderId("gcp")).toBe(false);
    expect(() => getProvider("gcp")).toThrow(/Unknown cloud provider/);
  });

  it("aws provider exposes exactly the 19 existing detection scanners", () => {
    const expected = expectedAwsModuleNames();
    expect(expected.size).toBe(19);
    expect(expected.has("ecr_image_cve")).toBe(false);

    const scanners = getProvider("aws").scanners();
    const actual = new Set(scanners.map((s) => s.moduleName));
    expect(scanners).toHaveLength(19);
    expect(actual).toEqual(expected);
    // Fresh instances every call.
    expect(getProvider("aws").scanners()[0]).not.toBe(scanners[0]);
  });

  it("aws provider builds ARNs from <service>:<type> resource types", () => {
    const aws = getProvider("aws");
    expect(aws.toResourceUrn("ec2:instance", "i-123", { region: "us-east-1", partition: "aws" }, "111122223333"))
      .toBe("arn:aws:ec2:us-east-1:111122223333:instance/i-123");
    expect(aws.toResourceUrn("s3", "my-bucket", { region: "cn-north-1" }, "111122223333"))
      .toBe("arn:aws-cn:s3:cn-north-1:111122223333:my-bucket");
  });

  it("aws provider listRegions echoes the requested region with its partition", async () => {
    const aws = getProvider("aws");
    await expect(aws.listRegions(undefined, "cn-northwest-1")).resolves.toEqual([
      { region: "cn-northwest-1", partition: "aws-cn" },
    ]);
    await expect(aws.listRegions()).resolves.toEqual([{ region: "us-east-1", partition: "aws" }]);
  });

  it("huaweicloud provider exposes its Phase 1 scanners and reserves multi-account", async () => {
    const hw = getProvider("huaweicloud");
    const scanners = hw.scanners();
    expect(scanners.map((s) => s.moduleName)).toEqual(["config_rules_findings", "public_access_verify", "secret_exposure", "ssl_certificate", "idle_resources", "tag_compliance"]);
    expect(hw.scanners()[0]).not.toBe(scanners[0]); // fresh instances
    expect(hw.toResourceUrn("ecs:server", "srv-1", { region: "cn-north-4", domainId: "d0m41n" }, "ignored"))
      .toBe("hws:cn-north-4:d0m41n:ecs:server:srv-1");
    await expect(hw.listAccounts!({ region: "cn-north-4" })).rejects.toThrow(/not implemented in Phase 1/);
    await expect(hw.assumeCrossAccount!({ id: "x" }, { region: "cn-north-4" })).rejects.toThrow(/not implemented in Phase 1/);
    await expect(hw.getAccountId({ region: "cn-north-4", domainId: "d0m41n" })).resolves.toBe("d0m41n");
  });
});

/**
 * Phase 2 T0 — Alibaba Cloud provider registration (skeleton) + credential discrimination.
 * Fake keys only; no network.
 */
import { describe, it, expect } from "vitest";

import {
  getProvider,
  isProviderId,
  listProviderIds,
  PROVIDER_IDS,
  EXPERIMENTAL_PROVIDER_IDS,
} from "../../src/providers/registry.js";
import {
  ALICLOUD_GLOBAL_MODULES,
  ALICLOUD_MULTI_ACCOUNT_WARNING,
  DEFAULT_ALICLOUD_REGION,
} from "../../src/providers/alicloud/index.js";
import {
  isAwsCredentials,
  isAlibabaCloudCredentials,
  isHuaweiCloudCredentials,
  type AlibabaCloudCredentials,
  type AwsCredentials,
  type HuaweiCloudCredentials,
} from "../../src/types.js";

const FAKE_ALI: AlibabaCloudCredentials = {
  accessKeyId: "LTAI5tFAKEFAKEFAKE0000001",
  accessKeySecret: "FakeSecretKeyDoNotUseXXXXXXXXXXXX01",
  kind: "alicloud",
};
const FAKE_ALI_STS: AlibabaCloudCredentials = {
  accessKeyId: "STS.FAKEFAKEFAKEFAKE0000001",
  accessKeySecret: "FakeSecretKeyDoNotUseXXXXXXXXXXXX01",
  securityToken: "CAISFAKEFAKEFAKEFAKE",
  kind: "alicloud",
  source: "explicit",
};
const FAKE_AWS: AwsCredentials = {
  accessKeyId: "AKIAFAKEFAKEFAKE0001",
  secretAccessKey: "FakeAwsSecretDoNotUseXXXXXXXXXXXXXXXXX01",
  sessionToken: "FwoFAKEFAKEFAKE",
};
const FAKE_HW: HuaweiCloudCredentials = {
  ak: "FAKEHWAKFAKEHWAK0001",
  sk: "FakeHwSecretDoNotUseXXXXXXXXXXXXXXXXXX01",
};

describe("provider registry — alicloud", () => {
  it("exports PROVIDER_IDS as the full ordered tuple", () => {
    expect(PROVIDER_IDS).toEqual(["aws", "huaweicloud", "alicloud"]);
  });

  it("registers alicloud (experimental) without changing the stable listing", () => {
    expect(isProviderId("alicloud")).toBe(true);
    expect(EXPERIMENTAL_PROVIDER_IDS.has("alicloud")).toBe(true);
    expect(listProviderIds()).toEqual(["aws", "huaweicloud"]);
    expect(listProviderIds({ includeExperimental: true })).toEqual(["aws", "huaweicloud", "alicloud"]);
  });

  it("getProvider('alicloud') returns the skeleton provider with its hooks", () => {
    const p = getProvider("alicloud");
    expect(p.id).toBe("alicloud");
    expect(p.defaultRegion).toBe("cn-hangzhou");
    expect(DEFAULT_ALICLOUD_REGION).toBe("cn-hangzhou");
    expect(p.partitionFor?.("cn-shanghai")).toBe("alicloud");
    expect(p.supportsMultiAccount).toBe(false);
    expect(p.scanners().map((s) => s.moduleName)).toEqual([
      "config_rules_findings",
      "config_compliance_findings",
      "service_detection",
      "public_access_verify",
      "secret_exposure",
      "imdsv2_enforcement",
      "ssl_certificate",
      "idle_resources",
      "tag_compliance",
      "network_reachability",
      "iam_privilege_escalation",
      "guardduty_findings",
      "inspector_findings",
      "patch_compliance_findings",
    ]);
    expect(p.redactDiagnostic?.("plain text")).toBe("plain text");
    expect(p.contextFor?.({ region: "cn-hangzhou" }, "1234567890123456")).toEqual({});
    expect(p.globalModules).toBe(ALICLOUD_GLOBAL_MODULES);
    expect([...ALICLOUD_GLOBAL_MODULES].sort()).toEqual([
      "config_compliance_findings",
      "config_rules_findings",
      "guardduty_findings",
      "iam_privilege_escalation",
      "inspector_findings",
      "patch_compliance_findings",
      "service_detection",
      "ssl_certificate",
    ]);
  });

  it("uses the plan §3.1 multi-account warning text verbatim", () => {
    expect(ALICLOUD_MULTI_ACCOUNT_WARNING).toBe(
      "org_mode requested but multi-account scanning (Resource Directory ListAccounts + STS AssumeRole) is not yet supported for alicloud (Phase 2). Scanning the current account only.",
    );
  });

  it("listAccounts / assumeCrossAccount throw a clear Phase 2 error", async () => {
    const p = getProvider("alicloud");
    await expect(p.listAccounts!({ region: "cn-hangzhou" })).rejects.toThrow(/not implemented in Phase 2/);
    await expect(
      p.assumeCrossAccount!({ id: "1234567890123456" }, { region: "cn-hangzhou" }),
    ).rejects.toThrow(/not implemented in Phase 2/);
  });

  it("listRegions falls back to the requested / default region (no network)", async () => {
    const p = getProvider("alicloud");
    await expect(p.listRegions(undefined, "cn-beijing")).resolves.toEqual([{ region: "cn-beijing" }]);
    await expect(p.listRegions()).resolves.toEqual([{ region: "cn-hangzhou" }]);
  });

  it("existing providers expose hooks equal to the historical hard-coded values", () => {
    const hw = getProvider("huaweicloud");
    expect(hw.defaultRegion).toBe("cn-north-4");
    expect(hw.partitionFor?.("cn-north-4")).toBe("huaweicloud");
    expect(hw.supportsMultiAccount).toBe(false);
    expect([...(hw.globalModules ?? [])].sort()).toEqual(["config_rules_findings", "rms_compliance_findings"]);
    expect(hw.contextFor?.({ region: "cn-north-4", projectId: "p1" }, "d0m41n")).toEqual({
      projectId: "p1",
      domainId: "d0m41n",
    });

    const aws = getProvider("aws");
    expect(aws.supportsMultiAccount).toBe(true);
    expect(aws.redactDiagnostic?.("arn:aws:iam::123456789012:role/x")).toBe("arn:aws:iam::123456789012:role/x");
  });
});

describe("credential discrimination", () => {
  it("isAwsCredentials never classifies Alibaba Cloud credentials as AWS", () => {
    expect(isAwsCredentials(FAKE_ALI)).toBe(false);
    expect(isAwsCredentials(FAKE_ALI_STS)).toBe(false);
    // Even a malformed object carrying both secret field names stays non-AWS when kind is set.
    expect(isAwsCredentials({ ...FAKE_ALI, secretAccessKey: "x" } as unknown as AwsCredentials)).toBe(false);
  });

  it("isAwsCredentials still accepts AWS credentials", () => {
    expect(isAwsCredentials(FAKE_AWS)).toBe(true);
    expect(isAwsCredentials({ ...FAKE_AWS, sessionToken: "" })).toBe(true);
    expect(isAwsCredentials(undefined)).toBe(false);
    expect(isAwsCredentials(FAKE_HW)).toBe(false);
  });

  it("isAlibabaCloudCredentials matches only kind=alicloud", () => {
    expect(isAlibabaCloudCredentials(FAKE_ALI)).toBe(true);
    expect(isAlibabaCloudCredentials(FAKE_ALI_STS)).toBe(true);
    expect(isAlibabaCloudCredentials(FAKE_AWS)).toBe(false);
    expect(isAlibabaCloudCredentials(FAKE_HW)).toBe(false);
    expect(isAlibabaCloudCredentials(undefined)).toBe(false);
    expect(isHuaweiCloudCredentials(FAKE_ALI)).toBe(false);
  });
});

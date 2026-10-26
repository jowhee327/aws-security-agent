/**
 * Phase 2 T1 — alibabaCloudProvider wiring: redactDiagnostic, getAccountId (STS
 * GetCallerIdentity), listRegions (ECS DescribeRegions), toResourceUrn. aliCall /
 * listAliRegions are mocked; the credential chain is pointed at a non-existent temp
 * file with the Alibaba env vars cleared. Fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { tmpdir } from "os";
import { join } from "path";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn(), listAliRegions: vi.fn() }));
vi.mock("../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall, listAliRegions: mocks.listAliRegions };
});

import { alibabaCloudProvider, DEFAULT_ALICLOUD_REGION } from "../../../src/providers/alicloud/index.js";
import { clearAliAccountIdCache } from "../../../src/providers/alicloud/credentials.js";
import { AliCloudError } from "../../../src/providers/alicloud/errors.js";
import type { AlibabaCloudCredentials } from "../../../src/types.js";

const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
const FAKE_SK = "FakeSecretKeyDoNotUseXXXXXXXXXXXX01";
const FAKE: AlibabaCloudCredentials = { kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK };

const ENV_KEYS = [
  "ALIBABA_CLOUD_ACCESS_KEY_ID",
  "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
  "ALIBABA_CLOUD_SECURITY_TOKEN",
  "ALICLOUD_ACCESS_KEY",
  "ALICLOUD_SECRET_KEY",
  "ALICLOUD_SECURITY_TOKEN",
  "ALIBABA_CLOUD_CREDENTIALS_FILE",
  "ALIBABA_CLOUD_PROFILE",
];
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.ALIBABA_CLOUD_CREDENTIALS_FILE = join(tmpdir(), `ali-provider-test-missing-${process.pid}`);
  mocks.aliCall.mockReset();
  mocks.listAliRegions.mockReset();
  clearAliAccountIdCache();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

const scope = { region: "cn-hangzhou" };
const authError = () =>
  new AliCloudError({ kind: "auth_failed", status: 404, code: "InvalidAccessKeyId.NotFound", message: "Specified access key is not found." }, "ecs:DescribeRegions");

describe("redactDiagnostic", () => {
  it("is the Alibaba redactor", () => {
    expect(alibabaCloudProvider.redactDiagnostic?.("plain text")).toBe("plain text");
    expect(alibabaCloudProvider.redactDiagnostic?.(`key ${FAKE_AK}`)).toBe("key [REDACTED]");
  });
});

describe("getAccountId", () => {
  it("resolves the UID via STS GetCallerIdentity (cached)", async () => {
    mocks.aliCall.mockResolvedValue({ AccountId: "1234567890123456" });
    expect(await alibabaCloudProvider.getAccountId(scope, FAKE)).toBe("1234567890123456");
    expect(await alibabaCloudProvider.getAccountId(scope, FAKE)).toBe("1234567890123456");
    expect(mocks.aliCall).toHaveBeenCalledTimes(1);
    expect(mocks.aliCall.mock.calls[0][0]).toMatchObject({ service: "sts", action: "GetCallerIdentity" });
  });

  it('is best-effort: "unknown" on failure or without credentials (no call)', async () => {
    mocks.aliCall.mockRejectedValue(authError());
    expect(await alibabaCloudProvider.getAccountId(scope, FAKE)).toBe("unknown");
    mocks.aliCall.mockReset();
    expect(await alibabaCloudProvider.getAccountId(scope)).toBe("unknown");
    expect(mocks.aliCall).not.toHaveBeenCalled();
  });

  it("ignores non-Alibaba credentials and falls back to the chain (env)", async () => {
    process.env.ALIBABA_CLOUD_ACCESS_KEY_ID = FAKE_AK;
    process.env.ALIBABA_CLOUD_ACCESS_KEY_SECRET = FAKE_SK;
    mocks.aliCall.mockResolvedValue({ AccountId: "1234567890123456" });
    expect(await alibabaCloudProvider.getAccountId(scope, { accessKeyId: "AKIAFAKE", secretAccessKey: "x" })).toBe("1234567890123456");
    expect(mocks.aliCall.mock.calls[0][1].credentials.accessKeyId).toBe(FAKE_AK);
  });
});

describe("listRegions", () => {
  it("without credentials returns only the requested / default region (no network)", async () => {
    expect(await alibabaCloudProvider.listRegions(undefined, "cn-beijing")).toEqual([{ region: "cn-beijing" }]);
    expect(await alibabaCloudProvider.listRegions()).toEqual([{ region: DEFAULT_ALICLOUD_REGION }]);
    expect(mocks.listAliRegions).not.toHaveBeenCalled();
  });

  it("with credentials lists ECS regions, requested region first", async () => {
    mocks.listAliRegions.mockResolvedValue(["ap-southeast-1", "cn-beijing", "cn-hangzhou", "cn-shanghai"]);
    expect(await alibabaCloudProvider.listRegions(FAKE, "cn-shanghai")).toEqual([
      { region: "cn-shanghai" },
      { region: "ap-southeast-1" },
      { region: "cn-beijing" },
      { region: "cn-hangzhou" },
    ]);
    expect(mocks.listAliRegions.mock.calls[0][0].accessKeyId).toBe(FAKE_AK);
  });

  it("falls back to the requested region on non-auth failures or an empty list", async () => {
    mocks.listAliRegions.mockRejectedValue(
      new AliCloudError({ kind: "access_denied", status: 403, code: "Forbidden.RAM", message: "denied" }, "ecs:DescribeRegions"),
    );
    expect(await alibabaCloudProvider.listRegions(FAKE, "cn-beijing")).toEqual([{ region: "cn-beijing" }]);
    mocks.listAliRegions.mockResolvedValue([]);
    expect(await alibabaCloudProvider.listRegions(FAKE)).toEqual([{ region: DEFAULT_ALICLOUD_REGION }]);
  });

  it("propagates authentication failures", async () => {
    mocks.listAliRegions.mockRejectedValue(authError());
    await expect(alibabaCloudProvider.listRegions(FAKE, "cn-beijing")).rejects.toThrow(/^Alibaba Cloud authentication failed/);
  });
});

describe("toResourceUrn", () => {
  it("uses an empty region for global services", () => {
    expect(alibabaCloudProvider.toResourceUrn("ram:user", "alice", scope, "1234567890123456")).toBe("acs:ram::1234567890123456:user/alice");
    expect(alibabaCloudProvider.toResourceUrn("config:rule", "cr-1", scope, "1234567890123456")).toBe("acs:config::1234567890123456:rule/cr-1");
  });

  it("keeps the scope region for regional services", () => {
    expect(alibabaCloudProvider.toResourceUrn("ecs:instance", "i-bp1abc", scope, "1234567890123456")).toBe(
      "acs:ecs:cn-hangzhou:1234567890123456:instance/i-bp1abc",
    );
    expect(alibabaCloudProvider.toResourceUrn("ecs", "x", scope, "1")).toBe("acs:ecs:cn-hangzhou:1:resource/x");
  });
});

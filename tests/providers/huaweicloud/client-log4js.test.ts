/**
 * Verifies the log4js kill-switch calls (module mocked). The real-instance
 * behaviour (no Authorization header on stdout) is covered in client.test.ts.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { configureMock } = vi.hoisted(() => ({ configureMock: vi.fn() }));
vi.mock("log4js", () => ({
  default: { configure: configureMock, getLogger: vi.fn(() => ({ error: vi.fn(), debug: vi.fn() })) },
}));

import { hwClient, silenceSdkLogging, SILENT_LOG4JS_CONFIG } from "../../../src/providers/huaweicloud/client.js";
import { createHuaweiCredentials } from "../../../src/providers/huaweicloud/credentials.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";

function silentCalls() {
  return configureMock.mock.calls.filter(([cfg]) => cfg?.categories?.default?.level === "off");
}

describe("client.ts silences log4js", () => {
  beforeEach(() => configureMock.mockClear());

  it("configured log4js with every category off at module load", () => {
    // Module evaluation happened before beforeEach could clear — re-import state is captured via the config constant.
    expect(SILENT_LOG4JS_CONFIG.categories.default.level).toBe("off");
    expect(SILENT_LOG4JS_CONFIG.categories.default.appenders).toEqual(["hwSdkSilent"]);
    expect(SILENT_LOG4JS_CONFIG.appenders.hwSdkSilent.type).toBe("stdout");
    silenceSdkLogging();
    expect(silentCalls()).toHaveLength(1);
    expect(configureMock.mock.calls[0][0]).toEqual(SILENT_LOG4JS_CONFIG);
  });

  it("re-applies level off inside the client factory before each client construction", async () => {
    const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    const build = vi.fn(() => ({ name: "fake" }));
    const builder = {
      withCredential: vi.fn(function (this: unknown) { return builder; }),
      withEndpoint: vi.fn(function (this: unknown) { return builder; }),
      build,
    };
    const FakeClient = { newBuilder: vi.fn(() => builder) };

    const client = await hwClient(FakeClient, "ecs", creds, { region: "cn-north-4", projectId: "p1" });
    expect(client).toEqual({ name: "fake" });
    expect(builder.withEndpoint).toHaveBeenCalledWith("https://ecs.cn-north-4.myhuaweicloud.com");
    expect(silentCalls().length).toBeGreaterThanOrEqual(1);
    // silence happened before build()
    const silenceOrder = configureMock.mock.invocationCallOrder.at(-1)!;
    expect(silenceOrder).toBeLessThan(build.mock.invocationCallOrder[0]);

    configureMock.mockClear();
    await hwClient(FakeClient, "rms", creds, { domainId: "d1" });
    expect(builder.withEndpoint).toHaveBeenLastCalledWith("https://rms.myhuaweicloud.com");
    expect(silentCalls()).toHaveLength(1);
  });

  it("does not throw if log4js.configure fails", () => {
    configureMock.mockImplementationOnce(() => { throw new Error("boom"); });
    expect(() => silenceSdkLogging()).not.toThrow();
  });
});

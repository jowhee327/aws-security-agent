/**
 * Phase 2 (Azure) T1 — credential chain (plan §3.2). Fake service principal and
 * in-memory env objects only; never reads real AZURE_* variables or ~/.azure.
 */
import { inspect } from "node:util";
import { describe, it, expect, vi, afterEach } from "vitest";

import {
  AZURE_ENV_CLIENT_ID,
  AZURE_ENV_CLIENT_SECRET,
  AZURE_ENV_TENANT_ID,
  AzureCredentialsError,
  AzureCredentialsNotFoundError,
  DEFAULT_AZURE_CLOUD,
  REDACTED,
  azureCredentialFromContext,
  createAzureCredentials,
  loadAzureCredentials,
  pinnedAzureSubscriptionId,
  redactAzureCredentials,
  resolveAzureCloud,
} from "../../../src/providers/azure/credentials.js";
import { redactAzureDiagnostic } from "../../../src/providers/azure/errors.js";
import type { AzureCredentials } from "../../../src/types.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const FAKE_SUB = "22222222-2222-2222-2222-22222222fake";

const SP_ENV: NodeJS.ProcessEnv = {
  AZURE_TENANT_ID: FAKE_TENANT,
  AZURE_CLIENT_ID: FAKE_CLIENT,
  AZURE_CLIENT_SECRET: FAKE_SECRET,
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("loadAzureCredentials — env chain", () => {
  it("reads the service principal from env; cloud defaults to china", () => {
    const creds = loadAzureCredentials({ env: { ...SP_ENV } });
    expect(creds).toEqual({
      kind: "azure",
      tenantId: FAKE_TENANT,
      clientId: FAKE_CLIENT,
      clientSecret: FAKE_SECRET,
      cloud: "china",
      source: "env",
    });
    expect(DEFAULT_AZURE_CLOUD).toBe("china");
  });

  it("AZURE_CLOUD=global (and aliases) selects Global; anything else is china", () => {
    expect(loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "global" } }).cloud).toBe("global");
    expect(loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "AzurePublicCloud" } }).cloud).toBe("global");
    expect(loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "china" } }).cloud).toBe("china");
    expect(loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "AzureChinaCloud" } }).cloud).toBe("china");
    expect(loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "" } }).cloud).toBe("china");
  });

  it("trims values", () => {
    const creds = loadAzureCredentials({
      env: { AZURE_TENANT_ID: ` ${FAKE_TENANT} `, AZURE_CLIENT_ID: `${FAKE_CLIENT}\n`, AZURE_CLIENT_SECRET: ` ${FAKE_SECRET}` },
    });
    expect(creds.tenantId).toBe(FAKE_TENANT);
    expect(creds.clientId).toBe(FAKE_CLIENT);
    expect(creds.clientSecret).toBe(FAKE_SECRET);
  });

  it("missing variables → AzureCredentialsNotFoundError listing only variable NAMES", () => {
    let caught: unknown;
    try {
      loadAzureCredentials({ env: { AZURE_TENANT_ID: FAKE_TENANT, AZURE_CLIENT_ID: FAKE_CLIENT, AZURE_CLIENT_SECRET: "  " } });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AzureCredentialsNotFoundError);
    const e = caught as AzureCredentialsNotFoundError;
    expect(e.missing).toEqual([AZURE_ENV_CLIENT_SECRET]);
    expect(e.message).toContain(AZURE_ENV_TENANT_ID);
    expect(e.message).toContain(AZURE_ENV_CLIENT_ID);
    expect(e.message).toContain(AZURE_ENV_CLIENT_SECRET);
    expect(e.message).toContain("AZURE_CLOUD");
    // Never the values that WERE present.
    expect(e.message).not.toContain(FAKE_TENANT);
    expect(e.message).not.toContain(FAKE_CLIENT);
  });

  it("an empty env lists all three variables as missing and never mentions a secret value", () => {
    const err = (() => {
      try {
        loadAzureCredentials({ env: {} });
      } catch (e) {
        return e as AzureCredentialsNotFoundError;
      }
      throw new Error("expected failure");
    })();
    expect(err.missing).toEqual([AZURE_ENV_TENANT_ID, AZURE_ENV_CLIENT_ID, AZURE_ENV_CLIENT_SECRET]);
    expect(err.sources).toEqual(["explicit credentials", "env AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET"]);
    expect(err.message).not.toContain(FAKE_SECRET);
  });

  it("does not use process.env when an env object is given", () => {
    vi.stubEnv("AZURE_TENANT_ID", FAKE_TENANT);
    vi.stubEnv("AZURE_CLIENT_ID", FAKE_CLIENT);
    vi.stubEnv("AZURE_CLIENT_SECRET", FAKE_SECRET);
    expect(() => loadAzureCredentials({ env: {} })).toThrow(AzureCredentialsNotFoundError);
    // …and defaults to process.env otherwise.
    expect(loadAzureCredentials().tenantId).toBe(FAKE_TENANT);
  });
});

describe("loadAzureCredentials — explicit", () => {
  it("explicit wins over env; a complete AzureCredentials object is returned as-is", () => {
    const explicit: AzureCredentials = {
      kind: "azure",
      tenantId: "33333333-3333-3333-3333-33333333fake",
      clientId: FAKE_CLIENT,
      clientSecret: FAKE_SECRET,
      cloud: "global",
    };
    expect(loadAzureCredentials({ explicit, env: { ...SP_ENV } })).toBe(explicit);
  });

  it("partial explicit input is normalised (cloud from env, default china)", () => {
    const creds = loadAzureCredentials({
      explicit: { tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: ` ${FAKE_SECRET} ` },
      env: {},
    });
    expect(creds).toEqual({
      kind: "azure",
      tenantId: FAKE_TENANT,
      clientId: FAKE_CLIENT,
      clientSecret: FAKE_SECRET,
      cloud: "china",
      source: "explicit",
    });
    expect(
      loadAzureCredentials({
        explicit: { tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET },
        env: { AZURE_CLOUD: "global" },
      }).cloud,
    ).toBe("global");
  });

  it("incomplete explicit input falls through to env", () => {
    const creds = loadAzureCredentials({ explicit: { tenantId: FAKE_TENANT }, env: { ...SP_ENV } });
    expect(creds.source).toBe("env");
  });

  it("azureCredentialFromContext: Azure context credentials, else env", () => {
    vi.stubEnv("AZURE_TENANT_ID", FAKE_TENANT);
    vi.stubEnv("AZURE_CLIENT_ID", FAKE_CLIENT);
    vi.stubEnv("AZURE_CLIENT_SECRET", FAKE_SECRET);
    vi.stubEnv("AZURE_CLOUD", "");
    const explicit = createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET, cloud: "global" });
    expect(azureCredentialFromContext({ credentials: explicit })).toBe(explicit);
    expect(azureCredentialFromContext({}).source).toBe("env");
    // Non-Azure credentials are ignored.
    expect(
      azureCredentialFromContext({ credentials: { accessKeyId: "AKIAFAKEFAKEFAKE0001", secretAccessKey: "FakeAwsSecretDoNotUse" } })
        .cloud,
    ).toBe("china");
  });
});

describe("credential objects never reveal the secret", () => {
  it("redactAzureCredentials masks the secret and keeps the IDs", () => {
    const creds = createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET, source: "env" });
    expect(redactAzureCredentials(creds)).toEqual({
      kind: "azure",
      tenantId: FAKE_TENANT,
      clientId: FAKE_CLIENT,
      clientSecret: REDACTED,
      cloud: "china",
      source: "env",
    });
  });

  it("JSON.stringify / util.inspect / String show only the redacted view", () => {
    const creds = createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET });
    for (const s of [JSON.stringify(creds), JSON.stringify({ nested: creds }), inspect(creds), String(creds), `${creds}`]) {
      expect(s).not.toContain(FAKE_SECRET);
    }
    expect(JSON.stringify(creds)).toContain(FAKE_TENANT);
    expect(Object.isFrozen(creds)).toBe(true);
  });

  it("registers the secret with the diagnostic redactor", () => {
    createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET });
    expect(redactAzureDiagnostic(`oops ${FAKE_SECRET} leaked`)).toBe("oops [REDACTED] leaked");
    // IDs are identifiers, never registered.
    expect(redactAzureDiagnostic(`tenant ${FAKE_TENANT} client ${FAKE_CLIENT}`)).toBe(`tenant ${FAKE_TENANT} client ${FAKE_CLIENT}`);
  });

  it("createAzureCredentials rejects missing fields naming only the fields", () => {
    expect(() => createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT })).toThrow(AzureCredentialsError);
    expect(() => createAzureCredentials({ tenantId: FAKE_TENANT, clientSecret: FAKE_SECRET })).toThrow(/missing clientId/);
    try {
      createAzureCredentials({ clientSecret: FAKE_SECRET });
    } catch (err) {
      expect((err as Error).message).not.toContain(FAKE_SECRET);
    }
  });

  it("nothing is written to stdout / console while loading credentials", () => {
    const writes: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
    const consoleSpies = (["log", "info", "debug", "warn", "error"] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => {}),
    );

    loadAzureCredentials({ env: { ...SP_ENV, AZURE_CLOUD: "global" } });
    try {
      loadAzureCredentials({ env: { AZURE_CLIENT_SECRET: FAKE_SECRET } });
    } catch {
      // expected: tenant / client missing
    }
    inspect(createAzureCredentials({ tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET }));

    expect(writes.join("")).not.toContain(FAKE_SECRET);
    for (const spy of consoleSpies) expect(spy).not.toHaveBeenCalled();
  });
});

describe("resolveAzureCloud / pinnedAzureSubscriptionId", () => {
  it("accepts a value or an env object; default china", () => {
    expect(resolveAzureCloud("global")).toBe("global");
    expect(resolveAzureCloud({ AZURE_CLOUD: "Global" })).toBe("global");
    expect(resolveAzureCloud({})).toBe("china");
    expect(resolveAzureCloud("usgov")).toBe("china");
  });

  it("reads AZURE_SUBSCRIPTION_ID (trimmed) from the given env", () => {
    expect(pinnedAzureSubscriptionId({ AZURE_SUBSCRIPTION_ID: ` ${FAKE_SUB} ` })).toBe(FAKE_SUB);
    expect(pinnedAzureSubscriptionId({ AZURE_SUBSCRIPTION_ID: "" })).toBeUndefined();
    expect(pinnedAzureSubscriptionId({})).toBeUndefined();
  });
});

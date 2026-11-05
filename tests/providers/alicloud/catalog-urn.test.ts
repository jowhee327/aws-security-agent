/**
 * Phase 2 T1 — Alibaba Cloud API catalog (plan §3.5) + URNs (plan §3.4) + the
 * "no inline API literals in scanners" guard. Pure / filesystem-only; no network.
 */
import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, resolve } from "path";

import { ALI_API, ALI_API_CATALOG, ALI_API_VERSIONS, type AliService } from "../../../src/providers/alicloud/api-catalog.js";
import { aliEndpoint } from "../../../src/providers/alicloud/client.js";
import { ALI_GLOBAL_URN_SERVICES, parseAliUrn, toAliUrn } from "../../../src/providers/alicloud/urn.js";

describe("ALI_API catalog", () => {
  it("every spec is well-formed and versioned per service", () => {
    expect(ALI_API_CATALOG.length).toBeGreaterThan(40);
    for (const spec of ALI_API_CATALOG) {
      expect(spec.action).toMatch(/^[A-Z][A-Za-z0-9]+$/);
      expect(spec.version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(spec.version).toBe(ALI_API_VERSIONS[spec.service]);
      expect(["GET", "POST"]).toContain(spec.method);
      expect(["RPC", "ROA"]).toContain(spec.style);
      if (spec.style === "ROA") expect(spec.pathname).toMatch(/^\//);
      else expect(spec.pathname).toBeUndefined();
      expect(Object.isFrozen(spec)).toBe(true);
    }
  });

  it("has no duplicate service:action entries", () => {
    const keys = ALI_API_CATALOG.map((s) => `${s.service}:${s.action}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("groups specs under their own service key", () => {
    for (const [svc, apis] of Object.entries(ALI_API)) {
      for (const [action, spec] of Object.entries(apis)) {
        expect(spec.service).toBe(svc);
        expect(spec.action).toBe(action);
      }
    }
  });

  it("Config GetCompliancePackReport is GET (POST → UnsupportedHTTPMethod)", () => {
    expect(ALI_API.config.GetCompliancePackReport).toMatchObject({ method: "GET", style: "RPC", version: "2020-09-07" });
  });

  it("FC3 ListFunctions is ROA GET /2023-03-30/functions", () => {
    expect(ALI_API.fc.ListFunctions).toEqual({
      service: "fc",
      action: "ListFunctions",
      version: "2023-03-30",
      method: "GET",
      style: "ROA",
      pathname: "/2023-03-30/functions",
    });
  });

  it("pins key versions from the API specs", () => {
    expect(ALI_API.ecs.DescribeInstances.version).toBe("2014-05-26");
    expect(ALI_API.sts.GetCallerIdentity.version).toBe("2015-04-01");
    expect(ALI_API.ram.ListUsers.version).toBe("2015-05-01");
    expect(ALI_API.ims.GetPasswordPolicy.version).toBe("2019-08-15");
    expect(ALI_API.sas.DescribeVersionConfig.version).toBe("2018-12-03");
    expect(ALI_API.kms.ListKeys.version).toBe("2016-01-20");
    expect(ALI_API.actiontrail.DescribeTrails.version).toBe("2020-07-06");
  });

  it("flags Phase-3 entries (listed for the API-existence probe only)", () => {
    expect(ALI_API.sts.AssumeRole.phase3).toBe(true);
    expect(ALI_API.resourcemanager.ListAccounts.phase3).toBe(true);
    expect(ALI_API.sts.GetCallerIdentity.phase3).toBeUndefined();
  });

  it("every service has an endpoint rule", () => {
    for (const svc of Object.keys(ALI_API_VERSIONS) as AliService[]) {
      expect(() => aliEndpoint(svc, "cn-hangzhou", "cn")).not.toThrow();
      expect(() => aliEndpoint(svc, "ap-southeast-1", "intl")).not.toThrow();
    }
  });
});

describe("toAliUrn / parseAliUrn", () => {
  it("builds regional and global URNs", () => {
    expect(toAliUrn("ecs", "instance", "i-bp1abc", "cn-hangzhou", "1234567890123456")).toBe(
      "acs:ecs:cn-hangzhou:1234567890123456:instance/i-bp1abc",
    );
    expect(toAliUrn("ram", "user", "alice", "", "1234567890123456")).toBe("acs:ram::1234567890123456:user/alice");
    expect(toAliUrn("ram", "user", "alice", undefined, "1234567890123456")).toBe("acs:ram::1234567890123456:user/alice");
  });

  it("round-trips, keeping '/' and ':' inside the id", () => {
    const urn = toAliUrn("oss", "bucket", "my-bucket/path:x", "cn-beijing", "1234567890123456");
    expect(parseAliUrn(urn)).toEqual({ svc: "oss", region: "cn-beijing", uid: "1234567890123456", type: "bucket", id: "my-bucket/path:x" });
    expect(parseAliUrn("acs:ram::1234567890123456:user/alice")).toEqual({ svc: "ram", region: "", uid: "1234567890123456", type: "user", id: "alice" });
  });

  it("handles the official slash-less form and rejects foreign formats", () => {
    expect(parseAliUrn("acs:oss:*:1234567890123456:my-bucket")).toEqual({ svc: "oss", region: "*", uid: "1234567890123456", type: "", id: "my-bucket" });
    expect(parseAliUrn("arn:aws:iam::123456789012:role/Admin")).toBeUndefined();
    expect(parseAliUrn("acs:ecs:cn-hangzhou")).toBeUndefined();
    expect(parseAliUrn("acs::cn-hangzhou:1:instance/i")).toBeUndefined();
    expect(parseAliUrn("acs:ecs:cn-hangzhou:1:")).toBeUndefined();
  });

  it("global URN services", () => {
    for (const svc of ["ram", "ims", "sts", "cas", "config", "sas"]) expect(ALI_GLOBAL_URN_SERVICES.has(svc)).toBe(true);
    for (const svc of ["ecs", "vpc", "slb", "rds", "kms", "oss", "fc"]) expect(ALI_GLOBAL_URN_SERVICES.has(svc)).toBe(false);
  });
});

describe("scanners never inline API literals", () => {
  function listTs(dir: string): string[] {
    if (!existsSync(dir)) return [];
    const out: string[] = [];
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) out.push(...listTs(p));
      else if (/\.[cm]?ts$/.test(name)) out.push(p);
    }
    return out;
  }

  it("src/providers/alicloud/scanners/** references ALI_API instead of `action:` literals", () => {
    const dir = resolve(__dirname, "../../../src/providers/alicloud/scanners");
    const offenders: string[] = [];
    for (const file of listTs(dir)) {
      const lines = readFileSync(file, "utf8").split(/\r?\n/);
      lines.forEach((line, i) => {
        if (/\baction\s*:\s*["'`]/.test(line) || /\bnew\s+\$?OpenApi(?:Util)?\.Params\b/.test(line)) offenders.push(`${file}:${i + 1}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});

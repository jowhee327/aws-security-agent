import { describe, it, expect } from "vitest";
import { SCAN_GROUPS } from "../../src/tools/scan-groups.js";

describe("SCAN_GROUPS", () => {
  it("defines valid scan groups with required fields", () => {
    const groupIds = Object.keys(SCAN_GROUPS);
    expect(groupIds.length).toBeGreaterThanOrEqual(11);

    for (const [id, group] of Object.entries(SCAN_GROUPS)) {
      expect(group.name, `${id} should have a name`).toBeTruthy();
      expect(group.description, `${id} should have a description`).toBeTruthy();
      expect(group.modules.length, `${id} should have at least one module`).toBeGreaterThanOrEqual(1);
    }
  });

  it("rejects unknown group IDs gracefully (lookup returns undefined)", () => {
    const unknown = SCAN_GROUPS["nonexistent_group"];
    expect(unknown).toBeUndefined();
  });

  it("mlps3_precheck includes all required MLPS scanner modules", () => {
    const mlps = SCAN_GROUPS["mlps3_precheck"];
    expect(mlps).toBeDefined();
    expect(mlps.reportType).toBe("mlps3");

    const requiredModules = [
      "service_detection", "security_hub_findings", "guardduty_findings",
      "inspector_findings", "trusted_advisor_findings",
      "iam_privilege_escalation", "network_reachability",
      "ssl_certificate", "disaster_recovery",
    ];
    for (const mod of requiredModules) {
      expect(mlps.modules, `mlps3_precheck should include ${mod}`).toContain(mod);
    }
  });

  it("removed groups no longer exist", () => {
    expect(SCAN_GROUPS["pre_launch"]).toBeUndefined();
    expect(SCAN_GROUPS["public_access_verify"]).toBeUndefined();
  });
});

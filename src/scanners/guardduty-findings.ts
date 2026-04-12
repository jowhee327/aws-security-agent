import {
  GuardDutyClient,
  ListDetectorsCommand,
} from "@aws-sdk/client-guardduty";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks if GuardDuty is enabled.
 * Findings are aggregated via Security Hub.
 */
export class GuardDutyFindingsScanner implements Scanner {
  readonly moduleName = "guardduty_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(GuardDutyClient, region, ctx.credentials);
      const detectorsResp = await client.send(new ListDetectorsCommand({}));
      const detectorIds = detectorsResp.DetectorIds ?? [];

      if (detectorIds.length > 0) {
        warnings.push("GuardDuty is enabled. Findings are aggregated via Security Hub.");
      } else {
        warnings.push("GuardDuty is not enabled in this region (no detectors found).");
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `GuardDuty detection check failed: ${msg}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

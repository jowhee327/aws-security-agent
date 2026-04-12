import {
  GuardDutyClient,
  ListDetectorsCommand,
} from "@aws-sdk/client-guardduty";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks whether GuardDuty is enabled.
 * Actual findings are aggregated via Security Hub.
 */
export class GuardDutyFindingsScanner implements Scanner {
  readonly moduleName = "guardduty_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(GuardDutyClient, region, ctx.credentials);
      const resp = await client.send(new ListDetectorsCommand({}));
      const detectorIds = resp.DetectorIds ?? [];

      if (detectorIds.length === 0) {
        warnings.push("GuardDuty is not enabled in this region (no detectors found).");
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
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

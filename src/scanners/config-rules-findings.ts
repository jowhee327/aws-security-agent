import {
  ConfigServiceClient,
  DescribeComplianceByConfigRuleCommand,
} from "@aws-sdk/client-config-service";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks if AWS Config Rules are configured.
 * Findings are aggregated via Security Hub.
 */
export class ConfigRulesFindingsScanner implements Scanner {
  readonly moduleName = "config_rules_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(ConfigServiceClient, region, ctx.credentials);

      // Count Config Rules to verify Config is active
      let ruleCount = 0;
      let nextToken: string | undefined;

      do {
        const resp = await client.send(
          new DescribeComplianceByConfigRuleCommand({ NextToken: nextToken }),
        );
        ruleCount += (resp.ComplianceByConfigRules ?? []).length;
        nextToken = resp.NextToken;
      } while (nextToken);

      if (ruleCount > 0) {
        warnings.push(`AWS Config is enabled with ${ruleCount} rule(s). Findings are aggregated via Security Hub.`);
      } else {
        warnings.push("AWS Config is not enabled in this region or no Config Rules are defined.");
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings,
        resourcesScanned: ruleCount,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);

      if (
        msg.includes("NoSuchConfigurationRecorder") ||
        msg.includes("InsufficientDeliveryPolicy") ||
        msg.includes("No Configuration Recorder")
      ) {
        warnings.push("AWS Config is not enabled in this region.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: [],
        };
      }

      return {
        module: this.moduleName,
        status: "error",
        error: `Config Rules detection check failed: ${msg}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

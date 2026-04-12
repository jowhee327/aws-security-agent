import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
} from "@aws-sdk/client-inspector2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks if Inspector is enabled.
 * Findings are aggregated via Security Hub.
 */
export class InspectorFindingsScanner implements Scanner {
  readonly moduleName = "inspector_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(Inspector2Client, region, ctx.credentials);
      const resp = await client.send(new BatchGetAccountStatusCommand({ accountIds: [ctx.accountId] }));
      const acct = resp.accounts?.[0];

      const ec2Status = acct?.resourceState?.ec2?.status;
      const lambdaStatus = acct?.resourceState?.lambda?.status;
      const anyEnabled = ec2Status === "ENABLED" || lambdaStatus === "ENABLED";

      if (anyEnabled) {
        warnings.push("Inspector is enabled. Findings are aggregated via Security Hub.");
      } else {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
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
      const errName = err instanceof Error ? err.name : "";

      const isAccessDenied = errName === "AccessDeniedException" || msg.includes("AccessDeniedException");
      const isNotEnabled = msg.includes("not enabled") || msg.includes("not subscribed");

      if (isAccessDenied) {
        warnings.push("Insufficient permissions to access Inspector. Grant inspector2:BatchGetAccountStatus to check enablement.");
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

      if (isNotEnabled) {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
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
        error: `Inspector detection check failed: ${msg}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

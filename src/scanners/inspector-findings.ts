import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
} from "@aws-sdk/client-inspector2";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks whether Inspector is enabled and which
 * resource scan types (EC2, ECR, Lambda, Lambda Code, Code Repository) are active.
 * Actual findings are aggregated via Security Hub.
 */
export class InspectorFindingsScanner implements Scanner {
  readonly moduleName = "inspector_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(Inspector2Client, region, ctx.credentials);
      const resp = await client.send(new BatchGetAccountStatusCommand({ accountIds: [] }));
      const account = resp.accounts?.[0];

      if (!account || account.state?.status !== "ENABLED") {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
      } else {
        // Check individual resource scan types
        const rs = account.resourceState;
        const types: Array<{ name: string; status: string | undefined }> = [
          { name: "EC2", status: rs?.ec2?.status },
          { name: "Lambda", status: rs?.lambda?.status },
          { name: "ECR", status: rs?.ecr?.status },
          { name: "Lambda Code", status: rs?.lambdaCode?.status },
          { name: "Code Repository", status: rs?.codeRepository?.status },
        ];
        const disabled = types.filter((t) => t.status && t.status !== "ENABLED");
        if (disabled.length > 0) {
          warnings.push(
            `Inspector scan types not enabled: ${disabled.map((t) => t.name).join(", ")}. Enable them for full vulnerability coverage.`,
          );
        }
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
      const errName = err instanceof Error ? err.name : "";

      const isAccessDenied = errName === "AccessDeniedException" || msg.includes("AccessDeniedException");
      if (isAccessDenied) {
        warnings.push("Insufficient permissions to access Inspector. Grant inspector2:BatchGetAccountStatus to check enablement.");
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
    }
  }
}

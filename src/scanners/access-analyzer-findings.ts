import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
} from "@aws-sdk/client-accessanalyzer";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks if IAM Access Analyzer is configured.
 * Findings are aggregated via Security Hub.
 */
export class AccessAnalyzerFindingsScanner implements Scanner {
  readonly moduleName = "access_analyzer_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(AccessAnalyzerClient, region, ctx.credentials);

      let analyzerCount = 0;
      let analyzerToken: string | undefined;

      do {
        const resp = await client.send(
          new ListAnalyzersCommand({ nextToken: analyzerToken }),
        );
        for (const analyzer of resp.analyzers ?? []) {
          if (analyzer.status === "ACTIVE") {
            analyzerCount++;
          }
        }
        analyzerToken = resp.nextToken;
      } while (analyzerToken);

      if (analyzerCount > 0) {
        warnings.push(`IAM Access Analyzer is configured (${analyzerCount} active analyzer${analyzerCount > 1 ? "s" : ""}). Findings are aggregated via Security Hub.`);
      } else {
        warnings.push("No IAM Access Analyzer found. Create an analyzer to detect external access to your resources.");
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
        error: `Access Analyzer detection check failed: ${msg}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

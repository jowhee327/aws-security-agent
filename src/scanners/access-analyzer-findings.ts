import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
} from "@aws-sdk/client-accessanalyzer";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext } from "../types.js";
import { createClient } from "../utils/aws-client.js";

/**
 * Detection-only scanner: checks whether IAM Access Analyzer is enabled.
 * Actual findings are aggregated via Security Hub.
 */
export class AccessAnalyzerFindingsScanner implements Scanner {
  readonly moduleName = "access_analyzer_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings: string[] = [];

    try {
      const client = createClient(AccessAnalyzerClient, region, ctx.credentials);

      let analyzerToken: string | undefined;
      let hasActiveAnalyzer = false;

      do {
        const resp = await client.send(
          new ListAnalyzersCommand({ nextToken: analyzerToken }),
        );
        for (const analyzer of resp.analyzers ?? []) {
          if (analyzer.status === "ACTIVE") {
            hasActiveAnalyzer = true;
            break;
          }
        }
        if (hasActiveAnalyzer) break;
        analyzerToken = resp.nextToken;
      } while (analyzerToken);

      if (!hasActiveAnalyzer) {
        warnings.push("No IAM Access Analyzer found. Create an analyzer to detect external access to your resources.");
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
        error: `Access Analyzer detection check failed: ${msg}`,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

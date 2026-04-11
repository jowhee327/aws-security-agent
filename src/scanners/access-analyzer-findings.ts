import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsV2Command,
  type AnalyzerSummary,
  type FindingSummaryV2,
} from "@aws-sdk/client-accessanalyzer";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

function aaSeverityToScore(severity: string | undefined): number {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return 9.5;
    case "HIGH": return 8.0;
    case "MEDIUM": return 5.5;
    case "LOW": return 3.0;
    default: return 5.5;
  }
}

export class AccessAnalyzerFindingsScanner implements Scanner {
  readonly moduleName = "access_analyzer_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(AccessAnalyzerClient, region, ctx.credentials);

      // Step 1: List active analyzers
      let analyzerToken: string | undefined;
      const analyzers: AnalyzerSummary[] = [];

      do {
        const resp = await client.send(
          new ListAnalyzersCommand({ nextToken: analyzerToken }),
        );
        for (const analyzer of resp.analyzers ?? []) {
          if (analyzer.status === "ACTIVE") {
            analyzers.push(analyzer);
          }
        }
        analyzerToken = resp.nextToken;
      } while (analyzerToken);

      if (analyzers.length === 0) {
        warnings.push("No IAM Access Analyzer found. Create an analyzer to detect external access to your resources.");
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

      // Step 2: For each active analyzer, list ACTIVE findings
      for (const analyzer of analyzers) {
        const analyzerArn = analyzer.arn ?? "unknown";

        let findingToken: string | undefined;
        do {
          const listResp = await client.send(
            new ListFindingsV2Command({
              analyzerArn,
              filter: {
                status: { eq: ["ACTIVE"] },
              },
              nextToken: findingToken,
            }),
          );

          for (const aaf of listResp.findings ?? []) {
            resourcesScanned++;
            const score = aaSeverityToScore(aaf.findingType);
            const severity = severityFromScore(score);

            const resourceArn = aaf.resource ?? "unknown";
            const resourceType = aaf.resourceType ?? "AWS::Unknown";
            const resourceId = resourceArn.split("/").pop() ?? resourceArn.split(":").pop() ?? "unknown";

            const descParts = [`Resource Type: ${resourceType}`];
            if (aaf.resourceOwnerAccount) descParts.push(`Owner Account: ${aaf.resourceOwnerAccount}`);
            if (aaf.findingType) descParts.push(`Finding Type: ${aaf.findingType}`);

            const title = buildFindingTitle(aaf);

            findings.push({
              severity,
              title,
              resourceType: mapResourceType(resourceType),
              resourceId,
              resourceArn,
              region,
              description: descParts.join(". "),
              impact: `Resource is accessible from outside the account. Type: ${aaf.findingType ?? "unknown"}`,
              riskScore: score,
              remediationSteps: [
                "Review the finding in the IAM Access Analyzer console.",
                `Check resource ${resourceId} for unintended external access.`,
                "Remove or restrict the resource policy to eliminate external access.",
              ],
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId: aaf.resourceOwnerAccount ?? accountId,
            });
          }

          findingToken = listResp.nextToken;
        } while (findingToken);
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `Access Analyzer scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

function buildFindingTitle(finding: FindingSummaryV2): string {
  const resourceType = finding.resourceType ?? "Resource";
  const resource = finding.resource
    ? (finding.resource.split("/").pop() ?? finding.resource.split(":").pop() ?? finding.resource)
    : "unknown";
  return `[Access Analyzer] ${resourceType} ${resource} — external access detected`;
}

function mapResourceType(aaType: string): string {
  const mapping: Record<string, string> = {
    "AWS::S3::Bucket": "AWS::S3::Bucket",
    "AWS::IAM::Role": "AWS::IAM::Role",
    "AWS::SQS::Queue": "AWS::SQS::Queue",
    "AWS::Lambda::Function": "AWS::Lambda::Function",
    "AWS::Lambda::LayerVersion": "AWS::Lambda::LayerVersion",
    "AWS::KMS::Key": "AWS::KMS::Key",
    "AWS::SecretsManager::Secret": "AWS::SecretsManager::Secret",
    "AWS::SNS::Topic": "AWS::SNS::Topic",
    "AWS::EFS::FileSystem": "AWS::EFS::FileSystem",
    "AWS::RDS::DBSnapshot": "AWS::RDS::DBSnapshot",
    "AWS::RDS::DBClusterSnapshot": "AWS::RDS::DBClusterSnapshot",
    "AWS::ECR::Repository": "AWS::ECR::Repository",
  };
  return mapping[aaType] ?? aaType;
}

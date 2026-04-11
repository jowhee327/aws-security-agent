import {
  SSMClient,
  DescribeInstanceInformationCommand,
  DescribeInstancePatchStatesCommand,
  type InstanceInformation,
  type InstancePatchState,
} from "@aws-sdk/client-ssm";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

export class PatchComplianceFindingsScanner implements Scanner {
  readonly moduleName = "patch_compliance_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const client = createClient(SSMClient, region, ctx.credentials);

      // Step 1: Get all managed instances
      let nextToken: string | undefined;
      const instances: InstanceInformation[] = [];

      do {
        const resp = await client.send(
          new DescribeInstanceInformationCommand({
            MaxResults: 50,
            NextToken: nextToken,
          }),
        );
        instances.push(...(resp.InstanceInformationList ?? []));
        nextToken = resp.NextToken;
      } while (nextToken);

      if (instances.length === 0) {
        warnings.push("No SSM-managed instances found in this region.");
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

      resourcesScanned = instances.length;

      // Step 2: Get patch states in batches
      const instanceIds = instances.map((i) => i.InstanceId).filter(Boolean) as string[];
      const patchStateMap = new Map<string, InstancePatchState>();

      // DescribeInstancePatchStates supports up to 50 instances per call
      for (let i = 0; i < instanceIds.length; i += 50) {
        const batch = instanceIds.slice(i, i + 50);
        let patchToken: string | undefined;

        do {
          const patchResp = await client.send(
            new DescribeInstancePatchStatesCommand({
              InstanceIds: batch,
              NextToken: patchToken,
            }),
          );

          for (const ps of patchResp.InstancePatchStates ?? []) {
            if (ps.InstanceId) {
              patchStateMap.set(ps.InstanceId, ps);
            }
          }

          patchToken = patchResp.NextToken;
        } while (patchToken);
      }

      // Step 3: Generate findings for instances with missing/failed patches
      for (const instance of instances) {
        const instanceId = instance.InstanceId ?? "unknown";
        const platform = instance.PlatformName ?? instance.PlatformType ?? "unknown";
        const instanceArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instanceId}`;

        const patchState = patchStateMap.get(instanceId);

        if (!patchState) {
          // Instance not managed for patching — INFO-level finding
          const riskScore = 3.0;
          const severity = severityFromScore(riskScore);
          findings.push({
            severity,
            title: `Instance ${instanceId} has no patch compliance data`,
            resourceType: "AWS::EC2::Instance",
            resourceId: instanceId,
            resourceArn: instanceArn,
            region,
            description: `Instance ${instanceId} (${platform}) is managed by SSM but has no patch compliance data. Patch Manager may not be configured for this instance.`,
            impact: "Patch compliance status is unknown — vulnerabilities may exist.",
            riskScore,
            remediationSteps: [
              "Configure AWS Systems Manager Patch Manager for this instance.",
              "Create a patch baseline and maintenance window.",
              "Run a patch scan to establish compliance status.",
            ],
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId,
          });
          continue;
        }

        const missingCount = patchState.MissingCount ?? 0;
        const failedCount = patchState.FailedCount ?? 0;
        const criticalNonCompliantCount = patchState.CriticalNonCompliantCount ?? 0;
        const securityNonCompliantCount = patchState.SecurityNonCompliantCount ?? 0;
        const otherNonCompliantCount = patchState.OtherNonCompliantCount ?? 0;
        const lastScanTime = patchState.OperationEndTime?.toISOString() ?? "unknown";

        if (
          missingCount === 0 &&
          failedCount === 0 &&
          criticalNonCompliantCount === 0 &&
          securityNonCompliantCount === 0 &&
          otherNonCompliantCount === 0
        ) {
          continue; // Instance is fully patched
        }

        // Determine severity based on patch issues
        let riskScore: number;
        if (criticalNonCompliantCount > 0 || securityNonCompliantCount > 0 || failedCount > 0) {
          riskScore = 7.5; // HIGH — critical/security patches missing or failed
        } else if (otherNonCompliantCount > 0) {
          riskScore = 5.5; // MEDIUM — other non-compliant patches
        } else {
          riskScore = 5.5; // MEDIUM — non-security patches missing
        }
        const severity = severityFromScore(riskScore);

        const titleParts: string[] = [];
        if (missingCount > 0) titleParts.push(`${missingCount} missing`);
        if (failedCount > 0) titleParts.push(`${failedCount} failed`);
        if (criticalNonCompliantCount > 0) titleParts.push(`${criticalNonCompliantCount} critical non-compliant`);
        if (securityNonCompliantCount > 0) titleParts.push(`${securityNonCompliantCount} security non-compliant`);
        if (otherNonCompliantCount > 0) titleParts.push(`${otherNonCompliantCount} other non-compliant`);

        const descParts = [
          `Instance: ${instanceId}`,
          `Platform: ${platform}`,
          `Missing patches: ${missingCount}`,
          `Failed patches: ${failedCount}`,
          `Critical non-compliant: ${criticalNonCompliantCount}`,
          `Security non-compliant: ${securityNonCompliantCount}`,
          `Other non-compliant: ${otherNonCompliantCount}`,
          `Last scan: ${lastScanTime}`,
        ];

        findings.push({
          severity,
          title: `Instance ${instanceId} has ${titleParts.join(", ")} patches`,
          resourceType: "AWS::EC2::Instance",
          resourceId: instanceId,
          resourceArn: instanceArn,
          region,
          description: descParts.join(". "),
          impact: `Instance has ${missingCount} missing and ${failedCount} failed patches — potential security vulnerabilities.`,
          riskScore,
          remediationSteps: [
            `Review patch compliance for instance ${instanceId} in the Systems Manager console.`,
            "Apply missing patches using a maintenance window or manual patching.",
            "Investigate and resolve any failed patch installations.",
            "Consider enabling automatic patching through Patch Manager.",
          ],
          priority: priorityFromSeverity(severity),
          module: this.moduleName,
          accountId,
        });
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
        error: `Patch compliance scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

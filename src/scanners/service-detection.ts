import {
  SecurityHubClient,
  DescribeHubCommand,
} from "@aws-sdk/client-securityhub";
import {
  GuardDutyClient,
  ListDetectorsCommand,
} from "@aws-sdk/client-guardduty";
import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
} from "@aws-sdk/client-inspector2";
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
} from "@aws-sdk/client-config-service";
import {
  Macie2Client,
  GetMacieSessionCommand,
} from "@aws-sdk/client-macie2";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
} from "@aws-sdk/client-cloudtrail";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

export interface ServiceStatus {
  name: string;
  enabled: boolean;
  details?: string;
  recommendation?: string;
  freeTrialAvailable?: boolean;
}

export interface ServiceDetectionResult {
  services: ServiceStatus[];
  coveragePercent: number;
  maturityLevel: "basic" | "intermediate" | "advanced" | "comprehensive";
}

function makeFinding(opts: {
  riskScore: number;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  remediationSteps: string[];
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}

function isAccessDenied(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const name = (err as Error & { name?: string }).name ?? "";
  const code = (err as Error & { Code?: string }).Code ?? "";
  return (
    name === "AccessDeniedException" ||
    name === "UnauthorizedAccess" ||
    name === "AccessDenied" ||
    code === "AccessDeniedException" ||
    code === "AccessDenied" ||
    name === "ForbiddenException" ||
    // AWS SDK v3 uses __type or $metadata for some errors
    (err.message?.includes("is not authorized to perform") ?? false) ||
    (err.message?.includes("Access Denied") ?? false)
  );
}

/** Macie is not available in China regions */
function isMacieAvailable(region: string): boolean {
  return !region.startsWith("cn-");
}

function computeMaturityLevel(
  enabledCount: number,
): "basic" | "intermediate" | "advanced" | "comprehensive" {
  if (enabledCount >= 6) return "comprehensive";
  if (enabledCount >= 4) return "advanced";
  if (enabledCount >= 2) return "intermediate";
  return "basic";
}

export class ServiceDetectionScanner implements Scanner {
  readonly moduleName = "service_detection";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    const services: ServiceStatus[] = [];

    // --- CloudTrail ---
    try {
      const ct = createClient(CloudTrailClient, region);
      const resp = await ct.send(new DescribeTrailsCommand({}));
      const trails = resp.trailList ?? [];
      if (trails.length > 0) {
        services.push({
          name: "CloudTrail",
          enabled: true,
          details: `${trails.length} trail(s) configured`,
        });
      } else {
        services.push({
          name: "CloudTrail",
          enabled: false,
          recommendation: "Create a multi-region trail for API logging",
        });
        // CloudTrail findings are handled by the dedicated cloudtrail scanner,
        // so we don't add a finding here.
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("CloudTrail: insufficient permissions to check status");
        services.push({ name: "CloudTrail", enabled: false, details: "Access denied" });
      } else {
        warnings.push(`CloudTrail detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "CloudTrail", enabled: false, details: "Detection error" });
      }
    }

    // --- Security Hub ---
    try {
      const sh = createClient(SecurityHubClient, region);
      await sh.send(new DescribeHubCommand({}));
      services.push({
        name: "Security Hub",
        enabled: true,
        details: "Enabled with automated security checks",
      });
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Security Hub: insufficient permissions to check status");
        services.push({ name: "Security Hub", enabled: false, details: "Access denied" });
      } else {
        services.push({
          name: "Security Hub",
          enabled: false,
          recommendation: "Enable Security Hub for 300+ automated security checks",
          freeTrialAvailable: true,
        });
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "AWS Security Hub is not enabled",
            resourceType: "AWS::SecurityHub::Hub",
            resourceId: "securityhub",
            resourceArn: `arn:${partition}:securityhub:${region}:${accountId}:hub/default`,
            region,
            description:
              "AWS Security Hub is not enabled in this region. Security Hub provides a comprehensive view of security alerts and compliance status.",
            impact:
              "Enables 300+ automated security checks across AWS services. Without it, security findings are fragmented across individual services.",
            remediationSteps: [
              "Open the AWS Security Hub console.",
              "Click 'Go to Security Hub' and enable it.",
              "Enable the AWS Foundational Security Best Practices standard.",
              "Security Hub offers a 30-day free trial.",
            ],
          }),
        );
      }
    }

    // --- GuardDuty ---
    try {
      const gd = createClient(GuardDutyClient, region);
      const resp = await gd.send(new ListDetectorsCommand({}));
      const detectors = resp.DetectorIds ?? [];
      if (detectors.length > 0) {
        services.push({
          name: "GuardDuty",
          enabled: true,
          details: `${detectors.length} detector(s) active`,
        });
      } else {
        services.push({
          name: "GuardDuty",
          enabled: false,
          recommendation: "Enable GuardDuty for continuous threat detection",
          freeTrialAvailable: true,
        });
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "Amazon GuardDuty is not enabled",
            resourceType: "AWS::GuardDuty::Detector",
            resourceId: "guardduty",
            resourceArn: `arn:${partition}:guardduty:${region}:${accountId}:detector/none`,
            region,
            description:
              "Amazon GuardDuty is not enabled in this region. GuardDuty provides intelligent threat detection by analyzing CloudTrail, VPC Flow Logs, and DNS logs.",
            impact:
              "Provides continuous threat detection for account compromise, instance compromise, and malicious reconnaissance. Without it, many attack patterns go undetected.",
            remediationSteps: [
              "Open the Amazon GuardDuty console.",
              "Click 'Get Started' and enable GuardDuty.",
              "GuardDuty offers a 30-day free trial.",
              "Consider enabling S3 protection and EKS protection add-ons.",
            ],
          }),
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("GuardDuty: insufficient permissions to check status");
        services.push({ name: "GuardDuty", enabled: false, details: "Access denied" });
      } else {
        warnings.push(`GuardDuty detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "GuardDuty", enabled: false, details: "Detection error" });
      }
    }

    // --- Inspector ---
    try {
      const insp = createClient(Inspector2Client, region);
      const resp = await insp.send(new BatchGetAccountStatusCommand({ accountIds: [accountId] }));
      const accounts = resp.accounts ?? [];
      const active = accounts.some(
        (a) =>
          a.state?.status === "ENABLED" ||
          a.state?.status === "ENABLING",
      );
      if (active) {
        services.push({
          name: "Inspector",
          enabled: true,
          details: "Vulnerability scanning active",
        });
      } else {
        services.push({
          name: "Inspector",
          enabled: false,
          recommendation: "Enable Inspector to scan for software vulnerabilities",
          freeTrialAvailable: true,
        });
        findings.push(
          makeFinding({
            riskScore: 6.0,
            title: "Amazon Inspector is not enabled",
            resourceType: "AWS::Inspector2::AccountStatus",
            resourceId: "inspector",
            resourceArn: `arn:${partition}:inspector2:${region}:${accountId}:account`,
            region,
            description:
              "Amazon Inspector is not enabled in this region. Inspector automatically discovers and scans EC2 instances, containers, and Lambda functions for software vulnerabilities.",
            impact:
              "Scans for software vulnerabilities in EC2 instances, container images, and Lambda functions. Without it, known CVEs may go undetected.",
            remediationSteps: [
              "Open the Amazon Inspector console.",
              "Click 'Get Started' and enable Inspector.",
              "Inspector offers a 15-day free trial.",
              "Enable scanning for EC2, ECR, and Lambda as appropriate.",
            ],
          }),
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Inspector: insufficient permissions to check status");
        services.push({ name: "Inspector", enabled: false, details: "Access denied" });
      } else {
        warnings.push(`Inspector detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "Inspector", enabled: false, details: "Detection error" });
      }
    }

    // --- AWS Config ---
    try {
      const cfg = createClient(ConfigServiceClient, region);
      const resp = await cfg.send(new DescribeConfigurationRecordersCommand({}));
      const recorders = resp.ConfigurationRecorders ?? [];
      if (recorders.length > 0) {
        services.push({
          name: "AWS Config",
          enabled: true,
          details: `${recorders.length} recorder(s) configured`,
        });
      } else {
        services.push({
          name: "AWS Config",
          enabled: false,
          recommendation: "Enable AWS Config to track configuration changes",
        });
        findings.push(
          makeFinding({
            riskScore: 6.0,
            title: "AWS Config is not enabled",
            resourceType: "AWS::Config::ConfigurationRecorder",
            resourceId: "config",
            resourceArn: `arn:${partition}:config:${region}:${accountId}:configuration-recorder/none`,
            region,
            description:
              "AWS Config is not enabled in this region. Config continuously records resource configurations and enables compliance auditing.",
            impact:
              "Tracks configuration changes and enables compliance rules. Without it, configuration drift and non-compliant resources go undetected.",
            remediationSteps: [
              "Open the AWS Config console.",
              "Click 'Get Started' and configure a recorder.",
              "Select the resource types to record.",
              "Configure an S3 bucket for configuration snapshots.",
            ],
          }),
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("AWS Config: insufficient permissions to check status");
        services.push({ name: "AWS Config", enabled: false, details: "Access denied" });
      } else {
        warnings.push(`AWS Config detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "AWS Config", enabled: false, details: "Detection error" });
      }
    }

    // --- Macie ---
    if (isMacieAvailable(region)) {
      try {
        const mc = createClient(Macie2Client, region);
        await mc.send(new GetMacieSessionCommand({}));
        services.push({
          name: "Macie",
          enabled: true,
          details: "Sensitive data detection active",
        });
      } catch (err) {
        if (isAccessDenied(err)) {
          warnings.push("Macie: insufficient permissions to check status");
          services.push({ name: "Macie", enabled: false, details: "Access denied" });
        } else {
          services.push({
            name: "Macie",
            enabled: false,
            recommendation: "Enable Macie to detect sensitive data in S3",
            freeTrialAvailable: true,
          });
          findings.push(
            makeFinding({
              riskScore: 5.0,
              title: "Amazon Macie is not enabled",
              resourceType: "AWS::Macie::Session",
              resourceId: "macie",
              resourceArn: `arn:${partition}:macie2:${region}:${accountId}:session`,
              region,
              description:
                "Amazon Macie is not enabled in this region. Macie uses machine learning to discover and protect sensitive data stored in S3.",
              impact:
                "Detects sensitive data (PII, credentials, financial data) in S3 buckets. Without it, sensitive data exposure may go unnoticed.",
              remediationSteps: [
                "Open the Amazon Macie console.",
                "Click 'Get Started' and enable Macie.",
                "Macie offers a 30-day free trial for sensitive data discovery.",
                "Configure automated sensitive data discovery jobs.",
              ],
            }),
          );
        }
      }
    } else {
      warnings.push("Macie: not available in China regions, skipping");
      services.push({
        name: "Macie",
        enabled: false,
        details: "Not available in this region",
      });
    }

    // Compute coverage and maturity
    const totalServices = services.length;
    const enabledCount = services.filter((s) => s.enabled).length;
    const coveragePercent = totalServices > 0 ? Math.round((enabledCount / totalServices) * 100) : 0;
    const maturityLevel = computeMaturityLevel(enabledCount);

    const detectionResult: ServiceDetectionResult = {
      services,
      coveragePercent,
      maturityLevel,
    };

    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : undefined,
      resourcesScanned: totalServices,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
      // Attach the structured detection result as a custom property via the findings metadata
      ...({ serviceDetection: detectionResult } as Record<string, unknown>),
    } as ScanResult & { serviceDetection: ServiceDetectionResult };
  }
}

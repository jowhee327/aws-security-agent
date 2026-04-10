import {
  ACMClient,
  ListCertificatesCommand,
  DescribeCertificateCommand,
  type CertificateSummary,
} from "@aws-sdk/client-acm";
import { Scanner } from "./base.js";
import { ScanResult, ScanContext, Finding } from "../types.js";
import { createClient } from "../utils/aws-client.js";
import { severityFromScore, priorityFromSeverity } from "../utils/risk-scoring.js";

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

export class SslCertificateScanner implements Scanner {
  readonly moduleName = "ssl_certificate";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(ACMClient, region);

      // List all certificates
      const certs: CertificateSummary[] = [];
      let nextToken: string | undefined;
      do {
        const resp = await client.send(
          new ListCertificatesCommand({ NextToken: nextToken }),
        );
        if (resp.CertificateSummaryList) {
          certs.push(...resp.CertificateSummaryList);
        }
        nextToken = resp.NextToken;
      } while (nextToken);

      for (const cert of certs) {
        const certArn = cert.CertificateArn ?? "unknown";
        const domainName = cert.DomainName ?? "unknown";

        let detail;
        try {
          const descResp = await client.send(
            new DescribeCertificateCommand({ CertificateArn: certArn }),
          );
          detail = descResp.Certificate;
        } catch (e: unknown) {
          warnings.push(`Could not describe certificate ${certArn}: ${e instanceof Error ? e.message : String(e)}`);
          continue;
        }

        if (!detail) continue;

        const status = detail.Status ?? "UNKNOWN";
        const inUseBy = detail.InUseBy ?? [];
        const inUseStr = inUseBy.length > 0 ? ` In use by ${inUseBy.length} resource(s).` : " Not currently in use.";

        // Check for FAILED status
        if (status === "FAILED") {
          findings.push(
            makeFinding({
              riskScore: 7.5,
              title: `Certificate for ${domainName} is in FAILED status`,
              resourceType: "AWS::ACM::Certificate",
              resourceId: domainName,
              resourceArn: certArn,
              region,
              description: `ACM certificate for "${domainName}" has status FAILED.${inUseStr}`,
              impact:
                "The certificate failed validation and cannot be used for TLS termination. Services relying on it may lose HTTPS protection.",
              remediationSteps: [
                "Check the failure reason in the ACM console.",
                "Request a new certificate with correct domain validation.",
                "If using DNS validation, ensure the CNAME records are correctly configured.",
              ],
            }),
          );
          continue;
        }

        // Check expiry (only for ISSUED certificates)
        if (status === "ISSUED" && detail.NotAfter) {
          const now = new Date();
          const expiryDate = new Date(detail.NotAfter);
          const daysUntilExpiry = Math.floor(
            (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
          );

          if (daysUntilExpiry < 0) {
            findings.push(
              makeFinding({
                riskScore: 8.0,
                title: `Certificate for ${domainName} has expired`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expired ${Math.abs(daysUntilExpiry)} days ago.${inUseStr}`,
                impact:
                  "Expired certificates cause TLS errors for end users. Browsers will display security warnings and block access.",
                remediationSteps: [
                  "Renew or replace the certificate immediately.",
                  "If using ACM-managed renewal, check why automatic renewal failed.",
                  "Verify domain validation records are still in place.",
                ],
              }),
            );
          } else if (daysUntilExpiry < 30) {
            findings.push(
              makeFinding({
                riskScore: 6.0,
                title: `Certificate for ${domainName} expires in ${daysUntilExpiry} days`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expires in ${daysUntilExpiry} days (${expiryDate.toISOString().split("T")[0]}).${inUseStr}`,
                impact:
                  "Certificate will expire soon. If not renewed, services will experience TLS errors.",
                remediationSteps: [
                  "Verify ACM automatic renewal is working (check renewal status).",
                  "If imported certificate, prepare and import the renewed certificate.",
                  "Set up CloudWatch alarms for certificate expiry.",
                ],
              }),
            );
          } else if (daysUntilExpiry < 90) {
            findings.push(
              makeFinding({
                riskScore: 4.0,
                title: `Certificate for ${domainName} expires in ${daysUntilExpiry} days`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expires in ${daysUntilExpiry} days (${expiryDate.toISOString().split("T")[0]}).${inUseStr}`,
                impact:
                  "Certificate is approaching expiry. Plan renewal to avoid service disruption.",
                remediationSteps: [
                  "Verify ACM automatic renewal is configured and working.",
                  "If imported certificate, begin the renewal process.",
                  "Consider setting up monitoring for certificate expiry dates.",
                ],
              }),
            );
          }
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: certs.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}

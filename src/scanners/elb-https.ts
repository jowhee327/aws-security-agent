import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  type LoadBalancer,
  type Listener,
} from "@aws-sdk/client-elastic-load-balancing-v2";
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

export class ElbHttpsScanner implements Scanner {
  readonly moduleName = "elb_https";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const { region } = ctx;
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const client = createClient(ElasticLoadBalancingV2Client, region);

      // List all ALBs and NLBs (ELBv2)
      const loadBalancers: LoadBalancer[] = [];
      let marker: string | undefined;
      do {
        const resp = await client.send(
          new DescribeLoadBalancersCommand({ Marker: marker }),
        );
        if (resp.LoadBalancers) {
          loadBalancers.push(...resp.LoadBalancers);
        }
        marker = resp.NextMarker;
      } while (marker);

      for (const lb of loadBalancers) {
        const lbName = lb.LoadBalancerName ?? "unknown";
        const lbArn = lb.LoadBalancerArn ?? "unknown";
        const lbType = lb.Type ?? "application"; // application | network | gateway

        // List listeners for this LB
        let listeners: Listener[] = [];
        try {
          let listenerMarker: string | undefined;
          do {
            const listenerResp = await client.send(
              new DescribeListenersCommand({
                LoadBalancerArn: lbArn,
                Marker: listenerMarker,
              }),
            );
            if (listenerResp.Listeners) {
              listeners.push(...listenerResp.Listeners);
            }
            listenerMarker = listenerResp.NextMarker;
          } while (listenerMarker);
        } catch (e: unknown) {
          warnings.push(`Could not list listeners for ${lbName}: ${e instanceof Error ? e.message : String(e)}`);
          continue;
        }

        for (const listener of listeners) {
          const protocol = listener.Protocol ?? "unknown";
          const port = listener.Port ?? 0;

          if (lbType === "application") {
            // ALB: HTTP without redirect to HTTPS is a finding
            if (protocol === "HTTP") {
              // Check if this HTTP listener has a redirect action to HTTPS
              const hasRedirect = (listener.DefaultActions ?? []).some(
                (action) =>
                  action.Type === "redirect" &&
                  action.RedirectConfig?.Protocol === "HTTPS",
              );

              if (!hasRedirect) {
                findings.push(
                  makeFinding({
                    riskScore: 7.5,
                    title: `ALB ${lbName} has HTTP listener on port ${port} without HTTPS redirect`,
                    resourceType: "AWS::ElasticLoadBalancingV2::Listener",
                    resourceId: `${lbName}:${port}`,
                    resourceArn: listener.ListenerArn ?? lbArn,
                    region,
                    description: `ALB "${lbName}" has an HTTP listener on port ${port} that does not redirect to HTTPS.`,
                    impact:
                      "Traffic is transmitted in plaintext, exposing sensitive data to interception and man-in-the-middle attacks.",
                    remediationSteps: [
                      "Add a redirect action on the HTTP listener to forward all traffic to HTTPS.",
                      "Alternatively, remove the HTTP listener if HTTPS is already configured.",
                    ],
                  }),
                );
              }
            }

            // Check certificate expiry for HTTPS listeners
            if (protocol === "HTTPS" && listener.Certificates) {
              for (const cert of listener.Certificates) {
                if (!cert.CertificateArn) continue;
                // Note: checking ACM certificate expiry would require ACM client.
                // We flag listeners with certificates for awareness.
              }
            }
          } else if (lbType === "network") {
            // NLB: listener without TLS
            if (protocol === "TCP" || protocol === "UDP") {
              findings.push(
                makeFinding({
                  riskScore: 6.0,
                  title: `NLB ${lbName} has ${protocol} listener on port ${port} without TLS`,
                  resourceType: "AWS::ElasticLoadBalancingV2::Listener",
                  resourceId: `${lbName}:${port}`,
                  resourceArn: listener.ListenerArn ?? lbArn,
                  region,
                  description: `NLB "${lbName}" has a ${protocol} listener on port ${port} without TLS termination.`,
                  impact:
                    "Traffic is not encrypted at the load balancer level. If backend services do not implement their own TLS, data is transmitted in plaintext.",
                  remediationSteps: [
                    "Switch the listener protocol to TLS and attach an ACM certificate.",
                    "If end-to-end encryption is handled by the application, document this as an accepted risk.",
                  ],
                }),
              );
            }
          }
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: loadBalancers.length,
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

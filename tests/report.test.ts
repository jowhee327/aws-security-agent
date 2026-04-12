import { describe, it, expect } from "vitest";
import { generateMarkdownReport } from "../src/tools/report-tool.js";
import type { FullScanResult } from "../src/types.js";

describe("generateMarkdownReport", () => {
  it("includes expected headers and finding titles", () => {
    const mockResult: FullScanResult = {
      scanStart: "2026-01-15T10:00:00.000Z",
      scanEnd: "2026-01-15T10:00:05.000Z",
      region: "us-east-1",
      accountId: "123456789012",
      modules: [
        {
          module: "network_reachability",
          status: "success",
          resourcesScanned: 3,
          findingsCount: 1,
          scanTimeMs: 500,
          findings: [
            {
              severity: "CRITICAL",
              title: "EC2 instance i-abc123 has SSH (22) reachable from 0.0.0.0/0",
              resourceType: "AWS::EC2::Instance",
              resourceId: "i-abc123",
              resourceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
              region: "us-east-1",
              description: "SSH reachable from the internet",
              impact: "SSH exposed",
              riskScore: 9.0,
              remediationSteps: ["Restrict port 22"],
              priority: "P0",
            },
          ],
        },
      ],
      summary: {
        totalFindings: 1,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        modulesSuccess: 1,
        modulesError: 0,
      },
    };

    const report = generateMarkdownReport(mockResult, "en");

    expect(report).toContain("# AWS Security Scan Report");
    expect(report).toContain("## Executive Summary");
    expect(report).toContain("## Findings by Severity");
    expect(report).toContain("## Scan Statistics");
    expect(report).toContain("i-abc123 has SSH");
    expect(report).toContain("123456789012");
  });

  it("shows 'No security issues' when 0 findings", () => {
    const emptyResult: FullScanResult = {
      scanStart: "2026-01-15T10:00:00.000Z",
      scanEnd: "2026-01-15T10:00:01.000Z",
      region: "us-east-1",
      accountId: "123456789012",
      modules: [
        {
          module: "service_detection",
          status: "success",
          resourcesScanned: 5,
          findingsCount: 0,
          scanTimeMs: 200,
          findings: [],
        },
      ],
      summary: {
        totalFindings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        modulesSuccess: 1,
        modulesError: 0,
      },
    };

    const report = generateMarkdownReport(emptyResult, "en");

    expect(report).toContain("No security issues");
  });
});

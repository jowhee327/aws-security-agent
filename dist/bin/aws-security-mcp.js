#!/usr/bin/env node
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/commands/dashboard.ts
var dashboard_exports = {};
__export(dashboard_exports, {
  startDashboard: () => startDashboard
});
import { createServer as createServer2 } from "http";
import { readFile } from "fs/promises";
import { join as join3, extname, resolve } from "path";
import { existsSync as existsSync2, copyFileSync } from "fs";
import { fileURLToPath as fileURLToPath2 } from "url";
import { exec } from "child_process";
function startDashboard(port = 3e3) {
  const dashboardDir = join3(__dirname, "../../dashboard/dist");
  if (!existsSync2(dashboardDir)) {
    console.error(
      `Dashboard not built. Run "npm run build:dashboard" first.
Expected: ${dashboardDir}`
    );
    process.exit(1);
  }
  const dataSource = join3(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".aws-security/dashboard/data.json"
  );
  const dataDest = join3(dashboardDir, "data.json");
  if (existsSync2(dataSource)) {
    copyFileSync(dataSource, dataDest);
    console.log(`Loaded scan data from ${dataSource}`);
  } else {
    console.log(
      "No scan data found at ~/.aws-security/dashboard/data.json \u2014 using bundled sample data"
    );
  }
  const resolvedBase = resolve(dashboardDir);
  const server = createServer2(async (req, res) => {
    const url = req.url?.split("?")[0] ?? "/";
    let filePath = resolve(
      join3(dashboardDir, url === "/" ? "index.html" : url)
    );
    if (!filePath.startsWith(resolvedBase + "/") && filePath !== resolvedBase) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }
    if (!existsSync2(filePath)) {
      filePath = join3(dashboardDir, "index.html");
    }
    try {
      const content = await readFile(filePath);
      const ext = extname(filePath);
      res.writeHead(200, {
        "Content-Type": MIME_TYPES[ext] || "application/octet-stream"
      });
      res.end(content);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
  });
  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(`
AWS Security Dashboard: ${url}
`);
    console.log("Press Ctrl+C to stop.\n");
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
    exec(`${cmd} ${url}`, () => {
    });
  });
  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${port} is already in use. Try --port <other>`);
      process.exit(1);
    }
    throw err;
  });
}
var __filename, __dirname, MIME_TYPES;
var init_dashboard = __esm({
  "src/commands/dashboard.ts"() {
    "use strict";
    __filename = fileURLToPath2(import.meta.url);
    __dirname = join3(__filename, "..");
    MIME_TYPES = {
      ".html": "text/html",
      ".js": "text/javascript",
      ".css": "text/css",
      ".json": "application/json",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".ico": "image/x-icon",
      ".woff": "font/woff",
      ".woff2": "font/woff2"
    };
  }
});

// src/commands/deploy-dashboard.ts
var deploy_dashboard_exports = {};
__export(deploy_dashboard_exports, {
  deployDashboard: () => deployDashboard
});
import { readdirSync, readFileSync as readFileSync3, existsSync as existsSync3, copyFileSync as copyFileSync2 } from "fs";
import { join as join4, extname as extname2, relative } from "path";
import { fileURLToPath as fileURLToPath3 } from "url";
import {
  S3Client as S3Client5,
  PutObjectCommand,
  PutBucketWebsiteCommand,
  PutBucketPolicyCommand
} from "@aws-sdk/client-s3";
function collectFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join4(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full));
    } else {
      files.push(full);
    }
  }
  return files;
}
async function deployDashboard(bucket, region) {
  const dashboardDir = join4(__dirname2, "../../dashboard/dist");
  if (!existsSync3(dashboardDir)) {
    console.error(
      `Dashboard not built. Run "npm run build:dashboard" first.
Expected: ${dashboardDir}`
    );
    process.exit(1);
  }
  const dataSource = join4(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".aws-security/dashboard/data.json"
  );
  const dataDest = join4(dashboardDir, "data.json");
  if (existsSync3(dataSource)) {
    copyFileSync2(dataSource, dataDest);
    console.log(`Loaded scan data from ${dataSource}`);
  } else {
    console.log(
      "No scan data at ~/.aws-security/dashboard/data.json \u2014 deploying with bundled sample data"
    );
  }
  const s3 = new S3Client5({ region });
  console.log(`Configuring s3://${bucket} for static website hosting...`);
  await s3.send(
    new PutBucketWebsiteCommand({
      Bucket: bucket,
      WebsiteConfiguration: {
        IndexDocument: { Suffix: "index.html" },
        ErrorDocument: { Key: "index.html" }
        // SPA fallback
      }
    })
  );
  const partition = region.startsWith("cn-") ? "aws-cn" : "aws";
  console.log(`Setting public read bucket policy on s3://${bucket}...`);
  await s3.send(
    new PutBucketPolicyCommand({
      Bucket: bucket,
      Policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "PublicReadGetObject",
            Effect: "Allow",
            Principal: "*",
            Action: "s3:GetObject",
            Resource: `arn:${partition}:s3:::${bucket}/*`
          }
        ]
      })
    })
  );
  const files = collectFiles(dashboardDir);
  console.log(`Uploading ${files.length} files to s3://${bucket}...`);
  for (const filePath of files) {
    const key = relative(dashboardDir, filePath);
    const ext = extname2(filePath);
    const contentType = CONTENT_TYPES[ext] || "application/octet-stream";
    const body = readFileSync3(filePath);
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: contentType
      })
    );
    console.log(`  ${key}`);
  }
  const domain = region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com";
  const websiteUrl = `http://${bucket}.s3-website.${region}.${domain}`;
  console.log(`
Dashboard deployed successfully!`);
  console.log(`Website URL: ${websiteUrl}`);
  console.log(
    "\nNote: Ensure S3 Block Public Access is disabled on this bucket for the website to be accessible.\n"
  );
}
var __filename2, __dirname2, CONTENT_TYPES;
var init_deploy_dashboard = __esm({
  "src/commands/deploy-dashboard.ts"() {
    "use strict";
    __filename2 = fileURLToPath3(import.meta.url);
    __dirname2 = join4(__filename2, "..");
    CONTENT_TYPES = {
      ".html": "text/html",
      ".js": "text/javascript",
      ".css": "text/css",
      ".json": "application/json",
      ".svg": "image/svg+xml",
      ".png": "image/png",
      ".ico": "image/x-icon",
      ".woff": "font/woff",
      ".woff2": "font/woff2"
    };
  }
});

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// src/version.ts
var VERSION = "0.5.0";

// src/utils/aws-client.ts
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
var cachedAccountId;
function getPartition(region) {
  if (region.startsWith("cn-")) return "aws-cn";
  if (region.startsWith("us-gov-")) return "aws-us-gov";
  return "aws";
}
function getIamRegion(region) {
  if (region.startsWith("cn-")) return region;
  return "us-east-1";
}
async function getAccountId(region) {
  if (cachedAccountId) return cachedAccountId;
  const stsRegion = region ?? "us-east-1";
  const sts = new STSClient({ region: stsRegion });
  const response = await sts.send(new GetCallerIdentityCommand({}));
  cachedAccountId = response.Account ?? "unknown";
  return cachedAccountId;
}
function createClient(ClientClass, region, credentials) {
  const config = { region: region ?? "us-east-1" };
  if (credentials) config.credentials = credentials;
  return new ClientClass(config);
}

// src/utils/assume-role.ts
import { STSClient as STSClient2, AssumeRoleCommand, GetCallerIdentityCommand as GetCallerIdentityCommand2 } from "@aws-sdk/client-sts";
var DEFAULT_EXTERNAL_ID = "aws-security-mcp-audit";
async function assumeRole(roleArn, region, options) {
  const sessionName = options?.sessionName ?? "aws-security-mcp";
  const externalId = options?.externalId ?? DEFAULT_EXTERNAL_ID;
  const sts = new STSClient2({ region });
  const result = await sts.send(new AssumeRoleCommand({
    RoleArn: roleArn,
    RoleSessionName: sessionName,
    ExternalId: externalId,
    DurationSeconds: 3600
  }));
  return {
    accessKeyId: result.Credentials.AccessKeyId,
    secretAccessKey: result.Credentials.SecretAccessKey,
    sessionToken: result.Credentials.SessionToken
  };
}
function buildRoleArn(accountId, roleName, partition = "aws") {
  return `arn:${partition}:iam::${accountId}:role/${roleName}`;
}

// src/utils/org-accounts.ts
import { OrganizationsClient, ListAccountsCommand } from "@aws-sdk/client-organizations";
async function listOrgAccounts(region) {
  const orgRegion = region.startsWith("cn-") ? "cn-northwest-1" : "us-east-1";
  const client = new OrganizationsClient({ region: orgRegion });
  const accounts = [];
  let nextToken;
  do {
    const result = await client.send(new ListAccountsCommand({ NextToken: nextToken }));
    for (const acct of result.Accounts || []) {
      if (acct.Status === "ACTIVE") {
        accounts.push({
          id: acct.Id,
          name: acct.Name || "",
          email: acct.Email || "",
          status: acct.Status
        });
      }
    }
    nextToken = result.NextToken;
  } while (nextToken);
  return accounts;
}

// src/scanners/runner.ts
var AGGREGATION_MODULES = /* @__PURE__ */ new Set([
  "security_hub_findings",
  "guardduty_findings",
  "inspector_findings"
]);
function buildSummary(modules) {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let modulesSuccess = 0;
  let modulesError = 0;
  for (const m of modules) {
    if (m.status === "success") {
      modulesSuccess++;
    } else {
      modulesError++;
    }
    for (const f of m.findings) {
      switch (f.severity) {
        case "CRITICAL":
          critical++;
          break;
        case "HIGH":
          high++;
          break;
        case "MEDIUM":
          medium++;
          break;
        case "LOW":
          low++;
          break;
      }
    }
  }
  return {
    totalFindings: critical + high + medium + low,
    critical,
    high,
    medium,
    low,
    modulesSuccess,
    modulesError
  };
}
async function runScannersWithContext(scanners, ctx) {
  const settled = await Promise.allSettled(scanners.map((s) => s.scan(ctx)));
  return settled.map((result, i) => {
    if (result.status === "fulfilled") {
      for (const f of result.value.findings) {
        if (!f.accountId) f.accountId = ctx.accountId;
        if (!f.accountAlias && ctx.accountAlias) f.accountAlias = ctx.accountAlias;
      }
      return result.value;
    }
    return {
      module: scanners[i].moduleName,
      status: "error",
      error: result.reason instanceof Error ? result.reason.message : String(result.reason),
      resourcesScanned: 0,
      findingsCount: 0,
      scanTimeMs: 0,
      findings: []
    };
  });
}
async function runAllScanners(scanners, region) {
  const scanStart = (/* @__PURE__ */ new Date()).toISOString();
  let accountId;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }
  const partition = getPartition(region);
  const ctx = { region, partition, accountId };
  const modules = await runScannersWithContext(scanners, ctx);
  const scanEnd = (/* @__PURE__ */ new Date()).toISOString();
  return {
    scanStart,
    scanEnd,
    region,
    accountId,
    modules,
    summary: buildSummary(modules)
  };
}
async function runMultiAccountScanners(scanners, region, opts) {
  const scanStart = (/* @__PURE__ */ new Date()).toISOString();
  const partition = getPartition(region);
  let adminAccountId;
  try {
    adminAccountId = await getAccountId(region);
  } catch {
    adminAccountId = "unknown";
  }
  let accounts;
  try {
    accounts = await listOrgAccounts(region);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const result = await runAllScanners(scanners, region);
    if (result.modules.length > 0) {
      if (!result.modules[0].warnings) result.modules[0].warnings = [];
      result.modules[0].warnings.unshift(`org_mode enabled but Organizations listing failed: ${errMsg}. Scanning current account only.`);
    }
    return result;
  }
  if (opts.accountIds?.length) {
    const idSet = new Set(opts.accountIds);
    accounts = accounts.filter((a) => idSet.has(a.id));
  }
  const aggregationScanners = scanners.filter((s) => AGGREGATION_MODULES.has(s.moduleName));
  const perAccountScanners = scanners.filter((s) => !AGGREGATION_MODULES.has(s.moduleName));
  const allModules = [];
  if (aggregationScanners.length > 0) {
    const adminCtx = { region, partition, accountId: adminAccountId };
    const aggResults = await runScannersWithContext(aggregationScanners, adminCtx);
    allModules.push(...aggResults);
  }
  for (const account of accounts) {
    let credentials;
    let accountAlias = account.name;
    if (account.id !== adminAccountId) {
      try {
        const roleArn = buildRoleArn(account.id, opts.roleName, partition);
        credentials = await assumeRole(roleArn, region);
      } catch (err) {
        allModules.push({
          module: `assume_role_${account.id}`,
          status: "error",
          error: `Failed to assume role in account ${account.id} (${account.name}): ${err instanceof Error ? err.message : String(err)}`,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: 0,
          findings: []
        });
        continue;
      }
    }
    const ctx = {
      region,
      partition,
      accountId: account.id,
      accountAlias,
      credentials
    };
    const accountResults = await runScannersWithContext(perAccountScanners, ctx);
    allModules.push(...accountResults);
  }
  const scanEnd = (/* @__PURE__ */ new Date()).toISOString();
  if (opts.accountIds?.length) {
    const idSet = new Set(opts.accountIds);
    for (const mod of allModules) {
      if (AGGREGATION_MODULES.has(mod.module)) {
        mod.findings = mod.findings.filter((f) => !f.accountId || idSet.has(f.accountId));
        mod.findingsCount = mod.findings.length;
      }
    }
  }
  return {
    scanStart,
    scanEnd,
    region,
    accountId: adminAccountId,
    modules: allModules,
    summary: buildSummary(allModules)
  };
}

// src/scanners/service-detection.ts
import {
  SecurityHubClient,
  DescribeHubCommand
} from "@aws-sdk/client-securityhub";
import {
  GuardDutyClient,
  ListDetectorsCommand
} from "@aws-sdk/client-guardduty";
import {
  Inspector2Client,
  BatchGetAccountStatusCommand
} from "@aws-sdk/client-inspector2";
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand
} from "@aws-sdk/client-config-service";
import {
  Macie2Client,
  GetMacieSessionCommand
} from "@aws-sdk/client-macie2";
import {
  CloudTrailClient,
  DescribeTrailsCommand
} from "@aws-sdk/client-cloudtrail";

// src/utils/risk-scoring.ts
function severityFromScore(score) {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}
function priorityFromSeverity(severity) {
  switch (severity) {
    case "CRITICAL":
      return "P0";
    case "HIGH":
      return "P1";
    case "MEDIUM":
      return "P2";
    case "LOW":
      return "P3";
  }
}

// src/scanners/service-detection.ts
function makeFinding(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function isAccessDenied(err) {
  if (!(err instanceof Error)) return false;
  const name = err.name ?? "";
  const code = err.Code ?? "";
  return name === "AccessDeniedException" || name === "UnauthorizedAccess" || name === "AccessDenied" || code === "AccessDeniedException" || code === "AccessDenied" || name === "ForbiddenException" || // AWS SDK v3 uses __type or $metadata for some errors
  (err.message?.includes("is not authorized to perform") ?? false) || (err.message?.includes("Access Denied") ?? false);
}
function isNotEnabled(err) {
  if (!(err instanceof Error)) return false;
  return err.name === "InvalidAccessException" || // Security Hub specific
  err.name === "DisabledException" || err.message.includes("not enabled") || err.message.includes("not subscribed");
}
function computeMaturityLevel(enabledCount) {
  if (enabledCount >= 6) return "comprehensive";
  if (enabledCount >= 4) return "advanced";
  if (enabledCount >= 2) return "intermediate";
  return "basic";
}
var ServiceDetectionScanner = class {
  moduleName = "service_detection";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    const services = [];
    try {
      const ct = createClient(CloudTrailClient, region, ctx.credentials);
      const resp = await ct.send(new DescribeTrailsCommand({}));
      const trails = resp.trailList ?? [];
      if (trails.length > 0) {
        services.push({
          name: "CloudTrail",
          enabled: true,
          details: `${trails.length} trail(s) configured`
        });
      } else {
        services.push({
          name: "CloudTrail",
          enabled: false,
          recommendation: "Create a multi-region trail for API logging"
        });
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("CloudTrail: insufficient permissions to check status");
        services.push({ name: "CloudTrail", enabled: null, details: "Access denied" });
      } else if (isNotEnabled(err)) {
        services.push({
          name: "CloudTrail",
          enabled: false,
          recommendation: "Create a multi-region trail for API logging"
        });
      } else {
        warnings.push(`CloudTrail detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "CloudTrail", enabled: null, details: "Detection error" });
      }
    }
    try {
      const sh = createClient(SecurityHubClient, region, ctx.credentials);
      await sh.send(new DescribeHubCommand({}));
      services.push({
        name: "Security Hub",
        enabled: true,
        details: "Enabled with automated security checks"
      });
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Security Hub: insufficient permissions to check status");
        services.push({ name: "Security Hub", enabled: null, details: "Access denied" });
      } else if (isNotEnabled(err)) {
        services.push({
          name: "Security Hub",
          enabled: false,
          recommendation: "Enable Security Hub for 300+ automated security checks",
          freeTrialAvailable: true
        });
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "AWS Security Hub is not enabled",
            resourceType: "AWS::SecurityHub::Hub",
            resourceId: "securityhub",
            resourceArn: `arn:${partition}:securityhub:${region}:${accountId}:hub/default`,
            region,
            description: "AWS Security Hub is not enabled in this region. Security Hub provides a comprehensive view of security alerts and compliance status.",
            impact: "Enables 300+ automated security checks across AWS services. Without it, security findings are fragmented across individual services.",
            remediationSteps: [
              "Open the AWS Security Hub console.",
              "Click 'Go to Security Hub' and enable it.",
              "Enable the AWS Foundational Security Best Practices standard.",
              "Security Hub offers a 30-day free trial."
            ]
          })
        );
      } else {
        warnings.push(`Security Hub detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "Security Hub", enabled: null, details: "Detection error" });
      }
    }
    try {
      const gd = createClient(GuardDutyClient, region, ctx.credentials);
      const resp = await gd.send(new ListDetectorsCommand({}));
      const detectors = resp.DetectorIds ?? [];
      if (detectors.length > 0) {
        services.push({
          name: "GuardDuty",
          enabled: true,
          details: `${detectors.length} detector(s) active`
        });
      } else {
        services.push({
          name: "GuardDuty",
          enabled: false,
          recommendation: "Enable GuardDuty for continuous threat detection",
          freeTrialAvailable: true
        });
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "Amazon GuardDuty is not enabled",
            resourceType: "AWS::GuardDuty::Detector",
            resourceId: "guardduty",
            resourceArn: `arn:${partition}:guardduty:${region}:${accountId}:detector/none`,
            region,
            description: "Amazon GuardDuty is not enabled in this region. GuardDuty provides intelligent threat detection by analyzing CloudTrail, VPC Flow Logs, and DNS logs.",
            impact: "Provides continuous threat detection for account compromise, instance compromise, and malicious reconnaissance. Without it, many attack patterns go undetected.",
            remediationSteps: [
              "Open the Amazon GuardDuty console.",
              "Click 'Get Started' and enable GuardDuty.",
              "GuardDuty offers a 30-day free trial.",
              "Consider enabling S3 protection and EKS protection add-ons."
            ]
          })
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("GuardDuty: insufficient permissions to check status");
        services.push({ name: "GuardDuty", enabled: null, details: "Access denied" });
      } else if (isNotEnabled(err)) {
        services.push({
          name: "GuardDuty",
          enabled: false,
          recommendation: "Enable GuardDuty for continuous threat detection",
          freeTrialAvailable: true
        });
        findings.push(
          makeFinding({
            riskScore: 7.5,
            title: "Amazon GuardDuty is not enabled",
            resourceType: "AWS::GuardDuty::Detector",
            resourceId: "guardduty",
            resourceArn: `arn:${partition}:guardduty:${region}:${accountId}:detector/none`,
            region,
            description: "Amazon GuardDuty is not enabled in this region. GuardDuty provides intelligent threat detection by analyzing CloudTrail, VPC Flow Logs, and DNS logs.",
            impact: "Provides continuous threat detection for account compromise, instance compromise, and malicious reconnaissance. Without it, many attack patterns go undetected.",
            remediationSteps: [
              "Open the Amazon GuardDuty console.",
              "Click 'Get Started' and enable GuardDuty.",
              "GuardDuty offers a 30-day free trial.",
              "Consider enabling S3 protection and EKS protection add-ons."
            ]
          })
        );
      } else {
        warnings.push(`GuardDuty detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "GuardDuty", enabled: null, details: "Detection error" });
      }
    }
    try {
      const insp = createClient(Inspector2Client, region, ctx.credentials);
      const resp = await insp.send(new BatchGetAccountStatusCommand({ accountIds: [accountId] }));
      const accounts = resp.accounts ?? [];
      const active = accounts.some(
        (a) => a.state?.status === "ENABLED" || a.state?.status === "ENABLING"
      );
      if (active) {
        services.push({
          name: "Inspector",
          enabled: true,
          details: "Vulnerability scanning active"
        });
      } else {
        services.push({
          name: "Inspector",
          enabled: false,
          recommendation: "Enable Inspector to scan for software vulnerabilities",
          freeTrialAvailable: true
        });
        findings.push(
          makeFinding({
            riskScore: 6,
            title: "Amazon Inspector is not enabled",
            resourceType: "AWS::Inspector2::AccountStatus",
            resourceId: "inspector",
            resourceArn: `arn:${partition}:inspector2:${region}:${accountId}:account`,
            region,
            description: "Amazon Inspector is not enabled in this region. Inspector automatically discovers and scans EC2 instances, containers, and Lambda functions for software vulnerabilities.",
            impact: "Scans for software vulnerabilities in EC2 instances, container images, and Lambda functions. Without it, known CVEs may go undetected.",
            remediationSteps: [
              "Open the Amazon Inspector console.",
              "Click 'Get Started' and enable Inspector.",
              "Inspector offers a 15-day free trial.",
              "Enable scanning for EC2, ECR, and Lambda as appropriate."
            ]
          })
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("Inspector: insufficient permissions to check status");
        services.push({ name: "Inspector", enabled: null, details: "Access denied" });
      } else if (isNotEnabled(err)) {
        services.push({
          name: "Inspector",
          enabled: false,
          recommendation: "Enable Inspector to scan for software vulnerabilities",
          freeTrialAvailable: true
        });
        findings.push(
          makeFinding({
            riskScore: 6,
            title: "Amazon Inspector is not enabled",
            resourceType: "AWS::Inspector2::AccountStatus",
            resourceId: "inspector",
            resourceArn: `arn:${partition}:inspector2:${region}:${accountId}:account`,
            region,
            description: "Amazon Inspector is not enabled in this region. Inspector automatically discovers and scans EC2 instances, containers, and Lambda functions for software vulnerabilities.",
            impact: "Scans for software vulnerabilities in EC2 instances, container images, and Lambda functions. Without it, known CVEs may go undetected.",
            remediationSteps: [
              "Open the Amazon Inspector console.",
              "Click 'Get Started' and enable Inspector.",
              "Inspector offers a 15-day free trial.",
              "Enable scanning for EC2, ECR, and Lambda as appropriate."
            ]
          })
        );
      } else {
        warnings.push(`Inspector detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "Inspector", enabled: null, details: "Detection error" });
      }
    }
    try {
      const cfg = createClient(ConfigServiceClient, region, ctx.credentials);
      const resp = await cfg.send(new DescribeConfigurationRecordersCommand({}));
      const recorders = resp.ConfigurationRecorders ?? [];
      if (recorders.length > 0) {
        services.push({
          name: "AWS Config",
          enabled: true,
          details: `${recorders.length} recorder(s) configured`
        });
      } else {
        services.push({
          name: "AWS Config",
          enabled: false,
          recommendation: "Enable AWS Config to track configuration changes"
        });
        findings.push(
          makeFinding({
            riskScore: 6,
            title: "AWS Config is not enabled",
            resourceType: "AWS::Config::ConfigurationRecorder",
            resourceId: "config",
            resourceArn: `arn:${partition}:config:${region}:${accountId}:configuration-recorder/none`,
            region,
            description: "AWS Config is not enabled in this region. Config continuously records resource configurations and enables compliance auditing.",
            impact: "Tracks configuration changes and enables compliance rules. Without it, configuration drift and non-compliant resources go undetected.",
            remediationSteps: [
              "Open the AWS Config console.",
              "Click 'Get Started' and configure a recorder.",
              "Select the resource types to record.",
              "Configure an S3 bucket for configuration snapshots."
            ]
          })
        );
      }
    } catch (err) {
      if (isAccessDenied(err)) {
        warnings.push("AWS Config: insufficient permissions to check status");
        services.push({ name: "AWS Config", enabled: null, details: "Access denied" });
      } else if (isNotEnabled(err)) {
        services.push({
          name: "AWS Config",
          enabled: false,
          recommendation: "Enable AWS Config to track configuration changes"
        });
        findings.push(
          makeFinding({
            riskScore: 6,
            title: "AWS Config is not enabled",
            resourceType: "AWS::Config::ConfigurationRecorder",
            resourceId: "config",
            resourceArn: `arn:${partition}:config:${region}:${accountId}:configuration-recorder/none`,
            region,
            description: "AWS Config is not enabled in this region. Config continuously records resource configurations and enables compliance auditing.",
            impact: "Tracks configuration changes and enables compliance rules. Without it, configuration drift and non-compliant resources go undetected.",
            remediationSteps: [
              "Open the AWS Config console.",
              "Click 'Get Started' and configure a recorder.",
              "Select the resource types to record.",
              "Configure an S3 bucket for configuration snapshots."
            ]
          })
        );
      } else {
        warnings.push(`AWS Config detection failed: ${err instanceof Error ? err.message : String(err)}`);
        services.push({ name: "AWS Config", enabled: null, details: "Detection error" });
      }
    }
    if (region.startsWith("cn-")) {
      services.push({ name: "Macie", enabled: null, details: "Not available in China regions" });
      warnings.push("Macie is not available in AWS China regions.");
    } else {
      try {
        const mc = createClient(Macie2Client, region, ctx.credentials);
        await mc.send(new GetMacieSessionCommand({}));
        services.push({
          name: "Macie",
          enabled: true,
          details: "Sensitive data detection active"
        });
      } catch (err) {
        if (isAccessDenied(err)) {
          warnings.push("Macie: insufficient permissions to check status");
          services.push({ name: "Macie", enabled: null, details: "Access denied" });
        } else if (isNotEnabled(err)) {
          services.push({
            name: "Macie",
            enabled: false,
            recommendation: "Enable Macie to detect sensitive data in S3",
            freeTrialAvailable: true
          });
          findings.push(
            makeFinding({
              riskScore: 5,
              title: "Amazon Macie is not enabled",
              resourceType: "AWS::Macie::Session",
              resourceId: "macie",
              resourceArn: `arn:${partition}:macie2:${region}:${accountId}:session`,
              region,
              description: "Amazon Macie is not enabled in this region. Macie uses machine learning to discover and protect sensitive data stored in S3.",
              impact: "Detects sensitive data (PII, credentials, financial data) in S3 buckets. Without it, sensitive data exposure may go unnoticed.",
              remediationSteps: [
                "Open the Amazon Macie console.",
                "Click 'Get Started' and enable Macie.",
                "Macie offers a 30-day free trial for sensitive data discovery.",
                "Configure automated sensitive data discovery jobs."
              ]
            })
          );
        } else {
          warnings.push(`Macie detection failed: ${err instanceof Error ? err.message : String(err)}`);
          services.push({ name: "Macie", enabled: null, details: "Detection error" });
        }
      }
    }
    const knownServices = services.filter((s) => s.enabled !== null);
    const enabledCount = services.filter((s) => s.enabled === true).length;
    const coveragePercent = knownServices.length > 0 ? Math.round(enabledCount / knownServices.length * 100) : 0;
    const maturityLevel = computeMaturityLevel(enabledCount);
    const detectionResult = {
      services,
      coveragePercent,
      maturityLevel
    };
    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : void 0,
      resourcesScanned: services.length,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
      // Attach the structured detection result as a custom property via the findings metadata
      ...{ serviceDetection: detectionResult }
    };
  }
};

// src/scanners/secret-exposure.ts
import {
  LambdaClient,
  ListFunctionsCommand
} from "@aws-sdk/client-lambda";
import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeInstanceAttributeCommand
} from "@aws-sdk/client-ec2";
var SECRET_PATTERNS = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/, matchType: "value" },
  { name: "Private Key", pattern: /-----BEGIN.*PRIVATE KEY-----/, matchType: "value" },
  { name: "Password in env var", pattern: /^(PASSWORD|PASSWD|DB_PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|AUTH_TOKEN)$/i, matchType: "name" }
];
function makeFinding2(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var SecretExposureScanner = class {
  moduleName = "secret_exposure";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      try {
        const lambda = createClient(LambdaClient, region, ctx.credentials);
        const functions = [];
        let marker;
        do {
          const resp = await lambda.send(
            new ListFunctionsCommand({ Marker: marker })
          );
          if (resp.Functions) functions.push(...resp.Functions);
          marker = resp.NextMarker;
        } while (marker);
        resourcesScanned += functions.length;
        for (const fn of functions) {
          const fnName = fn.FunctionName ?? "unknown";
          const fnArn = fn.FunctionArn ?? `arn:${partition}:lambda:${region}:${accountId}:function:${fnName}`;
          const envVars = fn.Environment?.Variables ?? {};
          for (const [varName, varValue] of Object.entries(envVars)) {
            for (const sp of SECRET_PATTERNS) {
              if (sp.matchType === "name") {
                if (sp.pattern.test(varName)) {
                  findings.push(
                    makeFinding2({
                      riskScore: 7.5,
                      title: `Lambda ${fnName} has suspicious env var "${varName}"`,
                      resourceType: "AWS::Lambda::Function",
                      resourceId: fnName,
                      resourceArn: fnArn,
                      region,
                      description: `Lambda function "${fnName}" has an environment variable named "${varName}" which may contain a secret.`,
                      impact: "Secrets in Lambda environment variables are visible to anyone with lambda:GetFunctionConfiguration permission and may leak through logs.",
                      remediationSteps: [
                        "Move the secret to AWS Secrets Manager or SSM Parameter Store (SecureString).",
                        "Update the Lambda function to fetch the secret at runtime.",
                        "Rotate the exposed credential immediately."
                      ]
                    })
                  );
                }
              } else {
                if (sp.pattern.test(varValue)) {
                  const riskScore = sp.name === "AWS Access Key" ? 9.5 : 9;
                  findings.push(
                    makeFinding2({
                      riskScore,
                      title: `Lambda ${fnName} env var contains ${sp.name}`,
                      resourceType: "AWS::Lambda::Function",
                      resourceId: fnName,
                      resourceArn: fnArn,
                      region,
                      description: `Lambda function "${fnName}" has an environment variable containing a ${sp.name} pattern.`,
                      impact: "Hard-coded credentials in Lambda environment variables can be extracted by any principal with read access to the function configuration.",
                      remediationSteps: [
                        "Remove the hard-coded credential from environment variables.",
                        "Use AWS Secrets Manager or SSM Parameter Store (SecureString) instead.",
                        "Rotate the exposed credential immediately.",
                        "Review CloudTrail logs for unauthorized use of the credential."
                      ]
                    })
                  );
                }
              }
            }
          }
        }
      } catch (e) {
        warnings.push(`Lambda scan error: ${e instanceof Error ? e.message : String(e)}`);
      }
      try {
        const ec2 = createClient(EC2Client, region, ctx.credentials);
        const instances = [];
        let nextToken;
        do {
          const resp = await ec2.send(
            new DescribeInstancesCommand({ NextToken: nextToken })
          );
          for (const res of resp.Reservations ?? []) {
            if (res.Instances) instances.push(...res.Instances);
          }
          nextToken = resp.NextToken;
        } while (nextToken);
        resourcesScanned += instances.length;
        for (const inst of instances) {
          const instId = inst.InstanceId ?? "unknown";
          const instArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`;
          let userData;
          try {
            const attrResp = await ec2.send(
              new DescribeInstanceAttributeCommand({
                InstanceId: instId,
                Attribute: "userData"
              })
            );
            const raw = attrResp.UserData?.Value;
            if (raw) {
              userData = Buffer.from(raw, "base64").toString("utf-8");
            }
          } catch (e) {
            warnings.push(`Could not read userData for ${instId}: ${e instanceof Error ? e.message : String(e)}`);
            continue;
          }
          if (!userData) continue;
          for (const sp of SECRET_PATTERNS) {
            if (sp.matchType === "name") continue;
            if (sp.pattern.test(userData)) {
              const riskScore = sp.name === "AWS Access Key" ? 9.5 : 8;
              findings.push(
                makeFinding2({
                  riskScore,
                  title: `EC2 ${instId} userData contains ${sp.name}`,
                  resourceType: "AWS::EC2::Instance",
                  resourceId: instId,
                  resourceArn: instArn,
                  region,
                  description: `EC2 instance "${instId}" has user data containing a ${sp.name} pattern.`,
                  impact: "Instance user data is accessible to anyone with ec2:DescribeInstanceAttribute permission and from the instance metadata service.",
                  remediationSteps: [
                    "Remove the secret from instance user data.",
                    "Use IAM instance profiles for AWS API access instead of embedding keys.",
                    "Use Secrets Manager or SSM Parameter Store for other secrets.",
                    "Rotate the exposed credential immediately."
                  ]
                })
              );
            }
          }
        }
      } catch (e) {
        warnings.push(`EC2 userData scan error: ${e instanceof Error ? e.message : String(e)}`);
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/ssl-certificate.ts
import {
  ACMClient,
  ListCertificatesCommand,
  DescribeCertificateCommand
} from "@aws-sdk/client-acm";
function makeFinding3(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var SslCertificateScanner = class {
  moduleName = "ssl_certificate";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      const client = createClient(ACMClient, region, ctx.credentials);
      const certs = [];
      let nextToken;
      do {
        const resp = await client.send(
          new ListCertificatesCommand({ NextToken: nextToken })
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
            new DescribeCertificateCommand({ CertificateArn: certArn })
          );
          detail = descResp.Certificate;
        } catch (e) {
          warnings.push(`Could not describe certificate ${certArn}: ${e instanceof Error ? e.message : String(e)}`);
          continue;
        }
        if (!detail) continue;
        const status = detail.Status ?? "UNKNOWN";
        const inUseBy = detail.InUseBy ?? [];
        const inUseStr = inUseBy.length > 0 ? ` In use by ${inUseBy.length} resource(s).` : " Not currently in use.";
        if (status === "FAILED") {
          findings.push(
            makeFinding3({
              riskScore: 7.5,
              title: `Certificate for ${domainName} is in FAILED status`,
              resourceType: "AWS::ACM::Certificate",
              resourceId: domainName,
              resourceArn: certArn,
              region,
              description: `ACM certificate for "${domainName}" has status FAILED.${inUseStr}`,
              impact: "The certificate failed validation and cannot be used for TLS termination. Services relying on it may lose HTTPS protection.",
              remediationSteps: [
                "Check the failure reason in the ACM console.",
                "Request a new certificate with correct domain validation.",
                "If using DNS validation, ensure the CNAME records are correctly configured."
              ]
            })
          );
          continue;
        }
        if (status === "ISSUED" && detail.NotAfter) {
          const now = /* @__PURE__ */ new Date();
          const expiryDate = new Date(detail.NotAfter);
          const daysUntilExpiry = Math.floor(
            (expiryDate.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24)
          );
          if (daysUntilExpiry < 0) {
            findings.push(
              makeFinding3({
                riskScore: 8,
                title: `Certificate for ${domainName} has expired`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expired ${Math.abs(daysUntilExpiry)} days ago.${inUseStr}`,
                impact: "Expired certificates cause TLS errors for end users. Browsers will display security warnings and block access.",
                remediationSteps: [
                  "Renew or replace the certificate immediately.",
                  "If using ACM-managed renewal, check why automatic renewal failed.",
                  "Verify domain validation records are still in place."
                ]
              })
            );
          } else if (daysUntilExpiry < 30) {
            findings.push(
              makeFinding3({
                riskScore: 6,
                title: `Certificate for ${domainName} expires in ${daysUntilExpiry} days`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expires in ${daysUntilExpiry} days (${expiryDate.toISOString().split("T")[0]}).${inUseStr}`,
                impact: "Certificate will expire soon. If not renewed, services will experience TLS errors.",
                remediationSteps: [
                  "Verify ACM automatic renewal is working (check renewal status).",
                  "If imported certificate, prepare and import the renewed certificate.",
                  "Set up CloudWatch alarms for certificate expiry."
                ]
              })
            );
          } else if (daysUntilExpiry < 90) {
            findings.push(
              makeFinding3({
                riskScore: 4,
                title: `Certificate for ${domainName} expires in ${daysUntilExpiry} days`,
                resourceType: "AWS::ACM::Certificate",
                resourceId: domainName,
                resourceArn: certArn,
                region,
                description: `ACM certificate for "${domainName}" expires in ${daysUntilExpiry} days (${expiryDate.toISOString().split("T")[0]}).${inUseStr}`,
                impact: "Certificate is approaching expiry. Plan renewal to avoid service disruption.",
                remediationSteps: [
                  "Verify ACM automatic renewal is configured and working.",
                  "If imported certificate, begin the renewal process.",
                  "Consider setting up monitoring for certificate expiry dates."
                ]
              })
            );
          }
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: certs.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/dns-dangling.ts
import {
  Route53Client,
  ListHostedZonesCommand,
  ListResourceRecordSetsCommand
} from "@aws-sdk/client-route-53";
import {
  S3Client,
  HeadBucketCommand
} from "@aws-sdk/client-s3";
import { promises as dns } from "dns";
function makeFinding4(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function extractS3BucketName(target) {
  const s3Pattern = /^([^.]+)\.s3[.-]/;
  const m = target.match(s3Pattern);
  return m ? m[1] : null;
}
function classifyTarget(target) {
  if (/\.s3[.-](.*\.)?amazonaws\.com(\.cn)?\.?$/.test(target)) return "s3";
  if (/\.elb\.amazonaws\.com(\.cn)?\.?$/.test(target)) return "elb";
  if (/\.cloudfront\.net\.?$/.test(target)) return "cloudfront";
  return null;
}
async function dnsResolves(hostname) {
  try {
    const h = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
    await dns.resolve(h);
    return true;
  } catch {
    return false;
  }
}
var DnsDanglingScanner = class {
  moduleName = "dns_dangling";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const route53 = createClient(Route53Client, region, ctx.credentials);
      const zones = [];
      let marker;
      do {
        const resp = await route53.send(
          new ListHostedZonesCommand({ Marker: marker })
        );
        if (resp.HostedZones) zones.push(...resp.HostedZones);
        marker = resp.IsTruncated ? resp.NextMarker : void 0;
      } while (marker);
      for (const zone of zones) {
        const zoneId = zone.Id ?? "unknown";
        const zoneName = zone.Name ?? "unknown";
        const shortZoneId = zoneId.replace("/hostedzone/", "");
        const records = [];
        let nextName;
        let nextType;
        do {
          const resp = await route53.send(
            new ListResourceRecordSetsCommand({
              HostedZoneId: shortZoneId,
              StartRecordName: nextName,
              StartRecordType: nextType
            })
          );
          if (resp.ResourceRecordSets) records.push(...resp.ResourceRecordSets);
          if (resp.IsTruncated) {
            nextName = resp.NextRecordName;
            nextType = resp.NextRecordType;
          } else {
            nextName = void 0;
            nextType = void 0;
          }
        } while (nextName);
        const cnameRecords = records.filter(
          (r) => r.Type === "CNAME" && r.ResourceRecords && r.ResourceRecords.length > 0
        );
        resourcesScanned += cnameRecords.length;
        for (const record of cnameRecords) {
          const recordName = record.Name ?? "unknown";
          const target = record.ResourceRecords[0].Value ?? "";
          const recordArn = `arn:${partition}:route53:::hostedzone/${shortZoneId}`;
          const targetType = classifyTarget(target);
          if (targetType === "s3") {
            const bucketName = extractS3BucketName(target);
            if (bucketName) {
              let bucketExists = false;
              try {
                const s3 = createClient(S3Client, region, ctx.credentials);
                await s3.send(new HeadBucketCommand({ Bucket: bucketName }));
                bucketExists = true;
              } catch (e) {
                const errName = e.name ?? "";
                if (errName === "Forbidden" || errName === "AccessDenied" || errName === "403") {
                  bucketExists = true;
                }
              }
              if (!bucketExists) {
                findings.push(
                  makeFinding4({
                    riskScore: 9.5,
                    title: `CNAME ${recordName} points to non-existent S3 bucket "${bucketName}"`,
                    resourceType: "AWS::Route53::RecordSet",
                    resourceId: recordName,
                    resourceArn: recordArn,
                    region,
                    description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to S3 bucket "${bucketName}" which does not exist. An attacker can claim this bucket for subdomain takeover.`,
                    impact: "Critical subdomain takeover vulnerability. An attacker can create the S3 bucket and serve arbitrary content on your domain, enabling phishing, cookie theft, and reputation damage.",
                    remediationSteps: [
                      "Immediately create the S3 bucket to prevent takeover.",
                      "Remove the dangling DNS record if the bucket is no longer needed.",
                      "Audit all CNAME records pointing to S3 buckets."
                    ]
                  })
                );
              }
            }
          } else if (targetType === "elb") {
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding4({
                  riskScore: 8,
                  title: `CNAME ${recordName} points to non-resolving ELB`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to ELB "${target}" which does not resolve. The load balancer may have been deleted.`,
                  impact: "Potential subdomain takeover if the ELB DNS name can be re-registered. Dangling DNS records indicate resource lifecycle gaps.",
                  remediationSteps: [
                    "Remove the dangling DNS record.",
                    "If the ELB was deleted, clean up all associated DNS records.",
                    "Implement automated DNS record cleanup when decommissioning resources."
                  ]
                })
              );
            }
          } else if (targetType === "cloudfront") {
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding4({
                  riskScore: 7.5,
                  title: `CNAME ${recordName} points to non-resolving CloudFront distribution`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to CloudFront "${target}" which does not resolve. The distribution may have been deleted.`,
                  impact: "Potential subdomain takeover via CloudFront. An attacker may create a distribution with this alternate domain name.",
                  remediationSteps: [
                    "Remove the dangling DNS record.",
                    "If the CloudFront distribution was deleted, clean up associated DNS records.",
                    "Use CloudFront Origin Access Identity to limit exposure."
                  ]
                })
              );
            }
          } else if (targetType === null) {
            const resolves = await dnsResolves(target);
            if (!resolves) {
              findings.push(
                makeFinding4({
                  riskScore: 5,
                  title: `CNAME ${recordName} target does not resolve`,
                  resourceType: "AWS::Route53::RecordSet",
                  resourceId: recordName,
                  resourceArn: recordArn,
                  region,
                  description: `DNS record "${recordName}" in zone "${zoneName}" has a CNAME to "${target}" which does not resolve.`,
                  impact: "Orphaned DNS record pointing to a non-existent target. May indicate incomplete resource cleanup.",
                  remediationSteps: [
                    "Verify the target resource still exists.",
                    "Remove the DNS record if it is no longer needed.",
                    "Implement DNS record lifecycle management."
                  ]
                })
              );
            }
          }
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/network-reachability.ts
import {
  EC2Client as EC2Client2,
  DescribeInstancesCommand as DescribeInstancesCommand2,
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeAddressesCommand
} from "@aws-sdk/client-ec2";
var HIGH_RISK_PORTS = {
  22: "SSH",
  3389: "RDP",
  3306: "MySQL",
  5432: "PostgreSQL",
  1433: "MSSQL",
  27017: "MongoDB",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached"
};
function makeFinding5(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function sgAllowsPort(sgs, port) {
  for (const sg of sgs) {
    for (const perm of sg.IpPermissions ?? []) {
      if (permissionAllowsWorldPort(perm, port)) return true;
    }
  }
  return false;
}
function sgAllowsAllPorts(sgs) {
  for (const sg of sgs) {
    for (const perm of sg.IpPermissions ?? []) {
      if (isAllPorts(perm) && hasWorldCidr(perm)) return true;
    }
  }
  return false;
}
function permissionAllowsWorldPort(perm, port) {
  if (!hasWorldCidr(perm)) return false;
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  if (from === -1 && to === -1) return true;
  return port >= from && port <= to;
}
function hasWorldCidr(perm) {
  const hasIpv4 = (perm.IpRanges ?? []).some((r) => r.CidrIp === "0.0.0.0/0");
  const hasIpv6 = (perm.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === "::/0");
  return hasIpv4 || hasIpv6;
}
function isAllPorts(perm) {
  const from = perm.FromPort ?? -1;
  const to = perm.ToPort ?? -1;
  return from === -1 && to === -1 || from === 0 && to === 65535;
}
function naclAllowsPort(nacl, port) {
  const inboundRules = (nacl.Entries ?? []).filter((e) => e.Egress === false).sort((a, b) => (a.RuleNumber ?? 0) - (b.RuleNumber ?? 0));
  for (const rule of inboundRules) {
    if (naclRuleMatchesPort(rule, port) && naclRuleMatchesWorldCidr(rule)) {
      return rule.RuleAction === "allow";
    }
  }
  return false;
}
function naclRuleMatchesPort(rule, port) {
  if (rule.Protocol === "-1") return true;
  if (rule.Protocol !== "6" && rule.Protocol !== "17") return false;
  const from = rule.PortRange?.From ?? 0;
  const to = rule.PortRange?.To ?? 65535;
  return port >= from && port <= to;
}
function naclRuleMatchesWorldCidr(rule) {
  return rule.CidrBlock === "0.0.0.0/0" || rule.Ipv6CidrBlock === "::/0";
}
var NetworkReachabilityScanner = class {
  moduleName = "network_reachability";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      const client = createClient(EC2Client2, region, ctx.credentials);
      const eipMap = /* @__PURE__ */ new Map();
      try {
        const eipResp = await client.send(new DescribeAddressesCommand({}));
        for (const addr of eipResp.Addresses ?? []) {
          if (addr.InstanceId && addr.PublicIp) {
            eipMap.set(addr.InstanceId, addr.PublicIp);
          }
        }
      } catch (e) {
        warnings.push(`Could not list Elastic IPs: ${e instanceof Error ? e.message : String(e)}`);
      }
      const instances = [];
      let nextToken;
      do {
        const resp = await client.send(
          new DescribeInstancesCommand2({ NextToken: nextToken })
        );
        for (const res of resp.Reservations ?? []) {
          if (res.Instances) instances.push(...res.Instances);
        }
        nextToken = resp.NextToken;
      } while (nextToken);
      const publicInstances = instances.filter((inst) => {
        const instId = inst.InstanceId ?? "";
        return inst.PublicIpAddress || eipMap.has(instId);
      });
      const sgIds = /* @__PURE__ */ new Set();
      const subnetIds = /* @__PURE__ */ new Set();
      for (const inst of publicInstances) {
        for (const sg of inst.SecurityGroups ?? []) {
          if (sg.GroupId) sgIds.add(sg.GroupId);
        }
        if (inst.SubnetId) subnetIds.add(inst.SubnetId);
      }
      const sgMap = /* @__PURE__ */ new Map();
      if (sgIds.size > 0) {
        const sgResp = await client.send(
          new DescribeSecurityGroupsCommand({
            GroupIds: [...sgIds]
          })
        );
        for (const sg of sgResp.SecurityGroups ?? []) {
          if (sg.GroupId) sgMap.set(sg.GroupId, sg);
        }
      }
      const subnetNaclMap = /* @__PURE__ */ new Map();
      if (subnetIds.size > 0) {
        let naclToken;
        const allNacls = [];
        do {
          const naclResp = await client.send(
            new DescribeNetworkAclsCommand({
              Filters: [{ Name: "association.subnet-id", Values: [...subnetIds] }],
              NextToken: naclToken
            })
          );
          if (naclResp.NetworkAcls) allNacls.push(...naclResp.NetworkAcls);
          naclToken = naclResp.NextToken;
        } while (naclToken);
        for (const nacl of allNacls) {
          for (const assoc of nacl.Associations ?? []) {
            if (assoc.SubnetId) {
              subnetNaclMap.set(assoc.SubnetId, nacl);
            }
          }
        }
      }
      for (const inst of publicInstances) {
        const instId = inst.InstanceId ?? "unknown";
        const instArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`;
        const publicIp = inst.PublicIpAddress ?? eipMap.get(instId) ?? "unknown";
        const subnetId = inst.SubnetId ?? "";
        const instSgs = [];
        for (const sg of inst.SecurityGroups ?? []) {
          if (sg.GroupId) {
            const fullSg = sgMap.get(sg.GroupId);
            if (fullSg) instSgs.push(fullSg);
          }
        }
        const nacl = subnetNaclMap.get(subnetId);
        for (const [portStr, portName] of Object.entries(HIGH_RISK_PORTS)) {
          const port = Number(portStr);
          const sgAllows = sgAllowsPort(instSgs, port);
          const naclAllows = nacl ? naclAllowsPort(nacl, port) : true;
          if (sgAllows && naclAllows) {
            findings.push(
              makeFinding5({
                riskScore: 9.5,
                title: `EC2 ${instId} (${publicIp}): ${portName} (${port}) reachable from internet`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" has public IP ${publicIp} and both its security group(s) and subnet NACL allow inbound ${portName} (port ${port}) from the internet.`,
                impact: `${portName} is directly reachable from the internet, enabling brute-force, exploitation, or unauthorized access.`,
                remediationSteps: [
                  `Restrict security group inbound rules for port ${port} to specific IPs.`,
                  "Use Systems Manager Session Manager or a bastion host instead of direct access.",
                  "Add NACL deny rules for high-risk ports as an additional layer.",
                  "Enable VPC Flow Logs to monitor connection attempts."
                ]
              })
            );
          } else if (sgAllows && !naclAllows) {
            findings.push(
              makeFinding5({
                riskScore: 2,
                title: `EC2 ${instId}: ${portName} (${port}) allowed by SG but blocked by NACL`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" (${publicIp}) has security group rules allowing ${portName} (port ${port}) from the internet, but the subnet NACL blocks it.`,
                impact: "Currently protected by NACL, but the SG is overly permissive. NACL changes could expose the port.",
                remediationSteps: [
                  `Tighten the security group rules for port ${port} to match the intended access.`,
                  "Do not rely solely on NACLs for access control."
                ]
              })
            );
          }
        }
        if (sgAllowsAllPorts(instSgs)) {
          const naclOpen = nacl ? naclAllowsPort(nacl, 80) : true;
          if (naclOpen) {
            findings.push(
              makeFinding5({
                riskScore: 8,
                title: `EC2 ${instId} (${publicIp}): all ports reachable from internet`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: instArn,
                region,
                description: `EC2 instance "${instId}" has public IP ${publicIp} and its security group allows all ports from the internet with no NACL restriction.`,
                impact: "All services on this instance are exposed to the internet, creating a large attack surface.",
                remediationSteps: [
                  "Replace the all-ports SG rule with specific port rules.",
                  "Implement NACL rules to restrict inbound traffic as defense in depth.",
                  "Audit all services running on the instance."
                ]
              })
            );
          }
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: publicInstances.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/iam-privilege-escalation.ts
import {
  IAMClient,
  ListUsersCommand,
  ListAttachedUserPoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand
} from "@aws-sdk/client-iam";
function makeFinding6(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function extractActions(doc) {
  const actions = [];
  if (!doc || typeof doc !== "object") return actions;
  const policy = doc;
  const stmts = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
  for (const stmt of stmts) {
    if (stmt.Effect !== "Allow") continue;
    const acts = Array.isArray(stmt.Action) ? stmt.Action : stmt.Action ? [stmt.Action] : [];
    actions.push(...acts);
  }
  return actions.map((a) => a.toLowerCase());
}
function hasAction(actions, pattern) {
  const pat = pattern.toLowerCase();
  return actions.some((a) => {
    if (a === "*") return true;
    if (a === pat) return true;
    if (a.endsWith("*")) {
      const prefix = a.slice(0, -1);
      if (pat.startsWith(prefix)) return true;
    }
    return false;
  });
}
var IamPrivilegeEscalationScanner = class {
  moduleName = "iam_privilege_escalation";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    const iamRegion = getIamRegion(region);
    warnings.push(
      "Note: This scanner currently checks IAM users only. Role and group policy analysis will be added in a future version."
    );
    try {
      const client = createClient(IAMClient, iamRegion, ctx.credentials);
      const users = [];
      let marker;
      do {
        const resp = await client.send(
          new ListUsersCommand({ Marker: marker })
        );
        if (resp.Users) users.push(...resp.Users);
        marker = resp.IsTruncated ? resp.Marker : void 0;
      } while (marker);
      for (const user of users) {
        const userName = user.UserName ?? "unknown";
        const userArn = user.Arn ?? `arn:${partition}:iam::${accountId}:user/${userName}`;
        const allActions = [];
        try {
          const attachedResp = await client.send(
            new ListAttachedUserPoliciesCommand({ UserName: userName })
          );
          for (const policy of attachedResp.AttachedPolicies ?? []) {
            const policyArn = policy.PolicyArn;
            if (!policyArn) continue;
            try {
              const policyResp = await client.send(
                new GetPolicyCommand({ PolicyArn: policyArn })
              );
              const versionId = policyResp.Policy?.DefaultVersionId ?? "v1";
              const versionResp = await client.send(
                new GetPolicyVersionCommand({
                  PolicyArn: policyArn,
                  VersionId: versionId
                })
              );
              const doc = versionResp.PolicyVersion?.Document;
              if (doc) {
                const parsed = JSON.parse(decodeURIComponent(doc));
                allActions.push(...extractActions(parsed));
              }
            } catch (e) {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(
                `Could not read policy ${policyArn} for user ${userName}: ${msg}`
              );
            }
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(
            `Could not list attached policies for user ${userName}: ${msg}`
          );
        }
        try {
          const inlineResp = await client.send(
            new ListUserPoliciesCommand({ UserName: userName })
          );
          for (const policyName of inlineResp.PolicyNames ?? []) {
            try {
              const inlinePolicyResp = await client.send(
                new GetUserPolicyCommand({
                  UserName: userName,
                  PolicyName: policyName
                })
              );
              const doc = inlinePolicyResp.PolicyDocument;
              if (doc) {
                const parsed = JSON.parse(decodeURIComponent(doc));
                allActions.push(...extractActions(parsed));
              }
            } catch (e) {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(
                `Could not read inline policy ${policyName} for user ${userName}: ${msg}`
              );
            }
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(
            `Could not list inline policies for user ${userName}: ${msg}`
          );
        }
        if (allActions.length === 0) continue;
        if (hasAction(allActions, "iam:*") || allActions.includes("*")) {
          findings.push(
            makeFinding6({
              riskScore: 9,
              title: `IAM user ${userName} has iam:* wildcard permissions`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has wildcard IAM permissions (iam:* or *), granting full control over identity and access management.`,
              impact: "The user can create, modify, or delete any IAM resource including creating admin users, modifying policies, and escalating privileges without restriction.",
              remediationSteps: [
                `Remove wildcard IAM permissions from user "${userName}".`,
                "Replace with specific, least-privilege IAM permissions.",
                "Use IAM Access Analyzer to identify actually used permissions."
              ]
            })
          );
          continue;
        }
        if (hasAction(allActions, "iam:putuserpolicy") || hasAction(allActions, "iam:attachuserpolicy")) {
          findings.push(
            makeFinding6({
              riskScore: 9.5,
              title: `IAM user ${userName} can self-grant admin via policy attachment`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:PutUserPolicy or iam:AttachUserPolicy, allowing them to attach AdministratorAccess or any policy to themselves.`,
              impact: "The user can escalate to full administrator access by attaching an admin policy to their own account.",
              remediationSteps: [
                `Remove iam:PutUserPolicy and iam:AttachUserPolicy from user "${userName}".`,
                "Use permission boundaries to restrict policy attachment scope.",
                "Require MFA for sensitive IAM operations via condition keys."
              ]
            })
          );
        }
        if (hasAction(allActions, "iam:createrole") && hasAction(allActions, "iam:attachrolepolicy")) {
          findings.push(
            makeFinding6({
              riskScore: 8,
              title: `IAM user ${userName} can create admin roles`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has both iam:CreateRole and iam:AttachRolePolicy, allowing creation of new roles with admin policies.`,
              impact: "The user can create a new IAM role with AdministratorAccess and assume it to gain full account access.",
              remediationSteps: [
                `Restrict iam:CreateRole and iam:AttachRolePolicy with resource conditions for user "${userName}".`,
                "Use permission boundaries on all created roles.",
                "Monitor IAM role creation via CloudTrail alerts."
              ]
            })
          );
        }
        if (hasAction(allActions, "iam:passrole") && hasAction(allActions, "lambda:createfunction")) {
          findings.push(
            makeFinding6({
              riskScore: 7.5,
              title: `IAM user ${userName} can escalate via Lambda role passing`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:PassRole and lambda:CreateFunction, allowing them to create a Lambda function with an admin role.`,
              impact: "The user can pass a high-privilege role to a Lambda function and invoke it to execute actions beyond their own permissions.",
              remediationSteps: [
                `Restrict iam:PassRole to specific role ARNs for user "${userName}".`,
                "Use condition keys to limit which roles can be passed to Lambda.",
                "Implement SCP guardrails for privilege escalation paths."
              ]
            })
          );
        }
        if (hasAction(allActions, "iam:createaccesskey")) {
          findings.push(
            makeFinding6({
              riskScore: 8,
              title: `IAM user ${userName} can create access keys for other users`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has iam:CreateAccessKey, which allows creating access keys for any IAM user unless restricted by resource conditions.`,
              impact: "The user can impersonate other IAM users (including admins) by generating access keys on their behalf.",
              remediationSteps: [
                `Restrict iam:CreateAccessKey to the user's own ARN using a resource condition.`,
                "Implement SCP to prevent cross-user key creation.",
                "Monitor CreateAccessKey events in CloudTrail."
              ]
            })
          );
        }
        if (hasAction(allActions, "sts:assumerole")) {
          findings.push(
            makeFinding6({
              riskScore: 8,
              title: `IAM user ${userName} can assume roles (potential admin escalation)`,
              resourceType: "AWS::IAM::User",
              resourceId: userName,
              resourceArn: userArn,
              region: "global",
              description: `User "${userName}" has sts:AssumeRole, which may allow assuming high-privilege or admin roles if not restricted by resource ARN.`,
              impact: "The user can escalate privileges by assuming roles with higher permissions than their own.",
              remediationSteps: [
                `Restrict sts:AssumeRole to specific role ARNs for user "${userName}".`,
                "Require MFA for assuming sensitive roles via role trust policy conditions.",
                "Audit which roles this user can assume and their permission levels."
              ]
            })
          );
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: users.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/public-access-verify.ts
import {
  S3Client as S3Client2,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketPolicyStatusCommand,
  GetBucketLocationCommand
} from "@aws-sdk/client-s3";
import {
  RDSClient,
  DescribeDBInstancesCommand
} from "@aws-sdk/client-rds";
import dns2 from "dns";
function makeFinding7(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function s3Endpoint(bucket, region) {
  const suffix = region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com";
  return `https://${bucket}.s3.${region}.${suffix}/`;
}
async function getBucketRegion(client, bucketName, defaultRegion, warnings) {
  try {
    const resp = await client.send(
      new GetBucketLocationCommand({ Bucket: bucketName })
    );
    const loc = String(resp.LocationConstraint ?? "") || "us-east-1";
    return loc;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`Failed to detect region for bucket ${bucketName}, using ${defaultRegion}: ${msg}`);
    return defaultRegion;
  }
}
async function isBucketMarkedPublic(client, bucketName, warnings) {
  let bpaBlocks = false;
  try {
    const bpa = await client.send(
      new GetPublicAccessBlockCommand({ Bucket: bucketName })
    );
    const cfg = bpa.PublicAccessBlockConfiguration;
    bpaBlocks = !!(cfg?.BlockPublicAcls && cfg?.IgnorePublicAcls && cfg?.BlockPublicPolicy && cfg?.RestrictPublicBuckets);
  } catch (e) {
    if (e instanceof Error && e.name === "NoSuchPublicAccessBlockConfiguration") {
      bpaBlocks = false;
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      warnings.push(`Could not check public access for bucket ${bucketName}: ${msg}`);
      return "skip";
    }
  }
  if (bpaBlocks) return false;
  try {
    const acl = await client.send(
      new GetBucketAclCommand({ Bucket: bucketName })
    );
    for (const grant of acl.Grants ?? []) {
      const uri = grant.Grantee?.URI ?? "";
      if (uri.includes("AllUsers") || uri.includes("AuthenticatedUsers")) {
        return true;
      }
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    warnings.push(`Could not check ACL for bucket ${bucketName}: ${msg}`);
  }
  try {
    const policyStatus = await client.send(
      new GetBucketPolicyStatusCommand({ Bucket: bucketName })
    );
    if (policyStatus.PolicyStatus?.IsPublic) return true;
  } catch (e) {
    if (e instanceof Error && !e.name.includes("NoSuchBucketPolicy")) {
      const msg = e instanceof Error ? e.message : String(e);
      warnings.push(`Could not check policy status for bucket ${bucketName}: ${msg}`);
    }
  }
  return false;
}
function isPrivateIp(ip) {
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1], 10);
    return second >= 16 && second <= 31;
  }
  if (ip.startsWith("127.")) return true;
  return false;
}
var PublicAccessVerifyScanner = class {
  moduleName = "public_access_verify";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      try {
        const s3Client = createClient(S3Client2, region, ctx.credentials);
        const listResp = await s3Client.send(new ListBucketsCommand({}));
        const buckets = listResp.Buckets ?? [];
        for (const bucket of buckets) {
          const name = bucket.Name ?? "unknown";
          const arn = `arn:${partition}:s3:::${name}`;
          const bucketRegion = await getBucketRegion(s3Client, name, region, warnings);
          const bucketClient = bucketRegion === region ? s3Client : createClient(S3Client2, bucketRegion, ctx.credentials);
          const markedPublic = await isBucketMarkedPublic(bucketClient, name, warnings);
          if (markedPublic === "skip" || !markedPublic) continue;
          resourcesScanned++;
          const url = s3Endpoint(name, bucketRegion);
          try {
            const resp = await fetch(url, {
              method: "HEAD",
              signal: AbortSignal.timeout(5e3)
            });
            if (resp.ok || resp.status === 200) {
              findings.push(
                makeFinding7({
                  riskScore: 9.5,
                  title: `S3 bucket ${name} is publicly readable (verified)`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `HTTP HEAD to ${url} returned status ${resp.status}. The bucket is confirmed publicly accessible from the internet.`,
                  impact: "Anyone on the internet can read objects from this bucket, potentially exposing sensitive data.",
                  remediationSteps: [
                    "Enable Block Public Access on the bucket immediately.",
                    "Review and remove public ACL grants and public bucket policies.",
                    "Audit bucket contents for sensitive data exposure."
                  ]
                })
              );
            } else if (resp.status === 403) {
              findings.push(
                makeFinding7({
                  riskScore: 2,
                  title: `S3 bucket ${name} is marked public but returns 403 (blocked)`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: bucketRegion,
                  description: `Bucket "${name}" has public ACL/policy configuration but HTTP access returns 403 Forbidden, likely blocked by other controls.`,
                  impact: "Currently not accessible, but the public configuration is a risk if blocking controls are removed.",
                  remediationSteps: [
                    "Clean up the public ACL or policy to match the intended access model.",
                    "Enable Block Public Access to formalize the restriction."
                  ]
                })
              );
            }
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`HTTP check for bucket ${name} failed: ${msg}`);
          }
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 public access verification failed: ${msg}`);
      }
      try {
        const rdsClient = createClient(RDSClient, region, ctx.credentials);
        const instances = [];
        let marker;
        do {
          const resp = await rdsClient.send(
            new DescribeDBInstancesCommand({ Marker: marker })
          );
          if (resp.DBInstances) instances.push(...resp.DBInstances);
          marker = resp.Marker;
        } while (marker);
        for (const db of instances) {
          if (!db.PubliclyAccessible) continue;
          const dbId = db.DBInstanceIdentifier ?? "unknown";
          const dbArn = db.DBInstanceArn ?? `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
          const endpoint = db.Endpoint?.Address;
          if (!endpoint) continue;
          resourcesScanned++;
          try {
            const addresses = await dns2.promises.resolve4(endpoint);
            const hasPublicIp = addresses.some((ip) => !isPrivateIp(ip));
            if (hasPublicIp) {
              findings.push(
                makeFinding7({
                  riskScore: 8,
                  title: `RDS instance ${dbId} endpoint resolves to public IP (verified)`,
                  resourceType: "AWS::RDS::DBInstance",
                  resourceId: dbId,
                  resourceArn: dbArn,
                  region,
                  description: `RDS endpoint ${endpoint} resolves to public IP(s): ${addresses.join(", ")}. The database is network-reachable from the internet.`,
                  impact: "The database can be reached from the public internet, making it vulnerable to brute-force, credential stuffing, and exploitation of database vulnerabilities.",
                  remediationSteps: [
                    "Set PubliclyAccessible to false on the RDS instance.",
                    "Move the instance to a private subnet.",
                    "Use VPN or bastion host for database access.",
                    "Restrict security group inbound rules to known IPs."
                  ]
                })
              );
            }
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`DNS resolution for RDS ${dbId} (${endpoint}) failed: ${msg}`);
          }
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`RDS public access verification failed: ${msg}`);
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/tag-compliance.ts
import {
  EC2Client as EC2Client3,
  DescribeInstancesCommand as DescribeInstancesCommand3
} from "@aws-sdk/client-ec2";
import {
  RDSClient as RDSClient2,
  DescribeDBInstancesCommand as DescribeDBInstancesCommand2
} from "@aws-sdk/client-rds";
import {
  S3Client as S3Client3,
  ListBucketsCommand as ListBucketsCommand2,
  GetBucketTaggingCommand
} from "@aws-sdk/client-s3";
var DEFAULT_REQUIRED_TAGS = ["Environment", "Project", "Owner"];
function makeFinding8(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
function getMissingTags(tags, requiredTags) {
  const tagKeys = new Set(tags.map((t) => t.Key ?? ""));
  return requiredTags.filter((rt) => !tagKeys.has(rt));
}
var TagComplianceScanner = class {
  moduleName = "tag_compliance";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    const requiredTags = DEFAULT_REQUIRED_TAGS;
    try {
      try {
        const ec2Client = createClient(EC2Client3, region, ctx.credentials);
        const instances = [];
        let nextToken;
        do {
          const resp = await ec2Client.send(
            new DescribeInstancesCommand3({ NextToken: nextToken })
          );
          for (const res of resp.Reservations ?? []) {
            if (res.Instances) instances.push(...res.Instances);
          }
          nextToken = resp.NextToken;
        } while (nextToken);
        resourcesScanned += instances.length;
        for (const instance of instances) {
          const id = instance.InstanceId ?? "unknown";
          const arn = `arn:${partition}:ec2:${region}:${accountId}:instance/${id}`;
          const tags = instance.Tags ?? [];
          const missing = getMissingTags(tags, requiredTags);
          if (missing.length > 0) {
            findings.push(
              makeFinding8({
                riskScore: 4,
                title: `EC2 instance ${id} missing required tags: ${missing.join(", ")}`,
                resourceType: "AWS::EC2::Instance",
                resourceId: id,
                resourceArn: arn,
                region,
                description: `EC2 instance "${id}" is missing the following required tags: ${missing.join(", ")}.`,
                impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                remediationSteps: [
                  `Add the missing tags (${missing.join(", ")}) to instance ${id}.`,
                  "Implement AWS Config rules or Tag Policies to enforce tagging.",
                  "Use AWS Tag Editor for bulk tagging operations."
                ]
              })
            );
          }
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`EC2 tag compliance check failed: ${msg}`);
      }
      try {
        const rdsClient = createClient(RDSClient2, region, ctx.credentials);
        const dbInstances = [];
        let marker;
        do {
          const resp = await rdsClient.send(
            new DescribeDBInstancesCommand2({ Marker: marker })
          );
          if (resp.DBInstances) dbInstances.push(...resp.DBInstances);
          marker = resp.Marker;
        } while (marker);
        resourcesScanned += dbInstances.length;
        for (const db of dbInstances) {
          const dbId = db.DBInstanceIdentifier ?? "unknown";
          const dbArn = db.DBInstanceArn ?? `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
          const tags = (db.TagList ?? []).map((t) => ({
            Key: t.Key,
            Value: t.Value
          }));
          const missing = getMissingTags(tags, requiredTags);
          if (missing.length > 0) {
            findings.push(
              makeFinding8({
                riskScore: 4,
                title: `RDS instance ${dbId} missing required tags: ${missing.join(", ")}`,
                resourceType: "AWS::RDS::DBInstance",
                resourceId: dbId,
                resourceArn: dbArn,
                region,
                description: `RDS instance "${dbId}" is missing the following required tags: ${missing.join(", ")}.`,
                impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                remediationSteps: [
                  `Add the missing tags (${missing.join(", ")}) to RDS instance ${dbId}.`,
                  "Implement AWS Config rules or Tag Policies to enforce tagging.",
                  "Use AWS Tag Editor for bulk tagging operations."
                ]
              })
            );
          }
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`RDS tag compliance check failed: ${msg}`);
      }
      try {
        const s3Client = createClient(S3Client3, region, ctx.credentials);
        const listResp = await s3Client.send(new ListBucketsCommand2({}));
        const buckets = listResp.Buckets ?? [];
        resourcesScanned += buckets.length;
        for (const bucket of buckets) {
          const name = bucket.Name ?? "unknown";
          const arn = `arn:${partition}:s3:::${name}`;
          try {
            const taggingResp = await s3Client.send(
              new GetBucketTaggingCommand({ Bucket: name })
            );
            const tags = (taggingResp.TagSet ?? []).map((t) => ({
              Key: t.Key,
              Value: t.Value
            }));
            const missing = getMissingTags(tags, requiredTags);
            if (missing.length > 0) {
              findings.push(
                makeFinding8({
                  riskScore: 4,
                  title: `S3 bucket ${name} missing required tags: ${missing.join(", ")}`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: "global",
                  description: `S3 bucket "${name}" is missing the following required tags: ${missing.join(", ")}.`,
                  impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                  remediationSteps: [
                    `Add the missing tags (${missing.join(", ")}) to bucket ${name}.`,
                    "Implement AWS Config rules or Tag Policies to enforce tagging.",
                    "Use AWS Tag Editor for bulk tagging operations."
                  ]
                })
              );
            }
          } catch (e) {
            if (e instanceof Error && e.name === "NoSuchTagSet") {
              findings.push(
                makeFinding8({
                  riskScore: 4,
                  title: `S3 bucket ${name} missing required tags: ${requiredTags.join(", ")}`,
                  resourceType: "AWS::S3::Bucket",
                  resourceId: name,
                  resourceArn: arn,
                  region: "global",
                  description: `S3 bucket "${name}" has no tags configured. Missing all required tags: ${requiredTags.join(", ")}.`,
                  impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                  remediationSteps: [
                    `Add the required tags (${requiredTags.join(", ")}) to bucket ${name}.`,
                    "Implement AWS Config rules or Tag Policies to enforce tagging.",
                    "Use AWS Tag Editor for bulk tagging operations."
                  ]
                })
              );
            } else {
              const msg = e instanceof Error ? e.message : String(e);
              warnings.push(`S3 tag check for ${name} failed: ${msg}`);
            }
          }
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 tag compliance check failed: ${msg}`);
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/idle-resources.ts
import {
  EC2Client as EC2Client4,
  DescribeVolumesCommand,
  DescribeAddressesCommand as DescribeAddressesCommand2,
  DescribeInstancesCommand as DescribeInstancesCommand4,
  DescribeNetworkInterfacesCommand,
  DescribeSecurityGroupsCommand as DescribeSecurityGroupsCommand2
} from "@aws-sdk/client-ec2";
var THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1e3;
function makeFinding9(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var IdleResourcesScanner = class {
  moduleName = "idle_resources";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      const client = createClient(EC2Client4, region, ctx.credentials);
      let resourcesScanned = 0;
      const volumes = [];
      let volToken;
      do {
        const resp = await client.send(
          new DescribeVolumesCommand({ NextToken: volToken })
        );
        if (resp.Volumes) volumes.push(...resp.Volumes);
        volToken = resp.NextToken;
      } while (volToken);
      resourcesScanned += volumes.length;
      for (const vol of volumes) {
        if (vol.State === "available") {
          const volId = vol.VolumeId ?? "unknown";
          findings.push(
            makeFinding9({
              riskScore: 3,
              title: `EBS volume ${volId} is unattached`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:volume/${volId}`,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB, ${vol.VolumeType ?? "unknown"}) is in "available" state with no attachments.`,
              impact: "Unattached volumes incur storage costs and may contain sensitive data that is no longer actively managed.",
              remediationSteps: [
                "Determine if the volume is still needed.",
                "If not needed, create a snapshot for archival and delete the volume.",
                "If needed, attach it to the appropriate instance."
              ]
            })
          );
        }
      }
      let addresses = [];
      try {
        const addrResp = await client.send(new DescribeAddressesCommand2({}));
        addresses = addrResp.Addresses ?? [];
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`Elastic IP check failed: ${msg}`);
      }
      resourcesScanned += addresses.length;
      for (const addr of addresses) {
        if (!addr.AssociationId) {
          const allocId = addr.AllocationId ?? "unknown";
          const publicIp = addr.PublicIp ?? "unknown";
          findings.push(
            makeFinding9({
              riskScore: 2,
              title: `Elastic IP ${publicIp} is not associated`,
              resourceType: "AWS::EC2::EIP",
              resourceId: allocId,
              resourceArn: `arn:${partition}:ec2:${region}:${accountId}:elastic-ip/${allocId}`,
              region,
              description: `Elastic IP ${publicIp} (${allocId}) is allocated but not associated with any instance or network interface.`,
              impact: "Unused Elastic IPs cost ~$3.60/month each and represent unnecessary spend.",
              remediationSteps: [
                "Associate the EIP with an instance or network interface if needed.",
                "Release the EIP if it is no longer required."
              ]
            })
          );
        }
      }
      const instances = [];
      let instToken;
      do {
        const instResp = await client.send(
          new DescribeInstancesCommand4({ NextToken: instToken })
        );
        for (const res of instResp.Reservations ?? []) {
          if (res.Instances) instances.push(...res.Instances);
        }
        instToken = instResp.NextToken;
      } while (instToken);
      resourcesScanned += instances.length;
      const now = Date.now();
      for (const inst of instances) {
        if (inst.State?.Name === "stopped") {
          const instId = inst.InstanceId ?? "unknown";
          const reason = inst.StateTransitionReason ?? "";
          const stoppedTime = reason ? parseStopTime(reason) : null;
          if (!stoppedTime) {
            warnings.push(
              `Could not determine stop date for instance ${instId}. StateTransitionReason: ${reason}`
            );
            continue;
          }
          const stoppedDays = Math.round(
            (now - stoppedTime) / (24 * 60 * 60 * 1e3)
          );
          if (stoppedDays > 30) {
            findings.push(
              makeFinding9({
                riskScore: 3,
                title: `EC2 instance ${instId} has been stopped for ${stoppedDays} days`,
                resourceType: "AWS::EC2::Instance",
                resourceId: instId,
                resourceArn: `arn:${partition}:ec2:${region}:${accountId}:instance/${instId}`,
                region,
                description: `EC2 instance "${instId}" (${inst.InstanceType ?? "unknown"}) is in stopped state for ${stoppedDays} days. Attached EBS volumes continue to incur charges.`,
                impact: "Stopped instances still incur EBS storage costs and may contain stale configurations or unpatched AMIs.",
                remediationSteps: [
                  "Determine if the instance is still needed.",
                  "If not needed, create an AMI for archival and terminate the instance.",
                  "If needed temporarily, consider using a launch template for on-demand recreation."
                ]
              })
            );
          }
        }
      }
      const securityGroups = [];
      let sgToken;
      do {
        const sgResp = await client.send(
          new DescribeSecurityGroupsCommand2({ NextToken: sgToken })
        );
        if (sgResp.SecurityGroups) securityGroups.push(...sgResp.SecurityGroups);
        sgToken = sgResp.NextToken;
      } while (sgToken);
      const usedSgIds = /* @__PURE__ */ new Set();
      let eniToken;
      do {
        const eniResp = await client.send(
          new DescribeNetworkInterfacesCommand({ NextToken: eniToken })
        );
        for (const eni of eniResp.NetworkInterfaces ?? []) {
          for (const group of eni.Groups ?? []) {
            if (group.GroupId) usedSgIds.add(group.GroupId);
          }
        }
        eniToken = eniResp.NextToken;
      } while (eniToken);
      resourcesScanned += securityGroups.length;
      for (const sg of securityGroups) {
        const sgId = sg.GroupId ?? "unknown";
        if (sg.GroupName === "default") continue;
        if (!usedSgIds.has(sgId)) {
          findings.push(
            makeFinding9({
              riskScore: 2,
              title: `Security group ${sgId} is not attached to any resource`,
              resourceType: "AWS::EC2::SecurityGroup",
              resourceId: sgId,
              resourceArn: `arn:${partition}:ec2:${region}:${sg.OwnerId ?? accountId}:security-group/${sgId}`,
              region,
              description: `Security group "${sg.GroupName}" (${sgId}) is not associated with any network interface.`,
              impact: "Unused security groups add clutter and may cause confusion during security reviews.",
              remediationSteps: [
                "Verify the security group is not referenced by other resources (e.g., launch templates).",
                "Delete the security group if it is no longer needed."
              ]
            })
          );
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};
function parseStopTime(reason) {
  const match = reason.match(/\((\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\w+)\)/);
  if (!match) return null;
  const parsed = Date.parse(match[1]);
  return isNaN(parsed) ? null : parsed;
}

// src/scanners/disaster-recovery.ts
import {
  RDSClient as RDSClient3,
  DescribeDBInstancesCommand as DescribeDBInstancesCommand3
} from "@aws-sdk/client-rds";
import {
  EC2Client as EC2Client5,
  DescribeVolumesCommand as DescribeVolumesCommand2,
  DescribeSnapshotsCommand
} from "@aws-sdk/client-ec2";
import {
  S3Client as S3Client4,
  ListBucketsCommand as ListBucketsCommand3,
  GetBucketVersioningCommand,
  GetBucketReplicationCommand
} from "@aws-sdk/client-s3";
var SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1e3;
function makeFinding10(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var DisasterRecoveryScanner = class {
  moduleName = "disaster_recovery";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      let resourcesScanned = 0;
      const rdsClient = createClient(RDSClient3, region, ctx.credentials);
      const instances = [];
      let marker;
      do {
        const resp = await rdsClient.send(
          new DescribeDBInstancesCommand3({ Marker: marker })
        );
        if (resp.DBInstances) instances.push(...resp.DBInstances);
        marker = resp.Marker;
      } while (marker);
      resourcesScanned += instances.length;
      for (const db of instances) {
        const dbId = db.DBInstanceIdentifier ?? "unknown";
        const dbArn = db.DBInstanceArn ?? `arn:${partition}:rds:${region}:${accountId}:db/${dbId}`;
        const engine = db.Engine ?? "unknown";
        if (!db.MultiAZ) {
          findings.push(
            makeFinding10({
              riskScore: 6,
              title: `RDS instance ${dbId} is not Multi-AZ`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) does not have Multi-AZ deployment enabled.`,
              impact: "Single-AZ deployments have no automatic failover. An AZ outage will cause downtime and potential data loss.",
              remediationSteps: [
                "Enable Multi-AZ deployment for the RDS instance.",
                "This provides automatic failover to a standby in a different AZ."
              ]
            })
          );
        }
        const retention = db.BackupRetentionPeriod ?? 0;
        if (retention === 0) {
          findings.push(
            makeFinding10({
              riskScore: 5.5,
              title: `RDS instance ${dbId} has automated backups disabled`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has backup retention period set to 0 (disabled).`,
              impact: "No automated backups or point-in-time recovery. Data loss from failures or corruption is unrecoverable.",
              remediationSteps: [
                "Set the backup retention period to at least 7 days.",
                "Consider cross-region backup replication for critical databases."
              ]
            })
          );
        } else if (retention < 7) {
          findings.push(
            makeFinding10({
              riskScore: 5.5,
              title: `RDS instance ${dbId} backup retention is only ${retention} day(s)`,
              resourceType: "AWS::RDS::DBInstance",
              resourceId: dbId,
              resourceArn: dbArn,
              region,
              description: `RDS instance "${dbId}" (${engine}) has backup retention period of ${retention} day(s), below the recommended 7 days.`,
              impact: "Short retention windows limit point-in-time recovery options and may not meet compliance requirements.",
              remediationSteps: [
                "Increase the backup retention period to at least 7 days.",
                "For production databases, consider 14-35 days retention."
              ]
            })
          );
        }
      }
      const ec2Client = createClient(EC2Client5, region, ctx.credentials);
      const volumes = [];
      let volToken;
      do {
        const resp = await ec2Client.send(
          new DescribeVolumesCommand2({ NextToken: volToken })
        );
        if (resp.Volumes) volumes.push(...resp.Volumes);
        volToken = resp.NextToken;
      } while (volToken);
      const snapshots = [];
      let snapToken;
      do {
        const resp = await ec2Client.send(
          new DescribeSnapshotsCommand({
            OwnerIds: ["self"],
            NextToken: snapToken
          })
        );
        if (resp.Snapshots) snapshots.push(...resp.Snapshots);
        snapToken = resp.NextToken;
      } while (snapToken);
      const latestSnapshotByVolume = /* @__PURE__ */ new Map();
      for (const snap of snapshots) {
        if (!snap.VolumeId || snap.State !== "completed") continue;
        const snapTime = snap.StartTime?.getTime() ?? 0;
        const existing = latestSnapshotByVolume.get(snap.VolumeId) ?? 0;
        if (snapTime > existing) {
          latestSnapshotByVolume.set(snap.VolumeId, snapTime);
        }
      }
      const inUseVolumes = volumes.filter((v) => v.State === "in-use");
      resourcesScanned += inUseVolumes.length;
      const now = Date.now();
      for (const vol of inUseVolumes) {
        const volId = vol.VolumeId ?? "unknown";
        const volArn = `arn:${partition}:ec2:${region}:${accountId}:volume/${volId}`;
        const latestSnap = latestSnapshotByVolume.get(volId);
        if (latestSnap === void 0) {
          findings.push(
            makeFinding10({
              riskScore: 7,
              title: `EBS volume ${volId} has no snapshots`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: volArn,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB, ${vol.VolumeType ?? "unknown"}) has no snapshots. Data cannot be recovered if the volume fails.`,
              impact: "Complete data loss if the volume becomes unavailable. No backup exists for disaster recovery.",
              remediationSteps: [
                "Create a snapshot of the volume immediately.",
                "Set up automated snapshots using AWS Backup or Amazon Data Lifecycle Manager."
              ]
            })
          );
        } else if (now - latestSnap > SEVEN_DAYS_MS) {
          const daysSince = Math.round((now - latestSnap) / (24 * 60 * 60 * 1e3));
          findings.push(
            makeFinding10({
              riskScore: 5,
              title: `EBS volume ${volId} has no recent snapshot (${daysSince} days old)`,
              resourceType: "AWS::EC2::Volume",
              resourceId: volId,
              resourceArn: volArn,
              region,
              description: `EBS volume "${volId}" (${vol.Size ?? "?"}GB) most recent snapshot is ${daysSince} days old, exceeding the 7-day threshold.`,
              impact: "Recovery from the latest snapshot would lose up to ${daysSince} days of data.",
              remediationSteps: [
                "Create a fresh snapshot of the volume.",
                "Configure automated snapshot schedules using AWS Backup or Data Lifecycle Manager."
              ]
            })
          );
        }
      }
      const s3Client = createClient(S3Client4, region, ctx.credentials);
      let bucketNames = [];
      try {
        const listResp = await s3Client.send(new ListBucketsCommand3({}));
        bucketNames = (listResp.Buckets ?? []).map((b) => b.Name).filter((n) => !!n);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        warnings.push(`S3 bucket list failed: ${msg}`);
      }
      resourcesScanned += bucketNames.length;
      for (const name of bucketNames) {
        const arn = `arn:${partition}:s3:::${name}`;
        try {
          const ver = await s3Client.send(
            new GetBucketVersioningCommand({ Bucket: name })
          );
          if (ver.Status !== "Enabled") {
            findings.push(
              makeFinding10({
                riskScore: 3,
                title: `S3 bucket ${name} does not have versioning enabled`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region,
                description: `Bucket "${name}" versioning is ${ver.Status ?? "not set"}. Object deletion or overwrite is irreversible.`,
                impact: "Accidental deletion or corruption of objects cannot be recovered without versioning.",
                remediationSteps: [
                  "Enable versioning on the bucket.",
                  "Consider adding lifecycle rules to manage version storage costs."
                ]
              })
            );
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          warnings.push(`Bucket ${name} versioning check failed: ${msg}`);
        }
        try {
          await s3Client.send(
            new GetBucketReplicationCommand({ Bucket: name })
          );
        } catch (e) {
          if (e instanceof Error && e.name === "ReplicationConfigurationNotFoundError") {
            findings.push(
              makeFinding10({
                riskScore: 3.5,
                title: `S3 bucket ${name} has no cross-region replication`,
                resourceType: "AWS::S3::Bucket",
                resourceId: name,
                resourceArn: arn,
                region,
                description: `Bucket "${name}" does not have cross-region replication configured.`,
                impact: "Data is stored in a single region. A regional outage could make the data unavailable.",
                remediationSteps: [
                  "Enable cross-region replication to a bucket in another region.",
                  "Ensure versioning is enabled (required for CRR).",
                  "Consider S3 Replication Time Control for critical data."
                ]
              })
            );
          } else {
            const msg = e instanceof Error ? e.message : String(e);
            warnings.push(`Bucket ${name} replication check failed: ${msg}`);
          }
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/security-hub-findings.ts
import {
  SecurityHubClient as SecurityHubClient2,
  GetFindingsCommand
} from "@aws-sdk/client-securityhub";
function shSeverityToScore(label) {
  switch (label) {
    case "CRITICAL":
      return 9.5;
    case "HIGH":
      return 8;
    case "MEDIUM":
      return 5.5;
    case "LOW":
      return 3;
    case "INFORMATIONAL":
      return null;
    // skip
    default:
      return null;
  }
}
var SecurityHubFindingsScanner = class {
  moduleName = "security_hub_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(SecurityHubClient2, region, ctx.credentials);
      let nextToken;
      do {
        const resp = await client.send(
          new GetFindingsCommand({
            Filters: {
              WorkflowStatus: [
                { Value: "NEW", Comparison: "EQUALS" },
                { Value: "NOTIFIED", Comparison: "EQUALS" }
              ],
              RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }]
            },
            MaxResults: 100,
            NextToken: nextToken
          })
        );
        const shFindings = resp.Findings ?? [];
        resourcesScanned += shFindings.length;
        for (const f of shFindings) {
          const severityLabel = f.Severity?.Label ?? "INFORMATIONAL";
          const score = shSeverityToScore(severityLabel);
          if (score === null) continue;
          const severity = severityFromScore(score);
          const resourceId = f.Resources?.[0]?.Id ?? "unknown";
          const resourceType = f.Resources?.[0]?.Type ?? "AWS::Unknown";
          const resourceArn = resourceId.startsWith("arn:") ? resourceId : `arn:${partition}:securityhub:${region}:${accountId}:finding/${f.Id ?? "unknown"}`;
          const remediationSteps = [];
          if (f.Remediation?.Recommendation?.Text) {
            remediationSteps.push(f.Remediation.Recommendation.Text);
          }
          if (f.Remediation?.Recommendation?.Url) {
            remediationSteps.push(`Reference: ${f.Remediation.Recommendation.Url}`);
          }
          if (remediationSteps.length === 0) {
            remediationSteps.push("Review the finding in the AWS Security Hub console and follow the recommended remediation.");
          }
          findings.push({
            severity,
            title: f.Title ?? "Security Hub Finding",
            resourceType,
            resourceId,
            resourceArn,
            region: f.Region ?? region,
            description: f.Description ?? f.Title ?? "No description",
            impact: `Source: ${f.ProductName ?? "Security Hub"} (${f.GeneratorId ?? "unknown"})`,
            riskScore: score,
            remediationSteps,
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: f.AwsAccountId ?? accountId
          });
        }
        nextToken = resp.NextToken;
      } while (nextToken);
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isNotEnabled2 = err instanceof Error && err.name === "InvalidAccessException" || msg.includes("not subscribed") || msg.includes("not enabled");
      if (isNotEnabled2) {
        warnings.push("Security Hub is not enabled in this region. Enable it to aggregate security findings.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      return {
        module: this.moduleName,
        status: "error",
        error: `Security Hub findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/guardduty-findings.ts
import {
  GuardDutyClient as GuardDutyClient2,
  ListDetectorsCommand as ListDetectorsCommand2,
  ListFindingsCommand,
  GetFindingsCommand as GetFindingsCommand2
} from "@aws-sdk/client-guardduty";
function gdSeverityToScore(severity) {
  if (severity >= 7) return 8;
  if (severity >= 4) return 5.5;
  return 3;
}
var GuardDutyFindingsScanner = class {
  moduleName = "guardduty_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(GuardDutyClient2, region, ctx.credentials);
      const detectorsResp = await client.send(new ListDetectorsCommand2({}));
      const detectorIds = detectorsResp.DetectorIds ?? [];
      if (detectorIds.length === 0) {
        warnings.push("GuardDuty is not enabled in this region (no detectors found).");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      const detectorId = detectorIds[0];
      let nextToken;
      const findingIds = [];
      do {
        const listResp = await client.send(
          new ListFindingsCommand({
            DetectorId: detectorId,
            FindingCriteria: {
              Criterion: {
                "service.archived": {
                  Eq: ["false"]
                }
              }
            },
            MaxResults: 50,
            NextToken: nextToken
          })
        );
        findingIds.push(...listResp.FindingIds ?? []);
        nextToken = listResp.NextToken;
      } while (nextToken);
      resourcesScanned = findingIds.length;
      if (findingIds.length === 0) {
        return {
          module: this.moduleName,
          status: "success",
          warnings: warnings.length > 0 ? warnings : void 0,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      for (let i = 0; i < findingIds.length; i += 50) {
        const batch = findingIds.slice(i, i + 50);
        const detailsResp = await client.send(
          new GetFindingsCommand2({
            DetectorId: detectorId,
            FindingIds: batch
          })
        );
        for (const gdf of detailsResp.Findings ?? []) {
          const gdSeverity = gdf.Severity ?? 0;
          const score = gdSeverityToScore(gdSeverity);
          const severity = severityFromScore(score);
          const resourceType = gdf.Resource?.ResourceType ?? "AWS::Unknown";
          const resourceId = gdf.Resource?.InstanceDetails?.InstanceId ?? gdf.Resource?.AccessKeyDetails?.AccessKeyId ?? gdf.Arn ?? "unknown";
          const resourceArn = gdf.Arn ?? `arn:${partition}:guardduty:${region}:${accountId}:detector/${detectorId}/finding/${gdf.Id ?? "unknown"}`;
          findings.push({
            severity,
            title: `[GuardDuty] ${gdf.Title ?? gdf.Type ?? "Finding"}`,
            resourceType,
            resourceId,
            resourceArn,
            region: gdf.Region ?? region,
            description: gdf.Description ?? gdf.Title ?? "No description",
            impact: `GuardDuty threat type: ${gdf.Type ?? "unknown"} (severity ${gdSeverity})`,
            riskScore: score,
            remediationSteps: [
              "Review the finding in the Amazon GuardDuty console.",
              `Finding type: ${gdf.Type ?? "unknown"}`,
              "Follow the recommended remediation in the GuardDuty documentation."
            ],
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: gdf.AccountId ?? accountId
          });
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `GuardDuty findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/inspector-findings.ts
import {
  Inspector2Client as Inspector2Client2,
  ListFindingsCommand as ListFindingsCommand2
} from "@aws-sdk/client-inspector2";
function inspectorSeverityToScore(label) {
  switch (label) {
    case "CRITICAL":
      return 9.5;
    case "HIGH":
      return 8;
    case "MEDIUM":
      return 5.5;
    case "LOW":
      return 3;
    case "INFORMATIONAL":
      return null;
    case "UNTRIAGED":
      return 5.5;
    default:
      return null;
  }
}
var InspectorFindingsScanner = class {
  moduleName = "inspector_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(Inspector2Client2, region, ctx.credentials);
      let nextToken;
      const filterCriteria = {
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      };
      do {
        const resp = await client.send(
          new ListFindingsCommand2({
            filterCriteria,
            maxResults: 100,
            nextToken
          })
        );
        const inspFindings = resp.findings ?? [];
        resourcesScanned += inspFindings.length;
        for (const f of inspFindings) {
          const severityLabel = f.severity ?? "INFORMATIONAL";
          const score = inspectorSeverityToScore(severityLabel);
          if (score === null) continue;
          const severity = severityFromScore(score);
          const cveId = f.packageVulnerabilityDetails?.vulnerabilityId;
          const titleBase = f.title ?? "Inspector Finding";
          const title = cveId ? `[${cveId}] ${titleBase}` : titleBase;
          const resourceId = f.resources?.[0]?.id ?? "unknown";
          const resourceType = f.resources?.[0]?.type ?? "AWS::Unknown";
          const resourceArn = resourceId.startsWith("arn:") ? resourceId : `arn:${partition}:inspector2:${region}:${accountId}:finding/${f.findingArn ?? "unknown"}`;
          const remediationSteps = [];
          if (f.remediation?.recommendation?.text) {
            remediationSteps.push(f.remediation.recommendation.text);
          }
          if (f.remediation?.recommendation?.Url) {
            remediationSteps.push(`Reference: ${f.remediation.recommendation.Url}`);
          }
          if (f.packageVulnerabilityDetails?.referenceUrls?.length) {
            remediationSteps.push(`CVE references: ${f.packageVulnerabilityDetails.referenceUrls.slice(0, 3).join(", ")}`);
          }
          if (remediationSteps.length === 0) {
            remediationSteps.push("Review the finding in the Amazon Inspector console and apply the recommended patch or update.");
          }
          const description = f.description ?? titleBase;
          const impact = cveId ? `Vulnerability ${cveId} \u2014 CVSS: ${f.packageVulnerabilityDetails?.cvss?.[0]?.baseScore ?? "N/A"}` : `Inspector finding type: ${f.type ?? "unknown"}`;
          findings.push({
            severity,
            title,
            resourceType,
            resourceId,
            resourceArn,
            region,
            description,
            impact,
            riskScore: score,
            remediationSteps,
            priority: priorityFromSeverity(severity),
            module: this.moduleName,
            accountId: f.awsAccountId ?? accountId
          });
        }
        nextToken = resp.nextToken;
      } while (nextToken);
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const errName = err instanceof Error ? err.name : "";
      const isAccessDenied2 = errName === "AccessDeniedException" || msg.includes("AccessDeniedException");
      const isNotEnabled2 = msg.includes("not enabled") || msg.includes("not subscribed");
      if (isAccessDenied2) {
        warnings.push("Insufficient permissions to access Inspector. Grant inspector2:ListFindings to scan for vulnerabilities.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      if (isNotEnabled2) {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      return {
        module: this.moduleName,
        status: "error",
        error: `Inspector findings scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/trusted-advisor-findings.ts
import {
  SupportClient,
  DescribeTrustedAdvisorChecksCommand,
  DescribeTrustedAdvisorCheckResultCommand
} from "@aws-sdk/client-support";
function taStatusToScore(status) {
  switch (status) {
    case "error":
      return 8;
    // RED = action required
    case "warning":
      return 5.5;
    // YELLOW = investigation recommended
    case "ok":
      return null;
    // GREEN = no issue
    case "not_available":
      return null;
    default:
      return null;
  }
}
var TrustedAdvisorFindingsScanner = class {
  moduleName = "trusted_advisor_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const supportRegion = region.startsWith("cn-") ? "cn-north-1" : "us-east-1";
      const clientConfig = { region: supportRegion };
      if (ctx.credentials) clientConfig.credentials = ctx.credentials;
      const client = new SupportClient(clientConfig);
      const checksResp = await client.send(
        new DescribeTrustedAdvisorChecksCommand({ language: "en" })
      );
      const allChecks = checksResp.checks ?? [];
      const securityChecks = allChecks.filter((c) => c.category === "security");
      if (securityChecks.length === 0) {
        warnings.push("No Trusted Advisor security checks found.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      for (const check of securityChecks) {
        if (!check.id) continue;
        try {
          const resultResp = await client.send(
            new DescribeTrustedAdvisorCheckResultCommand({
              checkId: check.id
            })
          );
          const result = resultResp.result;
          if (!result) continue;
          const status = result.status ?? "not_available";
          const score = taStatusToScore(status);
          resourcesScanned++;
          if (score === null) continue;
          const flaggedResources = result.flaggedResources ?? [];
          if (flaggedResources.length === 0) {
            const severity = severityFromScore(score);
            findings.push({
              severity,
              title: `[Trusted Advisor] ${check.name ?? "Security Check"}`,
              resourceType: "AWS::TrustedAdvisor::Check",
              resourceId: check.id,
              resourceArn: `arn:${partition}:trustedadvisor:${region}:${accountId}:check/${check.id}`,
              region,
              description: check.description ?? check.name ?? "Security check flagged",
              impact: `Trusted Advisor status: ${status}`,
              riskScore: score,
              remediationSteps: [
                "Review this Trusted Advisor check in the AWS console.",
                "Follow the recommended actions to resolve the flagged issue."
              ],
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId
            });
            continue;
          }
          const metadata = check.metadata ?? [];
          for (const fr of flaggedResources.slice(0, 25)) {
            if (fr.isSuppressed) continue;
            const severity = severityFromScore(score);
            const resourceMeta = fr.metadata ?? [];
            const resourceIdIdx = metadata.indexOf("Resource ID");
            const regionIdx = metadata.indexOf("Region");
            const flaggedResourceId = resourceIdIdx >= 0 && resourceMeta[resourceIdIdx] ? resourceMeta[resourceIdIdx] : fr.resourceId ?? "unknown";
            const flaggedRegion = regionIdx >= 0 && resourceMeta[regionIdx] ? resourceMeta[regionIdx] : region;
            findings.push({
              severity,
              title: `[Trusted Advisor] ${check.name ?? "Security Check"}: ${flaggedResourceId}`,
              resourceType: "AWS::TrustedAdvisor::FlaggedResource",
              resourceId: flaggedResourceId,
              resourceArn: `arn:${partition}:trustedadvisor:${flaggedRegion}:${accountId}:check/${check.id}/${fr.resourceId ?? "unknown"}`,
              region: flaggedRegion,
              description: `${check.name}: ${resourceMeta.join(" | ")}`,
              impact: `Trusted Advisor status: ${status} \u2014 ${check.name ?? "security check"}`,
              riskScore: score,
              remediationSteps: [
                `Review Trusted Advisor check: ${check.name}`,
                "Follow the recommended actions in the AWS Trusted Advisor console."
              ],
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId
            });
          }
        } catch (checkErr) {
          const checkMsg = checkErr instanceof Error ? checkErr.message : String(checkErr);
          warnings.push(`Trusted Advisor check ${check.name ?? check.id} failed: ${checkMsg}`);
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isSubscriptionRequired = msg.includes("SubscriptionRequiredException") || msg.includes("subscription") || msg.includes("AWS Premium Support") || err instanceof Error && err.name === "SubscriptionRequiredException";
      if (isSubscriptionRequired) {
        warnings.push("Trusted Advisor requires AWS Business or Enterprise Support plan. Skipping.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      return {
        module: this.moduleName,
        status: "error",
        error: `Trusted Advisor scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/config-rules-findings.ts
import {
  ConfigServiceClient as ConfigServiceClient2,
  DescribeComplianceByConfigRuleCommand,
  GetComplianceDetailsByConfigRuleCommand
} from "@aws-sdk/client-config-service";
var SECURITY_RULE_PATTERNS = [
  "securitygroup",
  "security-group",
  "encryption",
  "encrypted",
  "public",
  "unrestricted",
  "mfa",
  "password",
  "access-key",
  "root",
  "admin",
  "logging",
  "cloudtrail",
  "iam",
  "kms",
  "ssl",
  "tls",
  "vpc-flow",
  "guardduty",
  "securityhub"
];
function ruleIsSecurityRelated(ruleName) {
  const lower = ruleName.toLowerCase();
  return SECURITY_RULE_PATTERNS.some((pat) => lower.includes(pat));
}
var ConfigRulesFindingsScanner = class {
  moduleName = "config_rules_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(ConfigServiceClient2, region, ctx.credentials);
      let nextToken;
      const nonCompliantRules = [];
      do {
        const resp = await client.send(
          new DescribeComplianceByConfigRuleCommand({ NextToken: nextToken })
        );
        for (const rule of resp.ComplianceByConfigRules ?? []) {
          resourcesScanned++;
          if (rule.Compliance?.ComplianceType === "NON_COMPLIANT") {
            nonCompliantRules.push(rule);
          }
        }
        nextToken = resp.NextToken;
      } while (nextToken);
      if (resourcesScanned === 0) {
        warnings.push("AWS Config is not enabled in this region or no Config Rules are defined.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      for (const rule of nonCompliantRules) {
        const ruleName = rule.ConfigRuleName ?? "unknown";
        try {
          let detailToken;
          do {
            const detailResp = await client.send(
              new GetComplianceDetailsByConfigRuleCommand({
                ConfigRuleName: ruleName,
                ComplianceTypes: ["NON_COMPLIANT"],
                NextToken: detailToken
              })
            );
            for (const evalResult of detailResp.EvaluationResults ?? []) {
              const qualifier = evalResult.EvaluationResultIdentifier?.EvaluationResultQualifier;
              const resourceType = qualifier?.ResourceType ?? "AWS::Unknown";
              const resourceId = qualifier?.ResourceId ?? "unknown";
              const annotation = evalResult.Annotation;
              const isSecurityRule = ruleIsSecurityRelated(ruleName);
              const riskScore = isSecurityRule ? 7.5 : 5.5;
              const severity = severityFromScore(riskScore);
              const descParts = [`Config Rule: ${ruleName}`, `Resource Type: ${resourceType}`];
              if (annotation) descParts.push(`Annotation: ${annotation}`);
              findings.push({
                severity,
                title: `Config Rule: ${ruleName} - ${resourceType}/${resourceId} Non-Compliant`,
                resourceType,
                resourceId,
                resourceArn: resourceId,
                region,
                description: descParts.join(". "),
                impact: `Resource is non-compliant with Config Rule: ${ruleName}`,
                riskScore,
                remediationSteps: [
                  `Review the Config Rule "${ruleName}" in the AWS Config console.`,
                  `Check resource ${resourceId} for compliance violations.`,
                  "Follow the rule's remediation guidance to bring the resource into compliance."
                ],
                priority: priorityFromSeverity(severity),
                module: this.moduleName,
                accountId
              });
            }
            detailToken = detailResp.NextToken;
          } while (detailToken);
        } catch (detailErr) {
          const msg = detailErr instanceof Error ? detailErr.message : String(detailErr);
          warnings.push(`Failed to get details for rule ${ruleName}: ${msg}`);
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("NoSuchConfigurationRecorder") || msg.includes("InsufficientDeliveryPolicy") || msg.includes("No Configuration Recorder")) {
        warnings.push("AWS Config is not enabled in this region.");
        return {
          module: this.moduleName,
          status: "success",
          warnings,
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      return {
        module: this.moduleName,
        status: "error",
        error: `Config Rules scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/access-analyzer-findings.ts
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsV2Command
} from "@aws-sdk/client-accessanalyzer";
function findingTypeToScore(findingType) {
  const ft = findingType;
  switch (ft) {
    case "ExternalAccess":
      return 8;
    case "UnusedIAMRole":
    case "UnusedIAMUserAccessKey":
    case "UnusedIAMUserPassword":
      return 5.5;
    case "UnusedPermission":
      return 3;
    default:
      return 5.5;
  }
}
var UNUSED_FINDING_TYPES = /* @__PURE__ */ new Set([
  "UnusedIAMRole",
  "UnusedIAMUserAccessKey",
  "UnusedIAMUserPassword",
  "UnusedPermission"
]);
function isSecurityRelevant(findingType) {
  const ft = findingType;
  return ft === "ExternalAccess" || UNUSED_FINDING_TYPES.has(ft ?? "");
}
function isExternalAccess(findingType) {
  return findingType === "ExternalAccess";
}
var AccessAnalyzerFindingsScanner = class {
  moduleName = "access_analyzer_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(AccessAnalyzerClient, region, ctx.credentials);
      let analyzerToken;
      const analyzers = [];
      do {
        const resp = await client.send(
          new ListAnalyzersCommand({ nextToken: analyzerToken })
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
          findings: []
        };
      }
      for (const analyzer of analyzers) {
        const analyzerArn = analyzer.arn ?? "unknown";
        let findingToken;
        do {
          const listResp = await client.send(
            new ListFindingsV2Command({
              analyzerArn,
              filter: {
                status: { eq: ["ACTIVE"] }
              },
              nextToken: findingToken
            })
          );
          for (const aaf of listResp.findings ?? []) {
            if (!isSecurityRelevant(aaf.findingType)) {
              continue;
            }
            resourcesScanned++;
            const score = findingTypeToScore(aaf.findingType);
            const severity = severityFromScore(score);
            const resourceArn = aaf.resource ?? "unknown";
            const resourceType = aaf.resourceType ?? "AWS::Unknown";
            const resourceId = resourceArn.split("/").pop() ?? resourceArn.split(":").pop() ?? "unknown";
            const external = isExternalAccess(aaf.findingType);
            const descParts = [`Resource Type: ${resourceType}`];
            if (aaf.resourceOwnerAccount) descParts.push(`Owner Account: ${aaf.resourceOwnerAccount}`);
            if (aaf.findingType) descParts.push(`Finding Type: ${aaf.findingType}`);
            const title = buildFindingTitle(aaf);
            const impact = external ? `Resource is accessible from outside the account. Type: ${aaf.findingType ?? "unknown"}` : `Unused access detected \u2014 review and remove to follow least-privilege. Type: ${aaf.findingType ?? "unknown"}`;
            const remediationSteps = external ? [
              "Review the finding in the IAM Access Analyzer console.",
              `Check resource ${resourceId} for unintended external access.`,
              "Remove or restrict the resource policy to eliminate external access."
            ] : [
              "Review the finding in the IAM Access Analyzer console.",
              `Check resource ${resourceId} for unused access permissions.`,
              "Remove unused permissions, roles, or credentials to follow least-privilege."
            ];
            findings.push({
              severity,
              title,
              resourceType: mapResourceType(resourceType),
              resourceId,
              resourceArn,
              region,
              description: descParts.join(". "),
              impact,
              riskScore: score,
              remediationSteps,
              priority: priorityFromSeverity(severity),
              module: this.moduleName,
              accountId: aaf.resourceOwnerAccount ?? accountId
            });
          }
          findingToken = listResp.nextToken;
        } while (findingToken);
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `Access Analyzer scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};
function buildFindingTitle(finding) {
  const resourceType = finding.resourceType ?? "Resource";
  const resource = finding.resource ? finding.resource.split("/").pop() ?? finding.resource.split(":").pop() ?? finding.resource : "unknown";
  const label = isExternalAccess(finding.findingType) ? "external access detected" : "unused access detected";
  return `[Access Analyzer] ${resourceType} ${resource} \u2014 ${label}`;
}
function mapResourceType(aaType) {
  const mapping = {
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
    "AWS::ECR::Repository": "AWS::ECR::Repository"
  };
  return mapping[aaType] ?? aaType;
}

// src/scanners/patch-compliance-findings.ts
import {
  SSMClient,
  DescribeInstanceInformationCommand,
  DescribeInstancePatchStatesCommand
} from "@aws-sdk/client-ssm";
var PatchComplianceFindingsScanner = class {
  moduleName = "patch_compliance_findings";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    let resourcesScanned = 0;
    try {
      const client = createClient(SSMClient, region, ctx.credentials);
      let nextToken;
      const instances = [];
      do {
        const resp = await client.send(
          new DescribeInstanceInformationCommand({
            MaxResults: 50,
            NextToken: nextToken
          })
        );
        instances.push(...resp.InstanceInformationList ?? []);
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
          findings: []
        };
      }
      resourcesScanned = instances.length;
      const instanceIds = instances.map((i) => i.InstanceId).filter(Boolean);
      const patchStateMap = /* @__PURE__ */ new Map();
      for (let i = 0; i < instanceIds.length; i += 50) {
        const batch = instanceIds.slice(i, i + 50);
        let patchToken;
        do {
          const patchResp = await client.send(
            new DescribeInstancePatchStatesCommand({
              InstanceIds: batch,
              NextToken: patchToken
            })
          );
          for (const ps of patchResp.InstancePatchStates ?? []) {
            if (ps.InstanceId) {
              patchStateMap.set(ps.InstanceId, ps);
            }
          }
          patchToken = patchResp.NextToken;
        } while (patchToken);
      }
      for (const instance of instances) {
        const instanceId = instance.InstanceId ?? "unknown";
        const platform = instance.PlatformName ?? instance.PlatformType ?? "unknown";
        const instanceArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instanceId}`;
        const patchState = patchStateMap.get(instanceId);
        if (!patchState) {
          const riskScore2 = 3;
          const severity2 = severityFromScore(riskScore2);
          findings.push({
            severity: severity2,
            title: `Instance ${instanceId} has no patch compliance data`,
            resourceType: "AWS::EC2::Instance",
            resourceId: instanceId,
            resourceArn: instanceArn,
            region,
            description: `Instance ${instanceId} (${platform}) is managed by SSM but has no patch compliance data. Patch Manager may not be configured for this instance.`,
            impact: "Patch compliance status is unknown \u2014 vulnerabilities may exist.",
            riskScore: riskScore2,
            remediationSteps: [
              "Configure AWS Systems Manager Patch Manager for this instance.",
              "Create a patch baseline and maintenance window.",
              "Run a patch scan to establish compliance status."
            ],
            priority: priorityFromSeverity(severity2),
            module: this.moduleName,
            accountId
          });
          continue;
        }
        const missingCount = patchState.MissingCount ?? 0;
        const failedCount = patchState.FailedCount ?? 0;
        const criticalNonCompliantCount = patchState.CriticalNonCompliantCount ?? 0;
        const securityNonCompliantCount = patchState.SecurityNonCompliantCount ?? 0;
        const otherNonCompliantCount = patchState.OtherNonCompliantCount ?? 0;
        const lastScanTime = patchState.OperationEndTime?.toISOString() ?? "unknown";
        if (missingCount === 0 && failedCount === 0 && criticalNonCompliantCount === 0 && securityNonCompliantCount === 0 && otherNonCompliantCount === 0) {
          continue;
        }
        let riskScore;
        if (criticalNonCompliantCount > 0 || securityNonCompliantCount > 0 || failedCount > 0) {
          riskScore = 7.5;
        } else if (otherNonCompliantCount > 0) {
          riskScore = 5.5;
        } else {
          riskScore = 5.5;
        }
        const severity = severityFromScore(riskScore);
        const titleParts = [];
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
          `Last scan: ${lastScanTime}`
        ];
        findings.push({
          severity,
          title: `Instance ${instanceId} has ${titleParts.join(", ")} patches`,
          resourceType: "AWS::EC2::Instance",
          resourceId: instanceId,
          resourceArn: instanceArn,
          region,
          description: descParts.join(". "),
          impact: `Instance has ${missingCount} missing and ${failedCount} failed patches \u2014 potential security vulnerabilities.`,
          riskScore,
          remediationSteps: [
            `Review patch compliance for instance ${instanceId} in the Systems Manager console.`,
            "Apply missing patches using a maintenance window or manual patching.",
            "Investigate and resolve any failed patch installations.",
            "Consider enabling automatic patching through Patch Manager."
          ],
          priority: priorityFromSeverity(severity),
          module: this.moduleName,
          accountId
        });
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `Patch compliance scan failed: ${msg}`,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/imdsv2-enforcement.ts
import {
  EC2Client as EC2Client6,
  DescribeInstancesCommand as DescribeInstancesCommand5
} from "@aws-sdk/client-ec2";
function makeFinding11(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var Imdsv2EnforcementScanner = class {
  moduleName = "imdsv2_enforcement";
  async scan(ctx) {
    const { region, partition, accountId } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      const client = createClient(EC2Client6, region, ctx.credentials);
      const instances = [];
      let nextToken;
      do {
        const resp = await client.send(
          new DescribeInstancesCommand5({
            Filters: [{ Name: "instance-state-name", Values: ["running"] }],
            NextToken: nextToken
          })
        );
        if (resp.Reservations) {
          for (const reservation of resp.Reservations) {
            if (reservation.Instances) {
              instances.push(...reservation.Instances);
            }
          }
        }
        nextToken = resp.NextToken;
      } while (nextToken);
      for (const instance of instances) {
        const instanceId = instance.InstanceId ?? "unknown";
        const instanceType = instance.InstanceType ?? "unknown";
        const state = instance.State?.Name ?? "unknown";
        const httpTokens = instance.MetadataOptions?.HttpTokens ?? "unknown";
        const hopLimit = instance.MetadataOptions?.HttpPutResponseHopLimit ?? 1;
        const instanceArn = `arn:${partition}:ec2:${region}:${accountId}:instance/${instanceId}`;
        if (httpTokens !== "required") {
          const description = [
            `EC2 instance ${instanceId} (type: ${instanceType}, state: ${state}) has HttpTokens set to "${httpTokens}".`,
            `IMDSv1 is accessible, allowing unauthenticated metadata requests.`
          ];
          if (hopLimit > 1) {
            description.push(`HttpPutResponseHopLimit is ${hopLimit} (>1), which may allow containers to reach IMDS.`);
          }
          findings.push(
            makeFinding11({
              riskScore: 7.5,
              title: `EC2 instance ${instanceId} does not enforce IMDSv2`,
              resourceType: "AWS::EC2::Instance",
              resourceId: instanceId,
              resourceArn: instanceArn,
              region,
              description: description.join(" "),
              impact: "IMDSv1 allows attackers to steal IAM role credentials via SSRF attacks",
              remediationSteps: [
                "Enforce IMDSv2 by setting HttpTokens to 'required'.",
                "Run: aws ec2 modify-instance-metadata-options --instance-id " + instanceId + " --http-tokens required --http-endpoint enabled",
                "Set HttpPutResponseHopLimit to 1 unless running containers that need metadata access.",
                "Update launch templates and Auto Scaling groups to enforce IMDSv2 for new instances."
              ]
            })
          );
        } else if (hopLimit > 1) {
          warnings.push(
            `Instance ${instanceId} enforces IMDSv2 but HttpPutResponseHopLimit is ${hopLimit} (>1). Verify this is intentional for containerized workloads.`
          );
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: instances.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: err instanceof Error ? err.message : String(err),
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/scanners/waf-coverage.ts
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand
} from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  WAFV2Client,
  GetWebACLForResourceCommand
} from "@aws-sdk/client-wafv2";
function makeFinding12(opts) {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity) };
}
var WafCoverageScanner = class {
  moduleName = "waf_coverage";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const findings = [];
    const warnings = [];
    try {
      const elbClient = createClient(ElasticLoadBalancingV2Client, region, ctx.credentials);
      const wafClient = createClient(WAFV2Client, region, ctx.credentials);
      const loadBalancers = [];
      let marker;
      do {
        const resp = await elbClient.send(
          new DescribeLoadBalancersCommand({ Marker: marker })
        );
        if (resp.LoadBalancers) {
          loadBalancers.push(...resp.LoadBalancers);
        }
        marker = resp.NextMarker;
      } while (marker);
      const internetFacing = loadBalancers.filter((lb) => lb.Scheme === "internet-facing");
      for (const lb of internetFacing) {
        const lbName = lb.LoadBalancerName ?? "unknown";
        const lbArn = lb.LoadBalancerArn ?? "unknown";
        const lbType = lb.Type ?? "unknown";
        if (lbType !== "application") {
          warnings.push(
            `Skipping ${lbType} load balancer "${lbName}" \u2014 WAF Web ACL association is only supported for ALBs.`
          );
          continue;
        }
        try {
          const wafResp = await wafClient.send(
            new GetWebACLForResourceCommand({ ResourceArn: lbArn })
          );
          if (!wafResp.WebACL) {
            findings.push(
              makeFinding12({
                riskScore: 7.5,
                title: `Internet-facing ALB ${lbName} has no WAF protection`,
                resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
                resourceId: lbName,
                resourceArn: lbArn,
                region,
                description: `Internet-facing Application Load Balancer "${lbName}" does not have a WAF Web ACL associated. Traffic is not inspected for common web exploits.`,
                impact: "Without WAF, the ALB is exposed to SQL injection, XSS, and other OWASP Top 10 attacks",
                remediationSteps: [
                  "Create a WAFv2 Web ACL with managed rule groups (e.g., AWSManagedRulesCommonRuleSet).",
                  "Associate the Web ACL with the ALB using the REGIONAL scope.",
                  "Enable WAF logging for visibility into blocked requests.",
                  "Consider adding rate-based rules to mitigate DDoS at the application layer."
                ]
              })
            );
          }
        } catch (wafErr) {
          const errMsg = wafErr instanceof Error ? wafErr.message : String(wafErr);
          const errName = wafErr instanceof Error ? wafErr.name ?? "" : "";
          if (errName === "WAFNonexistentItemException") {
            findings.push(
              makeFinding12({
                riskScore: 7.5,
                title: `Internet-facing ALB ${lbName} has no WAF protection`,
                resourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
                resourceId: lbName,
                resourceArn: lbArn,
                region,
                description: `Internet-facing Application Load Balancer "${lbName}" does not have a WAF Web ACL associated. Traffic is not inspected for common web exploits.`,
                impact: "Without WAF, the ALB is exposed to SQL injection, XSS, and other OWASP Top 10 attacks",
                remediationSteps: [
                  "Create a WAFv2 Web ACL with managed rule groups (e.g., AWSManagedRulesCommonRuleSet).",
                  "Associate the Web ACL with the ALB using the REGIONAL scope.",
                  "Enable WAF logging for visibility into blocked requests.",
                  "Consider adding rate-based rules to mitigate DDoS at the application layer."
                ]
              })
            );
          } else if (errName === "AccessDeniedException" || errName === "WAFInvalidParameterException") {
            warnings.push(
              `Could not check WAF for ALB "${lbName}": ${errMsg}. Ensure wafv2:GetWebACLForResource permission is granted.`
            );
          } else {
            warnings.push(`Error checking WAF for ALB "${lbName}": ${errMsg}`);
          }
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: internetFacing.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings
      };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const errName = err instanceof Error ? err.name ?? "" : "";
      if (errName === "AccessDeniedException" || errName === "UnrecognizedClientException") {
        return {
          module: this.moduleName,
          status: "success",
          warnings: [`WAF coverage check skipped: ${errMsg}`],
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings: []
        };
      }
      return {
        module: this.moduleName,
        status: "error",
        error: errMsg,
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    }
  }
};

// src/tools/report-tool.ts
var SEVERITY_ICON = {
  CRITICAL: "\u{1F534}",
  HIGH: "\u{1F7E0}",
  MEDIUM: "\u{1F7E1}",
  LOW: "\u{1F7E2}"
};
var SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
function formatDuration(start, end) {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1e3) return `${ms}ms`;
  const secs = Math.round(ms / 1e3);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remainSecs = secs % 60;
  return `${mins}m ${remainSecs}s`;
}
function renderFinding(f) {
  const steps = f.remediationSteps.map((s, i) => `  ${i + 1}. ${s}`).join("\n");
  return [
    `#### ${f.title}`,
    `- **Resource:** ${f.resourceId} (\`${f.resourceArn}\`)`,
    `- **Description:** ${f.description}`,
    `- **Impact:** ${f.impact}`,
    `- **Risk Score:** ${f.riskScore}/10`,
    `- **Remediation:**`,
    steps,
    `- **Priority:** ${f.priority}`
  ].join("\n");
}
function generateMarkdownReport(scanResults) {
  const { summary, modules, accountId, region, scanStart, scanEnd } = scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration(scanStart, scanEnd);
  const lines = [];
  lines.push(`# AWS Security Scan Report \u2014 ${date}`);
  lines.push("");
  lines.push("## Executive Summary");
  lines.push(`- **Account:** ${accountId}`);
  lines.push(`- **Region:** ${region}`);
  lines.push(`- **Scan Duration:** ${duration}`);
  lines.push(
    `- **Total Findings:** ${summary.totalFindings} (\u{1F534} ${summary.critical} Critical | \u{1F7E0} ${summary.high} High | \u{1F7E1} ${summary.medium} Medium | \u{1F7E2} ${summary.low} Low)`
  );
  lines.push("");
  if (summary.totalFindings === 0) {
    lines.push("## Findings by Severity");
    lines.push("");
    lines.push("\u2705 No security issues found.");
    lines.push("");
  } else {
    const allFindings = modules.flatMap((m) => m.findings);
    const grouped = /* @__PURE__ */ new Map();
    for (const sev of SEVERITY_ORDER) {
      grouped.set(sev, []);
    }
    for (const f of allFindings) {
      grouped.get(f.severity).push(f);
    }
    lines.push("## Findings by Severity");
    lines.push("");
    for (const sev of SEVERITY_ORDER) {
      const findings = grouped.get(sev);
      const icon = SEVERITY_ICON[sev];
      lines.push(`### ${icon} ${sev.charAt(0)}${sev.slice(1).toLowerCase()}`);
      lines.push("");
      if (findings.length === 0) {
        lines.push(`No ${sev.toLowerCase()} findings.`);
        lines.push("");
        continue;
      }
      findings.sort((a, b) => b.riskScore - a.riskScore);
      for (const f of findings) {
        lines.push(renderFinding(f));
        lines.push("");
      }
    }
  }
  lines.push("## Scan Statistics");
  lines.push(
    "| Module | Resources Scanned | Findings | Status |"
  );
  lines.push("|--------|------------------|----------|--------|");
  for (const m of modules) {
    const status = m.status === "success" ? "\u2705" : "\u274C";
    lines.push(
      `| ${m.module} | ${m.resourcesScanned} | ${m.findingsCount} | ${status} |`
    );
  }
  lines.push("");
  if (summary.totalFindings > 0) {
    const allFindings = modules.flatMap((m) => m.findings);
    allFindings.sort((a, b) => b.riskScore - a.riskScore);
    lines.push("## Recommendations (Priority Order)");
    for (let i = 0; i < allFindings.length; i++) {
      const f = allFindings[i];
      lines.push(`${i + 1}. [${f.priority}] ${f.title}: ${f.remediationSteps[0] ?? "Review and remediate."}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// src/tools/mlps-report.ts
var MLPS_CHECKS = [
  // 一、身份鉴别
  {
    id: "8.1.4.1a",
    category: "\u8EAB\u4EFD\u9274\u522B",
    name: "\u5BC6\u7801\u7B56\u7565",
    modules: ["security_hub_findings"],
    findingPatterns: ["password policy", "password length", "complexity", "password expiry", "reuse prevention", "IAM.7", "IAM.10"]
  },
  {
    id: "8.1.4.1a",
    category: "\u8EAB\u4EFD\u9274\u522B",
    name: "\u5BC6\u94A5\u8F6E\u6362",
    modules: ["security_hub_findings"],
    findingPatterns: ["access key older", "access key rotated", "IAM.3", "IAM.4"]
  },
  {
    id: "8.1.4.1d",
    category: "\u8EAB\u4EFD\u9274\u522B",
    name: "\u53CC\u56E0\u7D20\u8BA4\u8BC1",
    modules: ["security_hub_findings"],
    findingPatterns: ["MFA", "IAM.5", "IAM.6"]
  },
  // 二、访问控制
  {
    id: "8.1.4.2c",
    category: "\u8BBF\u95EE\u63A7\u5236",
    name: "\u6700\u5C0F\u6743\u9650",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    findingPatterns: [
      "AdministratorAccess",
      "PowerUserAccess",
      "IAMFullAccess",
      "over-permissive",
      "privilege escalation",
      "self-grant",
      "iam:*",
      "create admin",
      "Lambda role passing",
      "CreateAccessKey",
      "AssumeRole"
    ]
  },
  {
    id: "8.1.4.2",
    category: "\u8BBF\u95EE\u63A7\u5236",
    name: "\u5B89\u5168\u7EC4",
    modules: ["network_reachability", "security_hub_findings"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP", "MySQL", "PostgreSQL", "MongoDB", "Redis", "high-risk port", "security group", "EC2.18", "EC2.19"]
  },
  // 三、安全审计
  {
    id: "8.1.4.3a",
    category: "\u5B89\u5168\u5BA1\u8BA1",
    name: "\u5BA1\u8BA1\u529F\u80FD",
    modules: ["security_hub_findings"],
    findingPatterns: ["CloudTrail", "not enabled", "multi-region", "not logging", "CloudTrail.1"]
  },
  {
    id: "8.1.4.3b",
    category: "\u5B89\u5168\u5BA1\u8BA1",
    name: "\u5BA1\u8BA1\u5B8C\u6574\u6027",
    modules: ["security_hub_findings"],
    findingPatterns: ["log file validation", "log integrity", "log validation", "CloudTrail.4", "CloudTrail.5"]
  },
  {
    id: "8.1.4.3c",
    category: "\u5B89\u5168\u5BA1\u8BA1",
    name: "\u5BA1\u8BA1\u4FDD\u62A4",
    modules: ["security_hub_findings"],
    findingPatterns: ["CloudTrail", "S3 bucket", "encryption", "versioning", "Block Public Access", "CloudTrail.6", "CloudTrail.7"]
  },
  // 四、入侵防范
  {
    id: "8.1.4.4a",
    category: "\u5165\u4FB5\u9632\u8303",
    name: "GuardDuty \u5A01\u80C1\u68C0\u6D4B",
    modules: ["service_detection", "guardduty_findings"],
    findingPatterns: ["GuardDuty"]
  },
  {
    id: "8.1.4.4a",
    category: "\u5165\u4FB5\u9632\u8303",
    name: "Inspector \u6F0F\u6D1E\u626B\u63CF",
    modules: ["service_detection", "inspector_findings"],
    findingPatterns: ["Inspector", "CVE-"]
  },
  // 五、数据安全
  {
    id: "8.1.4.5a",
    category: "\u6570\u636E\u5B89\u5168",
    name: "\u4F20\u8F93\u52A0\u5BC6",
    modules: ["ssl_certificate", "security_hub_findings"],
    findingPatterns: ["HTTPS", "TLS", "HTTP listener", "certificate", "ELB.1"]
  },
  {
    id: "8.1.4.5b",
    category: "\u6570\u636E\u5B89\u5168",
    name: "S3 \u5B58\u50A8\u52A0\u5BC6",
    modules: ["security_hub_findings"],
    findingPatterns: ["no default encryption", "not encrypted", "S3.4"]
  },
  {
    id: "8.1.4.5b",
    category: "\u6570\u636E\u5B89\u5168",
    name: "EBS \u9ED8\u8BA4\u52A0\u5BC6",
    modules: ["security_hub_findings"],
    findingPatterns: ["EBS default encryption", "EC2.7"]
  },
  {
    id: "8.1.4.5b",
    category: "\u6570\u636E\u5B89\u5168",
    name: "RDS \u5B58\u50A8\u52A0\u5BC6",
    modules: ["security_hub_findings"],
    findingPatterns: ["storage is not encrypted", "RDS.3"]
  },
  // 六、网络安全
  {
    id: "8.1.3.1a",
    category: "\u7F51\u7EDC\u5B89\u5168",
    name: "\u7F51\u7EDC\u67B6\u6784",
    modules: ["security_hub_findings"],
    findingPatterns: ["default VPC", "EC2.2"]
  },
  {
    id: "8.1.3.2a",
    category: "\u7F51\u7EDC\u5B89\u5168",
    name: "\u8FB9\u754C\u9632\u62A4",
    modules: ["network_reachability", "security_hub_findings"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP", "security group", "EC2.18", "EC2.19"]
  }
];
var CATEGORY_ORDER = [
  "\u8EAB\u4EFD\u9274\u522B",
  "\u8BBF\u95EE\u63A7\u5236",
  "\u5B89\u5168\u5BA1\u8BA1",
  "\u5165\u4FB5\u9632\u8303",
  "\u6570\u636E\u5B89\u5168",
  "\u7F51\u7EDC\u5B89\u5168"
];
var CATEGORY_SECTION = {
  "\u8EAB\u4EFD\u9274\u522B": "\u4E00\u3001\u8EAB\u4EFD\u9274\u522B",
  "\u8BBF\u95EE\u63A7\u5236": "\u4E8C\u3001\u8BBF\u95EE\u63A7\u5236",
  "\u5B89\u5168\u5BA1\u8BA1": "\u4E09\u3001\u5B89\u5168\u5BA1\u8BA1",
  "\u5165\u4FB5\u9632\u8303": "\u56DB\u3001\u5165\u4FB5\u9632\u8303",
  "\u6570\u636E\u5B89\u5168": "\u4E94\u3001\u6570\u636E\u5B89\u5168",
  "\u7F51\u7EDC\u5B89\u5168": "\u516D\u3001\u7F51\u7EDC\u5B89\u5168"
};
function evaluateCheck(check, allFindings, scanModules) {
  const allModulesPresent = check.modules.every(
    (mod) => scanModules.some((m) => m.module === mod && m.status === "success")
  );
  if (!allModulesPresent) {
    return { check, status: "unknown", relatedFindings: [] };
  }
  const relatedFindings = allFindings.filter((f) => {
    const moduleMatch = check.modules.some((mod) => f.module === mod);
    if (!moduleMatch) return false;
    const text = `${f.title} ${f.description}`.toLowerCase();
    return check.findingPatterns.some(
      (pattern) => text.includes(pattern.toLowerCase())
    );
  });
  return {
    check,
    status: relatedFindings.length === 0 ? "pass" : "fail",
    relatedFindings
  };
}
function generateMlps3Report(scanResults) {
  const { accountId, region, scanStart } = scanResults;
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const allFindings = scanResults.modules.flatMap(
    (m) => m.findings.map((f) => ({ ...f, module: f.module ?? m.module }))
  );
  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status
  }));
  const results = MLPS_CHECKS.map(
    (check) => evaluateCheck(check, allFindings, scanModules)
  );
  const passCount = results.filter((r) => r.status === "pass").length;
  const failCount = results.filter((r) => r.status === "fail").length;
  const unknownCount = results.filter((r) => r.status === "unknown").length;
  const checkedTotal = passCount + failCount;
  const total = results.length;
  const percent = checkedTotal > 0 ? Math.round(passCount / checkedTotal * 100) : 0;
  const lines = [];
  lines.push("# \u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0\u62A5\u544A");
  lines.push("> **\u672C\u62A5\u544A\u4E3A\u7B49\u4FDD\u9884\u68C0\u53C2\u8003\uFF0C\u4EC5\u8986\u76D6 AWS \u4E91\u5E73\u53F0\u914D\u7F6E\u68C0\u67E5\u3002\u5B8C\u6574\u7B49\u4FDD\u6D4B\u8BC4\u9700\u7531\u6301\u8BC1\u6D4B\u8BC4\u673A\u6784\u6267\u884C\u3002**");
  lines.push("");
  lines.push("## \u8D26\u6237\u4FE1\u606F");
  lines.push(`- Account: ${accountId} | Region: ${region} | \u626B\u63CF\u65F6\u95F4: ${scanTime}`);
  lines.push("");
  lines.push("## \u9884\u68C0\u603B\u89C8");
  lines.push(`- \u68C0\u67E5\u9879: ${total} | \u901A\u8FC7: ${passCount} | \u4E0D\u901A\u8FC7: ${failCount}${unknownCount > 0 ? ` | \u672A\u68C0\u67E5: ${unknownCount}` : ""}`);
  lines.push(`- \u901A\u8FC7\u7387: ${percent}%${unknownCount > 0 ? "\uFF08\u672A\u68C0\u67E5\u9879\u4E0D\u8BA1\u5165\u901A\u8FC7\u7387\uFF09" : ""}`);
  lines.push("");
  for (const category of CATEGORY_ORDER) {
    const sectionTitle = CATEGORY_SECTION[category];
    const categoryResults = results.filter((r) => r.check.category === category);
    if (categoryResults.length === 0) continue;
    lines.push(`## ${sectionTitle}`);
    lines.push("");
    const byId = /* @__PURE__ */ new Map();
    for (const r of categoryResults) {
      const existing = byId.get(r.check.id) ?? [];
      existing.push(r);
      byId.set(r.check.id, existing);
    }
    for (const [checkId, checkResults] of byId) {
      lines.push(`### ${checkId} ${checkResults[0].check.name}`);
      for (const r of checkResults) {
        const icon = r.status === "pass" ? "\u2705" : r.status === "fail" ? "\u274C" : "\u26A0\uFE0F";
        const label = r.status === "unknown" ? " \u672A\u68C0\u67E5" : "";
        lines.push(`- [${icon}] ${r.check.name}${label}`);
        if (r.status === "fail" && r.relatedFindings.length > 0) {
          for (const f of r.relatedFindings.slice(0, 3)) {
            lines.push(`  - ${f.severity}: ${f.title}`);
          }
          if (r.relatedFindings.length > 3) {
            lines.push(`  - ... \u53CA\u5176\u4ED6 ${r.relatedFindings.length - 3} \u9879`);
          }
        }
      }
      lines.push("");
    }
  }
  const failedResults = results.filter((r) => r.status === "fail");
  if (failedResults.length > 0) {
    lines.push("## \u5EFA\u8BAE\u6574\u6539\u9879\uFF08\u6309\u4F18\u5148\u7EA7\uFF09");
    lines.push("");
    const allFailedFindings = /* @__PURE__ */ new Map();
    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const key = `${f.resourceId}:${f.title}`;
        if (!allFailedFindings.has(key)) {
          allFailedFindings.set(key, f);
        }
      }
    }
    const sorted = [...allFailedFindings.values()].sort(
      (a, b) => b.riskScore - a.riskScore
    );
    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      const priority = f.riskScore >= 9 ? "P0" : f.riskScore >= 7 ? "P1" : f.riskScore >= 4 ? "P2" : "P3";
      const remediation = f.remediationSteps[0] ?? "Review and remediate.";
      lines.push(`${i + 1}. [${priority}] ${f.title} \u2014 ${remediation}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// src/tools/html-report.ts
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function calcScore(summary) {
  const raw = 100 - summary.critical * 15 - summary.high * 5 - summary.medium * 2 - summary.low * 0.5;
  return Math.max(0, Math.min(100, Math.round(raw)));
}
function formatDuration2(start, end) {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1e3) return `${ms}ms`;
  const secs = Math.round(ms / 1e3);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}
var SEV_COLOR = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e"
};
var SEVERITY_ORDER2 = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
function scoreColor(score) {
  if (score >= 80) return "#22c55e";
  if (score >= 50) return "#eab308";
  return "#ef4444";
}
var SERVICE_RECOMMENDATIONS = {
  security_hub_findings: {
    icon: "\u{1F534}",
    service: "Security Hub",
    impact: "\u65E0\u6CD5\u83B7\u53D6 300+ \u9879\u81EA\u52A8\u5316\u5B89\u5168\u68C0\u67E5\uFF08FSBP/CIS/PCI DSS \u6807\u51C6\uFF09",
    action: "\u542F\u7528 Security Hub \u83B7\u5F97\u6700\u5168\u9762\u7684\u5B89\u5168\u6001\u52BF\u8BC4\u4F30"
  },
  guardduty_findings: {
    icon: "\u{1F534}",
    service: "GuardDuty",
    impact: "\u65E0\u6CD5\u68C0\u6D4B\u5A01\u80C1\u6D3B\u52A8\uFF08\u6076\u610F IP\u3001\u5F02\u5E38 API \u8C03\u7528\u3001\u52A0\u5BC6\u8D27\u5E01\u6316\u77FF\u7B49\uFF09",
    action: "\u542F\u7528 GuardDuty \u83B7\u5F97\u6301\u7EED\u5A01\u80C1\u68C0\u6D4B\u80FD\u529B"
  },
  inspector_findings: {
    icon: "\u{1F7E1}",
    service: "Inspector",
    impact: "\u65E0\u6CD5\u626B\u63CF EC2/Lambda/\u5BB9\u5668\u7684\u8F6F\u4EF6\u6F0F\u6D1E\uFF08CVE\uFF09",
    action: "\u542F\u7528 Inspector \u53D1\u73B0\u5DF2\u77E5\u5B89\u5168\u6F0F\u6D1E"
  },
  trusted_advisor_findings: {
    icon: "\u{1F7E1}",
    service: "Trusted Advisor",
    impact: "\u65E0\u6CD5\u83B7\u53D6 AWS \u6700\u4F73\u5B9E\u8DF5\u5B89\u5168\u68C0\u67E5",
    action: "\u5347\u7EA7\u81F3 Business/Enterprise Support \u8BA1\u5212\u4EE5\u4F7F\u7528 Trusted Advisor \u5B89\u5168\u68C0\u67E5"
  },
  config_rules_findings: {
    icon: "\u{1F7E1}",
    service: "AWS Config",
    impact: "\u65E0\u6CD5\u68C0\u67E5\u8D44\u6E90\u914D\u7F6E\u5408\u89C4\u72B6\u6001",
    action: "\u542F\u7528 AWS Config \u5E76\u914D\u7F6E Config Rules"
  },
  access_analyzer_findings: {
    icon: "\u{1F7E1}",
    service: "IAM Access Analyzer",
    impact: "\u65E0\u6CD5\u68C0\u6D4B\u8D44\u6E90\u662F\u5426\u88AB\u5916\u90E8\u8D26\u53F7\u6216\u516C\u7F51\u8BBF\u95EE",
    action: "\u521B\u5EFA IAM Access Analyzer\uFF08\u8D26\u6237\u7EA7\u6216\u7EC4\u7EC7\u7EA7\uFF09"
  },
  patch_compliance_findings: {
    icon: "\u{1F7E1}",
    service: "SSM Patch Manager",
    impact: "\u65E0\u6CD5\u68C0\u67E5\u5B9E\u4F8B\u8865\u4E01\u5408\u89C4\u72B6\u6001",
    action: "\u5B89\u88C5 SSM Agent \u5E76\u914D\u7F6E Patch Manager"
  }
};
var SERVICE_NOT_ENABLED_PATTERNS = [
  "not enabled",
  "not found",
  "No IAM Access Analyzer",
  "No SSM-managed instances",
  "requires AWS Business or Enterprise Support",
  "not available",
  "is not enabled"
];
function getDisabledServices(modules) {
  const disabled = [];
  for (const mod of modules) {
    const rec = SERVICE_RECOMMENDATIONS[mod.module];
    if (!rec) continue;
    if (!mod.warnings?.length) continue;
    const hasNotEnabled = mod.warnings.some(
      (w) => SERVICE_NOT_ENABLED_PATTERNS.some((p) => w.includes(p))
    );
    if (hasNotEnabled) {
      disabled.push(rec);
    }
  }
  return disabled;
}
function buildServiceReminderHtml(modules) {
  const disabled = getDisabledServices(modules);
  if (disabled.length === 0) return "";
  const items = disabled.map((svc) => `
    <div style="margin-bottom:12px">
      <div style="font-weight:600;font-size:15px">${esc(svc.icon)} ${esc(svc.service)} \u672A\u542F\u7528</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">\u5F71\u54CD\uFF1A${esc(svc.impact)}</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">\u5EFA\u8BAE\uFF1A${esc(svc.action)}</div>
    </div>`).join("\n");
  return `
  <section>
    <div style="background:#2d1f00;border:1px solid #b45309;border-radius:8px;padding:20px;margin-bottom:32px">
      <div style="font-size:17px;font-weight:700;margin-bottom:12px">&#9889; \u4EE5\u4E0B\u5B89\u5168\u670D\u52A1\u672A\u542F\u7528\uFF0C\u90E8\u5206\u68C0\u67E5\u65E0\u6CD5\u6267\u884C\uFF1A</div>
      ${items}
      <div style="margin-top:12px;font-size:13px;color:#fbbf24;font-weight:500">\u542F\u7528\u4EE5\u4E0A\u670D\u52A1\u540E\u91CD\u65B0\u626B\u63CF\u53EF\u83B7\u5F97\u66F4\u5B8C\u6574\u7684\u5B89\u5168\u8BC4\u4F30\u3002</div>
    </div>
  </section>`;
}
function sharedCss() {
  return `
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0f172a;color:#f8fafc;font-family:Inter,system-ui,-apple-system,sans-serif;line-height:1.6;font-size:14px}
    .container{max-width:900px;margin:0 auto;padding:40px 24px}
    header{text-align:center;margin-bottom:40px;border-bottom:1px solid #334155;padding-bottom:24px}
    header h1{font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:-0.5px}
    .meta{color:#94a3b8;font-size:13px}
    .disclaimer{color:#94a3b8;font-size:12px;font-style:italic;margin-top:8px;max-width:640px;margin-left:auto;margin-right:auto}
    h2{font-size:20px;font-weight:600;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #334155}
    h3{font-size:16px;font-weight:600;margin:16px 0 8px}
    h4{font-size:14px;font-weight:600;margin:12px 0 4px}
    .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;margin-bottom:16px}
    .summary{display:flex;gap:24px;margin-bottom:32px;flex-wrap:wrap}
    .score-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px 32px;text-align:center;flex:0 0 auto}
    .score-value{font-size:48px;font-weight:700}
    .score-label{color:#94a3b8;font-size:13px;margin-top:4px}
    .severity-stats{display:flex;gap:12px;flex-wrap:wrap;flex:1;align-items:center;justify-content:center}
    .stat-card{border-radius:8px;padding:16px 20px;text-align:center;min-width:100px;border:1px solid #334155;background:#1e293b}
    .stat-count{font-size:28px;font-weight:700}
    .stat-label{font-size:12px;color:#94a3b8;margin-top:2px}
    .stat-critical .stat-count{color:#ef4444}
    .stat-high .stat-count{color:#f97316}
    .stat-medium .stat-count{color:#eab308}
    .stat-low .stat-count{color:#22c55e}
    .charts{display:flex;gap:24px;margin-bottom:32px;flex-wrap:wrap;justify-content:center}
    .chart-box{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;flex:1;min-width:280px}
    .chart-title{font-size:14px;font-weight:600;margin-bottom:12px;text-align:center;color:#cbd5e1}
    .sev-critical{border-left-color:#ef4444}
    .sev-high{border-left-color:#f97316}
    .sev-medium{border-left-color:#eab308}
    .sev-low{border-left-color:#22c55e}
    .badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.5px;color:#fff}
    .badge-critical{background:#ef4444}
    .badge-high{background:#f97316}
    .badge-medium{background:#eab308;color:#1e293b}
    .badge-low{background:#22c55e;color:#1e293b}
    .finding-title{font-size:15px;font-weight:600;margin-bottom:8px}
    .finding-detail{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .finding-detail strong{color:#f8fafc}
    .remediation-steps{margin-top:8px;padding-left:20px}
    .remediation-steps li{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    table{width:100%;border-collapse:collapse;margin-bottom:16px}
    th{background:#334155;color:#f8fafc;padding:10px 12px;text-align:left;font-size:13px;font-weight:600}
    td{padding:8px 12px;border-bottom:1px solid #334155;font-size:13px;color:#cbd5e1}
    tr:hover td{background:rgba(51,65,85,0.3)}
    .recommendations ol{padding-left:24px}
    .recommendations li{margin-bottom:8px;color:#cbd5e1;font-size:13px}
    .priority-p0{color:#ef4444;font-weight:700}
    .priority-p1{color:#f97316;font-weight:700}
    .priority-p2{color:#eab308;font-weight:700}
    .priority-p3{color:#22c55e;font-weight:700}
    footer{margin-top:48px;padding-top:24px;border-top:1px solid #334155;text-align:center}
    footer p{color:#64748b;font-size:12px;margin-bottom:4px}
    .check-item{display:flex;align-items:flex-start;gap:8px;padding:8px 12px;border-radius:6px;margin-bottom:4px;font-size:14px}
    .check-pass{background:rgba(34,197,94,0.1)}
    .check-fail{background:rgba(239,68,68,0.1)}
    .check-unknown{background:rgba(148,163,184,0.1)}
    .check-icon{font-size:16px;flex-shrink:0}
    .check-name{font-weight:500}
    .check-findings{margin-left:28px;margin-top:4px}
    .check-findings li{color:#94a3b8;font-size:12px;margin-bottom:2px;list-style:none}
    .no-findings{text-align:center;padding:40px;color:#22c55e;font-size:18px;font-weight:600}
    .finding-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:12px;border-left:4px solid;overflow:hidden}
    .finding-fold>summary{cursor:pointer;padding:12px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none}
    .finding-fold>summary::-webkit-details-marker{display:none}
    .finding-fold>summary::marker{content:""}
    .finding-fold>summary .badge{margin-bottom:0}
    .finding-fold>summary::after{content:"\\25B6";font-size:10px;color:#64748b;flex-shrink:0;transition:transform 0.2s}
    .finding-fold[open]>summary::after{transform:rotate(90deg)}
    .finding-fold[open]>summary{border-bottom:1px solid #334155}
    .finding-body{padding:12px 20px 16px}
    .finding-summary-title{font-weight:600;font-size:14px;flex:1}
    .finding-summary-score{color:#94a3b8;font-size:13px;font-weight:600;white-space:nowrap}
    .top5-card{display:flex;gap:16px;background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:16px;border-left:4px solid}
    .top5-card .badge{margin-bottom:0}
    .top5-rank{font-size:28px;font-weight:800;color:#475569;min-width:44px;display:flex;align-items:flex-start;justify-content:center}
    .top5-content{flex:1}
    .top5-title{font-size:17px;font-weight:700;margin:8px 0}
    .top5-detail{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .top5-detail strong{color:#f8fafc}
    .top5-remediation{margin-top:8px;padding-left:20px}
    .top5-remediation li{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .trend-section{margin-bottom:32px}
    .trend-chart{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;margin-bottom:16px}
    .trend-title{font-size:14px;font-weight:600;margin-bottom:12px;text-align:center;color:#cbd5e1}
    .category-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .category-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;font-size:18px;font-weight:600;user-select:none}
    .category-fold>summary::-webkit-details-marker{display:none}
    .category-fold>summary::marker{content:""}
    .category-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s}
    .category-fold[open]>summary::after{transform:rotate(90deg)}
    .category-fold[open]>summary{border-bottom:1px solid #334155}
    .category-body{padding:12px 20px 16px}
    .category-title{flex:1}
    .category-stats{display:inline-flex;gap:12px;font-size:13px}
    .category-stat-pass{color:#22c55e}
    .category-stat-fail{color:#ef4444}
    .category-stat-unknown{color:#94a3b8}
    .module-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .module-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none;flex-wrap:wrap}
    .module-fold>summary::-webkit-details-marker{display:none}
    .module-fold>summary::marker{content:""}
    .module-fold>summary h3{margin:0;font-size:16px}
    .module-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s;margin-left:auto}
    .module-fold[open]>summary::after{transform:rotate(90deg)}
    .module-fold[open]>summary{border-bottom:1px solid #334155}
    .module-body{padding:12px 20px 16px}
    .module-badges{display:inline-flex;gap:6px;flex-wrap:wrap}
    .severity-group{margin-bottom:16px}
    .severity-group-fold{margin-bottom:16px}
    .severity-group-fold>summary{cursor:pointer;padding:4px 0;list-style:none;user-select:none}
    .severity-group-fold>summary::-webkit-details-marker{display:none}
    .severity-group-fold>summary::marker{content:""}
    .severity-group-fold>summary h4{margin:0;display:inline}
    .finding-card{display:flex;align-items:center;gap:8px;padding:8px 12px;margin-bottom:4px;border-radius:6px;border-left:4px solid #334155;background:rgba(30,41,59,0.5);flex-wrap:wrap}
    .finding-title-text{font-weight:600;font-size:13px;flex:1;min-width:200px}
    .finding-resource{color:#94a3b8;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .finding-card>details{width:100%;margin-top:4px}
    .finding-card>details>summary{cursor:pointer;font-size:12px;color:#60a5fa;user-select:none}
    .finding-card-body{padding:8px 0}
    .finding-card-body p{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .finding-card-body ol{padding-left:20px}
    .finding-card-body li{color:#cbd5e1;font-size:13px;margin-bottom:2px}
    .rec-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .rec-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none}
    .rec-fold>summary::-webkit-details-marker{display:none}
    .rec-fold>summary::marker{content:""}
    .rec-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s;margin-left:auto}
    .rec-fold[open]>summary::after{transform:rotate(90deg)}
    .rec-fold[open]>summary{border-bottom:1px solid #334155}
    .rec-body{padding:12px 20px 16px}
    .rec-body ol{padding-left:24px}
    .rec-body li{margin-bottom:8px;color:#cbd5e1;font-size:13px}
    .rec-body .badge{margin-right:6px;vertical-align:middle}
    @media print{
      body{background:#fff;color:#1e293b;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .container{max-width:100%;padding:20px}
      .card,.score-card,.stat-card,.chart-box,.finding-fold,.top5-card,.trend-chart,.category-fold,.module-fold,.finding-card,.rec-fold{background:#fff;border:1px solid #e2e8f0}
      .badge{border:1px solid}
      header{border-bottom-color:#e2e8f0}
      h2{border-bottom-color:#e2e8f0}
      th{background:#f1f5f9;color:#1e293b}
      td{border-bottom-color:#e2e8f0;color:#475569}
      footer{border-top-color:#e2e8f0}
      .meta,.disclaimer{color:#64748b}
      .finding-detail,.top5-detail{color:#475569}
      .finding-detail strong,.top5-detail strong{color:#1e293b}
      .stat-label,.score-label{color:#64748b}
      .chart-title,.trend-title{color:#475569}
      .remediation-steps li,.top5-remediation li{color:#475569}
      .recommendations li{color:#475569}
      .finding-card-body p,.finding-card-body li{color:#475569}
      .finding-title-text{color:#1e293b}
      .finding-resource{color:#64748b}
      .check-findings li{color:#64748b}
      .finding-fold,.top5-card,.category-fold,.module-fold,.finding-card,.rec-fold{break-inside:avoid}
      .check-item{break-inside:avoid}
      svg text{fill:#1e293b !important}
      .finding-fold[open]>summary,.category-fold[open]>summary,.module-fold[open]>summary,.rec-fold[open]>summary{border-bottom-color:#e2e8f0}
      details{display:block}
      details>summary{display:block}
      details>:not(summary){display:block !important}
    }
  `;
}
function donutChart(summary) {
  const total = summary.totalFindings;
  const r = 80;
  const circ = 2 * Math.PI * r;
  if (total === 0) {
    return [
      '<svg viewBox="0 0 200 200" width="200" height="200">',
      '  <circle cx="100" cy="100" r="80" fill="none" stroke="#334155" stroke-width="20"/>',
      '  <text x="100" y="105" text-anchor="middle" fill="#22c55e" font-size="24" font-weight="700">0</text>',
      "</svg>"
    ].join("\n");
  }
  const segments = [
    { count: summary.critical, color: SEV_COLOR.CRITICAL },
    { count: summary.high, color: SEV_COLOR.HIGH },
    { count: summary.medium, color: SEV_COLOR.MEDIUM },
    { count: summary.low, color: SEV_COLOR.LOW }
  ].filter((s) => s.count > 0);
  let offset = 0;
  const circles = segments.map((s) => {
    const arc = s.count / total * circ;
    const el = `<circle cx="100" cy="100" r="80" fill="none" stroke="${s.color}" stroke-width="20" stroke-dasharray="${arc.toFixed(2)} ${(circ - arc).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 100 100)"/>`;
    offset += arc;
    return el;
  });
  return [
    '<svg viewBox="0 0 200 200" width="200" height="200">',
    ...circles.map((c) => `  ${c}`),
    `  <text x="100" y="105" text-anchor="middle" fill="#f8fafc" font-size="28" font-weight="700">${total}</text>`,
    "</svg>"
  ].join("\n");
}
function barChart(modules) {
  const withFindings = modules.filter((m) => m.findingsCount > 0).sort((a, b) => b.findingsCount - a.findingsCount).slice(0, 12);
  if (withFindings.length === 0) {
    return [
      '<svg viewBox="0 0 400 50" width="100%">',
      '  <text x="200" y="30" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="600">All modules clean</text>',
      "</svg>"
    ].join("\n");
  }
  const maxCount = withFindings[0].findingsCount;
  const barH = 22;
  const gap = 6;
  const labelW = 160;
  const maxBarW = 190;
  const height = withFindings.length * (barH + gap);
  const bars = withFindings.map((m, i) => {
    const y = i * (barH + gap);
    const w = Math.max(4, m.findingsCount / maxCount * maxBarW);
    const worstSev = m.findings.reduce((worst, f) => {
      const idx = SEVERITY_ORDER2.indexOf(f.severity);
      return idx < SEVERITY_ORDER2.indexOf(worst) ? f.severity : worst;
    }, "LOW");
    const color = SEV_COLOR[worstSev];
    return [
      `<text x="${labelW - 8}" y="${y + barH / 2 + 4}" text-anchor="end" fill="#94a3b8" font-size="11">${esc(m.module)}</text>`,
      `<rect x="${labelW}" y="${y}" width="${w.toFixed(1)}" height="${barH}" rx="3" fill="${color}" opacity="0.85"/>`,
      `<text x="${labelW + w + 6}" y="${y + barH / 2 + 4}" fill="#f8fafc" font-size="11">${m.findingsCount}</text>`
    ].join("\n");
  });
  return [
    `<svg viewBox="0 0 400 ${height}" width="100%">`,
    ...bars,
    "</svg>"
  ].join("\n");
}
function findingsTrendChart(history) {
  const entries = history.slice(-30);
  if (entries.length < 2) return "";
  const W = 800;
  const H = 260;
  const pad = { top: 30, right: 20, bottom: 50, left: 50 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const maxVal = Math.max(
    1,
    ...entries.flatMap((e) => [e.critical, e.high, e.medium, e.low])
  );
  const xPos = (i) => pad.left + i / Math.max(1, entries.length - 1) * plotW;
  const yPos = (v) => pad.top + plotH - v / maxVal * plotH;
  const lines = [
    { key: "critical", color: "#ef4444", label: "Critical" },
    { key: "high", color: "#f97316", label: "High" },
    { key: "medium", color: "#eab308", label: "Medium" },
    { key: "low", color: "#22c55e", label: "Low" }
  ];
  const polylines = lines.map((line) => {
    const pts = entries.map(
      (e, i) => `${xPos(i).toFixed(1)},${yPos(e[line.key]).toFixed(1)}`
    ).join(" ");
    return `<polyline points="${pts}" fill="none" stroke="${line.color}" stroke-width="2" stroke-linejoin="round"/>`;
  }).join("\n  ");
  const xLabels = entries.map((e, i) => {
    if (i % 5 !== 0 && i !== entries.length - 1) return "";
    return `<text x="${xPos(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${e.date.slice(5)}</text>`;
  }).filter(Boolean).join("\n  ");
  const ySteps = 5;
  const yLabels = Array.from({ length: ySteps + 1 }, (_, i) => {
    const val = Math.round(maxVal / ySteps * i);
    return [
      `<text x="${pad.left - 8}" y="${yPos(val).toFixed(1)}" text-anchor="end" fill="#94a3b8" font-size="10" dominant-baseline="middle">${val}</text>`,
      `<line x1="${pad.left}" y1="${yPos(val).toFixed(1)}" x2="${W - pad.right}" y2="${yPos(val).toFixed(1)}" stroke="#334155" stroke-width="0.5"/>`
    ].join("\n  ");
  }).join("\n  ");
  const legend = lines.map((line, i) => {
    const lx = pad.left + i * 110;
    return `<rect x="${lx}" y="8" width="14" height="3" rx="1" fill="${line.color}"/><text x="${lx + 18}" y="12" fill="#94a3b8" font-size="10">${line.label}</text>`;
  }).join("\n  ");
  return [
    `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">`,
    `  ${legend}`,
    `  ${yLabels}`,
    `  ${polylines}`,
    `  ${xLabels}`,
    "</svg>"
  ].join("\n");
}
function scoreTrendChart(history) {
  const entries = history.slice(-30);
  if (entries.length < 2) return "";
  const W = 800;
  const H = 220;
  const pad = { top: 20, right: 20, bottom: 50, left: 50 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;
  const xPos = (i) => pad.left + i / Math.max(1, entries.length - 1) * plotW;
  const yPos = (v) => pad.top + plotH - v / 100 * plotH;
  const pts = entries.map((e, i) => `${xPos(i).toFixed(1)},${yPos(e.score).toFixed(1)}`).join(" ");
  const zones = [
    `<rect x="${pad.left}" y="${yPos(100).toFixed(1)}" width="${plotW}" height="${(yPos(80) - yPos(100)).toFixed(1)}" fill="#22c55e" opacity="0.06"/>`,
    `<rect x="${pad.left}" y="${yPos(80).toFixed(1)}" width="${plotW}" height="${(yPos(50) - yPos(80)).toFixed(1)}" fill="#eab308" opacity="0.06"/>`,
    `<rect x="${pad.left}" y="${yPos(50).toFixed(1)}" width="${plotW}" height="${(yPos(0) - yPos(50)).toFixed(1)}" fill="#ef4444" opacity="0.06"/>`
  ].join("\n  ");
  const xLabels = entries.map((e, i) => {
    if (i % 5 !== 0 && i !== entries.length - 1) return "";
    return `<text x="${xPos(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${e.date.slice(5)}</text>`;
  }).filter(Boolean).join("\n  ");
  const yVals = [0, 25, 50, 75, 100];
  const yLabels = yVals.map(
    (val) => `<text x="${pad.left - 8}" y="${yPos(val).toFixed(1)}" text-anchor="end" fill="#94a3b8" font-size="10" dominant-baseline="middle">${val}</text>
  <line x1="${pad.left}" y1="${yPos(val).toFixed(1)}" x2="${W - pad.right}" y2="${yPos(val).toFixed(1)}" stroke="#334155" stroke-width="0.5"/>`
  ).join("\n  ");
  return [
    `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">`,
    `  ${zones}`,
    `  ${yLabels}`,
    `  <polyline points="${pts}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linejoin="round"/>`,
    `  ${xLabels}`,
    "</svg>"
  ].join("\n");
}
function generateHtmlReport(scanResults, history) {
  const { summary, modules, accountId, region, scanStart, scanEnd } = scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration2(scanStart, scanEnd);
  const score = calcScore(summary);
  const allFindings = modules.flatMap(
    (m) => m.findings.map((f) => ({ ...f, module: f.module ?? m.module }))
  );
  let top5Html = "";
  if (allFindings.length > 0) {
    const top5 = [...allFindings].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);
    const cards = top5.map(
      (f, i) => `
      <div class="top5-card sev-${esc(f.severity.toLowerCase())}">
        <div class="top5-rank">#${i + 1}</div>
        <div class="top5-content">
          <span class="badge badge-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
          <div class="top5-title">${esc(f.title)}</div>
          <div class="top5-detail"><strong>Resource:</strong> ${esc(f.resourceId)}</div>
          <div class="top5-detail"><strong>Impact:</strong> ${esc(f.impact)}</div>
          <div class="top5-detail"><strong>Risk Score:</strong> ${f.riskScore}/10</div>
          <h4>Remediation</h4>
          <ol class="top5-remediation">${f.remediationSteps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        </div>
      </div>`
    ).join("\n");
    top5Html = `
    <section>
      <h2>Top ${top5.length} Highest Risk Findings</h2>
      ${cards}
    </section>`;
  }
  let findingsHtml;
  if (summary.totalFindings === 0) {
    findingsHtml = '<div class="no-findings">No security issues found.</div>';
  } else {
    const FOLD_THRESHOLD = 20;
    const renderCard = (f) => {
      const sev = f.severity.toLowerCase();
      return `<div class="finding-card sev-${esc(sev)}">
        <span class="badge badge-${esc(sev)}">${esc(f.severity)}</span>
        <span class="finding-title-text">${esc(f.title)}</span>
        <span class="finding-resource">${esc(f.resourceArn || f.resourceId)}</span>
        <details><summary>Details</summary><div class="finding-card-body">
          <p>${esc(f.description)}</p>
          <p><strong>Remediation:</strong></p>
          <ol>${f.remediationSteps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        </div></details>
      </div>`;
    };
    const renderCards = (findings) => {
      if (findings.length <= FOLD_THRESHOLD) {
        return findings.map(renderCard).join("\n");
      }
      const first = findings.slice(0, FOLD_THRESHOLD).map(renderCard).join("\n");
      const rest = findings.slice(FOLD_THRESHOLD).map(renderCard).join("\n");
      return `${first}
<details><summary>Show remaining ${findings.length - FOLD_THRESHOLD} findings...</summary>
${rest}
</details>`;
    };
    const SEV_EMOJI = {
      CRITICAL: "&#128308;",
      HIGH: "&#128992;",
      MEDIUM: "&#128993;",
      LOW: "&#128309;"
    };
    const moduleMap = /* @__PURE__ */ new Map();
    for (const f of allFindings) {
      const mod = f.module ?? "unknown";
      if (!moduleMap.has(mod)) moduleMap.set(mod, []);
      moduleMap.get(mod).push(f);
    }
    const moduleEntries = [...moduleMap.entries()].sort((a, b) => {
      const aHasCritHigh = a[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      const bHasCritHigh = b[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      if (aHasCritHigh !== bHasCritHigh) return aHasCritHigh ? -1 : 1;
      return b[1].length - a[1].length;
    });
    findingsHtml = moduleEntries.map(([modName, modFindings]) => {
      const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      for (const f of modFindings) sevCounts[f.severity]++;
      const badges = SEVERITY_ORDER2.filter((sev) => sevCounts[sev] > 0).map((sev) => `<span class="badge badge-${sev.toLowerCase()}">${sevCounts[sev]} ${sev.charAt(0) + sev.slice(1).toLowerCase()}</span>`).join(" ");
      const sevGroups = SEVERITY_ORDER2.map((sev) => {
        const findings = modFindings.filter((f) => f.severity === sev);
        if (findings.length === 0) return "";
        findings.sort((a, b) => b.riskScore - a.riskScore);
        const emoji = SEV_EMOJI[sev] ?? "";
        const label = sev.charAt(0) + sev.slice(1).toLowerCase();
        return `<details class="severity-group-fold">
          <summary><h4>${emoji} ${label} (${findings.length})</h4></summary>
          ${renderCards(findings)}
        </details>`;
      }).filter(Boolean).join("\n");
      return `<details class="module-fold">
        <summary>
          <h3>&#128274; ${esc(modName)} (${modFindings.length})</h3>
          <span class="module-badges">${badges}</span>
        </summary>
        <div class="module-body">
          ${sevGroups}
        </div>
      </details>`;
    }).join("\n");
  }
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>30-Day Trends</h2>
      <div class="trend-chart">
        <div class="trend-title">Findings by Severity</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">Security Score</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }
  const statsRows = modules.map(
    (m) => `<tr><td>${esc(m.module)}</td><td>${m.resourcesScanned}</td><td>${m.findingsCount}</td><td>${m.status === "success" ? "&#10003;" : "&#10007;"}</td></tr>`
  ).join("\n");
  let recsHtml = "";
  if (summary.totalFindings > 0) {
    const recMap = /* @__PURE__ */ new Map();
    for (const f of allFindings) {
      const rem = f.remediationSteps[0] ?? "Review and remediate.";
      const existing = recMap.get(rem);
      if (existing) {
        existing.count++;
        if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing.severity)) {
          existing.severity = f.severity;
        }
      } else {
        recMap.set(rem, { text: rem, severity: f.severity, count: 1 });
      }
    }
    const uniqueRecs = [...recMap.values()].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER2.indexOf(a.severity) - SEVERITY_ORDER2.indexOf(b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });
    const renderRec = (r) => {
      const sev = r.severity.toLowerCase();
      const countLabel = r.count > 1 ? ` (&times; ${r.count})` : "";
      return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}</li>`;
    };
    const TOP_N = 10;
    const topItems = uniqueRecs.slice(0, TOP_N).map(renderRec).join("\n");
    const remaining = uniqueRecs.slice(TOP_N);
    const moreHtml = remaining.length > 0 ? `
<details><summary>Show ${remaining.length} more&hellip;</summary>
${remaining.map(renderRec).join("\n")}
</details>` : "";
    recsHtml = `
      <details class="rec-fold">
        <summary><h2 style="margin:0;border:0;display:inline">Recommendations (${uniqueRecs.length} unique)</h2></summary>
        <div class="rec-body">
          <ol>${topItems}${moreHtml}</ol>
        </div>
      </details>`;
  }
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Security Scan Report &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; AWS Security Scan Report</h1>
  <div class="meta">Account: ${esc(accountId)} | Region: ${esc(region)} | ${esc(date)} | Duration: ${esc(duration)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${scoreColor(score)}">${score}</div>
    <div class="score-label">Security Score</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card stat-critical"><div class="stat-count">${summary.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card stat-high"><div class="stat-count">${summary.high}</div><div class="stat-label">High</div></div>
    <div class="stat-card stat-medium"><div class="stat-count">${summary.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card stat-low"><div class="stat-count">${summary.low}</div><div class="stat-label">Low</div></div>
  </div>
</section>

<section class="charts">
  <div class="chart-box">
    <div class="chart-title">Severity Distribution</div>
    <div style="text-align:center">${donutChart(summary)}</div>
  </div>
  <div class="chart-box">
    <div class="chart-title">Findings by Module</div>
    ${barChart(modules)}
  </div>
</section>

${trendHtml}

${top5Html}

${buildServiceReminderHtml(modules)}

<section>
  <h2>Scan Statistics</h2>
  <table>
    <thead><tr><th>Module</th><th>Resources</th><th>Findings</th><th>Status</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
</section>

<section>
  <h2>All Findings</h2>
  ${findingsHtml}
</section>

${recsHtml}

<footer>
  <p>Generated by AWS Security MCP Server v${VERSION}</p>
  <p>This report is for informational purposes only.</p>
</footer>

</div>
</body>
</html>`;
}
function generateMlps3HtmlReport(scanResults, history) {
  const { accountId, region, scanStart } = scanResults;
  const date = scanStart.split("T")[0];
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const allFindings = scanResults.modules.flatMap(
    (m) => m.findings.map((f) => ({ ...f, module: f.module ?? m.module }))
  );
  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status
  }));
  const results = MLPS_CHECKS.map(
    (check) => evaluateCheck(check, allFindings, scanModules)
  );
  const passCount = results.filter((r) => r.status === "pass").length;
  const failCount = results.filter((r) => r.status === "fail").length;
  const unknownCount = results.filter((r) => r.status === "unknown").length;
  const checkedTotal = passCount + failCount;
  const percent = checkedTotal > 0 ? Math.round(passCount / checkedTotal * 100) : 0;
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>30\u65E5\u8D8B\u52BF</h2>
      <div class="trend-chart">
        <div class="trend-title">\u6309\u4E25\u91CD\u6027\u5206\u7C7B\u7684\u53D1\u73B0</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">\u5B89\u5168\u8BC4\u5206</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }
  const categorySections = CATEGORY_ORDER.map((category) => {
    const sectionTitle = CATEGORY_SECTION[category];
    const categoryResults = results.filter(
      (r) => r.check.category === category
    );
    if (categoryResults.length === 0) return "";
    const catPass = categoryResults.filter((r) => r.status === "pass").length;
    const catFail = categoryResults.filter((r) => r.status === "fail").length;
    const catUnknown = categoryResults.filter(
      (r) => r.status === "unknown"
    ).length;
    const byId = /* @__PURE__ */ new Map();
    for (const r of categoryResults) {
      const existing = byId.get(r.check.id) ?? [];
      existing.push(r);
      byId.set(r.check.id, existing);
    }
    const groups = [...byId.entries()].map(([checkId, checkResults]) => {
      const grpPass = checkResults.filter((r) => r.status === "pass").length;
      const grpFail = checkResults.filter((r) => r.status === "fail").length;
      const grpUnknown = checkResults.filter((r) => r.status === "unknown").length;
      const items = checkResults.map((r) => {
        const icon = r.status === "pass" ? "&#10004;" : r.status === "fail" ? "&#10008;" : "&#9888;";
        const cls = `check-${r.status}`;
        const label = r.status === "unknown" ? " (\u672A\u68C0\u67E5)" : "";
        let findingsHtml = "";
        if (r.status === "fail" && r.relatedFindings.length > 0) {
          const items2 = r.relatedFindings.slice(0, 3).map(
            (f) => `<li>${esc(f.severity)}: ${esc(f.title)}</li>`
          );
          if (r.relatedFindings.length > 3) {
            items2.push(
              `<li>... \u53CA\u5176\u4ED6 ${r.relatedFindings.length - 3} \u9879</li>`
            );
          }
          findingsHtml = `<ul class="check-findings">${items2.join("")}</ul>`;
        }
        return `<div class="check-item ${cls}"><span class="check-icon">${icon}</span><span class="check-name">${esc(r.check.name)}${label}</span></div>${findingsHtml}`;
      }).join("\n");
      const statusBadges = [
        grpPass > 0 ? `<span class="category-stat-pass">&#10003; ${grpPass}</span>` : "",
        grpFail > 0 ? `<span class="category-stat-fail">&#10007; ${grpFail}</span>` : "",
        grpUnknown > 0 ? `<span class="category-stat-unknown">? ${grpUnknown}</span>` : ""
      ].filter(Boolean).join(" ");
      return `<details class="severity-group-fold"><summary><h4>${esc(checkId)} ${esc(checkResults[0].check.name)} <span class="category-stats">${statusBadges}</span></h4></summary>
${items}
</details>`;
    }).join("\n");
    const statsHtml = [
      catPass > 0 ? `<span class="category-stat-pass">&#10003; ${catPass}</span>` : "",
      catFail > 0 ? `<span class="category-stat-fail">&#10007; ${catFail}</span>` : "",
      catUnknown > 0 ? `<span class="category-stat-unknown">? ${catUnknown}</span>` : ""
    ].filter(Boolean).join("");
    return `<details class="category-fold">
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats">${statsHtml}</span>
  </summary>
  <div class="category-body">${groups}</div>
</details>`;
  }).filter(Boolean).join("\n");
  const failedResults = results.filter((r) => r.status === "fail");
  let remediationHtml = "";
  if (failedResults.length > 0) {
    const mlpsRecMap = /* @__PURE__ */ new Map();
    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const rem = f.remediationSteps[0] ?? "Review and remediate.";
        const existing = mlpsRecMap.get(rem);
        if (existing) {
          existing.count++;
          if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing.severity)) {
            existing.severity = f.severity;
          }
        } else {
          mlpsRecMap.set(rem, { text: rem, severity: f.severity, count: 1 });
        }
      }
    }
    const mlpsUniqueRecs = [...mlpsRecMap.values()].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER2.indexOf(a.severity) - SEVERITY_ORDER2.indexOf(b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });
    const renderMlpsRec = (r) => {
      const sev = r.severity.toLowerCase();
      const countLabel = r.count > 1 ? ` (&times; ${r.count})` : "";
      return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}</li>`;
    };
    const MLPS_TOP_N = 10;
    const mlpsTopItems = mlpsUniqueRecs.slice(0, MLPS_TOP_N).map(renderMlpsRec).join("\n");
    const mlpsRemaining = mlpsUniqueRecs.slice(MLPS_TOP_N);
    const mlpsMoreHtml = mlpsRemaining.length > 0 ? `
<details><summary>\u663E\u793A\u5176\u4F59 ${mlpsRemaining.length} \u9879&hellip;</summary>
${mlpsRemaining.map(renderMlpsRec).join("\n")}
</details>` : "";
    remediationHtml = `
      <details class="rec-fold">
        <summary><h2 style="margin:0;border:0;display:inline">\u5EFA\u8BAE\u6574\u6539\u9879\uFF08${mlpsUniqueRecs.length} \u9879\u53BB\u91CD\uFF09</h2></summary>
        <div class="rec-body">
          <ol>${mlpsTopItems}${mlpsMoreHtml}</ol>
        </div>
      </details>`;
  }
  const passRateColor = percent >= 80 ? "#22c55e" : percent >= 50 ? "#eab308" : "#ef4444";
  const unknownNote = unknownCount > 0 ? `<div style="color:#94a3b8;font-size:12px;margin-top:8px">\uFF08\u672A\u68C0\u67E5\u9879\u4E0D\u8BA1\u5165\u901A\u8FC7\u7387\uFF09</div>` : "";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>\u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0\u62A5\u544A &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; \u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0\u62A5\u544A</h1>
  <div class="disclaimer">\u672C\u62A5\u544A\u4E3A\u7B49\u4FDD\u9884\u68C0\u53C2\u8003\uFF0C\u4EC5\u8986\u76D6 AWS \u4E91\u5E73\u53F0\u914D\u7F6E\u68C0\u67E5\u3002\u5B8C\u6574\u7B49\u4FDD\u6D4B\u8BC4\u9700\u7531\u6301\u8BC1\u6D4B\u8BC4\u673A\u6784\u6267\u884C\u3002</div>
  <div class="meta">\u8D26\u6237: ${esc(accountId)} | \u533A\u57DF: ${esc(region)} | \u626B\u63CF\u65F6\u95F4: ${esc(scanTime)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${passRateColor}">${percent}%</div>
    <div class="score-label">\u901A\u8FC7\u7387</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card" style="border-color:#22c55e30"><div class="stat-count" style="color:#22c55e">${passCount}</div><div class="stat-label">\u901A\u8FC7</div></div>
    <div class="stat-card" style="border-color:#ef444430"><div class="stat-count" style="color:#ef4444">${failCount}</div><div class="stat-label">\u4E0D\u901A\u8FC7</div></div>
    ${unknownCount > 0 ? `<div class="stat-card" style="border-color:#94a3b830"><div class="stat-count" style="color:#94a3b8">${unknownCount}</div><div class="stat-label">\u672A\u68C0\u67E5</div></div>` : ""}
  </div>
</section>
${unknownNote}

${trendHtml}

${buildServiceReminderHtml(scanResults.modules)}

${categorySections}

${remediationHtml}

<footer>
  <p>\u7531 AWS Security MCP Server v${VERSION} \u751F\u6210</p>
  <p>\u672C\u62A5\u544A\u4EC5\u4F9B\u53C2\u8003\u3002\u5B8C\u6574\u7B49\u4FDD\u6D4B\u8BC4\u9700\u7531\u6301\u8BC1\u6D4B\u8BC4\u673A\u6784\u6267\u884C\u3002</p>
</footer>

</div>
</body>
</html>`;
}

// src/tools/save-results.ts
import { writeFileSync, readFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";
function calculateScore(summary) {
  const raw = 100 - summary.critical * 15 - summary.high * 5 - summary.medium * 2 - summary.low * 0.5;
  return Math.max(0, Math.min(100, raw));
}
function saveResults(scanResults, outputDir) {
  const baseDir = outputDir ?? join(homedir(), ".aws-security");
  const today = scanResults.scanStart.slice(0, 10);
  const scanDir = join(baseDir, "scans", today);
  const dashboardDir = join(baseDir, "dashboard");
  mkdirSync(scanDir, { recursive: true });
  mkdirSync(dashboardDir, { recursive: true });
  writeFileSync(join(scanDir, "scan.json"), JSON.stringify(scanResults, null, 2));
  const dataPath = join(dashboardDir, "data.json");
  let existing = null;
  if (existsSync(dataPath)) {
    try {
      existing = JSON.parse(readFileSync(dataPath, "utf-8"));
    } catch {
      existing = null;
    }
  }
  const historyEntry = {
    date: today,
    score: calculateScore(scanResults.summary),
    critical: scanResults.summary.critical,
    high: scanResults.summary.high,
    medium: scanResults.summary.medium,
    low: scanResults.summary.low,
    totalFindings: scanResults.summary.totalFindings
  };
  let history = existing?.history ?? [];
  const idx = history.findIndex((h) => h.date === today);
  if (idx >= 0) {
    history[idx] = historyEntry;
  } else {
    history.push(historyEntry);
  }
  history = history.slice(-30);
  const dashboardData = {
    lastScan: {
      scanStart: scanResults.scanStart,
      scanEnd: scanResults.scanEnd,
      region: scanResults.region,
      accountId: scanResults.accountId,
      summary: scanResults.summary,
      modules: scanResults.modules.map((m) => ({
        module: m.module,
        findingsCount: m.findingsCount,
        status: m.status
      })),
      findings: scanResults.modules.flatMap(
        (m) => m.findings.map((f) => ({ ...f, module: m.module }))
      )
    },
    history,
    meta: {
      generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      version: "1.0.0",
      dataRetentionDays: 30
    }
  };
  writeFileSync(dataPath, JSON.stringify(dashboardData, null, 2));
  return dataPath;
}

// src/tools/scan-groups.ts
var SEVERITY_ORDER3 = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3
};
function applyFindingsFilter(moduleName, findings, filter) {
  let result = findings;
  if (filter.minSeverity) {
    const minLevel = SEVERITY_ORDER3[filter.minSeverity.toUpperCase()] ?? 0;
    result = result.filter((f) => (SEVERITY_ORDER3[f.severity] ?? 0) >= minLevel);
  }
  if (moduleName === "security_hub_findings" && filter.securityHubCategories?.length) {
    const keywords = filter.securityHubCategories;
    result = result.filter(
      (f) => keywords.some((kw) => {
        const lower = kw.toLowerCase();
        return f.title.toLowerCase().includes(lower) || f.description.toLowerCase().includes(lower) || f.impact.toLowerCase().includes(lower);
      })
    );
  }
  if (moduleName === "guardduty_findings" && filter.guardDutyTypes?.length) {
    const prefixes = filter.guardDutyTypes;
    result = result.filter(
      (f) => prefixes.some((prefix) => f.impact.includes(prefix))
    );
  }
  if (moduleName === "inspector_findings" && filter.inspectorTypes?.length) {
    const types = filter.inspectorTypes;
    result = result.filter(
      (f) => types.some((t) => f.impact.includes(t))
    );
  }
  return result;
}
var SCAN_GROUPS = {
  mlps3_precheck: {
    name: "\u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0",
    description: "GB/T 22239-2019 \u7B49\u4FDD\u4E09\u7EA7 AWS \u4E91\u79DF\u6237\u5C42\u914D\u7F6E\u68C0\u67E5",
    modules: ["service_detection", "secret_exposure", "ssl_certificate", "dns_dangling", "network_reachability", "iam_privilege_escalation", "tag_compliance", "disaster_recovery", "security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings", "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings", "imdsv2_enforcement", "waf_coverage"],
    reportType: "mlps3"
  },
  hw_defense: {
    name: "\u62A4\u7F51\u84DD\u961F\u52A0\u56FA",
    description: "\u62A4\u7F51\u524D\u5B89\u5168\u81EA\u67E5 \u2014 \u653B\u51FB\u9762+\u5F31\u70B9\u8BC4\u4F30",
    modules: ["service_detection", "secret_exposure", "network_reachability", "dns_dangling", "ssl_certificate", "iam_privilege_escalation", "security_hub_findings", "guardduty_findings", "inspector_findings", "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings", "imdsv2_enforcement", "waf_coverage"],
    findingsFilter: {
      guardDutyTypes: ["Backdoor", "Trojan", "PenTest", "CryptoCurrency"],
      minSeverity: "MEDIUM"
    }
  },
  exposure: {
    name: "\u516C\u7F51\u66B4\u9732\u9762\u8BC4\u4F30",
    description: "\u8BC4\u4F30\u516C\u7F51\u53EF\u8FBE\u7684\u8D44\u6E90\u548C\u7AEF\u53E3",
    modules: ["network_reachability", "dns_dangling", "public_access_verify", "ssl_certificate", "security_hub_findings", "access_analyzer_findings", "imdsv2_enforcement", "waf_coverage"],
    findingsFilter: {
      securityHubCategories: ["network", "public", "exposure", "port"]
    }
  },
  data_encryption: {
    name: "\u6570\u636E\u52A0\u5BC6\u5BA1\u8BA1",
    description: "\u5168\u9762\u68C0\u67E5\u5B58\u50A8\u548C\u4F20\u8F93\u52A0\u5BC6\u72B6\u6001",
    modules: ["ssl_certificate", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["encryption", "Encryption"]
    }
  },
  least_privilege: {
    name: "\u6700\u5C0F\u6743\u9650\u5BA1\u8BA1",
    description: "IAM \u6743\u9650\u6700\u5C0F\u5316\u8BC4\u4F30",
    modules: ["iam_privilege_escalation", "security_hub_findings", "access_analyzer_findings"],
    findingsFilter: {
      securityHubCategories: ["IAM", "iam", "access", "privilege"]
    }
  },
  log_integrity: {
    name: "\u65E5\u5FD7\u5B8C\u6574\u6027\u5BA1\u8BA1",
    description: "\u5BA1\u8BA1\u65E5\u5FD7\u5B8C\u6574\u6027\u548C\u4FDD\u62A4",
    modules: ["service_detection", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["logging", "CloudTrail", "audit"]
    }
  },
  disaster_recovery: {
    name: "\u707E\u5907\u8BC4\u4F30",
    description: "\u5907\u4EFD\u548C\u707E\u5907\u80FD\u529B\u8BC4\u4F30",
    modules: ["disaster_recovery", "security_hub_findings"]
  },
  idle_resources: {
    name: "\u95F2\u7F6E\u8D44\u6E90\u6E05\u7406",
    description: "\u53D1\u73B0\u672A\u4F7F\u7528\u7684\u8D44\u6E90",
    modules: ["idle_resources", "trusted_advisor_findings"]
  },
  tag_compliance: {
    name: "\u8D44\u6E90\u6807\u7B7E\u5408\u89C4",
    description: "\u68C0\u67E5\u5FC5\u9700\u6807\u7B7E",
    modules: ["tag_compliance"]
  },
  new_account_baseline: {
    name: "\u65B0\u8D26\u6237\u57FA\u7EBF\u68C0\u67E5",
    description: "\u65B0 AWS \u8D26\u6237\u5B89\u5168\u57FA\u7EBF",
    modules: ["service_detection", "secret_exposure", "iam_privilege_escalation", "security_hub_findings", "guardduty_findings", "access_analyzer_findings", "imdsv2_enforcement"]
  },
  aggregation: {
    name: "\u5B89\u5168\u670D\u52A1\u805A\u5408",
    description: "\u4ECE Security Hub / GuardDuty / Inspector / Trusted Advisor / Config Rules / Access Analyzer / Patch Compliance \u805A\u5408\u6240\u6709\u5B89\u5168\u53D1\u73B0",
    modules: ["security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings", "config_rules_findings", "access_analyzer_findings", "patch_compliance_findings"]
  }
};

// src/resources/index.ts
var SECURITY_RULES_CONTENT = `# AWS Security Scan Modules & Rules (19 modules)

## 1. Service Detection (service_detection)
Detects which AWS security services are enabled and assesses overall security maturity.
- **Security Hub not enabled** \u2014 Risk 7.5: Provides 300+ automated security checks.
- **GuardDuty not enabled** \u2014 Risk 7.5: Provides continuous threat detection.
- **Inspector not enabled** \u2014 Risk 6.0: Scans for software vulnerabilities.
- **AWS Config not enabled** \u2014 Risk 6.0: Tracks configuration changes.
- **Macie not enabled** \u2014 Risk 5.0: Detects sensitive data in S3 (not available in China regions).
- CloudTrail detection is included for coverage metrics.

### Maturity Levels
| Enabled Services | Level |
|------------------|-------|
| 0\u20131 | Basic |
| 2\u20133 | Intermediate |
| 4\u20135 | Advanced |
| 6   | Comprehensive |

## 2. Security Hub Findings (security_hub_findings)
Aggregates active findings from AWS Security Hub. Replaces individual config scanners (SG, S3, IAM, CloudTrail, RDS, EBS, VPC, etc.) with centralized compliance checks from FSBP, CIS, and PCI DSS standards.
- Findings are filtered to ACTIVE + NEW/NOTIFIED workflow status.
- Severity mapped: CRITICAL \u2192 9.5, HIGH \u2192 8.0, MEDIUM \u2192 5.5, LOW \u2192 3.0.
- INFORMATIONAL findings are skipped.

## 3. GuardDuty Findings (guardduty_findings)
Aggregates threat detection findings from Amazon GuardDuty.
- Covers account compromise, instance compromise, and reconnaissance.
- Severity mapped from GuardDuty 0\u201310 scale: \u22657 \u2192 HIGH, \u22654 \u2192 MEDIUM, <4 \u2192 LOW.
- Only non-archived findings are included.

## 4. Inspector Findings (inspector_findings)
Aggregates vulnerability findings from Amazon Inspector v2.
- Covers CVEs in EC2 instances, Lambda functions, and container images.
- Severity mapped: CRITICAL \u2192 9.5, HIGH \u2192 8.0, MEDIUM \u2192 5.5, LOW \u2192 3.0.
- CVE IDs are included in finding titles when available.

## 5. Trusted Advisor Findings (trusted_advisor_findings)
Aggregates security checks from AWS Trusted Advisor.
- Requires AWS Business or Enterprise Support plan.
- In China regions, uses cn-north-1 as the Support API endpoint.
- Status mapped: error (RED) \u2192 8.0, warning (YELLOW) \u2192 5.5, ok (GREEN) \u2192 skip.

## 6. Secret Exposure (secret_exposure)
Checks Lambda env vars and EC2 userData for exposed secrets (AWS keys, private keys, passwords).

## 7. SSL Certificate (ssl_certificate)
Checks ACM certificates for expiry, failed status, and upcoming renewals.

## 8. Dangling DNS (dns_dangling)
Checks Route53 CNAME records for dangling DNS (subdomain takeover risk).

## 9. Network Reachability (network_reachability)
Analyzes true network reachability by combining Security Group + NACL rules for public EC2 instances.

## 10. IAM Privilege Escalation (iam_privilege_escalation)
Detects IAM privilege escalation paths \u2014 users/roles that can escalate to admin via policy manipulation, role creation, or service abuse.

## 11. Public Access Verify (public_access_verify)
Verifies actual public accessibility of resources marked as public (S3 HTTP check, RDS DNS resolution).

## 12. Tag Compliance (tag_compliance)
Checks EC2, RDS, and S3 resources for required tags (Environment, Project, Owner).

## 13. Idle Resources (idle_resources)
Finds unused/idle AWS resources (unattached EBS volumes, unused EIPs, stopped instances, unused security groups).

## 14. Disaster Recovery (disaster_recovery)
Assesses disaster recovery readiness \u2014 RDS Multi-AZ & backups, EBS snapshot coverage, S3 versioning & cross-region replication.

## 15. Config Rules Findings (config_rules_findings)
Pulls non-compliant AWS Config Rule evaluation results.
- Lists all Config Rules and their compliance status.
- For NON_COMPLIANT rules, retrieves specific non-compliant resources.
- Security-related rules (encryption, IAM, public access, etc.) mapped to HIGH severity (7.5).
- Other non-compliant rules mapped to MEDIUM severity (5.5).
- Gracefully handles regions where AWS Config is not enabled.

## 16. IAM Access Analyzer Findings (access_analyzer_findings)
Pulls active IAM Access Analyzer findings \u2014 resources accessible from outside the account.
- Lists active analyzers (ACCOUNT or ORGANIZATION type).
- Retrieves ACTIVE findings showing external access to resources.
- Covers S3 buckets, IAM roles, SQS queues, Lambda functions, KMS keys, and more.
- Severity mapped: CRITICAL \u2192 9.5, HIGH \u2192 8.0, MEDIUM \u2192 5.5, LOW \u2192 3.0.
- Returns warning if no analyzer is configured.

## 17. SSM Patch Compliance (patch_compliance_findings)
Checks patch compliance status for SSM-managed instances.
- Lists all managed instances via SSM.
- Retrieves patch compliance state for each instance.
- Missing security patches or failed patches \u2192 HIGH (7.5).
- Missing non-security patches \u2192 MEDIUM (5.5).
- Instances without patch data flagged as LOW (3.0) for visibility.
- Includes platform info, missing/failed counts, and last scan time.

## 18. IMDSv2 Enforcement (imdsv2_enforcement)
Checks if EC2 instances enforce IMDSv2 (Instance Metadata Service v2).
- Lists all running EC2 instances and checks MetadataOptions.HttpTokens.
- **HttpTokens != "required"** \u2014 Risk 7.5: IMDSv1 allows credential theft via SSRF attacks.
- Also checks HttpPutResponseHopLimit \u2014 values >1 on containerized workloads noted as warning.
- Remediation: Set HttpTokens to "required" via modify-instance-metadata-options.

## 19. WAF Coverage (waf_coverage)
Checks if internet-facing ALBs have WAF Web ACL associated for protection.
- Lists all ELBv2 load balancers, filters to internet-facing only.
- For each internet-facing ALB, checks WAFv2 Web ACL association.
- **No WAF Web ACL** \u2014 Risk 7.5: ALB exposed to SQL injection, XSS, and OWASP Top 10 attacks.
- NLBs (L4) are skipped as WAF does not apply \u2014 noted in warnings.
- Gracefully handles WAFv2 access denied or unavailable regions.
`;
var RISK_SCORING_CONTENT = `# Risk Scoring Model

## Score Ranges
Each finding is assigned a risk score from 0.0 to 10.0 based on potential impact and exploitability.

| Score Range | Severity | Priority | Description |
|-------------|----------|----------|-------------|
| 9.0 \u2013 10.0 | CRITICAL | P0 | Immediate action required. Active exploitation risk. |
| 7.0 \u2013 8.9  | HIGH     | P1 | Address within 24-48 hours. Significant exposure. |
| 4.0 \u2013 6.9  | MEDIUM   | P2 | Address within 1-2 weeks. Moderate risk. |
| 0.0 \u2013 3.9  | LOW      | P3 | Address in next maintenance cycle. Minor risk. |

## Severity Mapping
\`\`\`
score >= 9.0  \u2192 CRITICAL
score >= 7.0  \u2192 HIGH
score >= 4.0  \u2192 MEDIUM
score <  4.0  \u2192 LOW
\`\`\`

## Priority Mapping
\`\`\`
CRITICAL \u2192 P0 (Immediate)
HIGH     \u2192 P1 (Urgent)
MEDIUM   \u2192 P2 (Normal)
LOW      \u2192 P3 (Low)
\`\`\`

## Scoring Factors
- **Exploitability**: How easily can this misconfiguration be exploited?
- **Blast radius**: What data or systems are at risk?
- **Public exposure**: Is the resource internet-facing?
- **Compliance**: Does this violate common compliance frameworks (CIS, SOC2)?
- **Data sensitivity**: Could sensitive data be exposed or lost?

## Examples
- Root account without MFA \u2192 10.0 (total account compromise risk)
- Public S3 ACL \u2192 9.5 (data breach via public access)
- Missing encryption at rest \u2192 6.0 (data exposure if storage is compromised)
- Versioning disabled \u2192 3.0 (data loss risk, low exploitability)
`;

// src/index.ts
import { readFileSync as readFileSync2 } from "fs";
import { join as join2, dirname } from "path";
import { fileURLToPath } from "url";
var MODULE_DESCRIPTIONS = {
  service_detection: "Detects which AWS security services (Security Hub, GuardDuty, Inspector, Config, Macie) are enabled and assesses security maturity.",
  secret_exposure: "Checks Lambda env vars and EC2 userData for exposed secrets (AWS keys, private keys, passwords).",
  ssl_certificate: "Checks ACM certificates for expiry, failed status, and upcoming renewals.",
  dns_dangling: "Checks Route53 CNAME records for dangling DNS (subdomain takeover risk).",
  network_reachability: "Analyzes true network reachability by combining Security Group + NACL rules for public EC2 instances.",
  iam_privilege_escalation: "Detects IAM privilege escalation paths \u2014 users/roles that can escalate to admin via policy manipulation, role creation, or service abuse.",
  public_access_verify: "Verifies actual public accessibility of resources marked as public (S3 HTTP check, RDS DNS resolution).",
  tag_compliance: "Checks EC2, RDS, and S3 resources for required tags (Environment, Project, Owner).",
  idle_resources: "Finds unused/idle AWS resources (unattached EBS volumes, unused EIPs, stopped instances, unused security groups) that waste money and increase attack surface.",
  disaster_recovery: "Assesses disaster recovery readiness \u2014 RDS Multi-AZ & backups, EBS snapshot coverage, S3 versioning & cross-region replication.",
  security_hub_findings: "Aggregates active findings from AWS Security Hub \u2014 replaces individual config scanners with centralized compliance checks.",
  guardduty_findings: "Aggregates threat detection findings from Amazon GuardDuty \u2014 account compromise, instance compromise, and reconnaissance.",
  inspector_findings: "Aggregates vulnerability findings from Amazon Inspector \u2014 CVEs in EC2, Lambda, and container images.",
  trusted_advisor_findings: "Aggregates security checks from AWS Trusted Advisor \u2014 requires Business or Enterprise Support plan.",
  config_rules_findings: "Pulls non-compliant AWS Config Rule evaluation results \u2014 configuration compliance violations across all resource types.",
  access_analyzer_findings: "Pulls active IAM Access Analyzer findings \u2014 resources accessible from outside the account (external principals, public access).",
  patch_compliance_findings: "Checks SSM Patch Manager compliance \u2014 managed instances with missing or failed security and system patches.",
  imdsv2_enforcement: "Checks if EC2 instances enforce IMDSv2 (HttpTokens: required) \u2014 IMDSv1 allows credential theft via SSRF.",
  waf_coverage: "Checks if internet-facing ALBs have WAF Web ACL associated for protection against common web exploits."
};
var HW_DEFENSE_CHECKLIST = `
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
\u{1F4CB} \u62A4\u7F51\u884C\u52A8\u8865\u5145\u63D0\u9192\uFF08\u8D85\u51FA\u81EA\u52A8\u5316\u626B\u63CF\u8303\u56F4\uFF09
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

\u4EE5\u4E0B\u4E8B\u9879\u9700\u8981\u4EBA\u5DE5\u786E\u8BA4\u548C\u6267\u884C\uFF1A

\u26A0\uFE0F \u5E94\u6025\u9694\u79BB/\u6B62\u8840\u65B9\u6848
  \u25A1 \u51C6\u5907\u4E13\u7528\u9694\u79BB\u5B89\u5168\u7EC4\uFF08\u65E0 Inbound/Outbound \u89C4\u5219\uFF09
  \u25A1 \u5236\u5B9A\u5B9E\u4F8B\u9694\u79BB SOP\uFF1A\u544A\u8B66 \u2192 \u6392\u67E5 \u2192 \u5C01\u9501\u653B\u51FBIP \u2192 \u7F51\u7EDC\u9694\u79BB \u2192 \u5B89\u5168\u5904\u7F6E \u2192 \u8BB0\u5F55\u653B\u51FB\u9879
  \u25A1 \u660E\u786E\u5404\u7CFB\u7EDF\uFF08\u751F\u4EA7\u6838\u5FC3/\u751F\u4EA7\u975E\u6838\u5FC3/\u6D4B\u8BD5/\u5F00\u53D1\uFF09\u7684\u5E94\u6025\u5904\u7F6E\u65B9\u5F0F
  \u25A1 \u660E\u786E\u5404\u9879\u76EE\u8D26\u6237\u53CA\u8D44\u6E90\u7684\u8D1F\u8D23\u4EBA\u4E0E\u8054\u7CFB\u65B9\u5F0F

\u26A0\uFE0F \u6D4B\u8BD5/\u5F00\u53D1\u73AF\u5883\u5904\u7F6E
  \u25A1 \u975E\u6838\u5FC3\u7CFB\u7EDF\u5728\u62A4\u7F51\u671F\u95F4\u5173\u95ED
  \u25A1 \u6D4B\u8BD5/\u5F00\u53D1\u73AF\u5883\u5173\u95ED\u6216\u4E0E\u751F\u4EA7\u4FDD\u6301\u540C\u7B49\u5B89\u5168\u57FA\u7EBF
  \u25A1 \u786E\u8BA4\u54EA\u4E9B\u73AF\u5883\u53EF\u4EE5\u7D27\u6025\u5173\u505C\uFF0C\u907F\u514D\u653B\u51FB\u6269\u6563

\u26A0\uFE0F \u503C\u5B88\u56E2\u961F\u7EC4\u5EFA
  \u25A1 7\xD724 \u76D1\u63A7\u5FEB\u901F\u54CD\u5E94\u56E2\u961F
  \u25A1 \u6280\u672F\u4E0E\u98CE\u9669\u5206\u6790\u7EC4
  \u25A1 \u5B89\u5168\u7B56\u7565\u4E0B\u53D1\u7EC4
  \u25A1 \u4E1A\u52A1\u54CD\u5E94\u7EC4
  \u25A1 \u660E\u786E AWS TAM/Support \u8054\u7CFB\u65B9\u5F0F\uFF08ES/EOP \u5BA2\u6237\uFF09

\u26A0\uFE0F \u51FA\u5165\u7AD9\u8DEF\u5F84\u67B6\u6784\u56FE
  \u25A1 \u786E\u4FDD\u6240\u6709\u4E92\u8054\u7F51/DX \u4E13\u7EBF\u51FA\u5165\u7AD9\u8DEF\u5F84\u5728\u67B6\u6784\u56FE\u4E2D\u6E05\u6670\u6807\u6CE8
  \u25A1 \u660E\u786E\u5404 ELB/Public EC2/S3/DX \u7684\u6570\u636E\u6D41\u5411
  \u25A1 \u8BC6\u522B\u6240\u6709\u9762\u5411\u4E92\u8054\u7F51\u7684\u6570\u636E\u4EA4\u4E92\u63A5\u53E3

\u26A0\uFE0F \u4E3B\u52A8\u5F0F\u6E17\u900F\u6D4B\u8BD5
  \u25A1 \u62A4\u7F51\u524D\u8054\u7CFB\u5B89\u5168\u5382\u5546\uFF08\u9752\u85E4/\u957F\u4EAD/\u5FAE\u6B65\u7B49\uFF09\u8FDB\u884C\u6A21\u62DF\u653B\u51FB\u6F14\u7EC3
  \u25A1 \u57FA\u4E8E\u6E17\u900F\u6D4B\u8BD5\u62A5\u544A\u8FDB\u884C\u6B63\u5F0F\u62A4\u7F51\u524D\u7684\u5B89\u5168\u52A0\u56FA
  \u25A1 \u5173\u6CE8 AWS \u5B89\u5168\u516C\u544A\uFF08\u5DF2\u77E5\u6F0F\u6D1E\u4E0E\u8865\u4E01\uFF09

\u26A0\uFE0F WAR-ROOM \u5B9E\u65F6\u6C9F\u901A
  \u25A1 \u521B\u5EFA\u62A4\u7F51\u671F\u95F4\u4E13\u7528\u6C9F\u901A\u6E20\u9053\uFF08\u4F01\u5FAE/\u9489\u9489/\u98DE\u4E66/Chime\uFF09
  \u25A1 \u4E0E AWS TAM \u5EFA\u7ACB WAR-ROOM \u8054\u7CFB\uFF08\u4F01\u4E1A\u7EA7\u652F\u6301\u5BA2\u6237\uFF09
  \u25A1 \u7EDF\u4E00\u6848\u4F8B\u6807\u9898\u683C\u5F0F\uFF1A"\u3010\u62A4\u7F51\u3011+ \u95EE\u9898\u63CF\u8FF0"

\u26A0\uFE0F \u5BC6\u7801\u4E0E\u51ED\u8BC1\u7BA1\u7406
  \u25A1 \u6240\u6709 IAM \u7528\u6237\u7ED1\u5B9A MFA
  \u25A1 AKSK \u8F6E\u8F6C\u5468\u671F \u2264 90 \u5929
  \u25A1 \u907F\u514D\u5171\u4EAB\u8D26\u6237\u4F7F\u7528
  \u25A1 S3/Lambda/\u5E94\u7528\u4EE3\u7801\u4E2D\u65E0\u660E\u6587\u5BC6\u7801

\u26A0\uFE0F \u62A4\u7F51\u540E\u4F18\u5316
  \u25A1 \u9488\u5BF9\u653B\u51FB\u62A5\u544A\u9010\u9879\u5E94\u7B54\u4E0E\u4FEE\u590D
  \u25A1 \u4E0E\u5B89\u5168\u56E2\u961F\u5EFA\u7ACB\u5468\u671F\u6027\u5B89\u5168\u7EF4\u62A4\u6D41\u7A0B
  \u25A1 \u6301\u7EED\u8865\u5168\u5B89\u5168\u98CE\u9669

\u53C2\u8003\uFF1AAWS \u62A4\u7F51\u884C\u52A8 Standard Operation Procedure (Compliance IEM)
`;
var SERVICE_RECOMMENDATIONS2 = {
  security_hub_findings: {
    icon: "\u{1F534}",
    service: "Security Hub",
    impact: "\u65E0\u6CD5\u83B7\u53D6 300+ \u9879\u81EA\u52A8\u5316\u5B89\u5168\u68C0\u67E5\uFF08FSBP/CIS/PCI DSS \u6807\u51C6\uFF09",
    action: "\u542F\u7528 Security Hub \u83B7\u5F97\u6700\u5168\u9762\u7684\u5B89\u5168\u6001\u52BF\u8BC4\u4F30"
  },
  guardduty_findings: {
    icon: "\u{1F534}",
    service: "GuardDuty",
    impact: "\u65E0\u6CD5\u68C0\u6D4B\u5A01\u80C1\u6D3B\u52A8\uFF08\u6076\u610F IP\u3001\u5F02\u5E38 API \u8C03\u7528\u3001\u52A0\u5BC6\u8D27\u5E01\u6316\u77FF\u7B49\uFF09",
    action: "\u542F\u7528 GuardDuty \u83B7\u5F97\u6301\u7EED\u5A01\u80C1\u68C0\u6D4B\u80FD\u529B"
  },
  inspector_findings: {
    icon: "\u{1F7E1}",
    service: "Inspector",
    impact: "\u65E0\u6CD5\u626B\u63CF EC2/Lambda/\u5BB9\u5668\u7684\u8F6F\u4EF6\u6F0F\u6D1E\uFF08CVE\uFF09",
    action: "\u542F\u7528 Inspector \u53D1\u73B0\u5DF2\u77E5\u5B89\u5168\u6F0F\u6D1E"
  },
  trusted_advisor_findings: {
    icon: "\u{1F7E1}",
    service: "Trusted Advisor",
    impact: "\u65E0\u6CD5\u83B7\u53D6 AWS \u6700\u4F73\u5B9E\u8DF5\u5B89\u5168\u68C0\u67E5",
    action: "\u5347\u7EA7\u81F3 Business/Enterprise Support \u8BA1\u5212\u4EE5\u4F7F\u7528 Trusted Advisor \u5B89\u5168\u68C0\u67E5"
  },
  config_rules_findings: {
    icon: "\u{1F7E1}",
    service: "AWS Config",
    impact: "\u65E0\u6CD5\u68C0\u67E5\u8D44\u6E90\u914D\u7F6E\u5408\u89C4\u72B6\u6001",
    action: "\u542F\u7528 AWS Config \u5E76\u914D\u7F6E Config Rules"
  },
  access_analyzer_findings: {
    icon: "\u{1F7E1}",
    service: "IAM Access Analyzer",
    impact: "\u65E0\u6CD5\u68C0\u6D4B\u8D44\u6E90\u662F\u5426\u88AB\u5916\u90E8\u8D26\u53F7\u6216\u516C\u7F51\u8BBF\u95EE",
    action: "\u521B\u5EFA IAM Access Analyzer\uFF08\u8D26\u6237\u7EA7\u6216\u7EC4\u7EC7\u7EA7\uFF09"
  },
  patch_compliance_findings: {
    icon: "\u{1F7E1}",
    service: "SSM Patch Manager",
    impact: "\u65E0\u6CD5\u68C0\u67E5\u5B9E\u4F8B\u8865\u4E01\u5408\u89C4\u72B6\u6001",
    action: "\u5B89\u88C5 SSM Agent \u5E76\u914D\u7F6E Patch Manager"
  }
};
var SERVICE_NOT_ENABLED_PATTERNS2 = [
  "not enabled",
  "not found",
  "No IAM Access Analyzer",
  "No SSM-managed instances",
  "requires AWS Business or Enterprise Support",
  "not available",
  "is not enabled"
];
function buildServiceReminder(modules) {
  const disabledServices = [];
  for (const mod of modules) {
    const rec = SERVICE_RECOMMENDATIONS2[mod.module];
    if (!rec) continue;
    if (!mod.warnings?.length) continue;
    const hasNotEnabled = mod.warnings.some(
      (w) => SERVICE_NOT_ENABLED_PATTERNS2.some((p) => w.includes(p))
    );
    if (hasNotEnabled) {
      disabledServices.push(rec);
    }
  }
  if (disabledServices.length === 0) return "";
  const lines = [
    "",
    "\u26A1 \u4EE5\u4E0B\u5B89\u5168\u670D\u52A1\u672A\u542F\u7528\uFF0C\u90E8\u5206\u68C0\u67E5\u65E0\u6CD5\u6267\u884C\uFF1A",
    ""
  ];
  for (const svc of disabledServices) {
    lines.push(`${svc.icon} ${svc.service} \u672A\u542F\u7528`);
    lines.push(`   \u5F71\u54CD\uFF1A${svc.impact}`);
    lines.push(`   \u5EFA\u8BAE\uFF1A${svc.action}`);
    lines.push("");
  }
  lines.push("\u542F\u7528\u4EE5\u4E0A\u670D\u52A1\u540E\u91CD\u65B0\u626B\u63CF\u53EF\u83B7\u5F97\u66F4\u5B8C\u6574\u7684\u5B89\u5168\u8BC4\u4F30\u3002");
  return lines.join("\n");
}
function summarizeResult(result) {
  const { summary } = result;
  const lines = [
    `Scan complete for account ${result.accountId} in ${result.region}.`,
    `Total findings: ${summary.totalFindings} (${summary.critical} Critical, ${summary.high} High, ${summary.medium} Medium, ${summary.low} Low)`,
    `Modules: ${summary.modulesSuccess} succeeded, ${summary.modulesError} errored`
  ];
  const reminder = buildServiceReminder(result.modules);
  if (reminder) {
    lines.push(reminder);
  }
  return lines.join("\n");
}
function summarizeScanResult(result) {
  const lines = [
    `Module: ${result.module} \u2014 ${result.status}`,
    `Resources scanned: ${result.resourcesScanned}, Findings: ${result.findingsCount}`
  ];
  if (result.warnings?.length) {
    lines.push(`Warnings: ${result.warnings.length}`);
  }
  return lines.join("\n");
}
async function buildScanContext(region) {
  let accountId;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }
  return { region, partition: getPartition(region), accountId };
}
function createServer(defaultRegion) {
  const server = new McpServer(
    { name: "aws-security-mcp", version: VERSION },
    { capabilities: { resources: {}, tools: {}, prompts: {} } }
  );
  const allScanners = [
    new ServiceDetectionScanner(),
    new SecretExposureScanner(),
    new SslCertificateScanner(),
    new DnsDanglingScanner(),
    new NetworkReachabilityScanner(),
    new IamPrivilegeEscalationScanner(),
    new PublicAccessVerifyScanner(),
    new TagComplianceScanner(),
    new IdleResourcesScanner(),
    new DisasterRecoveryScanner(),
    new SecurityHubFindingsScanner(),
    new GuardDutyFindingsScanner(),
    new InspectorFindingsScanner(),
    new TrustedAdvisorFindingsScanner(),
    new ConfigRulesFindingsScanner(),
    new AccessAnalyzerFindingsScanner(),
    new PatchComplianceFindingsScanner(),
    new Imdsv2EnforcementScanner(),
    new WafCoverageScanner()
  ];
  const scannerMap = /* @__PURE__ */ new Map();
  for (const s of allScanners) {
    scannerMap.set(s.moduleName, s);
  }
  server.tool(
    "scan_all",
    "Run all security scanners in parallel (including service detection). Read-only. Does not modify any AWS resources. Supports multi-account org scanning.",
    {
      region: z.string().optional().describe("AWS region to scan (default: server region)"),
      org_mode: z.boolean().optional().describe("Enable multi-account scanning via AWS Organizations"),
      role_name: z.string().optional().describe("IAM role name to assume in child accounts (default: AWSSecurityMCPAudit)"),
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)")
    },
    async ({ region, org_mode, role_name, account_ids }) => {
      try {
        const r = region ?? defaultRegion;
        let result;
        if (org_mode) {
          result = await runMultiAccountScanners(allScanners, r, {
            orgMode: true,
            roleName: role_name ?? "AWSSecurityMCPAudit",
            accountIds: account_ids
          });
        } else {
          result = await runAllScanners(allScanners, r);
        }
        return {
          content: [
            { type: "text", text: summarizeResult(result) },
            { type: "text", text: JSON.stringify(result, null, 2) }
          ]
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  const individualScanners = [
    { toolName: "detect_services", moduleName: "service_detection", label: "Security Service Detection" },
    { toolName: "scan_secret_exposure", moduleName: "secret_exposure", label: "Secret Exposure" },
    { toolName: "scan_ssl_certificate", moduleName: "ssl_certificate", label: "SSL Certificate" },
    { toolName: "scan_dns_dangling", moduleName: "dns_dangling", label: "Dangling DNS" },
    { toolName: "scan_network_reachability", moduleName: "network_reachability", label: "Network Reachability" },
    { toolName: "scan_iam_privilege_escalation", moduleName: "iam_privilege_escalation", label: "IAM Privilege Escalation" },
    { toolName: "scan_public_access_verify", moduleName: "public_access_verify", label: "Public Access Verify" },
    { toolName: "scan_tag_compliance", moduleName: "tag_compliance", label: "Tag Compliance" },
    { toolName: "scan_idle_resources", moduleName: "idle_resources", label: "Idle Resources" },
    { toolName: "scan_disaster_recovery", moduleName: "disaster_recovery", label: "Disaster Recovery" },
    { toolName: "scan_security_hub_findings", moduleName: "security_hub_findings", label: "Security Hub Findings" },
    { toolName: "scan_guardduty_findings", moduleName: "guardduty_findings", label: "GuardDuty Findings" },
    { toolName: "scan_inspector_findings", moduleName: "inspector_findings", label: "Inspector Findings" },
    { toolName: "scan_trusted_advisor_findings", moduleName: "trusted_advisor_findings", label: "Trusted Advisor Findings" },
    { toolName: "scan_config_rules_findings", moduleName: "config_rules_findings", label: "Config Rules Findings" },
    { toolName: "scan_access_analyzer_findings", moduleName: "access_analyzer_findings", label: "Access Analyzer Findings" },
    { toolName: "scan_patch_compliance_findings", moduleName: "patch_compliance_findings", label: "Patch Compliance Findings" },
    { toolName: "scan_imdsv2_enforcement", moduleName: "imdsv2_enforcement", label: "IMDSv2 Enforcement" },
    { toolName: "scan_waf_coverage", moduleName: "waf_coverage", label: "WAF Coverage" }
  ];
  for (const { toolName, moduleName, label } of individualScanners) {
    server.tool(
      toolName,
      `Run ${label} security scanner only. Read-only. Does not modify any AWS resources.`,
      { region: z.string().optional().describe("AWS region to scan (default: server region)") },
      async ({ region }) => {
        try {
          const r = region ?? defaultRegion;
          const ctx = await buildScanContext(r);
          const scanner = scannerMap.get(moduleName);
          const result = await scanner.scan(ctx);
          return {
            content: [
              { type: "text", text: summarizeScanResult(result) },
              { type: "text", text: JSON.stringify(result, null, 2) }
            ]
          };
        } catch (err) {
          return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
        }
      }
    );
  }
  server.tool(
    "scan_group",
    "Run a predefined group of security scanners for a specific scenario (e.g., MLPS compliance, network defense). Read-only. Supports multi-account org scanning.",
    {
      group: z.string().describe("Scan group ID: mlps3_precheck, hw_defense, exposure, data_encryption, least_privilege, log_integrity, disaster_recovery, idle_resources, tag_compliance, new_account_baseline, aggregation"),
      region: z.string().optional().describe("AWS region to scan (default: server region)"),
      org_mode: z.boolean().optional().describe("Enable multi-account scanning via AWS Organizations"),
      role_name: z.string().optional().describe("IAM role name to assume in child accounts (default: AWSSecurityMCPAudit)"),
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)")
    },
    async ({ group, region, org_mode, role_name, account_ids }) => {
      try {
        const groupDef = SCAN_GROUPS[group];
        if (!groupDef) {
          const available = Object.keys(SCAN_GROUPS).join(", ");
          return {
            content: [{ type: "text", text: `Error: Unknown scan group "${group}". Available groups: ${available}` }],
            isError: true
          };
        }
        const r = region ?? defaultRegion;
        let selectedScanners;
        const missingModules = [];
        if (groupDef.modules.includes("ALL")) {
          selectedScanners = allScanners;
        } else {
          selectedScanners = [];
          for (const mod of groupDef.modules) {
            const scanner = scannerMap.get(mod);
            if (scanner) {
              selectedScanners.push(scanner);
            } else {
              missingModules.push(mod);
            }
          }
        }
        if (selectedScanners.length === 0) {
          return {
            content: [{ type: "text", text: `Error: No available scanners for group "${group}". Requested modules: ${groupDef.modules.join(", ")}` }],
            isError: true
          };
        }
        let result;
        if (org_mode) {
          result = await runMultiAccountScanners(selectedScanners, r, {
            orgMode: true,
            roleName: role_name ?? "AWSSecurityMCPAudit",
            accountIds: account_ids
          });
        } else {
          result = await runAllScanners(selectedScanners, r);
        }
        if (groupDef.findingsFilter) {
          for (const mod of result.modules) {
            const originalCount = mod.findings.length;
            mod.findings = applyFindingsFilter(mod.module, mod.findings, groupDef.findingsFilter);
            mod.findingsCount = mod.findings.length;
            if (mod.findings.length < originalCount) {
              const filtered = originalCount - mod.findings.length;
              if (!mod.warnings) mod.warnings = [];
              mod.warnings.push(`Post-filter removed ${filtered} finding(s) not matching group criteria.`);
            }
          }
          let critical = 0, high = 0, medium = 0, low = 0;
          for (const m of result.modules) {
            for (const f of m.findings) {
              switch (f.severity) {
                case "CRITICAL":
                  critical++;
                  break;
                case "HIGH":
                  high++;
                  break;
                case "MEDIUM":
                  medium++;
                  break;
                case "LOW":
                  low++;
                  break;
              }
            }
          }
          result.summary.totalFindings = critical + high + medium + low;
          result.summary.critical = critical;
          result.summary.high = high;
          result.summary.medium = medium;
          result.summary.low = low;
        }
        const lines = [
          `Scan group: ${groupDef.name} (${group})`,
          groupDef.description,
          "",
          summarizeResult(result)
        ];
        if (missingModules.length > 0) {
          lines.push("");
          lines.push(`Warning: ${missingModules.length} requested module(s) not available: ${missingModules.join(", ")}`);
        }
        const content = [
          { type: "text", text: lines.join("\n") },
          { type: "text", text: JSON.stringify(result, null, 2) }
        ];
        if (group === "hw_defense") {
          const summaryContent = content[0];
          if (summaryContent && summaryContent.type === "text") {
            summaryContent.text += "\n\n" + HW_DEFENSE_CHECKLIST;
          }
        }
        return { content };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "list_groups",
    "List available scan groups with descriptions. Read-only.",
    async () => {
      try {
        const groups = Object.entries(SCAN_GROUPS).map(([id, def]) => ({
          id,
          name: def.name,
          description: def.description,
          modules: def.modules,
          reportType: def.reportType
        }));
        return { content: [{ type: "text", text: JSON.stringify(groups, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_report",
    "Generate a Markdown security report from scan results. Read-only. Does not modify any AWS resources.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const report = generateMarkdownReport(parsed);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_mlps3_report",
    "Generate a GB/T 22239-2019 \u7B49\u4FDD\u4E09\u7EA7 compliance pre-check report from scan results. Best used with scan_group mlps3_precheck results. Read-only.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_group mlps3_precheck or scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const report = generateMlps3Report(parsed);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_html_report",
    "Generate a professional HTML security report. Save the output as an .html file.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts")
    },
    async ({ scan_results, history }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : void 0;
        const report = generateHtmlReport(parsed, historyData);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_mlps3_html_report",
    "Generate a professional HTML MLPS Level 3 compliance report (\u7B49\u4FDD\u4E09\u7EA7). Save as .html file.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_group mlps3_precheck or scan_all"),
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts")
    },
    async ({ scan_results, history }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : void 0;
        const report = generateMlps3HtmlReport(parsed, historyData);
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_maturity_report",
    "Generate a security maturity assessment report from scan_all results. Requires service_detection module output. Read-only.",
    { scan_results: z.string().describe("JSON string of FullScanResult from scan_all") },
    async ({ scan_results }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const sdModule = parsed.modules.find((m) => m.module === "service_detection");
        if (!sdModule) {
          return {
            content: [{ type: "text", text: "Error: scan results do not include service_detection module. Run scan_all first." }],
            isError: true
          };
        }
        const detection = sdModule.serviceDetection;
        if (!detection) {
          return {
            content: [{ type: "text", text: "Error: service detection data is missing (possible JSON round-trip loss). Run scan_all to get fresh results with complete service detection data." }],
            isError: true
          };
        }
        const serviceImpacts = {
          "CloudTrail": "API activity logging",
          "Security Hub": "+300 security checks",
          "GuardDuty": "Threat detection",
          "Inspector": "Vulnerability scanning",
          "AWS Config": "Configuration tracking",
          "Macie": "Sensitive data detection"
        };
        const serviceFreeTrials = {
          "Security Hub": true,
          "GuardDuty": true,
          "Inspector": true,
          "Macie": true
        };
        const services = detection.services;
        const coveragePercent = detection.coveragePercent;
        const maturityLevel = detection.maturityLevel;
        const enabledCount = services.filter((s) => s.enabled === true).length;
        const knownCount = services.filter((s) => s.enabled !== null).length;
        const totalServices = services.length;
        const lines = [];
        lines.push("# AWS Security Maturity Assessment");
        lines.push("");
        lines.push(`## Account: ${parsed.accountId} | Region: ${parsed.region}`);
        lines.push("");
        lines.push(`## Security Service Coverage: ${coveragePercent}%`);
        lines.push(`## Maturity Level: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)}`);
        lines.push("");
        lines.push("### Service Status");
        lines.push("");
        lines.push("| Service | Status | Impact |");
        lines.push("|---------|--------|--------|");
        for (const svc of services) {
          const status = svc.enabled === true ? "\u2705 Enabled" : svc.enabled === false ? "\u274C Not Enabled" : "\u26A0\uFE0F Unknown";
          const impact = serviceImpacts[svc.name] ?? "";
          lines.push(`| ${svc.name} | ${status} | ${impact} |`);
        }
        const unknowns = services.filter((s) => s.enabled === null);
        if (unknowns.length > 0) {
          lines.push("");
          lines.push(`> \u26A0\uFE0F ${unknowns.length} service(s) could not be checked (access denied or detection error). Re-run with appropriate permissions for accurate coverage.`);
        }
        const disabled = services.filter((s) => s.enabled === false);
        if (disabled.length > 0) {
          lines.push("");
          lines.push("### Recommendations (Priority Order)");
          lines.push("");
          const priorityOrder = ["Security Hub", "GuardDuty", "Inspector", "AWS Config", "Macie", "CloudTrail"];
          const sorted = disabled.sort(
            (a, b) => priorityOrder.indexOf(a.name) - priorityOrder.indexOf(b.name)
          );
          let idx = 1;
          for (const svc of sorted) {
            const trial = serviceFreeTrials[svc.name] ? " \u2014 free trial available" : "";
            lines.push(`${idx}. Enable ${svc.name}${trial}`);
            idx++;
          }
        }
        lines.push("");
        lines.push("### Maturity Roadmap");
        lines.push("");
        if (unknowns.length > 0) {
          lines.push(`- **Current**: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)} (${enabledCount}/${knownCount} known services, ${unknowns.length} unknown)`);
        } else {
          lines.push(`- **Current**: ${maturityLevel.charAt(0).toUpperCase() + maturityLevel.slice(1)} (${enabledCount}/${totalServices} services)`);
        }
        if (maturityLevel !== "comprehensive") {
          const nextMilestones = {
            basic: { level: "Intermediate", target: 2, suggestions: ["Security Hub", "GuardDuty"] },
            intermediate: { level: "Advanced", target: 4, suggestions: ["Inspector", "AWS Config"] },
            advanced: { level: "Comprehensive", target: 6, suggestions: ["Macie"] }
          };
          const next = nextMilestones[maturityLevel];
          if (next) {
            const remaining = next.suggestions.filter(
              (s) => services.some((svc) => svc.name === s && !svc.enabled)
            );
            if (remaining.length > 0) {
              lines.push(`- **Next milestone**: ${next.level} (${next.target}/${knownCount}) \u2014 enable ${remaining.join(" + ")}`);
            }
          }
          lines.push(`- **Target**: Comprehensive (${knownCount}/${knownCount})`);
        }
        lines.push("");
        const report = lines.join("\n");
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
          isError: true
        };
      }
    }
  );
  server.tool(
    "save_results",
    "Saves scan results to local disk or S3 for dashboard display. Does not modify any AWS resources.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      output_dir: z.string().optional().describe("Output directory (default: ~/.aws-security)")
    },
    async ({ scan_results, output_dir }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const dataPath = saveResults(parsed, output_dir);
        return {
          content: [
            { type: "text", text: `Dashboard data saved to ${dataPath}` }
          ]
        };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
          isError: true
        };
      }
    }
  );
  server.tool(
    "list_modules",
    "List available security scan modules with descriptions. Read-only. Does not modify any AWS resources.",
    async () => {
      try {
        const modules = allScanners.map((s) => ({
          name: s.moduleName,
          description: MODULE_DESCRIPTIONS[s.moduleName] ?? s.moduleName
        }));
        return { content: [{ type: "text", text: JSON.stringify(modules, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "list_org_accounts",
    "List all accounts in the AWS Organization. Useful for discovering accounts before multi-account scanning. Read-only.",
    { region: z.string().optional().describe("AWS region (default: server region)") },
    async ({ region }) => {
      try {
        const r = region ?? defaultRegion;
        const accounts = await listOrgAccounts(r);
        return {
          content: [
            { type: "text", text: `Found ${accounts.length} active account(s) in the organization.` },
            { type: "text", text: JSON.stringify(accounts, null, 2) }
          ]
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "get_setup_template",
    "Returns the CloudFormation StackSet template for deploying the cross-account security audit IAM role. Read-only.",
    {
      format: z.enum(["yaml", "json"]).optional().describe("Template format: yaml or json (default: yaml)")
    },
    async ({ format }) => {
      try {
        const ext = format === "json" ? "json" : "yaml";
        const templateFileName = `stackset-audit-role.${ext}`;
        let templateContent;
        try {
          const currentDir = dirname(fileURLToPath(import.meta.url));
          const templatePath = join2(currentDir, "..", "templates", templateFileName);
          templateContent = readFileSync2(templatePath, "utf-8");
        } catch {
          try {
            const currentDir = dirname(fileURLToPath(import.meta.url));
            const templatePath = join2(currentDir, "..", "..", "templates", templateFileName);
            templateContent = readFileSync2(templatePath, "utf-8");
          } catch {
            return {
              content: [{ type: "text", text: `Error: Template file ${templateFileName} not found. Ensure the templates/ directory is included in the package.` }],
              isError: true
            };
          }
        }
        return {
          content: [
            { type: "text", text: `CloudFormation StackSet template (${ext.toUpperCase()}) for cross-account audit role:

Deploy this as a StackSet from your Management Account to all member accounts.` },
            { type: "text", text: templateContent }
          ]
        };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.resource(
    "security-rules",
    "security://rules",
    { description: "Describes all 19 scan modules and their check rules", mimeType: "text/markdown" },
    async () => ({
      contents: [{ uri: "security://rules", text: SECURITY_RULES_CONTENT, mimeType: "text/markdown" }]
    })
  );
  server.resource(
    "risk-scoring",
    "security://risk-scoring",
    { description: "Describes the risk scoring model and severity/priority mapping", mimeType: "text/markdown" },
    async () => ({
      contents: [{ uri: "security://risk-scoring", text: RISK_SCORING_CONTENT, mimeType: "text/markdown" }]
    })
  );
  server.prompt(
    "security-scan",
    "Run a full AWS security scan workflow: scan all modules, generate a report, and summarize findings.",
    async () => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: "Run scan_all to perform a full AWS security scan. Then take the JSON result and pass it to generate_report to create a Markdown report. Finally, summarize the top findings and recommend immediate actions based on priority."
          }
        }
      ]
    })
  );
  server.prompt(
    "analyze-finding",
    "Deep analysis of a specific security finding.",
    { finding: z.string().describe("JSON string of a single Finding object to analyze") },
    async ({ finding }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Analyze this AWS security finding in depth. Explain the risk, potential attack vectors, blast radius, and provide detailed step-by-step remediation guidance.

Finding:
${finding}`
          }
        }
      ]
    })
  );
  server.prompt(
    "hw_defense_checklist",
    "\u62A4\u7F51\u884C\u52A8\u5B8C\u6574\u68C0\u67E5\u6E05\u5355 \u2014 \u5305\u542B\u81EA\u52A8\u5316\u626B\u63CF\u9879\u548C\u4EBA\u5DE5\u68C0\u67E5\u9879",
    async () => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `\u8BF7\u57FA\u4E8E\u4EE5\u4E0B\u62A4\u7F51\u884C\u52A8\u68C0\u67E5\u6E05\u5355\uFF0C\u5E2E\u52A9\u6211\u5236\u5B9A\u62A4\u7F51\u51C6\u5907\u8BA1\u5212\uFF1A

${HW_DEFENSE_CHECKLIST}

\u81EA\u52A8\u5316\u626B\u63CF\u90E8\u5206\u8BF7\u4F7F\u7528 scan_group hw_defense \u6267\u884C\u3002\u4EE5\u4E0A\u4EBA\u5DE5\u68C0\u67E5\u9879\u8BF7\u9010\u9879\u786E\u8BA4\u5E76\u63D0\u4F9B\u5177\u4F53\u5EFA\u8BAE\u3002`
          }
        }
      ]
    })
  );
  return server;
}
async function startServer(defaultRegion) {
  const server = createServer(defaultRegion);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// bin/aws-security-mcp.ts
var args = process.argv.slice(2);
var subcommand = args[0];
var HELP = `Usage: aws-security-mcp [command] [options]

Commands:
  (default)            Start MCP server (stdio, for Kiro/Claude Code)
  dashboard            Start local HTTP server serving the security dashboard
  deploy-dashboard     Deploy dashboard to an S3 bucket as a static website

Options:
  --region <region>    AWS region (default: AWS_REGION env or us-east-1)
  --version            Print version and exit
  --help, -h           Show this help message

Dashboard options:
  --port <port>        Port for local dashboard server (default: 3000)

Deploy options:
  --bucket <name>      S3 bucket name (required)
  --region <region>    AWS region for the S3 bucket

Environment variables:
  AWS_REGION           Default AWS region
  AWS_DEFAULT_REGION   Fallback default region

The MCP server communicates over stdio using the MCP protocol.`;
if (args.includes("--help") || args.includes("-h")) {
  console.log(HELP);
  process.exit(0);
}
if (args.includes("--version")) {
  console.log(`aws-security-mcp ${VERSION}`);
  process.exit(0);
}
function getArg(name) {
  const idx = args.indexOf(name);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return void 0;
}
function getRegion() {
  return getArg("--region") ?? process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? "us-east-1";
}
if (subcommand === "dashboard") {
  const port = Number(getArg("--port")) || 3e3;
  Promise.resolve().then(() => (init_dashboard(), dashboard_exports)).then(({ startDashboard: startDashboard2 }) => {
    startDashboard2(port);
  });
} else if (subcommand === "deploy-dashboard") {
  const bucket = getArg("--bucket");
  if (!bucket) {
    console.error("Error: --bucket <name> is required for deploy-dashboard");
    process.exit(1);
  }
  const region = getRegion();
  Promise.resolve().then(() => (init_deploy_dashboard(), deploy_dashboard_exports)).then(({ deployDashboard: deployDashboard2 }) => {
    deployDashboard2(bucket, region).catch((err) => {
      console.error("Deploy failed:", err.message || err);
      process.exit(1);
    });
  });
} else if (subcommand && !subcommand.startsWith("--")) {
  console.error(`Unknown command: ${subcommand}`);
  console.error('Run "aws-security-mcp --help" for usage.');
  process.exit(1);
} else {
  const region = getRegion();
  startServer(region).catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}
//# sourceMappingURL=aws-security-mcp.js.map
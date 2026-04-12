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
var VERSION = "0.6.3";

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
  "inspector_findings",
  "config_rules_findings",
  "access_analyzer_findings"
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
  if (enabledCount >= 5) return "comprehensive";
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
      const active = accounts.some((a) => {
        const s = a.state?.status;
        if (s === "ENABLED" || s === "ENABLING") return true;
        const rs = a.resourceState;
        if (!rs) return false;
        return ["ec2", "ecr", "lambda", "lambdaCode", "codeRepository"].some(
          (k) => rs[k]?.status === "ENABLED"
        );
      });
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
          const title = f.Title ?? "Security Hub Finding";
          if (/^KB\d+$/.test(title)) {
            remediationSteps.push(`Install Windows patch ${title} via WSUS or SSM Patch Manager`);
            remediationSteps.push(`Microsoft KB article: https://support.microsoft.com/help/${title}`);
          } else if (/^CVE-/.test(title)) {
            remediationSteps.push(`Fix vulnerability ${title}: update affected software to patched version`);
          } else {
            remediationSteps.push(title);
          }
          if (f.Remediation?.Recommendation?.Url) {
            remediationSteps.push(`Documentation: ${f.Remediation.Recommendation.Url}`);
          }
          const recText = f.Remediation?.Recommendation?.Text ?? "";
          if (recText && !["See References", "None Provided", ""].includes(recText.trim())) {
            remediationSteps.push(recText);
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
  ListDetectorsCommand as ListDetectorsCommand2
} from "@aws-sdk/client-guardduty";
var GuardDutyFindingsScanner = class {
  moduleName = "guardduty_findings";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings = [];
    try {
      const client = createClient(GuardDutyClient2, region, ctx.credentials);
      const resp = await client.send(new ListDetectorsCommand2({}));
      const detectorIds = resp.DetectorIds ?? [];
      if (detectorIds.length === 0) {
        warnings.push("GuardDuty is not enabled in this region (no detectors found).");
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        module: this.moduleName,
        status: "error",
        error: `GuardDuty detection check failed: ${msg}`,
        resourcesScanned: 0,
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
  BatchGetAccountStatusCommand as BatchGetAccountStatusCommand2
} from "@aws-sdk/client-inspector2";
var InspectorFindingsScanner = class {
  moduleName = "inspector_findings";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings = [];
    try {
      const client = createClient(Inspector2Client2, region, ctx.credentials);
      const resp = await client.send(new BatchGetAccountStatusCommand2({ accountIds: [] }));
      const account = resp.accounts?.[0];
      if (!account || account.state?.status !== "ENABLED") {
        warnings.push("Inspector is not enabled in this region. Enable it to scan for software vulnerabilities.");
      } else {
        const rs = account.resourceState;
        const types = [
          { name: "EC2", status: rs?.ec2?.status },
          { name: "Lambda", status: rs?.lambda?.status },
          { name: "ECR", status: rs?.ecr?.status },
          { name: "Lambda Code", status: rs?.lambdaCode?.status },
          { name: "Code Repository", status: rs?.codeRepository?.status }
        ];
        const disabled = types.filter((t) => t.status && t.status !== "ENABLED");
        if (disabled.length > 0) {
          warnings.push(
            `Inspector scan types not enabled: ${disabled.map((t) => t.name).join(", ")}. Enable them for full vulnerability coverage.`
          );
        }
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const errName = err instanceof Error ? err.name : "";
      const isAccessDenied2 = errName === "AccessDeniedException" || msg.includes("AccessDeniedException");
      if (isAccessDenied2) {
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
  DescribeConfigurationRecordersCommand as DescribeConfigurationRecordersCommand2
} from "@aws-sdk/client-config-service";
var ConfigRulesFindingsScanner = class {
  moduleName = "config_rules_findings";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings = [];
    try {
      const client = createClient(ConfigServiceClient2, region, ctx.credentials);
      const resp = await client.send(new DescribeConfigurationRecordersCommand2({}));
      const recorders = resp.ConfigurationRecorders ?? [];
      if (recorders.length === 0) {
        warnings.push("AWS Config is not enabled in this region.");
      }
      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
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
        error: `Config Rules detection check failed: ${msg}`,
        resourcesScanned: 0,
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
  ListAnalyzersCommand
} from "@aws-sdk/client-accessanalyzer";
var AccessAnalyzerFindingsScanner = class {
  moduleName = "access_analyzer_findings";
  async scan(ctx) {
    const { region } = ctx;
    const startMs = Date.now();
    const warnings = [];
    try {
      const client = createClient(AccessAnalyzerClient, region, ctx.credentials);
      let analyzerToken;
      let hasActiveAnalyzer = false;
      do {
        const resp = await client.send(
          new ListAnalyzersCommand({ nextToken: analyzerToken })
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
        warnings: warnings.length > 0 ? warnings : void 0,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: []
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
        findings: []
      };
    }
  }
};

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

// src/i18n/zh.ts
var zhI18n = {
  // HTML Security Report
  securityReportTitle: "AWS \u5B89\u5168\u626B\u63CF\u62A5\u544A",
  securityScore: "\u5B89\u5168\u8BC4\u5206",
  critical: "\u4E25\u91CD",
  high: "\u9AD8",
  medium: "\u4E2D",
  low: "\u4F4E",
  scanStatistics: "\u626B\u63CF\u7EDF\u8BA1",
  module: "\u6A21\u5757",
  resources: "\u8D44\u6E90",
  findings: "\u53D1\u73B0",
  status: "\u72B6\u6001",
  allFindings: "\u6240\u6709\u53D1\u73B0",
  recommendations: "\u5EFA\u8BAE",
  unique: "\u53BB\u91CD",
  showMore: "\u663E\u793A\u66F4\u591A",
  noIssuesFound: "\u672A\u53D1\u73B0\u5B89\u5168\u95EE\u9898\u3002",
  allModulesClean: "\u6240\u6709\u6A21\u5757\u6B63\u5E38",
  generatedBy: "\u7531 AWS Security MCP Server \u751F\u6210",
  informationalOnly: "\u672C\u62A5\u544A\u4EC5\u4F9B\u53C2\u8003\u3002",
  // MLPS Report
  mlpsTitle: "\u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0\u62A5\u544A",
  mlpsDisclaimer: "\u672C\u62A5\u544A\u4E3A\u7B49\u4FDD\u4E09\u7EA7\u9884\u68C0\u53C2\u8003\uFF0C\u63D0\u4F9B\u4E91\u5E73\u53F0\u914D\u7F6E\u68C0\u67E5\u6570\u636E\u4E0E\u5EFA\u8BAE\u3002\u5408\u89C4\u5224\u5B9A\uFF08\u7B26\u5408/\u90E8\u5206\u7B26\u5408/\u4E0D\u7B26\u5408\uFF09\u9700\u7531\u6301\u8BC1\u6D4B\u8BC4\u673A\u6784\u6839\u636E\u5B9E\u9645\u60C5\u51B5\u786E\u8BA4\u3002\uFF08GB/T 22239-2019 \u5B8C\u6574\u68C0\u67E5\u6E05\u5355 184 \u9879\uFF09",
  checkedItems: "\u5DF2\u68C0\u67E5\u9879",
  noIssues: "\u672A\u53D1\u73B0\u95EE\u9898",
  issuesFound: "\u53D1\u73B0\u95EE\u9898",
  notChecked: "\u672A\u68C0\u67E5",
  cloudProvider: "\u4E91\u5E73\u53F0\u8D1F\u8D23",
  manualReview: "\u9700\u4EBA\u5DE5\u8BC4\u4F30",
  notApplicable: "\u4E0D\u9002\u7528",
  checkResult: "\u68C0\u67E5\u7ED3\u679C",
  noRelatedIssues: "\u68C0\u67E5\u7ED3\u679C\uFF1A\u672A\u53D1\u73B0\u76F8\u5173\u95EE\u9898",
  issuesFoundCount: (n) => `\u68C0\u67E5\u7ED3\u679C\uFF1A\u53D1\u73B0 ${n} \u4E2A\u76F8\u5173\u95EE\u9898`,
  remediation: "\u5EFA\u8BAE",
  remediationItems: (n) => `\u5EFA\u8BAE\u6574\u6539\u9879\uFF08${n} \u9879\u53BB\u91CD\uFF09`,
  showRemaining: (n) => `\u663E\u793A\u5176\u4F59 ${n} \u9879`,
  // HW Defense Checklist
  hwChecklistTitle: "\u{1F4CB} \u62A4\u7F51\u884C\u52A8\u8865\u5145\u63D0\u9192\uFF08\u8D85\u51FA\u81EA\u52A8\u5316\u626B\u63CF\u8303\u56F4\uFF09",
  hwChecklistSubtitle: "\u4EE5\u4E0B\u4E8B\u9879\u9700\u8981\u4EBA\u5DE5\u786E\u8BA4\u548C\u6267\u884C\uFF1A",
  hwEmergencyIsolation: `\u26A0\uFE0F \u5E94\u6025\u9694\u79BB/\u6B62\u8840\u65B9\u6848
  \u25A1 \u51C6\u5907\u4E13\u7528\u9694\u79BB\u5B89\u5168\u7EC4\uFF08\u65E0 Inbound/Outbound \u89C4\u5219\uFF09
  \u25A1 \u5236\u5B9A\u5B9E\u4F8B\u9694\u79BB SOP\uFF1A\u544A\u8B66 \u2192 \u6392\u67E5 \u2192 \u5C01\u9501\u653B\u51FBIP \u2192 \u7F51\u7EDC\u9694\u79BB \u2192 \u5B89\u5168\u5904\u7F6E \u2192 \u8BB0\u5F55\u653B\u51FB\u9879
  \u25A1 \u660E\u786E\u5404\u7CFB\u7EDF\uFF08\u751F\u4EA7\u6838\u5FC3/\u751F\u4EA7\u975E\u6838\u5FC3/\u6D4B\u8BD5/\u5F00\u53D1\uFF09\u7684\u5E94\u6025\u5904\u7F6E\u65B9\u5F0F
  \u25A1 \u660E\u786E\u5404\u9879\u76EE\u8D26\u6237\u53CA\u8D44\u6E90\u7684\u8D1F\u8D23\u4EBA\u4E0E\u8054\u7CFB\u65B9\u5F0F`,
  hwTestEnvShutdown: `\u26A0\uFE0F \u6D4B\u8BD5/\u5F00\u53D1\u73AF\u5883\u5904\u7F6E
  \u25A1 \u975E\u6838\u5FC3\u7CFB\u7EDF\u5728\u62A4\u7F51\u671F\u95F4\u5173\u95ED
  \u25A1 \u6D4B\u8BD5/\u5F00\u53D1\u73AF\u5883\u5173\u95ED\u6216\u4E0E\u751F\u4EA7\u4FDD\u6301\u540C\u7B49\u5B89\u5168\u57FA\u7EBF
  \u25A1 \u786E\u8BA4\u54EA\u4E9B\u73AF\u5883\u53EF\u4EE5\u7D27\u6025\u5173\u505C\uFF0C\u907F\u514D\u653B\u51FB\u6269\u6563`,
  hwDutyTeam: `\u26A0\uFE0F \u503C\u5B88\u56E2\u961F\u7EC4\u5EFA
  \u25A1 7\xD724 \u76D1\u63A7\u5FEB\u901F\u54CD\u5E94\u56E2\u961F
  \u25A1 \u6280\u672F\u4E0E\u98CE\u9669\u5206\u6790\u7EC4
  \u25A1 \u5B89\u5168\u7B56\u7565\u4E0B\u53D1\u7EC4
  \u25A1 \u4E1A\u52A1\u54CD\u5E94\u7EC4
  \u25A1 \u660E\u786E AWS TAM/Support \u8054\u7CFB\u65B9\u5F0F\uFF08ES/EOP \u5BA2\u6237\uFF09`,
  hwNetworkDiagram: `\u26A0\uFE0F \u51FA\u5165\u7AD9\u8DEF\u5F84\u67B6\u6784\u56FE
  \u25A1 \u786E\u4FDD\u6240\u6709\u4E92\u8054\u7F51/DX \u4E13\u7EBF\u51FA\u5165\u7AD9\u8DEF\u5F84\u5728\u67B6\u6784\u56FE\u4E2D\u6E05\u6670\u6807\u6CE8
  \u25A1 \u660E\u786E\u5404 ELB/Public EC2/S3/DX \u7684\u6570\u636E\u6D41\u5411
  \u25A1 \u8BC6\u522B\u6240\u6709\u9762\u5411\u4E92\u8054\u7F51\u7684\u6570\u636E\u4EA4\u4E92\u63A5\u53E3`,
  hwPentest: `\u26A0\uFE0F \u4E3B\u52A8\u5F0F\u6E17\u900F\u6D4B\u8BD5
  \u25A1 \u62A4\u7F51\u524D\u8054\u7CFB\u5B89\u5168\u5382\u5546\uFF08\u9752\u85E4/\u957F\u4EAD/\u5FAE\u6B65\u7B49\uFF09\u8FDB\u884C\u6A21\u62DF\u653B\u51FB\u6F14\u7EC3
  \u25A1 \u57FA\u4E8E\u6E17\u900F\u6D4B\u8BD5\u62A5\u544A\u8FDB\u884C\u6B63\u5F0F\u62A4\u7F51\u524D\u7684\u5B89\u5168\u52A0\u56FA
  \u25A1 \u5173\u6CE8 AWS \u5B89\u5168\u516C\u544A\uFF08\u5DF2\u77E5\u6F0F\u6D1E\u4E0E\u8865\u4E01\uFF09`,
  hwWarRoom: `\u26A0\uFE0F WAR-ROOM \u5B9E\u65F6\u6C9F\u901A
  \u25A1 \u521B\u5EFA\u62A4\u7F51\u671F\u95F4\u4E13\u7528\u6C9F\u901A\u6E20\u9053\uFF08\u4F01\u5FAE/\u9489\u9489/\u98DE\u4E66/Chime\uFF09
  \u25A1 \u4E0E AWS TAM \u5EFA\u7ACB WAR-ROOM \u8054\u7CFB\uFF08\u4F01\u4E1A\u7EA7\u652F\u6301\u5BA2\u6237\uFF09
  \u25A1 \u7EDF\u4E00\u6848\u4F8B\u6807\u9898\u683C\u5F0F\uFF1A\u201C\u3010\u62A4\u7F51\u3011+ \u95EE\u9898\u63CF\u8FF0\u201D`,
  hwCredentials: `\u26A0\uFE0F \u5BC6\u7801\u4E0E\u51ED\u8BC1\u7BA1\u7406
  \u25A1 \u6240\u6709 IAM \u7528\u6237\u7ED1\u5B9A MFA
  \u25A1 AKSK \u8F6E\u8F6C\u5468\u671F \u2264 90 \u5929
  \u25A1 \u907F\u514D\u5171\u4EAB\u8D26\u6237\u4F7F\u7528
  \u25A1 S3/Lambda/\u5E94\u7528\u4EE3\u7801\u4E2D\u65E0\u660E\u6587\u5BC6\u7801`,
  hwPostOptimization: `\u26A0\uFE0F \u62A4\u7F51\u540E\u4F18\u5316
  \u25A1 \u9488\u5BF9\u653B\u51FB\u62A5\u544A\u9010\u9879\u5E94\u7B54\u4E0E\u4FEE\u590D
  \u25A1 \u4E0E\u5B89\u5168\u56E2\u961F\u5EFA\u7ACB\u5468\u671F\u6027\u5B89\u5168\u7EF4\u62A4\u6D41\u7A0B
  \u25A1 \u6301\u7EED\u8865\u5168\u5B89\u5168\u98CE\u9669`,
  hwReference: "\u53C2\u8003\uFF1AAWS \u62A4\u7F51\u884C\u52A8 Standard Operation Procedure (Compliance IEM)",
  // Service Reminders
  serviceReminderTitle: "\u26A1 \u4EE5\u4E0B\u5B89\u5168\u670D\u52A1\u672A\u542F\u7528\uFF0C\u90E8\u5206\u68C0\u67E5\u65E0\u6CD5\u6267\u884C\uFF1A",
  serviceReminderFooter: "\u542F\u7528\u4EE5\u4E0A\u670D\u52A1\u540E\u91CD\u65B0\u626B\u63CF\u53EF\u83B7\u5F97\u66F4\u5B8C\u6574\u7684\u5B89\u5168\u8BC4\u4F30\u3002",
  serviceImpact: "\u5F71\u54CD",
  serviceAction: "\u5EFA\u8BAE",
  // Common
  account: "\u8D26\u6237",
  region: "\u533A\u57DF",
  scanTime: "\u626B\u63CF\u65F6\u95F4",
  duration: "\u8017\u65F6",
  severityDistribution: "\u4E25\u91CD\u6027\u5206\u5E03",
  findingsByModule: "\u6309\u6A21\u5757\u5206\u7C7B\u7684\u53D1\u73B0",
  details: "\u8BE6\u60C5",
  // Extended — HTML Security Report extras
  topHighestRiskFindings: (n) => `\u524D ${n} \u9879\u6700\u9AD8\u98CE\u9669\u53D1\u73B0`,
  resource: "\u8D44\u6E90",
  impact: "\u5F71\u54CD",
  riskScore: "\u98CE\u9669\u8BC4\u5206",
  showRemainingFindings: (n) => `\u663E\u793A\u5269\u4F59 ${n} \u9879\u53D1\u73B0\u2026`,
  trendTitle: "30\u65E5\u8D8B\u52BF",
  findingsBySeverity: "\u6309\u4E25\u91CD\u6027\u5206\u7C7B\u7684\u53D1\u73B0",
  showMoreCount: (n) => `\u663E\u793A\u5269\u4F59 ${n} \u9879\u2026`,
  // Filter toolbar
  filterSeverity: "\u4E25\u91CD\u6027\uFF1A",
  filterModule: "\u6A21\u5757\uFF1A",
  filterAll: "\u5168\u90E8",
  filterAllModules: "\u5168\u90E8\u6A21\u5757",
  filterCountTpl: "\u663E\u793A {shown} / {total} \u4E2A\u53D1\u73B0",
  // Extended — MLPS extras
  // Markdown report
  executiveSummary: "\u6267\u884C\u6458\u8981",
  totalFindingsLabel: "\u53D1\u73B0\u603B\u6570",
  description: "\u63CF\u8FF0",
  priority: "\u4F18\u5148\u7EA7",
  noFindingsForSeverity: (severity) => `\u65E0${severity}\u53D1\u73B0\u3002`,
  preCheckOverview: "\u9884\u68C0\u603B\u89C8",
  accountInfo: "\u8D26\u6237\u4FE1\u606F",
  checkedCount: (total, clean, issues) => `\u5DF2\u68C0\u67E5: ${total} \u9879\uFF08\u672A\u53D1\u73B0\u95EE\u9898: ${clean} \u9879 | \u53D1\u73B0\u95EE\u9898: ${issues} \u9879\uFF09`,
  uncheckedCount: (n) => `\u672A\u68C0\u67E5: ${n} \u9879\uFF08\u5BF9\u5E94\u626B\u63CF\u6A21\u5757\u672A\u8FD0\u884C\uFF09`,
  cloudProviderCount: (n) => `\u4E91\u5E73\u53F0\u8D1F\u8D23: ${n} \u9879`,
  manualReviewCount: (n) => `\u9700\u4EBA\u5DE5\u8BC4\u4F30: ${n} \u9879`,
  naCount: (n) => `\u4E0D\u9002\u7528: ${n} \u9879`,
  naNote: (n) => `\u4E0D\u9002\u7528\u9879: ${n} \u9879\uFF08\u7269\u8054\u7F51/\u65E0\u7EBF\u7F51\u7EDC/\u79FB\u52A8\u7EC8\u7AEF/\u5DE5\u63A7\u7CFB\u7EDF/\u53EF\u4FE1\u9A8C\u8BC1\u7B49\uFF09`,
  unknownNote: (n) => `\uFF08${n} \u9879\u672A\u68C0\u67E5\uFF0C\u5BF9\u5E94\u626B\u63CF\u6A21\u5757\u672A\u8FD0\u884C\uFF09`,
  cloudItemsNote: (n) => `\u4EE5\u4E0B ${n} \u9879\u7531 AWS \u4E91\u5E73\u53F0\u8D1F\u8D23\uFF0C\u6839\u636E\u5B89\u5168\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\u4E0D\u5728\u672C\u62A5\u544A\u68C0\u67E5\u8303\u56F4\u5185\u3002`,
  mlpsFooterGenerated: (version) => `\u7531 AWS Security MCP Server v${version} \u751F\u6210`,
  mlpsFooterDisclaimer: "\u672C\u62A5\u544A\u4E3A\u8BC1\u636E\u6536\u96C6\u53C2\u8003\uFF0C\u4E0D\u5305\u542B\u5408\u89C4\u5224\u5B9A\u3002\u5B8C\u6574\u7B49\u4FDD\u6D4B\u8BC4\u9700\u7531\u6301\u8BC1\u6D4B\u8BC4\u673A\u6784\u6267\u884C\u3002",
  andMore: (n) => `... \u53CA\u5176\u4ED6 ${n} \u9879`,
  remediationByPriority: "\u5EFA\u8BAE\u6574\u6539\u9879\uFF08\u6309\u4F18\u5148\u7EA7\uFF09",
  affectedResources: (n) => `\u6D89\u53CA ${n} \u4E2A\u8D44\u6E90`,
  installWindowsPatches: (n, kbs) => `\u5B89\u88C5 ${n} \u4E2A Windows \u8865\u4E01 (${kbs})`,
  mlpsCategorySection: {
    "\u5B89\u5168\u7269\u7406\u73AF\u5883": "\u4E00\u3001\u5B89\u5168\u7269\u7406\u73AF\u5883",
    "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC": "\u4E8C\u3001\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    "\u5B89\u5168\u533A\u57DF\u8FB9\u754C": "\u4E09\u3001\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883": "\u56DB\u3001\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3": "\u4E94\u3001\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3"
  },
  // Module display names
  moduleNames: {
    service_detection: "\u5B89\u5168\u670D\u52A1\u68C0\u6D4B",
    secret_exposure: "\u5BC6\u94A5\u66B4\u9732",
    ssl_certificate: "SSL \u8BC1\u4E66",
    dns_dangling: "\u60AC\u6302 DNS",
    network_reachability: "\u7F51\u7EDC\u53EF\u8FBE\u6027",
    iam_privilege_escalation: "IAM \u63D0\u6743\u5206\u6790",
    public_access_verify: "\u516C\u7F51\u8BBF\u95EE\u9A8C\u8BC1",
    tag_compliance: "\u6807\u7B7E\u5408\u89C4",
    idle_resources: "\u95F2\u7F6E\u8D44\u6E90",
    disaster_recovery: "\u707E\u5907\u8BC4\u4F30",
    security_hub_findings: "Security Hub",
    guardduty_findings: "GuardDuty",
    inspector_findings: "Inspector",
    trusted_advisor_findings: "Trusted Advisor",
    config_rules_findings: "Config Rules",
    access_analyzer_findings: "Access Analyzer",
    patch_compliance_findings: "\u8865\u4E01\u5408\u89C4",
    imdsv2_enforcement: "IMDSv2 \u5F3A\u5236",
    waf_coverage: "WAF \u8986\u76D6",
    // Security Hub sub-categories
    "sh:FSBP": "\u5B89\u5168\u6700\u4F73\u5B9E\u8DF5",
    "sh:Inspector": "\u8F6F\u4EF6\u6F0F\u6D1E",
    "sh:GuardDuty": "\u5A01\u80C1\u68C0\u6D4B",
    "sh:Config": "\u914D\u7F6E\u5408\u89C4",
    "sh:Access Analyzer": "\u5916\u90E8\u8BBF\u95EE",
    "sh:Other": "\u5176\u4ED6\u5B89\u5168\u53D1\u73B0"
  },
  // Security Hub sub-categories
  securityHubSubCategories: {
    FSBP: { label: "\u5B89\u5168\u6700\u4F73\u5B9E\u8DF5" },
    Inspector: { label: "\u8F6F\u4EF6\u6F0F\u6D1E" },
    GuardDuty: { label: "\u5A01\u80C1\u68C0\u6D4B" },
    Config: { label: "\u914D\u7F6E\u5408\u89C4" },
    "Access Analyzer": { label: "\u5916\u90E8\u8BBF\u95EE" },
    Other: { label: "\u5176\u4ED6\u5B89\u5168\u53D1\u73B0" }
  },
  // Service Recommendations
  notEnabled: "\u672A\u542F\u7528",
  serviceRecommendations: {
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
  },
  // HW Checklist (full composite)
  hwChecklist: `
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
\u{1F4CB} \u62A4\u7F51\u884C\u52A8\u8865\u5145\u63D0\u9192\uFF08\u8D85\u51FA\u81EA\u52A8\u5316\u626B\u63CF\u8303\u56F4\uFF09
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

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
  \u25A1 \u7EDF\u4E00\u6848\u4F8B\u6807\u9898\u683C\u5F0F\uFF1A\u201C\u3010\u62A4\u7F51\u3011+ \u95EE\u9898\u63CF\u8FF0\u201D

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
`
};

// src/i18n/en.ts
var enI18n = {
  // HTML Security Report
  securityReportTitle: "AWS Security Scan Report",
  securityScore: "Security Score",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  scanStatistics: "Scan Statistics",
  module: "Module",
  resources: "Resources",
  findings: "Findings",
  status: "Status",
  allFindings: "All Findings",
  recommendations: "Recommendations",
  unique: "unique",
  showMore: "Show more",
  noIssuesFound: "No security issues found.",
  allModulesClean: "All modules clean",
  generatedBy: "Generated by AWS Security MCP Server",
  informationalOnly: "This report is for informational purposes only.",
  // MLPS Report
  mlpsTitle: "MLPS Level 3 Pre-Check Report",
  mlpsDisclaimer: "This report is for MLPS Level 3 pre-check reference, providing cloud platform configuration check data and recommendations. Compliance determination (compliant/partially compliant/non-compliant) must be confirmed by a certified assessment institution. (GB/T 22239-2019 full checklist: 184 items)",
  checkedItems: "Checked Items",
  noIssues: "No Issues Found",
  issuesFound: "Issues Found",
  notChecked: "Not Checked",
  cloudProvider: "Cloud Provider Responsible",
  manualReview: "Manual Review Required",
  notApplicable: "Not Applicable",
  checkResult: "Check Result",
  noRelatedIssues: "Check Result: No related issues found",
  issuesFoundCount: (n) => `Check Result: Found ${n} related issue${n === 1 ? "" : "s"}`,
  remediation: "Remediation",
  remediationItems: (n) => `Remediation Items (${n} unique)`,
  showRemaining: (n) => `Show remaining ${n} items`,
  // HW Defense Checklist
  hwChecklistTitle: "\u{1F4CB} Cyber Defense Drill Supplementary Reminders (Beyond Automated Scanning)",
  hwChecklistSubtitle: "The following items require manual verification and execution:",
  hwEmergencyIsolation: `\u26A0\uFE0F Emergency Isolation / Incident Response Plan
  \u25A1 Prepare dedicated isolation security groups (no Inbound/Outbound rules)
  \u25A1 Establish instance isolation SOP: Alert \u2192 Investigate \u2192 Block attacker IP \u2192 Network isolation \u2192 Security response \u2192 Log attack details
  \u25A1 Define emergency response procedures for each system (production core/non-core/test/dev)
  \u25A1 Identify responsible personnel and contacts for each project account and resource`,
  hwTestEnvShutdown: `\u26A0\uFE0F Test/Development Environment Handling
  \u25A1 Shut down non-critical systems during the drill period
  \u25A1 Shut down test/dev environments or maintain same security baseline as production
  \u25A1 Confirm which environments can be emergency-stopped to prevent attack propagation`,
  hwDutyTeam: `\u26A0\uFE0F On-Duty Team Formation
  \u25A1 7\xD724 monitoring and rapid response team
  \u25A1 Technical and risk analysis team
  \u25A1 Security policy deployment team
  \u25A1 Business response team
  \u25A1 Confirm AWS TAM/Support contact information (ES/EOP customers)`,
  hwNetworkDiagram: `\u26A0\uFE0F Ingress/Egress Path Architecture Diagram
  \u25A1 Ensure all Internet/DX dedicated line ingress/egress paths are clearly marked in architecture diagrams
  \u25A1 Clarify data flow for each ELB/Public EC2/S3/DX
  \u25A1 Identify all internet-facing data interaction interfaces`,
  hwPentest: `\u26A0\uFE0F Proactive Penetration Testing
  \u25A1 Contact security vendors for simulated attack drills before the exercise
  \u25A1 Conduct security hardening based on penetration test reports
  \u25A1 Monitor AWS security advisories (known vulnerabilities and patches)`,
  hwWarRoom: `\u26A0\uFE0F WAR-ROOM Real-Time Communication
  \u25A1 Create dedicated communication channels for the drill period (Teams/Slack/Chime)
  \u25A1 Establish WAR-ROOM connection with AWS TAM (Enterprise Support customers)
  \u25A1 Standardize case title format: "[CyberDrill] + Issue Description"`,
  hwCredentials: `\u26A0\uFE0F Password & Credential Management
  \u25A1 All IAM users must have MFA enabled
  \u25A1 Access key rotation cycle \u2264 90 days
  \u25A1 Avoid shared account usage
  \u25A1 No plaintext passwords in S3/Lambda/application code`,
  hwPostOptimization: `\u26A0\uFE0F Post-Drill Optimization
  \u25A1 Address and remediate each item from the attack report
  \u25A1 Establish periodic security maintenance processes with the security team
  \u25A1 Continuously fill security risk gaps`,
  hwReference: "Reference: AWS Cyber Defense Drill Standard Operation Procedure (Compliance IEM)",
  // Service Reminders
  serviceReminderTitle: "\u26A1 The following security services are not enabled; some checks cannot be performed:",
  serviceReminderFooter: "Re-scan after enabling the above services for a more complete security assessment.",
  serviceImpact: "Impact",
  serviceAction: "Action",
  // Common
  account: "Account",
  region: "Region",
  scanTime: "Scan Time",
  duration: "Duration",
  severityDistribution: "Severity Distribution",
  findingsByModule: "Findings by Module",
  details: "Details",
  // Extended \u2014 HTML Security Report extras
  topHighestRiskFindings: (n) => `Top ${n} Highest Risk Findings`,
  resource: "Resource",
  impact: "Impact",
  riskScore: "Risk Score",
  showRemainingFindings: (n) => `Show remaining ${n} findings\u2026`,
  trendTitle: "30-Day Trends",
  findingsBySeverity: "Findings by Severity",
  showMoreCount: (n) => `Show ${n} more\u2026`,
  // Filter toolbar
  filterSeverity: "Severity:",
  filterModule: "Module:",
  filterAll: "All",
  filterAllModules: "All Modules",
  filterCountTpl: "Showing {shown} / {total} findings",
  // Extended \u2014 MLPS extras
  // Markdown report
  executiveSummary: "Executive Summary",
  totalFindingsLabel: "Total Findings",
  description: "Description",
  priority: "Priority",
  noFindingsForSeverity: (severity) => `No ${severity.toLowerCase()} findings.`,
  preCheckOverview: "Pre-Check Overview",
  accountInfo: "Account Information",
  checkedCount: (total, clean, issues) => `Checked: ${total} items (No issues: ${clean} | Issues found: ${issues})`,
  uncheckedCount: (n) => `Not checked: ${n} items (corresponding scan modules not run)`,
  cloudProviderCount: (n) => `Cloud provider responsible: ${n} items`,
  manualReviewCount: (n) => `Manual review required: ${n} items`,
  naCount: (n) => `Not applicable: ${n} items`,
  naNote: (n) => `Not applicable: ${n} items (IoT/wireless networks/mobile terminals/ICS/trusted verification, etc.)`,
  unknownNote: (n) => `(${n} items not checked \u2014 corresponding scan modules not run)`,
  cloudItemsNote: (n) => `The following ${n} items are the responsibility of the AWS cloud platform and are outside the scope of this report per the shared responsibility model.`,
  mlpsFooterGenerated: (version) => `Generated by AWS Security MCP Server v${version}`,
  mlpsFooterDisclaimer: "This report is for evidence collection reference and does not include compliance determination. A complete MLPS assessment must be conducted by a certified assessment institution.",
  andMore: (n) => `\u2026 and ${n} more`,
  remediationByPriority: "Remediation Items (by Priority)",
  affectedResources: (n) => `${n} resource${n === 1 ? "" : "s"} affected`,
  installWindowsPatches: (n, kbs) => `Install ${n} Windows patch${n === 1 ? "" : "es"} (${kbs})`,
  mlpsCategorySection: {
    "\u5B89\u5168\u7269\u7406\u73AF\u5883": "I. Physical Environment Security",
    "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC": "II. Communication Network Security",
    "\u5B89\u5168\u533A\u57DF\u8FB9\u754C": "III. Area Boundary Security",
    "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883": "IV. Computing Environment Security",
    "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3": "V. Security Management Center"
  },
  // Module display names
  moduleNames: {
    service_detection: "Security Service Detection",
    secret_exposure: "Secret Exposure",
    ssl_certificate: "SSL Certificate",
    dns_dangling: "Dangling DNS",
    network_reachability: "Network Reachability",
    iam_privilege_escalation: "IAM Privilege Escalation",
    public_access_verify: "Public Access Verification",
    tag_compliance: "Tag Compliance",
    idle_resources: "Idle Resources",
    disaster_recovery: "Disaster Recovery",
    security_hub_findings: "Security Hub",
    guardduty_findings: "GuardDuty",
    inspector_findings: "Inspector",
    trusted_advisor_findings: "Trusted Advisor",
    config_rules_findings: "Config Rules",
    access_analyzer_findings: "Access Analyzer",
    patch_compliance_findings: "Patch Compliance",
    imdsv2_enforcement: "IMDSv2 Enforcement",
    waf_coverage: "WAF Coverage",
    // Security Hub sub-categories
    "sh:FSBP": "Security Best Practices",
    "sh:Inspector": "Software Vulnerabilities",
    "sh:GuardDuty": "Threat Detection",
    "sh:Config": "Configuration Compliance",
    "sh:Access Analyzer": "External Access",
    "sh:Other": "Other Security Findings"
  },
  // Security Hub sub-categories
  securityHubSubCategories: {
    FSBP: { label: "Security Best Practices" },
    Inspector: { label: "Software Vulnerabilities" },
    GuardDuty: { label: "Threat Detection" },
    Config: { label: "Configuration Compliance" },
    "Access Analyzer": { label: "External Access" },
    Other: { label: "Other Security Findings" }
  },
  // Service Recommendations
  notEnabled: "Not Enabled",
  serviceRecommendations: {
    security_hub_findings: {
      icon: "\u{1F534}",
      service: "Security Hub",
      impact: "Cannot obtain 300+ automated security checks (FSBP/CIS/PCI DSS standards)",
      action: "Enable Security Hub for the most comprehensive security posture assessment"
    },
    guardduty_findings: {
      icon: "\u{1F534}",
      service: "GuardDuty",
      impact: "Cannot detect threat activity (malicious IPs, anomalous API calls, crypto mining, etc.)",
      action: "Enable GuardDuty for continuous threat detection"
    },
    inspector_findings: {
      icon: "\u{1F7E1}",
      service: "Inspector",
      impact: "Cannot scan EC2/Lambda/container software vulnerabilities (CVEs)",
      action: "Enable Inspector to discover known security vulnerabilities"
    },
    trusted_advisor_findings: {
      icon: "\u{1F7E1}",
      service: "Trusted Advisor",
      impact: "Cannot obtain AWS best practice security checks",
      action: "Upgrade to Business/Enterprise Support plan to use Trusted Advisor security checks"
    },
    config_rules_findings: {
      icon: "\u{1F7E1}",
      service: "AWS Config",
      impact: "Cannot check resource configuration compliance status",
      action: "Enable AWS Config and configure Config Rules"
    },
    access_analyzer_findings: {
      icon: "\u{1F7E1}",
      service: "IAM Access Analyzer",
      impact: "Cannot detect whether resources are accessed by external accounts or public networks",
      action: "Create IAM Access Analyzer (account-level or organization-level)"
    },
    patch_compliance_findings: {
      icon: "\u{1F7E1}",
      service: "SSM Patch Manager",
      impact: "Cannot check instance patch compliance status",
      action: "Install SSM Agent and configure Patch Manager"
    }
  },
  // HW Checklist (full composite)
  hwChecklist: `
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
\u{1F4CB} Cyber Defense Drill Supplementary Reminders (Beyond Automated Scanning)
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

The following items require manual verification and execution:

\u26A0\uFE0F Emergency Isolation / Incident Response Plan
  \u25A1 Prepare dedicated isolation security groups (no Inbound/Outbound rules)
  \u25A1 Establish instance isolation SOP: Alert \u2192 Investigate \u2192 Block attacker IP \u2192 Network isolation \u2192 Security response \u2192 Log attack details
  \u25A1 Define emergency response procedures for each system (production core/non-core/test/dev)
  \u25A1 Identify responsible personnel and contacts for each project account and resource

\u26A0\uFE0F Test/Development Environment Handling
  \u25A1 Shut down non-critical systems during the drill period
  \u25A1 Shut down test/dev environments or maintain same security baseline as production
  \u25A1 Confirm which environments can be emergency-stopped to prevent attack propagation

\u26A0\uFE0F On-Duty Team Formation
  \u25A1 7\xD724 monitoring and rapid response team
  \u25A1 Technical and risk analysis team
  \u25A1 Security policy deployment team
  \u25A1 Business response team
  \u25A1 Confirm AWS TAM/Support contact information (ES/EOP customers)

\u26A0\uFE0F Ingress/Egress Path Architecture Diagram
  \u25A1 Ensure all Internet/DX dedicated line ingress/egress paths are clearly marked in architecture diagrams
  \u25A1 Clarify data flow for each ELB/Public EC2/S3/DX
  \u25A1 Identify all internet-facing data interaction interfaces

\u26A0\uFE0F Proactive Penetration Testing
  \u25A1 Contact security vendors for simulated attack drills before the exercise
  \u25A1 Conduct security hardening based on penetration test reports
  \u25A1 Monitor AWS security advisories (known vulnerabilities and patches)

\u26A0\uFE0F WAR-ROOM Real-Time Communication
  \u25A1 Create dedicated communication channels for the drill period (Teams/Slack/Chime)
  \u25A1 Establish WAR-ROOM connection with AWS TAM (Enterprise Support customers)
  \u25A1 Standardize case title format: "[CyberDrill] + Issue Description"

\u26A0\uFE0F Password & Credential Management
  \u25A1 All IAM users must have MFA enabled
  \u25A1 Access key rotation cycle \u2264 90 days
  \u25A1 Avoid shared account usage
  \u25A1 No plaintext passwords in S3/Lambda/application code

\u26A0\uFE0F Post-Drill Optimization
  \u25A1 Address and remediate each item from the attack report
  \u25A1 Establish periodic security maintenance processes with the security team
  \u25A1 Continuously fill security risk gaps

Reference: AWS Cyber Defense Drill Standard Operation Procedure (Compliance IEM)
`
};

// src/i18n/index.ts
var translations = {
  zh: zhI18n,
  en: enI18n
};
function getI18n(lang = "zh") {
  return translations[lang] ?? translations.zh;
}

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
function generateMarkdownReport(scanResults, lang) {
  const t = getI18n(lang ?? "zh");
  const { summary, modules, accountId, region, scanStart, scanEnd } = scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration(scanStart, scanEnd);
  const sevLabel = {
    CRITICAL: t.critical,
    HIGH: t.high,
    MEDIUM: t.medium,
    LOW: t.low
  };
  function renderFinding(f) {
    const steps = f.remediationSteps.map((s, i) => `  ${i + 1}. ${s}`).join("\n");
    return [
      `#### ${f.title}`,
      `- **${t.resource}:** ${f.resourceId} (\`${f.resourceArn}\`)`,
      `- **${t.description}:** ${f.description}`,
      `- **${t.impact}:** ${f.impact}`,
      `- **${t.riskScore}:** ${f.riskScore}/10`,
      `- **${t.remediation}:**`,
      steps,
      `- **${t.priority}:** ${f.priority}`
    ].join("\n");
  }
  const lines = [];
  lines.push(`# ${t.securityReportTitle} \u2014 ${date}`);
  lines.push("");
  lines.push(`## ${t.executiveSummary}`);
  lines.push(`- **${t.account}:** ${accountId}`);
  lines.push(`- **${t.region}:** ${region}`);
  lines.push(`- **${t.duration}:** ${duration}`);
  lines.push(
    `- **${t.totalFindingsLabel}:** ${summary.totalFindings} (${SEVERITY_ICON.CRITICAL} ${summary.critical} ${t.critical} | ${SEVERITY_ICON.HIGH} ${summary.high} ${t.high} | ${SEVERITY_ICON.MEDIUM} ${summary.medium} ${t.medium} | ${SEVERITY_ICON.LOW} ${summary.low} ${t.low})`
  );
  lines.push("");
  if (summary.totalFindings === 0) {
    lines.push(`## ${t.findingsBySeverity}`);
    lines.push("");
    lines.push(`\u2705 ${t.noIssuesFound}`);
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
    lines.push(`## ${t.findingsBySeverity}`);
    lines.push("");
    for (const sev of SEVERITY_ORDER) {
      const findings = grouped.get(sev);
      const icon = SEVERITY_ICON[sev];
      lines.push(`### ${icon} ${sevLabel[sev]}`);
      lines.push("");
      if (findings.length === 0) {
        lines.push(t.noFindingsForSeverity(sevLabel[sev]));
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
  lines.push(`## ${t.scanStatistics}`);
  lines.push(
    `| ${t.module} | ${t.resources} | ${t.findings} | ${t.status} |`
  );
  lines.push("|--------|------------------|----------|--------|");
  for (const m of modules) {
    const status = m.status === "success" ? "\u2705" : "\u274C";
    lines.push(
      `| ${t.moduleNames[m.module] ?? m.module} | ${m.resourcesScanned} | ${m.findingsCount} | ${status} |`
    );
  }
  lines.push("");
  if (summary.totalFindings > 0) {
    const allFindings = modules.flatMap((m) => m.findings);
    allFindings.sort((a, b) => b.riskScore - a.riskScore);
    lines.push(`## ${t.recommendations}`);
    for (let i = 0; i < allFindings.length; i++) {
      const f = allFindings[i];
      lines.push(`${i + 1}. [${f.priority}] ${f.title}: ${f.remediationSteps[0] ?? "Review and remediate."}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// src/data/mlps3-full-checklist.json
var mlps3_full_checklist_default = [
  {
    id: "L3-PES1-01",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7269\u7406\u4F4D\u7F6E\u9009\u62E9",
    controlEn: "Physical Location Alteration",
    requirementCn: "\u673A\u623F\u573A\u5730\u5E94\u9009\u62E9\u5728\u5177\u6709\u9632\u9707\u3001\u9632\u98CE\u548C\u9632\u96E8\u7B49\u80FD\u529B\u7684\u5EFA\u7B51\u5185",
    requirementEn: "The computer room should be located in buildings with the ability to be shockproof, windproof and rainproof",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-02",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7269\u7406\u4F4D\u7F6E\u9009\u62E9",
    controlEn: "Physical Location Alteration",
    requirementCn: "\u673A\u623F\u573A\u5730\u5E94\u907F\u514D\u8BBE\u5728\u5EFA\u7B51\u7269\u7684\u9876\u5C42\u6216\u5730\u4E0B\u5BA4\uFF0C\u5426\u5219\u5E94\u52A0\u5F3A\u9632\u6C34\u548C\u9632\u6F6E\u63AA\u65BD",
    requirementEn: "The computer room should avoid being located at the top of the building or the basement, otherwise waterproof and moisture-proof measures should be strengthened.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-03",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7269\u7406\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Physical Access Control",
    requirementCn: "\u673A\u623F\u51FA\u5165\u53E3\u5E94\u914D\u7F6E\u7535\u5B50\u95E8\u7981\u7CFB\u7EDF\uFF0C\u63A7\u5236\u3001\u9274\u522B\u548C\u8BB0\u5F55\u8FDB\u5165\u7684\u4EBA\u5458",
    requirementEn: "Entrance and exit of the computer room should be equipped with an electronic access control system to control, identify and record the incoming personnel.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-04",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u76D7\u7A83\u548C\u9632\u7834\u574F",
    controlEn: "Anti-theft and Anti-vandalism",
    requirementCn: "\u5E94\u5C06\u8BBE\u5907\u6216\u4E3B\u8981\u90E8\u4EF6\u8FDB\u884C\u56FA\u5B9A\uFF0C\u5E76\u8BBE\u7F6E\u660E\u663E\u7684\u4E0D\u6613\u9664\u53BB\u7684\u6807\u8BC6",
    requirementEn: "Device or main components should be fixed and marked with obvious labels that are difficult to remove",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-05",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u76D7\u7A83\u548C\u9632\u7834\u574F",
    controlEn: "Anti-theft and Anti-vandalism",
    requirementCn: "\u5E94\u5C06\u901A\u4FE1\u7EBF\u7F06\u94FA\u8BBE\u5728\u9690\u853D\u5B89\u5168\u5904",
    requirementEn: "The communication cable should be laid in a safe and concealed place",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-06",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u76D7\u7A83\u548C\u9632\u7834\u574F",
    controlEn: "Anti-theft and Anti-vandalism",
    requirementCn: "\u5E94\u8BBE\u7F6E\u673A\u623F\u9632\u76D7\u62A5\u8B66\u7CFB\u7EDF\u6216\u8BBE\u7F6E\u6709\u4E13\u4EBA\u503C\u5B88\u7684\u89C6\u9891\u76D1\u63A7\u7CFB\u7EDF",
    requirementEn: "A computer room anti-theft alarm system or a video surveillance system with a special person should be set up.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-07",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u96F7\u51FB",
    controlEn: "Lightning Protection",
    requirementCn: "\u5E94\u5C06\u5404\u7C7B\u673A\u67DC\u3001\u8BBE\u65BD\u548C\u8BBE\u5907\u7B49\u901A\u8FC7\u63A5\u5730\u7CFB\u7EDF\u5B89\u5168\u63A5\u5730",
    requirementEn: "All types of cabinets, facilities and equipment should be safely grounded through the grounding system",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-08",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u96F7\u51FB",
    controlEn: "Lightning Protection",
    requirementCn: "\u5E94\u91C7\u53D6\u63AA\u65BD\u9632\u6B62\u611F\u5E94\u96F7\uFF0C\u4F8B\u5982\u8BBE\u7F6E\u9632\u96F7\u4FDD\u5B89\u5668\u6216\u8FC7\u538B\u4FDD\u62A4\u88C5\u7F6E\u7B49",
    requirementEn: "Measures should be taken to prevent inductive lightning, such as set up lightning protection or overvoltage protection devices.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-09",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u706B",
    controlEn: "Fire Protection",
    requirementCn: "\u673A\u623F\u5E94\u8BBE\u7F6E\u706B\u707E\u81EA\u52A8\u6D88\u9632\u7CFB\u7EDF\uFF0C\u80FD\u591F\u81EA\u52A8\u68C0\u6D4B\u706B\u60C5\u3001\u81EA\u52A8\u62A5\u8B66\uFF0C\u5E76\u81EA\u52A8\u706D\u706B",
    requirementEn: "Automatic fire protection system which can automatically detect, alarm and extinguish should be set up.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-10",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u706B",
    controlEn: "Fire Protection",
    requirementCn: "\u673A\u623F\u53CA\u76F8\u5173\u7684\u5DE5\u4F5C\u623F\u95F4\u548C\u8F85\u52A9\u623F\u5E94\u91C7\u7528\u5177\u6709\u8010\u706B\u7B49\u7EA7\u7684\u5EFA\u7B51\u6750\u6599",
    requirementEn: "The computer room and related work rooms and auxiliary rooms shall be constructed of fire-resistant building materials",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-11",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u706B",
    controlEn: "Fire Protection",
    requirementCn: "\u5E94\u5BF9\u673A\u623F\u5212\u5206\u533A\u57DF\u8FDB\u884C\u7BA1\u7406\uFF0C\u533A\u57DF\u548C\u533A\u57DF\u4E4B\u95F4\u8BBE\u7F6E\u9694\u79BB\u9632\u706B\u63AA\u65BD",
    requirementEn: "The computer room should be managed dividedly, and set fire prevention measures for each region",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-12",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u6C34\u548C\u9632\u6F6E",
    controlEn: "Waterproof and Moisture Proof",
    requirementCn: "\u5E94\u91C7\u53D6\u63AA\u65BD\u9632\u6B62\u96E8\u6C34\u901A\u8FC7\u673A\u623F\u7A97\u6237\u3001\u5C4B\u9876\u548C\u5899\u58C1\u6E17\u900F",
    requirementEn: "Measures should be taken to avoid rainwater penetrating through the windows, roof and walls of the computer room",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-13",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u6C34\u548C\u9632\u6F6E",
    controlEn: "Waterproof and Moisture Proof",
    requirementCn: "\u5E94\u91C7\u53D6\u63AA\u65BD\u9632\u6B62\u673A\u623F\u5185\u6C34\u84B8\u6C14\u7ED3\u9732\u548C\u5730\u4E0B\u79EF\u6C34\u7684\u8F6C\u79FB\u4E0E\u6E17\u900F",
    requirementEn: "Measures should be taken to prevent water vapor condensation, and to prevent transfer and penetration of underground water in the computer room",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-14",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u6C34\u548C\u9632\u6F6E",
    controlEn: "Waterproof and Moisture Proof",
    requirementCn: "\u5E94\u5B89\u88C5\u5BF9\u6C34\u654F\u611F\u7684\u68C0\u6D4B\u4EEA\u8868\u6216\u5143\u4EF6\uFF0C\u5BF9\u673A\u623F\u8FDB\u884C\u9632\u6C34\u68C0\u6D4B\u548C\u62A5\u8B66",
    requirementEn: "Water-sensitive detection instruments or components should be installed to conduct waterproof detection and alarm for the computer room.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-15",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u9759\u7535",
    controlEn: "Anti-static",
    requirementCn: "\u5E94\u91C7\u7528\u9632\u9759\u7535\u5730\u677F\u6216\u5730\u9762\u5E76\u91C7\u7528\u5FC5\u8981\u7684\u63A5\u5730\u9632\u9759\u7535\u63AA\u65BD",
    requirementEn: "Anti-static floor or ground should be used and necessary grounding anti-static measures should be adopted",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-16",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u9632\u9759\u7535",
    controlEn: "Anti-static",
    requirementCn: "\u5E94\u91C7\u53D6\u63AA\u65BD\u9632\u6B62\u9759\u7535\u7684\u4EA7\u751F\uFF0C\u4F8B\u5982\u91C7\u7528\u9759\u7535\u6D88\u9664\u5668\u3001\u4F69\u6234\u9632\u9759\u7535\u624B\u73AF\u7B49",
    requirementEn: "Measures such as use static eliminators and wear anti-static wrist straps should be taken to prevent from generating static electricity.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-17",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u6E29\u6E7F\u5EA6\u63A7\u5236",
    controlEn: "Temperature and Humidity Control",
    requirementCn: "\u5E94\u8BBE\u7F6E\u6E29\u6E7F\u5EA6\u81EA\u52A8\u8C03\u8282\u8BBE\u65BD\uFF0C\u4F7F\u673A\u623F\u6E29\u6E7F\u5EA6\u7684\u53D8\u5316\u5728\u8BBE\u5907\u8FD0\u884C\u6240\u5141\u8BB8\u7684\u8303\u56F4\u4E4B\u5185",
    requirementEn: "Temperature and humidity automatic adjustment facilities should be set up so that the temperature and humidity changes are within the allowable range of equipment operation.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-18",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7535\u529B\u4F9B\u5E94",
    controlEn: "Electricity Supply",
    requirementCn: "\u5E94\u5728\u673A\u623F\u4F9B\u7535\u7EBF\u8DEF\u4E0A\u914D\u7F6E\u7A33\u538B\u5668\u548C\u8FC7\u7535\u538B\u9632\u62A4\u8BBE\u5907",
    requirementEn: "Voltage stabilizer and overvoltage protection equipment should be configured for the power supply line of the computer room",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-19",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7535\u529B\u4F9B\u5E94",
    controlEn: "Electricity Supply",
    requirementCn: "\u5E94\u63D0\u4F9B\u77ED\u671F\u7684\u5907\u7528\u7535\u529B\u4F9B\u5E94\uFF0C\u81F3\u5C11\u6EE1\u8DB3\u8BBE\u5907\u5728\u65AD\u7535\u60C5\u51B5\u4E0B\u7684\u6B63\u5E38\u8FD0\u884C\u8981\u6C42",
    requirementEn: "A short-term backup power supply shall be provided to meet the normal operational requirements of the equipment in the event of a power outage",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-20",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7535\u529B\u4F9B\u5E94",
    controlEn: "Electricity Supply",
    requirementCn: "\u5E94\u8BBE\u7F6E\u5197\u4F59\u6216\u5E76\u884C\u7684\u7535\u529B\u7535\u7F06\u7EBF\u8DEF\u4E3A\u8BA1\u7B97\u673A\u7CFB\u7EDF\u4F9B\u7535",
    requirementEn: "Equip backup or parallel power cable lines to power the computer system when necessary.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-21",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7535\u78C1\u9632\u62A4",
    controlEn: "Electromagnetic Protection",
    requirementCn: "\u7535\u6E90\u7EBF\u548C\u901A\u4FE1\u7EBF\u7F06\u5E94\u9694\u79BB\u94FA\u8BBE\uFF0C\u907F\u514D\u4E92\u76F8\u5E72\u6270",
    requirementEn: "Power cables and communication cables should be laid isolated to avoid mutual interference",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-PES1-22",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u7535\u78C1\u9632\u62A4",
    controlEn: "Electromagnetic Protection",
    requirementCn: "\u5E94\u5BF9\u5173\u952E\u8BBE\u5907\u5B9E\u65BD\u7535\u78C1\u5C4F\u853D",
    requirementEn: "Electromagnetic shielding should be implemented for critical equipment.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u7269\u7406\u73AF\u5883\u5B89\u5168"
  },
  {
    id: "L3-CNS1-01",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u4FDD\u8BC1\u7F51\u7EDC\u8BBE\u5907\u7684\u4E1A\u52A1\u5904\u7406\u80FD\u529B\u6EE1\u8DB3\u4E1A\u52A1\u9AD8\u5CF0\u671F\u9700\u8981",
    requirementEn: "Service processing capability of network should be guaranteed to meet the peak business needs",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u4E92\u8054\u7F51\u63A5\u5165\u6EE1\u8DB3\u4E1A\u52A1\u9AD8\u5CF0\u9700\u6C42\uFF1B\u5BA2\u6237\u6570\u636E\u4E2D\u5FC3\u548C\u4E9A\u9A6C\u900A\u4E91\u4E4B\u95F4\u7684\u8FDE\u63A5\u4F8B\u5982VPN\uFF0C\u4E13\u7EBF\u7684\u5904\u7406\u80FD\u529B\u9700\u8981\u5BA2\u6237\u6839\u636E\u4E1A\u52A1\u89C4\u5212\uFF1BVPC\u5185\u90E8\u7F51\u7EDC\u670D\u52A1\u6709\u81EA\u8EAB\u7684\u9650\u5236\uFF0C\u5F00Case\u63D0\u5347\u9650\u5236\uFF1BEC2\u81EA\u8EAB\u7684\u7F51\u7EDC\u5904\u7406\u80FD\u529B\u53EF\u4EE5\u6839\u636E\u4E1A\u52A1\u9700\u6C42\u8FDB\u884C\u9009\u62E9"
  },
  {
    id: "L3-CNS1-02",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u4FDD\u8BC1\u7F51\u7EDC\u5404\u4E2A\u90E8\u5206\u7684\u5E26\u5BBD\u6EE1\u8DB3\u4E1A\u52A1\u9AD8\u5CF0\u671F\u9700\u8981",
    requirementEn: "Ensure that the bandwidth of each part of the network meets the peak business needs",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4E9A\u9A6C\u900A\u4E91\u79D1\u6280\u8D1F\u8D23Cloud\u672C\u8EAB\u7684\u4E92\u8054\u7F51\u63A5\u5165\u6EE1\u8DB3\u4E1A\u52A1\u9AD8\u5CF0\u9700\u6C42\uFF1B\u5BA2\u6237\u6570\u636E\u4E2D\u5FC3\u548C\u4E9A\u9A6C\u900A\u4E91\u4E4B\u95F4\u7684\u8FDE\u63A5\u4F8B\u5982VPN\uFF0C\u4E13\u7EBF\u7684\u5904\u7406\u80FD\u529B\u9700\u8981\u5BA2\u6237\u6839\u636E\u4E1A\u52A1\u89C4\u5212\uFF1BVPC\u5185\u90E8\u7F51\u7EDC\u670D\u52A1\u6709\u81EA\u8EAB\u7684\u9650\u5236\uFF0C\u5F00Case\u63D0\u5347\u9650\u5236\uFF1BEC2\u81EA\u8EAB\u7684\u7F51\u7EDC\u5904\u7406\u80FD\u529B\u53EF\u4EE5\u6839\u636E\u4E1A\u52A1\u9700\u6C42\u8FDB\u884C\u9009\u62E9"
  },
  {
    id: "L3-CNS1-03",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u5212\u5206\u4E0D\u540C\u7684\u7F51\u7EDC\u533A\u57DF\uFF0C\u5E76\u6309\u7167\u65B9\u4FBF\u7BA1\u7406\u548C\u63A7\u5236\u7684\u539F\u5219\u4E3A\u5404\u7F51\u7EDC\u533A\u57DF\u5206\u914D\u5730\u5740",
    requirementEn: "Different network areas should be divided, and addresses should be assigned to each network area in accordance with the principle of convenient management and control",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5229\u7528VPC\u8FDB\u884C\u533A\u57DF\u548C\u5730\u5740\u5212\u5206"
  },
  {
    id: "L3-CNS1-04",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u907F\u514D\u5C06\u91CD\u8981\u7F51\u7EDC\u533A\u57DF\u90E8\u7F72\u5728\u8FB9\u754C\u5904\uFF0C\u91CD\u8981\u7F51\u7EDC\u533A\u57DF\u4E0E\u5176\u4ED6\u7F51\u7EDC\u533A\u57DF\u4E4B\u95F4\u5E94\u91C7\u53D6\u53EF\u9760\u7684\u6280\u672F\u9694\u79BB\u624B\u6BB5",
    requirementEn: "Critical network areas should not be deployed at the network boundaries or without border protection, and reliable technical isolation should be used between important network areas and other network areas",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. AWS\u4FA7\u91C7\u7528\u9632\u706B\u5899\u6216\u8005Network ACL\uFF08\u5EFA\u8BAE\u786E\u8BA4global region\u8BBE\u8BA1\uFF09\n2. On-premise\u91C7\u7528\u9632\u706B\u5899"
  },
  {
    id: "L3-CNS1-05",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u63D0\u4F9B\u901A\u4FE1\u7EBF\u8DEF\u3001\u5173\u952E\u7F51\u7EDC\u8BBE\u5907\u548C\u5173\u952E\u8BA1\u7B97\u8BBE\u5907\u7684\u786C\u4EF6\u5197\u4F59\uFF0C\u4FDD\u8BC1\u7CFB\u7EDF\u7684\u53EF\u7528\u6027",
    requirementEn: "The communication lines and hardware of critical network equipment should be adequately backed up to ensure system availability.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u670D\u52A1\u786E\u4FDD\u591A\u53EF\u7528\u533A\u90E8\u7F72\u4EE5\u53CA\u591A\u533A\u57DF\u90E8\u7F72\uFF1B\u591A\u6761\u4E13\u7EBF\u63A5\u5165\u5230\u4E0D\u540C\u7684\u4E13\u7EBF\u63A5\u5165\u70B9\u786E\u4FDD\u9AD8\u53EF\u7528"
  },
  {
    id: "L3-CNS1-06",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u901A\u4FE1\u4F20\u8F93",
    controlEn: "Communication",
    requirementCn: "\u5E94\u91C7\u7528\u6821\u9A8C\u6280\u672F\u6216\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u901A\u4FE1\u8FC7\u7A0B\u4E2D\u6570\u636E\u7684\u5B8C\u6574\u6027",
    requirementEn: "Verification techniques or cryptographic techniques should be used to ensure the integrity of the data during communication",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5F00\u542F\u4F20\u8F93\u52A0\u5BC6"
  },
  {
    id: "L3-CNS1-07",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u901A\u4FE1\u4F20\u8F93",
    controlEn: "Communication",
    requirementCn: "\u5E94\u91C7\u7528\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u901A\u4FE1\u8FC7\u7A0B\u4E2D\u6570\u636E\u7684\u4FDD\u5BC6\u6027",
    requirementEn: "Cryptographic techniques should be used to ensure the   confidentiality of the data during communication",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u542F\u7528SSL/TLS\u4F20\u8F93\u52A0\u5BC6\uFF0C\u5229\u7528ACM\u7BA1\u7406\u4F20\u8F93\u52A0\u5BC6\u7684\u5BC6\u94A5"
  },
  {
    id: "L3-CNS1-08",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u53EF\u4FE1\u9A8C\u8BC1",
    controlEn: "Trusted Verification",
    requirementCn: "\u53EF\u57FA\u4E8E\u53EF\u4FE1\u6839\u5BF9\u901A\u4FE1\u8BBE\u5907\u7684\u7CFB\u7EDF\u5F15\u5BFC\u7A0B\u5E8F\u3001\u7CFB\u7EDF\u7A0B\u5E8F\u3001\u91CD\u8981\u914D\u7F6E\u53C2\u6570\u548C\u901A\u4FE1\u5E94\u7528\u7A0B\u5E8F\u7B49\u8FDB\u884C\u53EF\u4FE1\u9A8C\u8BC1\uFF0C\u5E76\u5728\u5E94\u7528\u7A0B\u5E8F\u7684\u5173\u952E\u6267\u884C\u73AF\u8282\u8FDB\u884C\u52A8\u6001\u53EF\u4FE1\u9A8C\u8BC1\uFF0C\u5728\u68C0\u6D4B\u5230\u5176\u53EF\u4FE1\u6027\u53D7\u5230\u7834\u574F\u540E\u8FDB\u884C\u62A5\u8B66\uFF0C\u5E76\u5C06\u9A8C\u8BC1\u7ED3\u679C\u5F62\u6210\u5BA1\u8BA1\u8BB0\u5F55\u9001\u81F3\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    requirementEn: "Trusted verification, based on the trusted root, can be applied to system boot program, system program, important configuration parameters, and communication applications of the communication device, and dynamic trusted verification can be used in the key execution of the application, and when detecting the credibility thereof. After being damaged, an alarm is issued, and after detecting that its credibility has been damaged, an alarm should be issued and the verification result should be sent to the Security Management Center.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS1-01",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8FB9\u754C\u9632\u62A4",
    controlEn: "Border Protection",
    requirementCn: "\u5E94\u4FDD\u8BC1\u8DE8\u8D8A\u8FB9\u754C\u7684\u8BBF\u95EE\u548C\u6570\u636E\u6D41\u901A\u8FC7\u8FB9\u754C\u9632\u62A4\u8BBE\u5907\u63D0\u4F9B\u7684\u53D7\u63A7\u63A5\u53E3\u8FDB\u884C\u901A\u4FE1",
    requirementEn: "It should be ensured that access and data flows across the boundary are communicated through a controlled interface provided by the border protection device.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-02",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8FB9\u754C\u9632\u62A4",
    controlEn: "Border Protection",
    requirementCn: "\u5E94\u80FD\u591F\u5BF9\u975E\u6388\u6743\u8BBE\u5907\u79C1\u81EA\u8054\u5230\u5185\u90E8\u7F51\u7EDC\u7684\u884C\u4E3A\u8FDB\u884C\u9650\u5236\u6216\u68C0\u67E5",
    requirementEn: "It should be able to restrict or check the behavior of unauthorized devices connected to the internal network",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-03",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8FB9\u754C\u9632\u62A4",
    controlEn: "Border Protection",
    requirementCn: "\u5E94\u80FD\u591F\u5BF9\u5185\u90E8\u7528\u6237\u975E\u6388\u6743\u8054\u5230\u5916\u90E8\u7F51\u7EDC\u7684\u884C\u4E3A\u8FDB\u884C\u9650\u5236\u6216\u68C0\u67E5",
    requirementEn: "It should be able to restrict or inspect the behavior of internal users who are privately linked to the external network",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u5229\u7528NAT \u6216\u8005 NAT Gateway\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n4. \u542F\u7528VPC Endpoint \u4FDD\u8BC1\u901A\u8FC7\u79C1\u6709\u7F51\u7EDC\u8BBF\u95EEAWS\u670D\u52A1"
  },
  {
    id: "L3-ABS1-04",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8FB9\u754C\u9632\u62A4",
    controlEn: "Border Protection",
    requirementCn: "\u5E94\u9650\u5236\u65E0\u7EBF\u7F51\u7EDC\u7684\u4F7F\u7528\uFF0C\u786E\u4FDD\u65E0\u7EBF\u7F51\u7EDC\u901A\u8FC7\u53D7\u63A7\u7684\u8FB9\u754C\u9632\u62A4\u8BBE\u5907\u63A5\u5165\u5185\u90E8\u7F51\u7EDC",
    requirementEn: "The use of the wireless network should be limited to ensure that the wireless network accesses the internal network through controlled border protection equipment.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS1-05",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5728\u7F51\u7EDC\u8FB9\u754C\u6216\u533A\u57DF\u4E4B\u95F4\u6839\u636E\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\u8BBE\u7F6E\u8BBF\u95EE\u63A7\u5236\u89C4\u5219\uFF0C\u9ED8\u8BA4\u60C5\u51B5\u4E0B\u9664\u5141\u8BB8\u901A\u4FE1\u5916\u53D7\u63A7\u63A5\u53E3\u62D2\u7EDD\u6240\u6709\u901A\u4FE1",
    requirementEn: "Access control rules should be set between network boundaries or regions based on access control policies, and the controlled interfaces should reject any communication by default except for those that allow communication",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u6309\u7167\u6700\u5C0F\u66B4\u9732\u539F\u5219\u8BBE\u7F6E"
  },
  {
    id: "L3-ABS1-06",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5220\u9664\u591A\u4F59\u6216\u65E0\u6548\u7684\u8BBF\u95EE\u63A7\u5236\u89C4\u5219\uFF0C\u4F18\u5316\u8BBF\u95EE\u63A7\u5236\u5217\u8868\uFF0C\u5E76\u4FDD\u8BC1\u8BBF\u95EE\u63A7\u5236\u89C4\u5219\u6570\u91CF\u6700\u5C0F\u5316",
    requirementEn: "Extra or invalid access control rules should be removed to optimize the access control lists, and the number of access control rules should be minimized",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u6309\u7167\u6700\u5C0F\u66B4\u9732\u539F\u5219\u8BBE\u7F6E"
  },
  {
    id: "L3-ABS1-07",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5BF9\u6E90\u5730\u5740\u3001\u76EE\u7684\u5730\u5740\u3001\u6E90\u7AEF\u53E3\u3001\u76EE\u7684\u7AEF\u53E3\u548C\u534F\u8BAE\u7B49\u8FDB\u884C\u68C0\u67E5\uFF0C\u4EE5\u5141\u8BB8/\u62D2\u7EDD\u6570\u636E\u5305\u8FDB\u51FA",
    requirementEn: "Check the source address, destination address, source port, destination port, protocol, etc. to allow/deny packets in and out",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n4. \u5229\u7528VPC Flow log \u5BF9\u8FDB\u51FAVPC\u7684\u901A\u8BAF\u8FDB\u884C\u5206\u6790\n5. \u5FC5\u8981\u65F6\u53EF\u4EE5\u542F\u7528VPC Traffic Mirror\uFF0C\u5E76\u5229\u7528\u4E13\u4E1A\u5206\u6790\u8F6F\u4EF6\u8FDB\u884C\u6D41\u91CF\u5206\u6790"
  },
  {
    id: "L3-ABS1-08",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u80FD\u6839\u636E\u4F1A\u8BDD\u72B6\u6001\u4FE1\u606F\u4E3A\u8FDB\u51FA\u6570\u636E\u6D41\u63D0\u4F9B\u660E\u786E\u7684\u5141\u8BB8/\u62D2\u7EDD\u8BBF\u95EE\u7684\u80FD\u529B",
    requirementEn: "Explicit ability to allow/deny access to incoming and outgoing data streams should be provided based on session state information",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-09",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5BF9\u8FDB\u51FA\u7F51\u7EDC\u7684\u6570\u636E\u6D41\u5B9E\u73B0\u57FA\u4E8E\u5E94\u7528\u534F\u8BAE\u548C\u5E94\u7528\u5185\u5BB9\u7684\u8BBF\u95EE\u63A7\u5236",
    requirementEn: "Access control based on application protocols and application content should be applied to data flows to and from the network.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '"1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"'
  },
  {
    id: "L3-ABS1-10",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u5728\u5173\u952E\u7F51\u7EDC\u8282\u70B9\u5904\u68C0\u6D4B\u3001\u9632\u6B62\u6216\u9650\u5236\u4ECE\u5916\u90E8\u53D1\u8D77\u7684\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A",
    requirementEn: "Externally initiated cyber attacks should be detected, prevented or restricted at critical network nodes",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-11",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u5728\u5173\u952E\u7F51\u7EDC\u8282\u70B9\u5904\u68C0\u6D4B\u3001\u9632\u6B62\u6216\u9650\u5236\u4ECE\u5185\u90E8\u53D1\u8D77\u7684\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A",
    requirementEn: "Internally initiated cyber attacks should be detected, prevented or restricted at critical network nodes",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528GuardDuty\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-12",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u91C7\u53D6\u6280\u672F\u63AA\u65BD\u5BF9\u7F51\u7EDC\u884C\u4E3A\u8FDB\u884C\u5206\u6790\uFF0C\u5B9E\u73B0\u5BF9\u7F51\u7EDC\u653B\u51FB\u7279\u522B\u662F\u65B0\u578B\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A\u7684\u5206\u6790",
    requirementEn: "Technical measures should be taken to analyze the network behavior, as well as analyze network attacks, especially the new types of attacks.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-ABS1-13",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5F53\u68C0\u6D4B\u5230\u653B\u51FB\u884C\u4E3A\u65F6\uFF0C\u8BB0\u5F55\u653B\u51FB\u6E90IP\u3001\u653B\u51FB\u7C7B\u578B\u3001\u653B\u51FB\u76EE\u7684\u3001\u653B\u51FB\u65F6\u95F4\uFF0C\u5728\u53D1\u751F\u4E25\u91CD\u5165\u4FB5\u4E8B\u4EF6\u65F6\u5E94\u63D0\u4F9B\u62A5\u8B66",
    requirementEn: "When an attack is detected, the attack source IP, attack type, attack purpose, and attack time should be recorded, and alarm when a serious intrusion occurs.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72"
  },
  {
    id: "L3-ABS1-14",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u6076\u610F\u4EE3\u7801\u548C\u5783\u573E\u90AE\u4EF6\u9632\u8303",
    controlEn: "Malicious Code and Spam Prevention",
    requirementCn: "\u5E94\u5728\u5173\u952E\u7F51\u7EDC\u8282\u70B9\u5904\u5BF9\u6076\u610F\u4EE3\u7801\u8FDB\u884C\u68C0\u6D4B\u548C\u6E05\u9664\uFF0C\u5E76\u7EF4\u62A4\u6076\u610F\u4EE3\u7801\u9632\u62A4\u673A\u5236\u7684\u5347\u7EA7\u548C\u66F4\u65B0",
    requirementEn: "Malicious code should be detected and purged at key network nodes, and the upgrade and update of malicious code protection mechanism should be maintained.",
    referenceStatus: "\u4E0D\u7B26\u5408 Gap Exist",
    referenceComment: "1.\u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n2.\u5728\u64CD\u4F5C\u7CFB\u7EDF\u5B89\u88C5\u7B2C\u4E09\u65B9\u5B89\u5168\u9632\u62A4\u548C\u6740\u6BD2\u8F6F\u4EF6"
  },
  {
    id: "L3-ABS1-15",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u6076\u610F\u4EE3\u7801\u548C\u5783\u573E\u90AE\u4EF6\u9632\u8303",
    controlEn: "Malicious Code and Spam Prevention",
    requirementCn: "\u5E94\u5728\u5173\u952E\u7F51\u7EDC\u8282\u70B9\u5904\u5BF9\u5783\u573E\u90AE\u4EF6\u8FDB\u884C\u68C0\u6D4B\u548C\u9632\u62A4\uFF0C\u5E76\u7EF4\u62A4\u5783\u573E\u90AE\u4EF6\u9632\u62A4\u673A\u5236\u7684\u5347\u7EA7\u548C\u66F4\u65B0",
    requirementEn: "Spam should be detected and protect at critical network nodes and upgrades and update of spam protection mechanisms should be maintained.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS1-16",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u5728\u7F51\u7EDC\u8FB9\u754C\u3001\u91CD\u8981\u7F51\u7EDC\u8282\u70B9\u8FDB\u884C\u5B89\u5168\u5BA1\u8BA1\uFF0C\u5BA1\u8BA1\u8986\u76D6\u5230\u6BCF\u4E2A\u7528\u6237\uFF0C\u5BF9\u91CD\u8981\u7684\u7528\u6237\u884C\u4E3A\u548C\u91CD\u8981\u5B89\u5168\u4E8B\u4EF6\u8FDB\u884C\u5BA1\u8BA1",
    requirementEn: "Security audits should be conducted at network borders and important network nodes, and audits should be covered to each user to audit important user behaviors and important security incidents",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. IAM\n2,\u5821\u5792\u673A\uFF08session manager\u6216\u8005\u7B2C\u4E09\u65B9\u7684\u5821\u5792\u673A)"
  },
  {
    id: "L3-ABS1-17",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5BA1\u8BA1\u8BB0\u5F55\u5E94\u5305\u62EC\u4E8B\u4EF6\u7684\u65E5\u671F\u548C\u65F6\u95F4\u3001\u7528\u6237\u3001\u4E8B\u4EF6\u7C7B\u578B\u3001\u4E8B\u4EF6\u662F\u5426\u6210\u529F\u53CA\u5176\u4ED6\u4E0E\u5BA1\u8BA1\u76F8\u5173\u7684\u4FE1\u606F",
    requirementEn: "The audit record should include the event date and time, user, event type, success or failure of the event, and other audit-related information",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudTrail"
  },
  {
    id: "L3-ABS1-18",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u5BF9\u5BA1\u8BA1\u8BB0\u5F55\u8FDB\u884C\u4FDD\u62A4\uFF0C\u5B9A\u671F\u5907\u4EFD\uFF0C\u907F\u514D\u53D7\u5230\u672A\u9884\u671F\u7684\u5220\u9664\u3001\u4FEE\u6539\u6216\u8986\u76D6\u7B49",
    requirementEn: "Audit records should be protected and backed up regularly to avoid unintended deletions, modifications or overwrites.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudTrail"
  },
  {
    id: "L3-ABS1-19",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u80FD\u5BF9\u8FDC\u7A0B\u8BBF\u95EE\u7684\u7528\u6237\u884C\u4E3A\u3001\u8BBF\u95EE\u4E92\u8054\u7F51\u7684\u7528\u6237\u884C\u4E3A\u7B49\u5355\u72EC\u8FDB\u884C\u884C\u4E3A\u5BA1\u8BA1\u548C\u6570\u636E\u5206\u6790",
    requirementEn: "It should be possible to conduct separate behavioral audits and data analysis on user behaviors of remote access, user behaviors of accessing the Internet, and so on.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. CloudTraiil\n2. S3\u548CALB Access Logs\n3.\u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\u6216\u8005\u4E0A\u7F51\u884C\u4E3A\u7BA1\u7406\u4EA7\u54C1"
  },
  {
    id: "L3-ABS1-20",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u53EF\u4FE1\u9A8C\u8BC1",
    controlEn: "Trusted Verification",
    requirementCn: "\u53EF\u57FA\u4E8E\u53EF\u4FE1\u6839\u5BF9\u8FB9\u754C\u8BBE\u5907\u7684\u7CFB\u7EDF\u5F15\u5BFC\u7A0B\u5E8F\u3001\u7CFB\u7EDF\u7A0B\u5E8F\u3001\u91CD\u8981\u914D\u7F6E\u53C2\u6570\u548C\u8FB9\u754C\u9632\u62A4\u5E94\u7528\u7A0B\u5E8F\u7B49\u8FDB\u884C\u53EF\u4FE1\u9A8C\u8BC1\uFF0C\u5E76\u5728\u5E94\u7528\u7A0B\u5E8F\u7684\u5173\u952E\u6267\u884C\u73AF\u8282\u8FDB\u884C\u52A8\u6001\u53EF\u4FE1\u9A8C\u8BC1\uFF0C\u5728\u68C0\u6D4B\u5230\u5176\u53EF\u4FE1\u6027\u53D7\u5230\u7834\u574F\u540E\u8FDB\u884C\u62A5\u8B66\uFF0C \u5E76\u5C06\u9A8C\u8BC1\u7ED3\u679C\u5F62\u6210\u5BA1\u8BA1\u8BB0\u5F55\u9001\u81F3\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    requirementEn: "Trusted verification, based on the trusted root, can be applied to system boot program, system program, important configuration parameters, and network border protection applications of the network border devices, and dynamic trusted verification can be used in the key execution of the application, and when detecting the credibility thereof. After being damaged, an alarm is issued, and after detecting that its credibility has been damaged, an alarm should be issued and the verification result should be sent to the Security Management Center.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES1-01",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8EAB\u4EFD\u9274\u522B",
    controlEn: "Identification and Authentication",
    requirementCn: "\u5E94\u5BF9\u767B\u5F55\u7684\u7528\u6237\u8FDB\u884C\u8EAB\u4EFD\u6807\u8BC6\u548C\u9274\u522B\uFF0C\u8EAB\u4EFD\u6807\u8BC6\u5177\u6709\u552F\u4E00\u6027\uFF0C\u8EAB\u4EFD\u9274\u522B\u4FE1\u606F\u5177\u6709\u590D\u6742\u5EA6\u8981\u6C42\u5E76\u5B9A\u671F\u66F4\u6362",
    requirementEn: "The logged-in user should be identified and authenticated. And the identity shall be unique. The identity authentication information should have complexity requirements and be replaced periodically.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-CES1-02",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8EAB\u4EFD\u9274\u522B",
    controlEn: "Identification and Authentication",
    requirementCn: "\u5E94\u5177\u6709\u767B\u5F55\u5931\u8D25\u5904\u7406\u529F\u80FD\uFF0C\u5E94\u914D\u7F6E\u5E76\u542F\u7528\u7ED3\u675F\u4F1A\u8BDD\u3001\u9650\u5236\u975E\u6CD5\u767B\u5F55\u6B21\u6570\u548C\u5F53\u767B\u5F55\u8FDE\u63A5\u8D85\u65F6\u81EA\u52A8\u9000\u51FA\u7B49\u76F8\u5173\u63AA\u65BD",
    requirementEn: "It should have the login failure processing function, and configure and enable the functions of end session, limit the number of illegal logins, and automatically exit when the login connection times out",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u7B2C\u4E09\u65B9\u7684\u5821\u5792\u673A\n2.AWS\u5E73\u53F0\u53EF\u8003\u8651\u57FA\u4E8ECLoudTrail\u65E5\u5FD7+Cloudwatch Alarm + Lambda\u5B9E\u73B0"
  },
  {
    id: "L3-CES1-03",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8EAB\u4EFD\u9274\u522B",
    controlEn: "Identification and Authentication",
    requirementCn: "\u5F53\u8FDB\u884C\u8FDC\u7A0B\u7BA1\u7406\u65F6\uFF0C\u5E94\u91C7\u53D6\u5FC5\u8981\u63AA\u65BD\u9632\u6B62\u9274\u522B\u4FE1\u606F\u5728\u7F51\u7EDC\u4F20\u8F93\u8FC7\u7A0B\u4E2D\u88AB\u7A83\u542C",
    requirementEn: "Necessary measures should be taken to prevent the authentication information from being eavesdropped during network transmission when performing remote management.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u542F\u7528\u4F20\u8F93\u5C42\u52A0\u5BC6\n2. \u5229\u7528SSH\u548C\u52A0\u5BC6\u7684RDP\u8FDB\u884C\u8BBF\u95EEEC2"
  },
  {
    id: "L3-CES1-04",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8EAB\u4EFD\u9274\u522B",
    controlEn: "Identification and Authentication",
    requirementCn: "\u5E94\u91C7\u7528\u53E3\u4EE4\u3001\u5BC6\u7801\u6280\u672F\u3001\u751F\u7269\u6280\u672F\u7B49\u4E24\u79CD\u6216\u4E24\u79CD\u4EE5\u4E0A\u7EC4\u5408\u7684\u9274\u522B\u6280\u672F\u5BF9\u7528\u6237\u8FDB\u884C\u8EAB\u4EFD\u9274\u522B\uFF0C \u4E14\u5176\u4E2D\u4E00\u79CD\u9274\u522B\u6280\u672F\u81F3\u5C11\u5E94\u4F7F\u7528\u5BC6\u7801\u6280\u672F\u6765\u5B9E\u73B0",
    requirementEn: "Two or more authentication technologies, e.g. password, cryptography, biotechnology and etc., should be used to identify users, and at least one of them should be implemented by cryptography.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u542F\u7528MFA"
  },
  {
    id: "L3-CES1-05",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5BF9\u767B\u5F55\u7684\u7528\u6237\u5206\u914D\u8D26\u53F7\u548C\u6743\u9650",
    requirementEn: "Accounts and permissions should be assigned to the logged in user",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: '"1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"'
  },
  {
    id: "L3-CES1-06",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u91CD\u547D\u540D\u6216\u5220\u9664\u9ED8\u8BA4\u8D26\u6237\uFF0C\u4FEE\u6539\u9ED8\u8BA4\u8D26\u6237\u7684\u9ED8\u8BA4\u53E3\u4EE4",
    requirementEn: "The default account should be renamed or deleted, and the default password of the default account should be changed.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u7BA1\u7406\u6D41\u7A0B"
  },
  {
    id: "L3-CES1-07",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u53CA\u65F6\u5220\u9664\u6216\u505C\u7528\u591A\u4F59\u7684\u3001\u8FC7\u671F\u7684\u8D26\u53F7\uFF0C\u907F\u514D\u5171\u4EAB\u8D26\u53F7\u7684\u5B58\u5728",
    requirementEn: "The redundant and expired accounts should be deleted or deactivated in time and share accounts is not allowed",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-CES1-08",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u6388\u4E88\u7BA1\u7406\u7528\u6237\u6240\u9700\u7684\u6700\u5C0F\u6743\u9650\uFF0C\u5B9E\u73B0\u7BA1\u7406\u7528\u6237\u7684\u6743\u9650\u5206\u79BB",
    requirementEn: "Administrator access should be reduced to an absolute minimum to achieve separation of administrator privileges",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-CES1-09",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u7531\u6388\u6743\u4E3B\u4F53\u914D\u7F6E\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\uFF0C\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\u89C4\u5B9A\u4E3B\u4F53\u5BF9\u5BA2\u4F53\u7684\u8BBF\u95EE\u89C4\u5219",
    requirementEn: "The access control policy should be configured by the authorized subject, and the access control policy stipulates the access rules of the subject to the object",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u652F\u6301\u57FA\u4E8E\u4EBA\u5458\u548C\u57FA\u4E8E\u8D44\u6E90\u7684\u6743\u9650\u5206\u914D"
  },
  {
    id: "L3-CES1-10",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u8BBF\u95EE\u63A7\u5236\u7684\u7C92\u5EA6\u5E94\u8FBE\u5230\u4E3B\u4F53\u4E3A\u7528\u6237\u7EA7\u6216\u8FDB\u7A0B\u7EA7\uFF0C\u5BA2\u4F53\u4E3A\u6587\u4EF6\u3001\u6570\u636E\u5E93\u8868\u7EA7",
    requirementEn: "The granularity of access control should be at the user level or process level, and the object is at the file and database table level",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-CES1-11",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5BF9\u654F\u611F\u4FE1\u606F\u8D44\u6E90\u8BBE\u7F6E\u5B89\u5168\u6807\u8BB0\uFF0C\u5E76\u63A7\u5236\u4E3B\u4F53\u5BF9\u6709\u5B89\u5168\u6807\u8BB0\u4FE1\u606F\u8D44\u6E90\u7684\u8BBF\u95EE",
    requirementEn: "Set security tokens for sensitive information resources and control the subject's access to resources with security-tagged information.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "\u9700\u8981\u5E94\u7528\u5C42\u9762\u5148\u8FDB\u884C\u654F\u611F\u4FE1\u606F\u7684\u5206\u7C7B\uFF0C\u7136\u540E\u5229\u7528Tag\u6216\u8005Metadata\u5BF9\u6570\u636E\u8FDB\u884C\u6807\u8BB0\uFF0C\u7136\u540E\u5229\u7528\u63A7\u5236\u8BBF\u95EE\u7B56\u7565\u8FDB\u884C\u7BA1\u63A7"
  },
  {
    id: "L3-CES1-12",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u542F\u7528\u5B89\u5168\u5BA1\u8BA1\u529F\u80FD\uFF0C\u5BA1\u8BA1\u8986\u76D6\u5230\u6BCF\u4E2A\u7528\u6237\uFF0C\u5BF9\u91CD\u8981\u7684\u7528\u6237\u884C\u4E3A\u548C\u91CD\u8981\u5B89\u5168\u4E8B\u4EF6\u8FDB\u884C\u5BA1\u8BA1",
    requirementEn: "Security auditing should be enabled, and covers each user, important user behaviors and security incidents",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. CloudTrail \n2. CloudWatch\n3. AWS Config \u6216\u8005 Palo Alto\u7684Prisma Cloud"
  },
  {
    id: "L3-CES1-13",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5BA1\u8BA1\u8BB0\u5F55\u5E94\u5305\u62EC\u4E8B\u4EF6\u7684\u65E5\u671F\u548C\u65F6\u95F4\u3001\u7528\u6237\u3001\u4E8B\u4EF6\u7C7B\u578B\u3001\u4E8B\u4EF6\u662F\u5426\u6210\u529F\u53CA\u5176\u4ED6\u4E0E\u5BA1\u8BA1\u76F8\u5173\u7684\u4FE1\u606F",
    requirementEn: "The audit record should include the event date and time, user, event type, success or failure of the event, and other audit-related information",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. CloudTrail \n2. CloudWatch\n3. AWS Config \u6216\u8005 Palo Alto\u7684Prisma Cloud"
  },
  {
    id: "L3-CES1-14",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u5BF9\u5BA1\u8BA1\u8BB0\u5F55\u8FDB\u884C\u4FDD\u62A4\uFF0C\u5B9A\u671F\u5907\u4EFD\uFF0C\u907F\u514D\u53D7\u5230\u672A\u9884\u671F\u7684\u5220\u9664\u3001\u4FEE\u6539\u6216\u8986\u76D6\u7B49",
    requirementEn: "Audit records should be protected and backed up regularly to avoid unintended deletions, modifications or overwrites.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. CloudTrail \n2. CloudWatch\n3. AWS Config \u6216\u8005 Palo Alto\u7684Prisma Cloud"
  },
  {
    id: "L3-CES1-15",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u5BF9\u5BA1\u8BA1\u8FDB\u7A0B\u8FDB\u884C\u4FDD\u62A4\uFF0C\u9632\u6B62\u672A\u7ECF\u6388\u6743\u7684\u4E2D\u65AD",
    requirementEn: "The audit record time shall be synchronized with an accurate time source within the system to ensure the correctness of the audit analysis.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. CloudTrail \n2. CloudWatch\n3. AWS Config \u6216\u8005 Palo Alto\u7684Prisma Cloud"
  },
  {
    id: "L3-CES1-17",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u9075\u5FAA\u6700\u5C0F\u5B89\u88C5\u7684\u539F\u5219\uFF0C\u4EC5\u5B89\u88C5\u9700\u8981\u7684\u7EC4\u4EF6\u548C\u5E94\u7528\u7A0B\u5E8F",
    requirementEn: "Follow the principle of minimum installation, and install only the required components and applications.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-CES1-18",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u5173\u95ED\u4E0D\u9700\u8981\u7684\u7CFB\u7EDF\u670D\u52A1\u3001\u9ED8\u8BA4\u5171\u4EAB\u548C\u9AD8\u5371\u7AEF\u53E3",
    requirementEn: "Unneeded system services, default shares, and high-risk ports should be turned off",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-CES1-19",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u901A\u8FC7\u8BBE\u5B9A\u7EC8\u7AEF\u63A5\u5165\u65B9\u5F0F\u6216\u7F51\u7EDC\u5730\u5740\u8303\u56F4\u5BF9\u901A\u8FC7\u7F51\u7EDC\u8FDB\u884C\u7BA1\u7406\u7684\u7BA1\u7406\u7EC8\u7AEF\u8FDB\u884C\u9650\u5236",
    requirementEn: "The management terminal managed through the network should be restricted by setting the terminal access mode or network address range",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: '1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-CES1-20",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u63D0\u4F9B\u6570\u636E\u6709\u6548\u6027\u68C0\u9A8C\u529F\u80FD\uFF0C\u4FDD\u8BC1\u901A\u8FC7\u4EBA\u673A\u63A5\u53E3\u8F93\u5165\u6216\u901A\u8FC7\u901A\u4FE1\u63A5\u53E3\u8F93\u5165\u7684\u5185\u5BB9\u7B26\u5408\u7CFB\u7EDF\u8BBE\u5B9A\u8981\u6C42",
    requirementEn: "The data validity check function shall be provided to ensure that the content input through the human machine interface or input through the communication interface complies with the system setting requirements",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '"1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-CES1-21",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u53D1\u73B0\u53EF\u80FD\u5B58\u5728\u7684\u6F0F\u6D1E\uFF0C\u5E76\u5728\u7ECF\u8FC7\u5145\u5206\u6D4B\u8BD5\u8BC4\u4F30\u540E\uFF0C\u53CA\u65F6\u4FEE\u8865\u6F0F\u6D1E",
    requirementEn: "It should be able to identify possible vulnerabilities and fix the vulnerabilities in time after thorough testing and evaluation",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '1. \u542F\u7528WAF\n2. \u542F\u7528GuardDuty\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n4. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-CES1-22",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u68C0\u6D4B\u5230\u5BF9\u91CD\u8981\u8282\u70B9\u8FDB\u884C\u5165\u4FB5\u7684\u884C\u4E3A\uFF0C\u5E76\u5728\u53D1\u751F\u4E25\u91CD\u5165\u4FB5\u4E8B\u4EF6\u65F6\u63D0\u4F9B\u62A5\u8B66",
    requirementEn: "It should be able to detect intrusions on important nodes and alert when there is serious intrusion.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u542F\u7528WAF\n2. \u542F\u7528GuardDuty\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n4. \u64CD\u4F5C\u7CFB\u7EDF\u5C42\u5B89\u88C5\u7B2C\u4E09\u65B9\u5B89\u5168\u9632\u62A4\u8F6F\u4EF6"
  },
  {
    id: "L3-CES1-23",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6076\u610F\u4EE3\u7801\u9632\u8303",
    controlEn: "Malicious Code Prevention",
    requirementCn: "\u5E94\u91C7\u7528\u514D\u53D7\u6076\u610F\u4EE3\u7801\u653B\u51FB\u7684\u6280\u672F\u63AA\u65BD\u6216\u4E3B\u52A8\u514D\u75AB\u53EF\u4FE1\u9A8C\u8BC1\u673A\u5236\u53CA\u65F6\u8BC6\u522B\u5165\u4FB5\u548C\u75C5\u6BD2\u884C\u4E3A\uFF0C\u5E76\u5C06\u5176\u6709\u6548\u963B\u65AD",
    requirementEn: "Intrusion and virus behavior should be identified and effectively blocked by technical measures against malicious code attacks or active immune trusted authentication mechanisms.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u542F\u7528WAF\n2. \u542F\u7528GuardDuty\n3. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n4. \u64CD\u4F5C\u7CFB\u7EDF\u5C42\u5B89\u88C5\u7B2C\u4E09\u65B9\u6740\u6BD2\u4EA7\u54C1"
  },
  {
    id: "L3-CES1-24",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u53EF\u4FE1\u9A8C\u8BC1",
    controlEn: "Trusted Verification",
    requirementCn: "\u53EF\u57FA\u4E8E\u53EF\u4FE1\u6839\u5BF9\u8BA1\u7B97\u8BBE\u5907\u7684\u7CFB\u7EDF\u5F15\u5BFC\u7A0B\u5E8F\u3001\u7CFB\u7EDF\u7A0B\u5E8F\u3001\u91CD\u8981\u914D\u7F6E\u53C2\u6570\u548C\u5E94\u7528\u7A0B\u5E8F\u7B49\u8FDB\u884C\u53EF\u4FE1\u9A8C\u8BC1\uFF0C \u5E76\u5728\u5E94\u7528\u7A0B\u5E8F\u7684\u5173\u952E\u6267\u884C\u73AF\u8282\u8FDB\u884C\u52A8\u6001\u53EF\u4FE1\u9A8C\u8BC1\uFF0C\u5728\u68C0\u6D4B\u5230\u5176\u53EF\u4FE1\u6027\u53D7\u5230\u7834\u574F\u540E\u8FDB\u884C\u62A5\u8B66\uFF0C\u5E76\u5C06\u9A8C\u8BC1 \u7ED3\u679C\u5F62\u6210\u5BA1\u8BA1\u8BB0\u5F55\u9001\u81F3\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    requirementEn: "Trusted verification, based on the trusted root, can be applied to system boot program, system program, important configuration parameters, and applications of the computing devices, and dynamic trusted verification can be used in the key execution of the application, and when detecting the credibility thereof. After being damaged, an alarm is issued, and after detecting that its credibility has been damaged, an alarm should be issued and the verification result should be sent to the Security Management Center.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES1-25",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027",
    controlEn: "Data Confidentiality",
    requirementCn: "\u5E94\u91C7\u7528\u6821\u9A8C\u6280\u672F\u6216\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u91CD\u8981\u6570\u636E\u5728\u4F20\u8F93\u8FC7\u7A0B\u4E2D\u7684\u5B8C\u6574\u6027\uFF0C\u5305\u62EC\u4F46\u4E0D\u9650\u4E8E\u9274\u522B\u6570\u636E\u3001\u91CD\u8981\u4E1A\u52A1\u6570\u636E\u3001\u91CD\u8981\u5BA1\u8BA1\u6570\u636E\u3001\u91CD\u8981\u914D\u7F6E\u6570\u636E\u3001\u91CD\u8981\u89C6\u9891\u6570\u636E\u548C\u91CD\u8981\u4E2A\u4EBA\u4FE1\u606F\u7B49",
    requirementEn: "Verification techniques or cryptographic techniques should be used to ensure the integrity of important data during transmission, including but not limited to authentication data, important business data, important audit data, important configuration data, important video data and important personal information",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u542F\u7528\u4F20\u8F93\u52A0\u5BC6\uFF0C\u5E76\u4E14\u53EF\u4EE5\u5229\u7528Amazon ACM\u7BA1\u7406\u5BC6\u94A5\n2. S3 \u4F1A\u9A8C\u8BC1\u5DF2\u4E0A\u4F20\u5BF9\u8C61\u7684\u5B8C\u6574\u6027\n3. \u6309\u7167\u7B2C\u4E09\u65B9\u9632\u7BE1\u6539\u8F6F\u4EF6"
  },
  {
    id: "L3-CES1-26",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027",
    controlEn: "Data Confidentiality",
    requirementCn: "\u5E94\u91C7\u7528\u6821\u9A8C\u6280\u672F\u6216\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u91CD\u8981\u6570\u636E\u5728\u5B58\u50A8\u8FC7\u7A0B\u4E2D\u7684\u5B8C\u6574\u6027\uFF0C\u5305\u62EC\u4F46\u4E0D\u9650\u4E8E\u9274\u522B\u6570\u636E\u3001\u91CD\u8981\u4E1A\u52A1\u6570\u636E\u3001\u91CD\u8981\u5BA1\u8BA1\u6570\u636E\u3001\u91CD\u8981\u914D\u7F6E\u6570\u636E\u3001\u91CD\u8981\u89C6\u9891\u6570\u636E\u548C\u91CD\u8981\u4E2A\u4EBA\u4FE1\u606F\u7B49",
    requirementEn: "Verification techniques or cryptographic techniques should be used to ensure the integrity of important data when stored including but not limited to authentication data, important business data, important audit data, important configuration data, important video data and important personal information",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u542F\u7528\u4F20\u8F93\u52A0\u5BC6\uFF0C\u5E76\u4E14\u53EF\u4EE5\u5229\u7528Amazon ACM\u7BA1\u7406\u5BC6\u94A5\n2. S3 \u4F1A\u9A8C\u8BC1\u5DF2\u4E0A\u4F20\u5BF9\u8C61\u7684\u5B8C\u6574\u6027\n3. \u6309\u7167\u7B2C\u4E09\u65B9\u9632\u7BE1\u6539\u8F6F\u4EF6"
  },
  {
    id: "L3-CES1-27",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity",
    requirementCn: "\u5E94\u91C7\u7528\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u91CD\u8981\u6570\u636E\u5728\u4F20\u8F93\u8FC7\u7A0B\u4E2D\u7684\u4FDD\u5BC6\u6027\uFF0C\u5305\u62EC\u4F46\u4E0D\u9650\u4E8E\u9274\u522B\u6570\u636E\u3001\u91CD\u8981\u4E1A\u52A1\u6570\u636E\u548C\u91CD\u8981\u4E2A\u4EBA\u4FE1\u606F\u7B49",
    requirementEn: "Cryptographic technology should be used to ensure the confidentiality of important data during transmission, including but not limited to authentication data, important business data and important personal information",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u542F\u7528KMS"
  },
  {
    id: "L3-CES1-28",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity",
    requirementCn: "\u5E94\u91C7\u7528\u5BC6\u7801\u6280\u672F\u4FDD\u8BC1\u91CD\u8981\u6570\u636E\u5728\u5B58\u50A8\u8FC7\u7A0B\u4E2D\u7684\u4FDD\u5BC6\u6027\uFF0C\u5305\u62EC\u4F46\u4E0D\u9650\u4E8E\u9274\u522B\u6570\u636E\u3001\u91CD\u8981\u4E1A\u52A1\u6570\u636E\u548C\u91CD\u8981\u4E2A\u4EBA\u4FE1\u606F\u7B49",
    requirementEn: "Cryptographic technology should be used to ensure the confidentiality of important data when stored, including but not limited to authentication data, important business data and important personal information",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u542F\u7528KMS"
  },
  {
    id: "L3-CES1-29",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u5E94\u63D0\u4F9B\u91CD\u8981\u6570\u636E\u7684\u672C\u5730\u6570\u636E\u5907\u4EFD\u4E0E\u6062\u590D\u529F\u80FD",
    requirementEn: "Local data backup and recovery functions for important data should be provided",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u5B58\u50A8\u670D\u52A1\u539F\u751F\u652F\u6301\u591A\u526F\u672C\uFF0C\u5BA2\u6237\u53EF\u4EE5\u901A\u8FC7\u5FEB\u7167\u7684\u65B9\u5F0F\u5BF9\u6570\u636E\u8FDB\u884C\u989D\u5916\u5907\u4EFD\n2. \u5229\u7528AWS Backup \u4E2D\u5FC3\u5316\u7BA1\u7406\u5907\u4EFD\u7684\u5DE5\u5177\u3002\u4E5F\u53EF\u4EE5\u4F7F\u7528AWS\u5404\u670D\u52A1\u4E2D\u76F8\u5E94\u7684\u5907\u4EFD\u529F\u80FD\uFF0C\u5355\u72EC\u7BA1\u7406"
  },
  {
    id: "L3-CES1-30",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u5E94\u63D0\u4F9B\u5F02\u5730\u5B9E\u65F6\u5907\u4EFD\u529F\u80FD\uFF0C\u5229\u7528\u901A\u4FE1\u7F51\u7EDC\u5C06\u91CD\u8981\u6570\u636E\u5B9E\u65F6\u5907\u4EFD\u81F3\u5907\u4EFD\u573A\u5730",
    requirementEn: "Remote real-time backup function should be provided, and use the communication network to back up important data to the backup site in real time",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. \u5B58\u50A8\u670D\u52A1\u539F\u751F\u652F\u6301\u591A\u526F\u672C\uFF0C\u5BA2\u6237\u53EF\u4EE5\u901A\u8FC7\u5FEB\u7167\u7684\u65B9\u5F0F\u5BF9\u6570\u636E\u8FDB\u884C\u989D\u5916\u5907\u4EFD\n2. \u5229\u7528AWS Backup \u4E2D\u5FC3\u5316\u7BA1\u7406\u5907\u4EFD\u7684\u5DE5\u5177\u3002\u4E5F\u53EF\u4EE5\u4F7F\u7528AWS\u5404\u670D\u52A1\u4E2D\u76F8\u5E94\u7684\u5907\u4EFD\u529F\u80FD\uFF0C\u5355\u72EC\u7BA1\u7406\n3. \u914D\u7F6E\u5FEB\u7167\u548CS3\u8DE8\u533A\u57DF\u6570\u636E\u590D\u5236"
  },
  {
    id: "L3-CES1-31",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u5E94\u63D0\u4F9B\u91CD\u8981\u6570\u636E\u5904\u7406\u7CFB\u7EDF\u7684\u70ED\u5197\u4F59\uFF0C\u4FDD\u8BC1\u7CFB\u7EDF\u7684\u9AD8\u53EF\u7528\u6027",
    requirementEn: "Redundancy of critical data processing systems should be provided to ensure high system availability.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: '"1. \u5B58\u50A8\u670D\u52A1\u539F\u751F\u652F\u6301\u591A\u526F\u672C\uFF0C\u5BA2\u6237\u53EF\u4EE5\u901A\u8FC7\u5FEB\u7167\u7684\u65B9\u5F0F\u5BF9\u6570\u636E\u8FDB\u884C\u989D\u5916\u5907\u4EFD\n2. \u5229\u7528AWS Backup \u4E2D\u5FC3\u5316\u7BA1\u7406\u5907\u4EFD\u7684\u5DE5\u5177\u3002\u4E5F\u53EF\u4EE5\u4F7F\u7528AWS\u5404\u670D\u52A1\u4E2D\u76F8\u5E94\u7684\u5907\u4EFD\u529F\u80FD\uFF0C\u5355\u72EC\u7BA1\u7406"'
  },
  {
    id: "L3-CES1-32",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5269\u4F59\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Residual Information Protection",
    requirementCn: "\u5E94\u4FDD\u8BC1\u9274\u522B\u4FE1\u606F\u6240\u5728\u7684\u5B58\u50A8\u7A7A\u95F4\u88AB\u91CA\u653E\u6216\u91CD\u65B0\u5206\u914D\u524D\u5F97\u5230\u5B8C\u5168\u6E05\u9664",
    requirementEn: "Ensure that the storage space where the authentication information is located is completely cleared before being released or redistributed",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. AWS \u5B58\u50A8\u670D\u52A1\u7684\u6570\u636E\u6E05\u9664\u7B56\u7565\u5728\u7B49\u4FDD\u4E91\u6269\u5C55\u8981\u6C42\u4E2D\u8986\u76D6"
  },
  {
    id: "L3-CES1-33",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5269\u4F59\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Residual Information Protection",
    requirementCn: "\u5E94\u4FDD\u8BC1\u5B58\u6709\u654F\u611F\u6570\u636E\u7684\u5B58\u50A8\u7A7A\u95F4\u88AB\u91CA\u653E\u6216\u91CD\u65B0\u5206\u914D\u524D\u5F97\u5230\u5B8C\u5168\u6E05\u9664",
    requirementEn: "Ensure that the storage space containing sensitive data is completely cleared before being released or redistributed.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. AWS \u5B58\u50A8\u670D\u52A1\u7684\u6570\u636E\u6E05\u9664\u7B56\u7565\u5728\u7B49\u4FDD\u4E91\u6269\u5C55\u8981\u6C42\u4E2D\u8986\u76D6"
  },
  {
    id: "L3-CES1-34",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u4E2A\u4EBA\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Personal Information Protection",
    requirementCn: "\u5E94\u4EC5\u91C7\u96C6\u548C\u4FDD\u5B58\u4E1A\u52A1\u5FC5\u9700\u7684\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F",
    requirementEn: "Only personal information necessary for the business should be collected and stored",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5E94\u7528\u4FA7\u884C\u4E3A\uFF0CAWS\u4E0D\u4E3B\u52A8\u91C7\u96C6\u548C\u4FDD\u5B58\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F"
  },
  {
    id: "L3-CES1-35",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u4E2A\u4EBA\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Personal Information Protection",
    requirementCn: "\u5E94\u7981\u6B62\u672A\u6388\u6743\u8BBF\u95EE\u548C\u975E\u6CD5\u4F7F\u7528\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F",
    requirementEn: "Unauthorized access and illegal use of user's personal information should be prohibited.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5E94\u7528\u4FA7\u884C\u4E3A\uFF0CAWS\u4E0D\u4E3B\u52A8\u91C7\u96C6\u548C\u4FDD\u5B58\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F"
  },
  {
    id: "L3-SMC1-01",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u7CFB\u7EDF\u7BA1\u7406",
    controlEn: "System Management",
    requirementCn: "\u5E94\u5BF9\u7CFB\u7EDF\u7BA1\u7406\u5458\u8FDB\u884C\u8EAB\u4EFD\u9274\u522B\uFF0C\u53EA\u5141\u8BB8\u5176\u901A\u8FC7\u7279\u5B9A\u7684\u547D\u4EE4\u6216\u64CD\u4F5C\u754C\u9762\u8FDB\u884C\u7CFB\u7EDF\u7BA1\u7406\u64CD\u4F5C\uFF0C\u5E76\u5BF9\u8FD9\u4E9B\u64CD\u4F5C\u8FDB\u884C\u5BA1\u8BA1",
    requirementEn: "The system administrator should be authenticated and only allowed to perform system management operations through specific commands or operation interfaces. These operations need to be audited",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-02",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u7CFB\u7EDF\u7BA1\u7406",
    controlEn: "System Management",
    requirementCn: "\u5E94\u901A\u8FC7\u7CFB\u7EDF\u7BA1\u7406\u5458\u5BF9\u7CFB\u7EDF\u7684\u8D44\u6E90\u548C\u8FD0\u884C\u8FDB\u884C\u914D\u7F6E\u3001\u63A7\u5236\u548C\u7BA1\u7406\uFF0C\u5305\u62EC\u7528\u6237\u8EAB\u4EFD\u3001\u7CFB\u7EDF\u8D44\u6E90\u914D\u7F6E\u3001\u7CFB\u7EDF\u52A0\u8F7D\u548C\u542F\u52A8\u3001\u7CFB\u7EDF\u8FD0\u884C\u7684\u5F02\u5E38\u5904\u7406\u3001\u6570\u636E\u548C\u8BBE\u5907\u7684\u5907\u4EFD\u4E0E\u6062\u590D\u7B49",
    requirementEn: "The configuration, control, and management of system resources and operations should be performed by system administrators, including user identity, system resource configuration, system loading and startup, system operation exception handling, data and device backup and recovery.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-03",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u5BA1\u8BA1\u7BA1\u7406",
    controlEn: "Audit Management",
    requirementCn: "\u5E94\u5BF9\u5BA1\u8BA1\u7BA1\u7406\u5458\u8FDB\u884C\u8EAB\u4EFD\u9274\u522B\uFF0C\u53EA\u5141\u8BB8\u5176\u901A\u8FC7\u7279\u5B9A\u7684\u547D\u4EE4\u6216\u64CD\u4F5C\u754C\u9762\u8FDB\u884C\u5B89\u5168\u5BA1\u8BA1\u64CD\u4F5C\uFF0C\u5E76\u5BF9\u8FD9\u4E9B\u64CD\u4F5C\u8FDB\u884C\u5BA1\u8BA1",
    requirementEn: "The audit administrator should be authenticated and only allowed to perform security audit operations through specific commands or operation interfaces. These operations need to be audited",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-04",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u5BA1\u8BA1\u7BA1\u7406",
    controlEn: "Audit Management",
    requirementCn: "\u5E94\u901A\u8FC7\u5BA1\u8BA1\u7BA1\u7406\u5458\u5BF9\u5BA1\u8BA1\u8BB0\u5F55\u5E94\u8FDB\u884C\u5206\u6790\uFF0C\u5E76\u6839\u636E\u5206\u6790\u7ED3\u679C\u8FDB\u884C\u5904\u7406\uFF0C\u5305\u62EC\u6839\u636E\u5B89\u5168\u5BA1\u8BA1\u7B56\u7565\u5BF9\u5BA1\u8BA1\u8BB0\u5F55\u8FDB\u884C\u5B58\u50A8\u3001\u7BA1\u7406\u548C\u67E5\u8BE2\u7B49",
    requirementEn: "The audit administrator should analyze the audit records and dispose them according to the analysis results. The disposals include storage, management and query of the audit records according to the security audit policy.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-05",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u5B89\u5168\u7BA1\u7406",
    controlEn: "Security Management",
    requirementCn: "\u5E94\u5BF9\u5B89\u5168\u7BA1\u7406\u5458\u8FDB\u884C\u8EAB\u4EFD\u9274\u522B\uFF0C\u53EA\u5141\u8BB8\u5176\u901A\u8FC7\u7279\u5B9A\u7684\u547D\u4EE4\u6216\u64CD\u4F5C\u754C\u9762\u8FDB\u884C\u5B89\u5168\u7BA1\u7406\u64CD\u4F5C\uFF0C\u5E76\u5BF9\u8FD9\u4E9B\u64CD\u4F5C\u8FDB\u884C\u5BA1\u8BA1",
    requirementEn: "The security administrator should be authenticated and only allowed to perform security management operations through specific commands or operation interfaces. These operations need to be audited",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-06",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u5B89\u5168\u7BA1\u7406",
    controlEn: "Security Management",
    requirementCn: "\u5E94\u901A\u8FC7\u5B89\u5168\u7BA1\u7406\u5458\u5BF9\u7CFB\u7EDF\u4E2D\u7684\u5B89\u5168\u7B56\u7565\u8FDB\u884C\u914D\u7F6E\uFF0C\u5305\u62EC\u5B89\u5168\u53C2\u6570\u7684\u8BBE\u7F6E\uFF0C\u4E3B\u4F53\u3001\u5BA2\u4F53\u8FDB\u884C\u7EDF\u4E00\u5B89\u5168\u6807\u8BB0\uFF0C\u5BF9\u4E3B\u4F53\u8FDB\u884C\u6388\u6743\uFF0C\u914D\u7F6E\u53EF\u4FE1\u9A8C\u8BC1\u7B56\u7565\u7B49",
    requirementEn: "The security policy should be configured by the security administrator, including the setting of security parameters, the unified security mark of the subject and the object, the authorization and trusted authentication policy configuration of the subject.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09"
  },
  {
    id: "L3-SMC1-07",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u5212\u5206\u51FA\u7279\u5B9A\u7684\u7BA1\u7406\u533A\u57DF\uFF0C\u5BF9\u5206\u5E03\u5728\u7F51\u7EDC\u4E2D\u7684\u5B89\u5168\u8BBE\u5907\u6216\u5B89\u5168\u7EC4\u4EF6\u8FDB\u884C\u7BA1\u63A7",
    requirementEn: "A specific network management area should be divided to control the security devices or security components distributed in the network",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5229\u7528Firewall Manager\u53EF\u4EE5\u5BF9WAF\u8FDB\u884C\u7EDF\u4E00\u7BA1\u7406\nGuardDuty\u53EF\u4EE5\u8DE8\u8D26\u53F7\u7EDF\u4E00\u7BA1\u7406\u5B89\u5168\u53D1\u73B0\nCloudTrail\u53EF\u4EE5\u96C6\u4E2D\u5BF9\u8DE8\u8D26\u53F7\u8FDB\u884C\u5206\u6790\nSecurityHub\u53EF\u4EE5\u8DE8\u8D26\u53F7\u7EDF\u4E00\u8FDB\u884C\u5B89\u5168\u53D1\u73B0"
  },
  {
    id: "L3-SMC1-08",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u80FD\u591F\u5EFA\u7ACB\u4E00\u6761\u5B89\u5168\u7684\u4FE1\u606F\u4F20\u8F93\u8DEF\u5F84\uFF0C\u5BF9\u7F51\u7EDC\u4E2D\u7684\u5B89\u5168\u8BBE\u5907\u6216\u5B89\u5168\u7EC4\u4EF6\u8FDB\u884C\u7BA1\u7406",
    requirementEn: "A secure information transmission channel should be established to manage security devices or security components in the network",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5229\u7528Firewall Manager\u53EF\u4EE5\u5BF9WAF\u8FDB\u884C\u7EDF\u4E00\u7BA1\u7406\nGuardDuty\u53EF\u4EE5\u8DE8\u8D26\u53F7\u7EDF\u4E00\u7BA1\u7406\u5B89\u5168\u53D1\u73B0\nCloudTrail\u53EF\u4EE5\u96C6\u4E2D\u5BF9\u8DE8\u8D26\u53F7\u8FDB\u884C\u5206\u6790\nSecurityHub\u53EF\u4EE5\u8DE8\u8D26\u53F7\u7EDF\u4E00\u8FDB\u884C\u5B89\u5168\u53D1\u73B0"
  },
  {
    id: "L3-SMC1-09",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u5BF9\u7F51\u7EDC\u94FE\u8DEF\u3001\u5B89\u5168\u8BBE\u5907\u3001\u7F51\u7EDC\u8BBE\u5907\u548C\u670D\u52A1\u5668\u7B49\u7684\u8FD0\u884C\u72B6\u51B5\u8FDB\u884C\u96C6\u4E2D\u76D1\u6D4B",
    requirementEn: "Centralized monitoring of network links, security devices, network devices and servers should be carried out.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudWatch\u548CSplunk\u8FDB\u884C\u7EDF\u4E00\u76D1\u6D4B"
  },
  {
    id: "L3-SMC1-10",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u5BF9\u5206\u6563\u5728\u5404\u4E2A\u8BBE\u5907\u4E0A\u7684\u5BA1\u8BA1\u6570\u636E\u8FDB\u884C\u6536\u96C6\u6C47\u603B\u548C\u96C6\u4E2D\u5206\u6790\uFF0C\u5E76\u4FDD\u8BC1\u5BA1\u8BA1\u8BB0\u5F55\u7684\u7559\u5B58\u65F6\u95F4\u7B26\u5408\u6CD5\u5F8B\u6CD5\u89C4\u8981\u6C42",
    requirementEn: "The audit data scattered on various equipment should be collected, summarized and centralized analyzed, and the retention time of audit records should be guaranteed to meet the requirements of laws and regulations.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudTrail"
  },
  {
    id: "L3-SMC1-11",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u5BF9\u5B89\u5168\u7B56\u7565\u3001\u6076\u610F\u4EE3\u7801\u3001\u8865\u4E01\u5347\u7EA7\u7B49\u5B89\u5168\u76F8\u5173\u4E8B\u9879\u8FDB\u884C\u96C6\u4E2D\u7BA1\u7406",
    requirementEn: "Security policy, malicious code, patch upgrade and other security related matters should be centrally managed.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "\u9700\u8981\u7B2C\u4E09\u65B9\u9632\u5165\u4FB5\u548C\u9632\u75C5\u6BD2\u652F\u6301"
  },
  {
    id: "L3-SMC1-12",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u80FD\u5BF9\u7F51\u7EDC\u4E2D\u53D1\u751F\u7684\u5404\u7C7B\u5B89\u5168\u4E8B\u4EF6\u8FDB\u884C\u8BC6\u522B\u3001\u62A5\u8B66\u548C\u5206\u6790",
    requirementEn: "Various types of security incidents occurring in the network can be identified, alerted, and analyzed.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudWatch\u548CSplunk\u8FDB\u884C\u7EDF\u4E00\u62A5\u8B66\u548C\u5206\u6790"
  },
  {
    id: "L3-PES2-01",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u57FA\u7840\u8BBE\u65BD\u4F4D\u7F6E",
    controlEn: "Location of Infrastructure",
    requirementCn: "\u5E94\u4FDD\u8BC1\u4E91\u8BA1\u7B97\u57FA\u7840\u8BBE\u65BD\u4F4D\u4E8E\u4E2D\u56FD\u5883\u5185",
    requirementEn: "Ensure that the cloud computing infrastructure is located in China.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1.\u53C2\u8003\u5B89\u5168\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\n2. AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CNS2-01",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u4FDD\u8BC1\u4E91\u8BA1\u7B97\u5E73\u53F0\u4E0D\u627F\u8F7D\u9AD8\u4E8E\u5176\u5B89\u5168\u4FDD\u62A4\u7B49\u7EA7\u7684\u4E1A\u52A1\u5E94\u7528\u7CFB\u7EDF",
    requirementEn: "Ensure that the cloud computing platform shall not carry business application systems higher than its security protection level.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1.\u53C2\u8003\u5B89\u5168\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\n2. AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CNS2-02",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u5B9E\u73B0\u4E0D\u540C\u4E91\u670D\u52A1\u5BA2\u6237\u865A\u62DF\u7F51\u7EDC\u4E4B\u95F4\u7684\u9694\u79BB",
    requirementEn: "It should implement the independence between different cloud service customer virtual networks.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CNS2-03",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u5177\u6709\u6839\u636E\u4E91\u670D\u52A1\u5BA2\u6237\u4E1A\u52A1\u9700\u6C42\u63D0\u4F9B\u901A\u4FE1\u4F20\u8F93\u3001\u8FB9\u754C\u9632\u62A4\u3001\u5165\u4FB5\u9632\u8303\u7B49\u5B89\u5168\u673A\u5236\u7684\u80FD\u529B",
    requirementEn: "It should have the ability to provide security mechanisms, such as communication transmission, border protection and intrusion prevention, based on the business requirements of cloud service customers.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-CNS2-04",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u5177\u6709\u6839\u636E\u4E91\u670D\u52A1\u5BA2\u6237\u4E1A\u52A1\u9700\u6C42\u81EA\u4E3B\u8BBE\u7F6E\u5B89\u5168\u7B56\u7565\u7684\u80FD\u529B\uFF0C\u5305\u62EC\u5B9A\u4E49\u8BBF\u95EE\u8DEF\u5F84\u3001\u9009\u62E9\u5B89\u5168\u7EC4\u4EF6\u3001\u914D\u7F6E\u5B89\u5168\u7B56\u7565",
    requirementEn: "It should have the ability to independently set security policies based on the business requirements of cloud service customers, including defining access paths, selecting security components and configuring security policies.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CNS2-05",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5E94\u63D0\u4F9B\u5F00\u653E\u63A5\u53E3\u6216\u5F00\u653E\u6027\u5B89\u5168\u670D\u52A1\uFF0C\u5141\u8BB8\u4E91\u670D\u52A1\u5BA2\u6237\u63A5\u5165\u7B2C\u4E09\u65B9\u5B89\u5168\u4EA7\u54C1\u6216\u5728\u4E91\u8BA1\u7B97\u5E73\u53F0\u9009\u62E9\u7B2C\u4E09\u65B9\u5B89\u5168\u670D\u52A1",
    requirementEn: "It should provide open interfaces or open security services to allow cloud service customers to access third-party security products or select third-party security services on cloud computing platforms.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-ABS2-01",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5728\u865A\u62DF\u5316\u7F51\u7EDC\u8FB9\u754C\u90E8\u7F72\u8BBF\u95EE\u63A7\u5236\u673A\u5236\uFF0C\u5E76\u8BBE\u7F6E\u8BBF\u95EE\u63A7\u5236\u89C4\u5219",
    requirementEn: "It should deploy access control mechanisms at the boundaries of the virtualized network and set access control rules.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-ABS2-02",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5728\u4E0D\u540C\u7B49\u7EA7\u7684\u7F51\u7EDC\u533A\u57DF\u8FB9\u754C\u90E8\u7F72\u8BBF\u95EE\u63A7\u5236\u673A\u5236\uFF0C\u8BBE\u7F6E\u8BBF\u95EE\u63A7\u5236\u89C4\u5219",
    requirementEn: "It should deploy access control mechanisms at different levels of network area boundaries and set access control rules.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-ABS2-03",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u68C0\u6D4B\u5230\u4E91\u670D\u52A1\u5BA2\u6237\u53D1\u8D77\u7684\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A\uFF0C\u5E76\u80FD\u8BB0\u5F55\u653B\u51FB\u7C7B\u578B\u3001\u653B\u51FB\u65F6\u95F4\u3001\u653B\u51FB\u6D41\u91CF\u7B49",
    requirementEn: "It should be able to detect the network attack behavior initiated by cloud service customers, and record the attack type, attack time, attack traffic, etc.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"
  },
  {
    id: "L3-ABS2-04",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u68C0\u6D4B\u5230\u5BF9\u865A\u62DF\u7F51\u7EDC\u8282\u70B9\u7684\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A\uFF0C\u5E76\u80FD\u8BB0\u5F55\u653B\u51FB\u7C7B\u578B\u3001\u653B\u51FB\u65F6\u95F4\u3001\u653B\u51FB\u6D41\u91CF\u7B49",
    requirementEn: "It should be able to detect the network attack behavior of virtual network nodes and record the attack type, attack time, attack traffic, etc.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '"1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-ABS2-05",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u68C0\u6D4B\u5230\u865A\u62DF\u673A\u4E0E\u5BBF\u4E3B\u673A\u3001\u865A\u62DF\u673A\u4E0E\u865A\u62DF\u673A\u4E4B\u95F4\u7684\u5F02\u5E38\u6D41\u91CF",
    requirementEn: "It should be able to detect abnormal traffic between virtual machines and hosts, and between virtual machines and virtual machines.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '"1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-ABS2-06",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u5728\u68C0\u6D4B\u5230\u7F51\u7EDC\u653B\u51FB\u884C\u4E3A\u3001\u5F02\u5E38\u6D41\u91CF\u60C5\u51B5\u65F6\u8FDB\u884C\u544A\u8B66",
    requirementEn: "It should give an alarm when network attack and abnormal traffic are detected.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: '"1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u4EA7\u54C1"'
  },
  {
    id: "L3-ABS2-07",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u5BF9\u4E91\u670D\u52A1\u5546\u548C\u4E91\u670D\u52A1\u5BA2\u6237\u5728\u8FDC\u7A0B\u7BA1\u7406\u65F6\u6267\u884C\u7684\u7279\u6743\u547D\u4EE4\u8FDB\u884C\u5BA1\u8BA1\uFF0C\u81F3\u5C11\u5305\u62EC\u865A\u62DF\u673A\u5220\u9664\u3001\u865A\u62DF\u673A\u91CD\u542F",
    requirementEn: "Audit the privileged commands executed by the cloud service provider and cloud service customers while remote administration, including at least virtual machine deletion and virtual machine restart.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudTrail and CloudWatch"
  },
  {
    id: "L3-ABS2-08",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5B89\u5168\u5BA1\u8BA1",
    controlEn: "Security Audit",
    requirementCn: "\u5E94\u4FDD\u8BC1\u4E91\u670D\u52A1\u5546\u5BF9\u4E91\u670D\u52A1\u5BA2\u6237\u7CFB\u7EDF\u548C\u6570\u636E\u7684\u64CD\u4F5C\u53EF\u88AB\u4E91\u670D\u52A1\u5BA2\u6237\u5BA1\u8BA1",
    requirementEn: "Ensure that operations of cloud service providers on cloud service customer systems and data can be audited by cloud service customers.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "CloudTrail"
  },
  {
    id: "L3-CES2-01",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8EAB\u4EFD\u9274\u522B",
    controlEn: "Identification and Authentication",
    requirementCn: "\u5F53\u8FDC\u7A0B\u7BA1\u7406\u4E91\u8BA1\u7B97\u5E73\u53F0\u4E2D\u8BBE\u5907\u65F6\uFF0C\u7BA1\u7406\u7EC8\u7AEF\u548C\u4E91\u8BA1\u7B97\u5E73\u53F0\u4E4B\u95F4\u5E94\u5EFA\u7ACB\u53CC\u5411\u8EAB\u4EFD\u9A8C\u8BC1\u673A\u5236",
    requirementEn: "It should establish a mutual authentication mechanism between the management terminal and the cloud computing platform, when remotely managing devices in a cloud computing platform.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09\n3. \u5229\u7528SSH\u548C\u52A0\u5BC6\u7684RDP\u8FDB\u884C\u8BBF\u95EEEC2\n4. \u5821\u5792\u673A"
  },
  {
    id: "L3-CES2-02",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u4FDD\u8BC1\u5F53\u865A\u62DF\u673A\u8FC1\u79FB\u65F6\uFF0C\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\u968F\u5176\u8FC1\u79FB",
    requirementEn: "Ensure that access control policies migrate with the virtual machine as it migrates.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09\n3. \u5229\u7528SSH\u548C\u52A0\u5BC6\u7684RDP\u8FDB\u884C\u8BBF\u95EEEC2\n4. \u5821\u5792\u673A"
  },
  {
    id: "L3-CES2-03",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5141\u8BB8\u4E91\u670D\u52A1\u5BA2\u6237\u8BBE\u7F6E\u4E0D\u540C\u865A\u62DF\u673A\u4E4B\u95F4\u7684\u8BBF\u95EE\u63A7\u5236\u7B56\u7565",
    requirementEn: "It should allow cloud service customers to set access control policies between different virtual machines.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1. IAM\n2. \u5355\u70B9\u767B\u5F55\uFF08Tesla Bounce\u4EA7\u54C1\u6216\u8005AWS SSO \u670D\u52A1\u5C06\u4E8EQ2,2022\u63A8\u51FA\uFF09\n3. \u5229\u7528SSH\u548C\u52A0\u5BC6\u7684RDP\u8FDB\u884C\u8BBF\u95EEEC2\n4. \u5821\u5792\u673A"
  },
  {
    id: "L3-CES2-04",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u68C0\u6D4B\u865A\u62DF\u673A\u4E4B\u95F4\u7684\u8D44\u6E90\u9694\u79BB\u5931\u6548\uFF0C\u5E76\u8FDB\u884C\u544A\u8B66",
    requirementEn: "It should be able to detect and alert resource isolation failures between virtual machines.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CES2-05",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u68C0\u6D4B\u975E\u6388\u6743\u65B0\u5EFA\u865A\u62DF\u673A\u6216\u8005\u91CD\u65B0\u542F\u7528\u865A\u62DF\u673A\uFF0C\u5E76\u8FDB\u884C\u544A\u8B66",
    requirementEn: "It should be able to detect and alert unauthorized new or re-enabled virtual machines.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u53EF\u901A\u8FC7cloudtrail\u68C0\u6D4B\u975E\u6388\u6743\u7684\u65B0\u5EFA\u673A\u5668\u884C\u4E3A\uFF0C\u5E76\u8FDB\u884C\u544A\u8B66"
  },
  {
    id: "L3-CES2-06",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u68C0\u6D4B\u6076\u610F\u4EE3\u7801\u611F\u67D3\u53CA\u5728\u865A\u62DF\u673A\u95F4\u8513\u5EF6\u7684\u60C5\u51B5\uFF0C\u5E76\u8FDB\u884C\u544A\u8B66",
    requirementEn: "It should be able to detect and alert malicious code infections and spread between virtual machines.",
    referenceStatus: "\u90E8\u5206\u7B26\u5408 Partially",
    referenceComment: "1. \u6309\u7167\u4E0D\u540C\u5B50\u7F51\u8BBE\u7F6E\uFF0C\u91C7\u7528\u5B89\u5168\u7EC4\u6216\u8005Network ACL\uFF0C\u5E76\u6309\u7167\u6700\u5C0F\u5316\u539F\u5219\u673A\u8FDB\u884C\u914D\u7F6E\n2. \u542F\u7528WAF\n3. \u542F\u7528GuardDuty\n4. \u4F7F\u7528\u7B2C\u4E09\u65B9\u7684\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\uFF0C\u5E76\u7ED3\u5408GLWB\u8FDB\u884C\u9AD8\u53EF\u7528\u90E8\u7F72\n5. \u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u548C\u6740\u6BD2\u4EA7\u54C1"
  },
  {
    id: "L3-CES2-07",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u955C\u50CF\u548C\u5FEB\u7167\u4FDD\u62A4",
    controlEn: "Image and Snapshot Protection",
    requirementCn: "\u5E94\u9488\u5BF9\u91CD\u8981\u4E1A\u52A1\u7CFB\u7EDF\u63D0\u4F9B\u52A0\u56FA\u7684\u64CD\u4F5C\u7CFB\u7EDF\u955C\u50CF\u6216\u64CD\u4F5C\u7CFB\u7EDF\u5B89\u5168\u52A0\u56FA\u670D\u52A1",
    requirementEn: "It should provide hardened operating system mirroring or operating system security hardening services for critical business systems.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u82E5\u4E0D\u4F7F\u7528AWS\u955C\u50CF\uFF0C\u9700\u8981\u81EA\u884C\u52A0\u56FA"
  },
  {
    id: "L3-CES2-08",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u955C\u50CF\u548C\u5FEB\u7167\u4FDD\u62A4",
    controlEn: "Image and Snapshot Protection",
    requirementCn: "\u5E94\u63D0\u4F9B\u865A\u62DF\u673A\u955C\u50CF\u3001\u5FEB\u7167\u5B8C\u6574\u6027\u6821\u9A8C\u529F\u80FD\uFF0C\u9632\u6B62\u865A\u62DF\u673A\u955C\u50CF\u88AB\u6076\u610F\u7BE1\u6539",
    requirementEn: "It should provide virtual machine image and snapshot integrity check function to prevent malicious tampering of virtual machine image.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u82E5\u4E0D\u4F7F\u7528AWS\u955C\u50CF\uFF0C\u9700\u8981\u81EA\u884C\u52A0\u56FA"
  },
  {
    id: "L3-CES2-09",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u955C\u50CF\u548C\u5FEB\u7167\u4FDD\u62A4",
    controlEn: "Image and Snapshot Protection",
    requirementCn: "\u5E94\u91C7\u53D6\u5BC6\u7801\u6280\u672F\u6216\u5176\u4ED6\u6280\u672F\u624B\u6BB5\u9632\u6B62\u865A\u62DF\u673A\u955C\u50CF\u3001\u5FEB\u7167\u4E2D\u53EF\u80FD\u5B58\u5728\u7684\u654F\u611F\u8D44\u6E90\u88AB\u975E\u6CD5\u8BBF\u95EE",
    requirementEn: "It should adopt cryptography or other techniques to prevent unauthorized access to sensitive resources that may exist in virtual machine images and snapshots.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u5229\u7528KMS\u5BF9\u5FEB\u7167\u8FDB\u884C\u52A0\u5BC6"
  },
  {
    id: "L3-CES2-10",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027\u548C\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity and Confidentiality",
    requirementCn: "\u5E94\u786E\u4FDD\u4E91\u670D\u52A1\u5BA2\u6237\u6570\u636E\u3001\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F\u7B49\u5B58\u50A8\u4E8E\u4E2D\u56FD\u5883\u5185\uFF0C\u5982\u9700\u51FA\u5883\u5E94\u9075\u5FAA\u56FD\u5BB6\u76F8\u5173\u89C4\u5B9A",
    requirementEn: "Ensure that cloud service customer data and user personal information are stored in China, and follow relevant national regulations when cross-border transferring.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CES2-11",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027\u548C\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity and Confidentiality",
    requirementCn: "\u5E94\u786E\u4FDD\u53EA\u6709\u5728\u4E91\u670D\u52A1\u5BA2\u6237\u6388\u6743\u4E0B\uFF0C\u4E91\u670D\u52A1\u5546\u6216\u7B2C\u4E09\u65B9\u624D\u5177\u6709\u4E91\u670D\u52A1\u5BA2\u6237\u6570\u636E\u7684\u7BA1\u7406\u6743\u9650",
    requirementEn: "Ensure that the cloud service provider or a third party has the right to manage the cloud service customer data only under the authorization of the cloud service customer.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CES2-12",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027\u548C\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity and Confidentiality",
    requirementCn: "\u5E94\u4F7F\u7528\u6821\u9A8C\u7801\u6216\u5BC6\u7801\u6280\u672F\u786E\u4FDD\u865A\u62DF\u673A\u8FC1\u79FB\u8FC7\u7A0B\u4E2D\u91CD\u8981\u6570\u636E\u7684\u5B8C\u6574\u6027\uFF0C\u5E76\u5728\u68C0\u6D4B\u5230\u5B8C\u6574\u6027\u53D7\u5230\u7834\u574F\u65F6\u91C7\u53D6\u5FC5\u8981\u7684\u6062\u590D\u63AA\u65BD",
    requirementEn: "It should adopt checksum or cryptographic techniques to ensure the integrity of important data during virtual machine migration and take necessary recovery measures when integrity is detected to be compromised.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4F20\u8F93\u52A0\u5BC6 - ACM\n\u5B58\u50A8\u9759\u6001\u52A0\u5BC6 - KMS\n\u5FEB\u7167\u5907\u4EFD\u670D\u52A1"
  },
  {
    id: "L3-CES2-13",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5B8C\u6574\u6027\u548C\u4FDD\u5BC6\u6027",
    controlEn: "Data Integrity and Confidentiality",
    requirementCn: "\u5E94\u652F\u6301\u4E91\u670D\u52A1\u5BA2\u6237\u90E8\u7F72\u5BC6\u94A5\u7BA1\u7406\u89E3\u51B3\u65B9\u6848\uFF0C\u4FDD\u8BC1\u4E91\u670D\u52A1\u5BA2\u6237\u81EA\u884C\u5B9E\u73B0\u6570\u636E\u7684\u52A0\u89E3\u5BC6\u8FC7\u7A0B",
    requirementEn: "It should support cloud service customers to deploy key management solutions to ensure that cloud service customers can implement the data encryption and decryption process by themselves.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "\u4F20\u8F93\u52A0\u5BC6 - ACM\n\u5B58\u50A8\u9759\u6001\u52A0\u5BC6 - KMS"
  },
  {
    id: "L3-CES2-14",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u4E91\u670D\u52A1\u5BA2\u6237\u5E94\u5728\u672C\u5730\u4FDD\u5B58\u5176\u4E1A\u52A1\u6570\u636E\u7684\u5907\u4EFD",
    requirementEn: "Ensure cloud service customers keep a backup of their business data locally.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: "\u8BF7\u786E\u8BA4\u662F\u5426\u5FC5\u987B"
  },
  {
    id: "L3-CES2-15",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u5E94\u63D0\u4F9B\u67E5\u8BE2\u4E91\u670D\u52A1\u5BA2\u6237\u6570\u636E\u53CA\u5907\u4EFD\u5B58\u50A8\u4F4D\u7F6E\u7684\u80FD\u529B",
    requirementEn: "It should provide the ability to query cloud service customer data and back up storage locations.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CES2-16",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u4E91\u670D\u52A1\u5546\u7684\u4E91\u5B58\u50A8\u670D\u52A1\u5E94\u4FDD\u8BC1\u4E91\u670D\u52A1\u5BA2\u6237\u6570\u636E\u5B58\u5728\u82E5\u5E72\u4E2A\u53EF\u7528\u7684\u526F\u672C\uFF0C\u5404\u526F\u672C\u4E4B\u95F4\u7684\u5185\u5BB9\u5E94\u4FDD\u6301\u4E00\u81F4",
    requirementEn: "The cloud storage service of the cloud service provider It should ensure that there are several available copies of the customer data of the cloud service, and the contents of each copy It should be consistent.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-CES2-17",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u5907\u4EFD\u6062\u590D",
    controlEn: "Data Backup and Recovery",
    requirementCn: "\u5E94\u4E3A\u4E91\u670D\u52A1\u5BA2\u6237\u5C06\u4E1A\u52A1\u7CFB\u7EDF\u53CA\u6570\u636E\u8FC1\u79FB\u5230\u5176\u4ED6\u4E91\u8BA1\u7B97\u5E73\u53F0\u548C\u672C\u5730\u7CFB\u7EDF\u63D0\u4F9B\u6280\u672F\u624B\u6BB5\uFF0C\u5E76\u534F\u52A9\u5B8C\u6210\u8FC1\u79FB\u8FC7\u7A0B",
    requirementEn: "It should provide technical means for cloud service customers to migrate business systems and data to other cloud computing platforms and local systems and assist in the migration process.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: "\u8BF7\u786E\u8BA4\u662F\u5426\u5FC5\u987B"
  },
  {
    id: "L3-CES2-18",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5269\u4F59\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Residual Information Protection",
    requirementCn: "\u5E94\u4FDD\u8BC1\u865A\u62DF\u673A\u6240\u4F7F\u7528\u7684\u5185\u5B58\u548C\u5B58\u50A8\u7A7A\u95F4\u56DE\u6536\u65F6\u5F97\u5230\u5B8C\u5168\u6E05\u9664",
    requirementEn: "Ensure that the memory and storage space used by the virtual machine is completely cleared when reclaimed.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6\uFF0C\u4E0D\u540C\u5B58\u50A8\u670D\u52A1\u5747\u63D0\u4F9B\u6570\u636E\u5B8C\u5168\u5220\u9664\u6216\u8005\u64E6\u9664\u7684\u65B9\u6CD5"
  },
  {
    id: "L3-CES2-19",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u5269\u4F59\u4FE1\u606F\u4FDD\u62A4",
    controlEn: "Residual Information Protection",
    requirementCn: "\u4E91\u670D\u52A1\u5BA2\u6237\u5220\u9664\u4E1A\u52A1\u5E94\u7528\u6570\u636E\u65F6\uFF0C\u4E91\u8BA1\u7B97\u5E73\u53F0\u5E94\u5C06\u4E91\u5B58\u50A8\u4E2D\u6240\u6709\u526F\u672C\u5220\u9664",
    requirementEn: "The cloud computing platform It should delete all copies in the cloud storage, when a cloud service customer deletes business application data.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6\uFF0C\u4E0D\u540C\u5B58\u50A8\u670D\u52A1\u5747\u63D0\u4F9B\u6570\u636E\u5B8C\u5168\u5220\u9664\u6216\u8005\u64E6\u9664\u7684\u65B9\u6CD5"
  },
  {
    id: "L3-SMC2-01",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u80FD\u5BF9\u7269\u7406\u8D44\u6E90\u548C\u865A\u62DF\u8D44\u6E90\u6309\u7167\u7B56\u7565\u505A\u7EDF\u4E00\u7BA1\u7406\u8C03\u5EA6\u4E0E\u5206\u914D",
    requirementEn: "It should be able to uniformly manage and allocate physical resources and virtual resources according to the policy.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-SMC2-02",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u4FDD\u8BC1\u4E91\u8BA1\u7B97\u5E73\u53F0\u7BA1\u7406\u6D41\u91CF\u4E0E\u4E91\u670D\u52A1\u5BA2\u6237\u4E1A\u52A1\u6D41\u91CF\u5206\u79BB",
    requirementEn: "Ensure the separation of cloud computing platform management traffic and cloud service customer business traffic.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-SMC2-03",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u6839\u636E\u4E91\u670D\u52A1\u5546\u548C\u4E91\u670D\u52A1\u5BA2\u6237\u7684\u804C\u8D23\u5212\u5206\uFF0C\u6536\u96C6\u5404\u81EA\u63A7\u5236\u90E8\u5206\u7684\u5BA1\u8BA1\u6570\u636E\u5E76\u5B9E\u73B0\u5404\u81EA\u7684\u96C6\u4E2D\u5BA1\u8BA1",
    requirementEn: "It should collect the audit data of each control part and implement centralized audit of each control part, according to the responsibilities of cloud service providers and cloud service customers.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1.\u53C2\u8003\u5B89\u5168\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\n2. AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-SMC2-04",
    categoryCn: "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3",
    categoryEn: "Security Management Center",
    controlCn: "\u96C6\u4E2D\u7BA1\u63A7",
    controlEn: "Centralized Management and Control",
    requirementCn: "\u5E94\u6839\u636E\u4E91\u670D\u52A1\u5546\u548C\u4E91\u670D\u52A1\u5BA2\u6237\u7684\u804C\u8D23\u5212\u5206\uFF0C\u5B9E\u73B0\u5404\u81EA\u63A7\u5236\u90E8\u5206\uFF0C\u5305\u62EC\u865A\u62DF\u5316\u7F51\u7EDC\u3001\u865A\u62DF\u673A\u3001\u865A\u62DF\u5316\u5B89\u5168\u8BBE\u5907\u7B49\u7684\u8FD0\u884C\u72B6\u51B5\u7684\u96C6\u4E2D\u76D1\u6D4B",
    requirementEn: "According to the responsibilities of cloud service providers and cloud service customers, It should realize centralized monitoring of the operation status of their respective control parts, including virtualized networks, virtual machines and virtualized security devices.",
    referenceStatus: "\u7B26\u5408 No Gap",
    referenceComment: "1.\u53C2\u8003\u5B89\u5168\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\n2. AWS\u81EA\u8EAB\u7684\u7B49\u4FDD\u6DB5\u76D6"
  },
  {
    id: "L3-PES3-01",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u65E0\u7EBF\u63A5\u5165\u70B9\u7684\u7269\u7406\u4F4D\u7F6E",
    controlEn: "Location of Wireless Access Point",
    requirementCn: "\u5E94\u4E3A\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u7684\u5B89\u88C5\u9009\u62E9\u5408\u7406\u4F4D\u7F6E\uFF0C\u907F\u514D\u8FC7\u5EA6\u8986\u76D6\u548C\u7535\u78C1\u5E72\u6270",
    requirementEn: "Choose a reasonable location for the installation of wireless access equipment to avoid excessive coverage and electromagnetic interference",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-01",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8FB9\u754C\u9632\u62A4",
    controlEn: "Border Protection",
    requirementCn: "\u5E94\u4FDD\u8BC1\u6709\u7EBF\u7F51\u7EDC\u4E0E\u65E0\u7EBF\u7F51\u7EDC\u8FB9\u754C\u4E4B\u95F4\u7684\u8BBF\u95EE\u548C\u6570\u636E\u6D41\u901A\u8FC7\u65E0\u7EBF\u63A5\u5165\u7F51\u5173\u8BBE\u5907",
    requirementEn: "Ensure access and data flow between the wired network and the wireless network boundary pass through the wireless access gateway device",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-02",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u5E94\u5F00\u542F\u63A5\u5165\u8BA4\u8BC1\u529F\u80FD\uFF0C\u5E76\u652F\u6301\u91C7\u7528\u8BA4\u8BC1\u670D\u52A1\u5668\u8BA4\u8BC1\u6216\u56FD\u5BB6\u5BC6\u7801\u7BA1\u7406\u673A\u6784\u6279\u51C6\u7684\u5BC6\u7801\u6A21\u5757\u8FDB\u884C\u8BA4\u8BC1",
    requirementEn: "Wireless access devices should turn on access authentication function and support to use the authentication server or cryptographic module approved by the State Cryptography Authority of China (SCA).",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-03",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u68C0\u6D4B\u5230\u975E\u6388\u6743\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u548C\u975E\u6388\u6743\u79FB\u52A8\u7EC8\u7AEF\u7684\u63A5\u5165\u884C\u4E3A",
    requirementEn: "Unauthorized wireless access devices and unauthorized mobile terminals should be detected",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-04",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u68C0\u6D4B\u5230\u9488\u5BF9\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u7684\u7F51\u7EDC\u626B\u63CF\u3001DDoS \u653B\u51FB\u3001\u5BC6\u94A5\u7834\u89E3\u3001\u4E2D\u95F4\u4EBA\u653B\u51FB\u548C\u6B3A\u9A97\u653B\u51FB\u7B49\u884C\u4E3A",
    requirementEn: "It should be able to detect network scanning, DDoS attacks, key cracking, man-in-the-middle attacks and deception attacks against wireless access devices.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-05",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u68C0\u6D4B\u5230\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u7684 SSID \u5E7F\u64AD\u3001WPS \u7B49\u9AD8\u98CE\u9669\u529F\u80FD\u7684\u5F00\u542F\u72B6\u6001",
    requirementEn: "It should be able to detect the use status of high-risk functions such as SSID broadcast and WPS of the wireless access device.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-06",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u7981\u7528\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u548C\u65E0\u7EBF\u63A5\u5165\u7F51\u5173\u5B58\u5728\u98CE\u9669\u7684\u529F\u80FD\uFF0C\u5982\uFF1ASSID \u5E7F\u64AD\u3001WEP \u8BA4\u8BC1\u7B49",
    requirementEn: "Disable high risk functions of the wireless access device and the wireless access gateway, such as SSID broadcast, WEP authentication, etc.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-07",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u7981\u6B62\u591A\u4E2A AP \u4F7F\u7528\u540C\u4E00\u4E2A\u8BA4\u8BC1\u5BC6\u94A5",
    requirementEn: "Multiple APs should be prohibited from using the same authentication key",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS3-08",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u963B\u65AD\u975E\u6388\u6743\u65E0\u7EBF\u63A5\u5165\u8BBE\u5907\u6216\u975E\u6388\u6743\u79FB\u52A8\u7EC8\u7AEF",
    requirementEn: "It should be able to block the unauthorized wireless access devices or unauthorized mobile terminals",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES3-01",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u79FB\u52A8\u7EC8\u7AEF\u7BA1\u63A7",
    controlEn: "Mobile Terminal Control",
    requirementCn: "\u5E94\u4FDD\u8BC1\u79FB\u52A8\u7EC8\u7AEF\u5B89\u88C5\u3001\u6CE8\u518C\u5E76\u8FD0\u884C\u7EC8\u7AEF\u7BA1\u7406\u5BA2\u6237\u7AEF\u8F6F\u4EF6",
    requirementEn: "The mobile terminal should be guaranteed to install, register and run the terminal management client software.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES3-02",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u79FB\u52A8\u7EC8\u7AEF\u7BA1\u63A7",
    controlEn: "Mobile Terminal Control",
    requirementCn: "\u79FB\u52A8\u7EC8\u7AEF\u5E94\u63A5\u53D7\u79FB\u52A8\u7EC8\u7AEF\u7BA1\u7406\u670D\u52A1\u7AEF\u7684\u8BBE\u5907\u751F\u547D\u5468\u671F\u7BA1\u7406\u3001\u8BBE\u5907\u8FDC\u7A0B\u63A7\u5236\uFF0C\u5982\uFF1A\u8FDC\u7A0B\u9501\u5B9A\u3001\u8FDC\u7A0B\u64E6\u9664\u7B49",
    requirementEn: "The mobile terminal shall accept the device lifecycle management and remote control from the mobile terminal management server, such as remote locking, remote erasing, etc.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES3-03",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u79FB\u52A8\u5E94\u7528\u7BA1\u63A7",
    controlEn: "Mobile Application Control",
    requirementCn: "\u5E94\u5177\u6709\u9009\u62E9\u5E94\u7528\u8F6F\u4EF6\u5B89\u88C5\u3001\u8FD0\u884C\u7684\u529F\u80FD",
    requirementEn: "It should provide the function which allows to select application software to install and run",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES3-04",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u79FB\u52A8\u5E94\u7528\u7BA1\u63A7",
    controlEn: "Mobile Application Control",
    requirementCn: "\u5E94\u53EA\u5141\u8BB8\u6307\u5B9A\u8BC1\u4E66\u7B7E\u540D\u7684\u5E94\u7528\u8F6F\u4EF6\u5B89\u88C5\u548C\u8FD0\u884C",
    requirementEn: "Only applications that have specify certificate and signature should be allowed to install and run",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES3-05",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u79FB\u52A8\u5E94\u7528\u7BA1\u63A7",
    controlEn: "Mobile Application Control",
    requirementCn: "\u5E94\u5177\u6709\u8F6F\u4EF6\u767D\u540D\u5355\u529F\u80FD\uFF0C\u5E94\u80FD\u6839\u636E\u767D\u540D\u5355\u63A7\u5236\u5E94\u7528\u8F6F\u4EF6\u5B89\u88C5\u3001\u8FD0\u884C",
    requirementEn: "It should provide the software whitelist function, and the installation and operation of applications should be controlled according to the whitelist",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES4-01",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Sensor Node",
    requirementCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u6240\u5904\u7684\u7269\u7406\u73AF\u5883\u5E94\u4E0D\u5BF9\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u9020\u6210\u7269\u7406\u7834\u574F\uFF0C\u5982\u6324\u538B\u3001\u5F3A\u632F\u52A8",
    requirementEn: "The physical environment in which the sensor node is located should not cause physical damage to the sensor node, such as extrusion and strong vibration.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES4-02",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Sensor Node",
    requirementCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5728\u5DE5\u4F5C\u72B6\u6001\u6240\u5904\u7269\u7406\u73AF\u5883\u5E94\u80FD\u6B63\u786E\u53CD\u6620\u73AF\u5883\u72B6\u6001\uFF08\u5982\u6E29\u6E7F\u5EA6\u4F20\u611F\u5668\u4E0D\u80FD\u5B89\u88C5\u5728\u9633\u5149\u76F4\u5C04\u533A\u57DF\uFF09",
    requirementEn: "The physical environment in which the sensor node is in working status should correctly reflect the environmental state (for example, the temperature and humidity sensor cannot be installed in a direct sunlight area)",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES4-03",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Sensor Node",
    requirementCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5728\u5DE5\u4F5C\u72B6\u6001\u6240\u5904\u7269\u7406\u73AF\u5883\u5E94\u4E0D\u5BF9\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u7684\u6B63\u5E38\u5DE5\u4F5C\u9020\u6210\u5F71\u54CD\uFF0C\u5982\u5F3A\u5E72\u6270\u3001\u963B\u6321\u5C4F\u853D\u7B49",
    requirementEn: "The physical environment in which the sensor node is located should not affect the normal operation of the sensor node, such as strong interference, blocking shielding, etc.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES4-04",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Sensor Node",
    requirementCn: "\u5173\u952E\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5E94\u5177\u6709\u53EF\u4F9B\u957F\u65F6\u95F4\u5DE5\u4F5C\u7684\u7535\u529B\u4F9B\u5E94\uFF08\u5173\u952E\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5E94\u5177\u6709\u6301\u4E45\u7A33\u5B9A\u7684\u7535\u529B\u4F9B\u5E94\u80FD\u529B\uFF09",
    requirementEn: "Critical sensor nodes should have a power supply for long periods of time (critical gateway node should have a durable and stable power supply capability)",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS4-01",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u63A5\u5165\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u4FDD\u8BC1\u53EA\u6709\u6388\u6743\u7684\u611F\u77E5\u8282\u70B9\u53EF\u4EE5\u63A5\u5165",
    requirementEn: "Ensured that only authorized sensor nodes can access",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS4-02",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u9650\u5236\u4E0E\u611F\u77E5\u8282\u70B9\u901A\u4FE1\u7684\u76EE\u6807\u5730\u5740\uFF0C\u4EE5\u907F\u514D\u5BF9\u964C\u751F\u5730\u5740\u7684\u653B\u51FB\u884C\u4E3A",
    requirementEn: "The target address to communicate with the sensor node should be restricted, thus avoiding attacks to unfamiliar addresses",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS4-03",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u5165\u4FB5\u9632\u8303",
    controlEn: "Intrusion Prevention",
    requirementCn: "\u5E94\u80FD\u591F\u9650\u5236\u4E0E\u7F51\u5173\u8282\u70B9\u901A\u4FE1\u7684\u76EE\u6807\u5730\u5740\uFF0C\u4EE5\u907F\u514D\u5BF9\u964C\u751F\u5730\u5740\u7684\u653B\u51FB\u884C\u4E3A",
    requirementEn: "The target address to communicate with the gateway node should be restricted, thus avoiding attacks to unfamiliar addresses",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-01",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Sensor Node Security",
    requirementCn: "\u5E94\u4FDD\u8BC1\u53EA\u6709\u6388\u6743\u7684\u7528\u6237\u53EF\u4EE5\u5BF9\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u4E0A\u7684\u8F6F\u4EF6\u5E94\u7528\u8FDB\u884C\u914D\u7F6E\u6216\u53D8\u66F4",
    requirementEn: "Ensured that only authorized users can configure or change software applications on the sensor node device.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-02",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Sensor Node Security",
    requirementCn: "\u5E94\u5177\u6709\u5BF9\u5176\u8FDE\u63A5\u7684\u7F51\u5173\u8282\u70B9\u8BBE\u5907\uFF08\u5305\u62EC\u8BFB\u5361\u5668\uFF09\u8FDB\u884C\u8EAB\u4EFD\u6807\u8BC6\u548C\u9274\u522B\u7684\u80FD\u529B",
    requirementEn: "It should be able to identify and authenticate the gateway nodes (including card readers) to which they are connected",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-03",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u611F\u77E5\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Sensor Node Security",
    requirementCn: "\u5E94\u5177\u6709\u5BF9\u5176\u8FDE\u63A5\u7684\u5176\u4ED6\u611F\u77E5\u8282\u70B9\u8BBE\u5907\uFF08\u5305\u62EC\u8DEF\u7531\u8282\u70B9\uFF09\u8FDB\u884C\u8EAB\u4EFD\u6807\u8BC6\u548C\u9274\u522B\u7684\u80FD\u529B",
    requirementEn: "It should be able to identify and authenticate other connected node (including routing nodes) to which they are connected",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-04",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Gateway Node Security",
    requirementCn: "\u5E94\u8BBE\u7F6E\u6700\u5927\u5E76\u53D1\u8FDE\u63A5\u6570",
    requirementEn: "The maximum number of concurrent connections of the gateway node should be set.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-05",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Gateway Node Security",
    requirementCn: "\u5E94\u5177\u5907\u5BF9\u5408\u6CD5\u8FDE\u63A5\u8BBE\u5907\uFF08\u5305\u62EC\u7EC8\u7AEF\u8282\u70B9\u3001\u8DEF\u7531\u8282\u70B9\u3001\u6570\u636E\u5904\u7406\u4E2D\u5FC3\uFF09\u8FDB\u884C\u6807\u8BC6\u548C\u9274\u522B\u7684\u80FD\u529B",
    requirementEn: "Ability to identify and authenticate legitimate connected devices (including endpoints, routing nodes, data processing centers)",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-06",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Gateway Node Security",
    requirementCn: "\u5E94\u5177\u5907\u8FC7\u6EE4\u975E\u6CD5\u8282\u70B9\u548C\u4F2A\u9020\u8282\u70B9\u6240\u53D1\u9001\u7684\u6570\u636E\u7684\u80FD\u529B",
    requirementEn: "It should be able to filter data sent by illegal and forged nodes",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-07",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Gateway Node Security",
    requirementCn: "\u6388\u6743\u7528\u6237\u5E94\u80FD\u591F\u5728\u8BBE\u5907\u4F7F\u7528\u8FC7\u7A0B\u4E2D\u5BF9\u5173\u952E\u5BC6\u94A5\u8FDB\u884C\u5728\u7EBF\u66F4\u65B0",
    requirementEn: "Authorized users should be able to update critical keys online during device use",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-08",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u7F51\u5173\u8282\u70B9\u8BBE\u5907\u5B89\u5168",
    controlEn: "Gateway Node Security",
    requirementCn: "\u6388\u6743\u7528\u6237\u5E94\u80FD\u591F\u5728\u8BBE\u5907\u4F7F\u7528\u8FC7\u7A0B\u4E2D\u5BF9\u5173\u952E\u914D\u7F6E\u53C2\u6570\u8FDB\u884C\u5728\u7EBF\u66F4\u65B0",
    requirementEn: "Authorized users should be able to update critical configuration parameters online while the device is in use",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-09",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6297\u6570\u636E\u91CD\u653E",
    controlEn: "Anti-data Playback",
    requirementCn: "\u5E94\u80FD\u591F\u9274\u522B\u6570\u636E\u7684\u65B0\u9C9C\u6027\uFF0C\u907F\u514D\u5386\u53F2\u6570\u636E\u7684\u91CD\u653E\u653B\u51FB",
    requirementEn: "Identify the freshness of data and avoid replay attacks of historical data",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-10",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6297\u6570\u636E\u91CD\u653E",
    controlEn: "Anti-data Playback",
    requirementCn: "\u5E94\u80FD\u591F\u9274\u522B\u5386\u53F2\u6570\u636E\u7684\u975E\u6CD5\u4FEE\u6539\uFF0C\u907F\u514D\u6570\u636E\u7684\u4FEE\u6539\u91CD\u653E\u653B\u51FB",
    requirementEn: "Identifies illegal modification of historical data to avoid data modification and replay attacks",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES4-11",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u6570\u636E\u878D\u5408\u5904\u7406",
    controlEn: "Data Aggregation Processing",
    requirementCn: "\u5E94\u5BF9\u6765\u81EA\u4F20\u611F\u7F51\u7684\u6570\u636E\u8FDB\u884C\u6570\u636E\u878D\u5408\u5904\u7406\uFF0C\u4F7F\u4E0D\u540C\u79CD\u7C7B\u7684\u6570\u636E\u53EF\u4EE5\u5728\u540C\u4E00\u4E2A\u5E73\u53F0\u88AB\u4F7F\u7528",
    requirementEn: "Data from the sensor network should be aggregated to make different types of data be used on the same platform",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES5-01",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u5BA4\u5916\u63A7\u5236\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Outdoor Control Equipment",
    requirementCn: "\u5BA4\u5916\u63A7\u5236\u8BBE\u5907\u5E94\u653E\u7F6E\u4E8E\u91C7\u7528\u94C1\u677F\u6216\u5176\u4ED6\u9632\u706B\u6750\u6599\u5236\u4F5C\u7684\u7BB1\u4F53\u6216\u88C5\u7F6E\u4E2D\u5E76\u7D27\u56FA\u7BB1\u4F53\u6216\u88C5\u7F6E\u5177\u6709\u900F\u98CE\u3001\u6563\u70ED\u3001\u9632\u76D7\u3001\u9632\u96E8\u548C\u9632\u706B\u80FD\u529B\u7B49",
    requirementEn: "The outdoor control equipment shall be placed in a box or device made of iron plates or other fireproof materials and fastened to the cabinet or device to have ventilation, heat dissipation, anti-theft, rainproof and fireproof capabilities, etc.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-PES5-02",
    categoryCn: "\u5B89\u5168\u7269\u7406\u73AF\u5883",
    categoryEn: "Physical Environment Security",
    controlCn: "\u5BA4\u5916\u63A7\u5236\u8BBE\u5907\u7269\u7406\u9632\u62A4",
    controlEn: "Physical Protection of Outdoor Control Equipment",
    requirementCn: "\u5BA4\u5916\u63A7\u5236\u8BBE\u5907\u653E\u7F6E\u5E94\u8FDC\u79BB\u5F3A\u7535\u78C1\u5E72\u6270\u3001\u5F3A\u70ED\u6E90\u7B49\u73AF\u5883\uFF0C\u5982\u65E0\u6CD5\u907F\u514D\u5E94\u53CA\u65F6\u505A\u597D\u5E94\u6025\u5904\u7F6E\u53CA\u68C0\u4FEE\uFF0C \u4FDD\u8BC1\u8BBE\u5907\u6B63\u5E38\u8FD0\u884C",
    requirementEn: "The outdoor control equipment should be placed away from strong electromagnetic interference, strong heat source and other extreme environments. If it is unavoidable, emergency treatment and maintenance should be done in time to ensure the normal operation of the equipment.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CNS5-01",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u4E0E\u4F01\u4E1A\u5176\u4ED6\u7CFB\u7EDF\u4E4B\u95F4\u5E94\u5212\u5206\u4E3A\u4E24\u4E2A\u533A\u57DF\uFF0C\u533A\u57DF\u95F4\u5E94\u91C7\u7528\u5355\u5411\u7684\u6280\u672F\u9694\u79BB\u624B\u6BB5",
    requirementEn: "The industrial control system and other systems of the enterprise should be divided into two areas, and one-way technical isolation should be adopted between the areas.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CNS5-02",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u5185\u90E8\u5E94\u6839\u636E\u4E1A\u52A1\u7279\u70B9\u5212\u5206\u4E3A\u4E0D\u540C\u7684\u5B89\u5168\u57DF\uFF0C\u5B89\u5168\u57DF\u4E4B\u95F4\u5E94\u91C7\u7528\u6280\u672F\u9694\u79BB\u624B\u6BB5",
    requirementEn: "The industrial control system should be intenally divided into different security domains according to the business feature. Technical isolation should be adopted between different security domains.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CNS5-03",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u7F51\u7EDC\u67B6\u6784",
    controlEn: "Network Architecture",
    requirementCn: "\u6D89\u53CA\u5B9E\u65F6\u63A7\u5236\u548C\u6570\u636E\u4F20\u8F93\u7684\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\uFF0C\u5E94\u4F7F\u7528\u72EC\u7ACB\u7684\u7F51\u7EDC\u8BBE\u5907\u7EC4\u7F51\uFF0C\u5728\u7269\u7406\u5C42\u9762\u4E0A\u5B9E\u73B0\u4E0E\u5176\u5B83\u6570\u636E\u7F51\u53CA\u5916\u90E8\u516C\u5171\u4FE1\u606F\u7F51\u7684\u5B89\u5168\u9694\u79BB",
    requirementEn: "Industrial control systems involving real-time control and data transmission should use independent network equipment to set up a network to achieve secure isolation from other data networks and external public information networks at physical level.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CNS5-04",
    categoryCn: "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
    categoryEn: "Communication Network Security",
    controlCn: "\u901A\u4FE1\u4F20\u8F93",
    controlEn: "Communication Transmission",
    requirementCn: "\u5728\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u5185\u4F7F\u7528\u5E7F\u57DF\u7F51\u8FDB\u884C\u63A7\u5236\u6307\u4EE4\u6216\u76F8\u5173\u6570\u636E\u4EA4\u6362\u7684\u5E94\u91C7\u7528\u52A0\u5BC6\u8BA4\u8BC1\u6280\u672F\u624B\u6BB5\u5B9E\u73B0\u8EAB\u4EFD\u8BA4\u8BC1\u3001\u8BBF\u95EE\u63A7\u5236\u548C\u6570\u636E\u52A0\u5BC6\u4F20\u8F93",
    requirementEn: "If WAN is used in industrial control system to control instructions or exchange related data, encryption and authentication technology should be adopted to realize identity authentication, access control and data encryption transmission",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-01",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5728\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u4E0E\u4F01\u4E1A\u5176\u4ED6\u7CFB\u7EDF\u4E4B\u95F4\u90E8\u7F72\u8BBF\u95EE\u63A7\u5236\u8BBE\u5907\uFF0C\u914D\u7F6E\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\uFF0C\u7981\u6B62\u4EFB\u4F55\u7A7F\u8D8A\u533A\u57DF\u8FB9\u754C\u7684 E-Mail\u3001Web\u3001Telnet\u3001Rlogin\u3001FTP \u7B49\u901A\u7528\u7F51\u7EDC\u670D\u52A1",
    requirementEn: "The access control device should be deployed between the industrial control system and other enterprise systems, and the access control policy should be configured to prohibit any common network services such as E-Mail, Web, Telnet, Rlogin, and FTP that traverse the boundary of the area.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-02",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u8BBF\u95EE\u63A7\u5236",
    controlEn: "Access Control",
    requirementCn: "\u5E94\u5728\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u5185\u5B89\u5168\u57DF\u548C\u5B89\u5168\u57DF\u4E4B\u95F4\u7684\u8FB9\u754C\u9632\u62A4\u673A\u5236\u5931\u6548\u65F6\uFF0C\u53CA\u65F6\u8FDB\u884C\u62A5\u8B66",
    requirementEn: "The alarm should be promptly issued when the boundary protection mechanism between different security domains fails in the industrial control system.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-03",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u62E8\u53F7\u4F7F\u7528\u63A7\u5236",
    controlEn: "Dail-up Use Control",
    requirementCn: "\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\u786E\u9700\u4F7F\u7528\u62E8\u53F7\u8BBF\u95EE\u670D\u52A1\u7684\uFF0C\u5E94\u9650\u5236\u5177\u6709\u62E8\u53F7\u8BBF\u95EE\u6743\u9650\u7684\u7528\u6237\u6570\u91CF\uFF0C\u5E76\u91C7\u53D6\u7528\u6237\u8EAB\u4EFD\u9274\u522B\u548C\u8BBF\u95EE\u63A7\u5236\u7B49\u63AA\u65BD",
    requirementEn: "If the industrial control system needs to use the dial-up access service, it should limit the number of users with dial-up access rights, and take measures such as user identity authentication and access control.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-04",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u62E8\u53F7\u4F7F\u7528\u63A7\u5236",
    controlEn: "Dail-up Use Control",
    requirementCn: "\u62E8\u53F7\u670D\u52A1\u5668\u548C\u5BA2\u6237\u7AEF\u5747\u5E94\u4F7F\u7528\u7ECF\u5B89\u5168\u52A0\u56FA\u7684\u64CD\u4F5C\u7CFB\u7EDF\uFF0C\u5E76\u91C7\u53D6\u6570\u5B57\u8BC1\u4E66\u8BA4\u8BC1\u3001\u4F20\u8F93\u52A0\u5BC6\u548C\u8BBF\u95EE\u63A7\u5236\u7B49\u63AA\u65BD",
    requirementEn: "Both the dial-up server and the client should use a security-hardened operating system and take measures such as digital certificate authentication, transport encryption, and access control.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-05",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u65E0\u7EBF\u4F7F\u7528\u63A7\u5236",
    controlEn: "Wireless Use Control",
    requirementCn: "\u5E94\u5BF9\u6240\u6709\u53C2\u4E0E\u65E0\u7EBF\u901A\u4FE1\u7684\u7528\u6237\uFF08\u4EBA\u5458\u3001\u8F6F\u4EF6\u8FDB\u7A0B\u6216\u8005\u8BBE\u5907\uFF09\u63D0\u4F9B\u552F\u4E00\u6027\u6807\u8BC6\u548C\u9274\u522B",
    requirementEn: "Provide unique identification and authentication to all users (personnel, software processes or devices) involved in wireless communications",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-06",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u65E0\u7EBF\u4F7F\u7528\u63A7\u5236",
    controlEn: "Wireless Use Control",
    requirementCn: "\u5E94\u5BF9\u6240\u6709\u53C2\u4E0E\u65E0\u7EBF\u901A\u4FE1\u7684\u7528\u6237\uFF08\u4EBA\u5458\u3001\u8F6F\u4EF6\u8FDB\u7A0B\u6216\u8005\u8BBE\u5907\uFF09\u8FDB\u884C\u6388\u6743\u4EE5\u53CA\u6267\u884C\u4F7F\u7528\u8FDB\u884C\u9650\u5236",
    requirementEn: "Restrictions on the authorization and execution of all users (personnel, software processes or devices) involved in wireless communication",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-07",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u65E0\u7EBF\u4F7F\u7528\u63A7\u5236",
    controlEn: "Wireless Use Control",
    requirementCn: "\u5E94\u5BF9\u65E0\u7EBF\u901A\u4FE1\u91C7\u53D6\u4F20\u8F93\u52A0\u5BC6\u7684\u5B89\u5168\u63AA\u65BD\uFF0C\u5B9E\u73B0\u4F20\u8F93\u62A5\u6587\u7684\u673A\u5BC6\u6027\u4FDD\u62A4",
    requirementEn: "Security measures for transmission encryption should be adopted for wireless communication to achieve confidentiality protection of transmitted messages.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-ABS5-08",
    categoryCn: "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
    categoryEn: "Area Boundary Security",
    controlCn: "\u65E0\u7EBF\u4F7F\u7528\u63A7\u5236",
    controlEn: "Wireless Use Control",
    requirementCn: "\u5BF9\u91C7\u7528\u65E0\u7EBF\u901A\u4FE1\u6280\u672F\u8FDB\u884C\u63A7\u5236\u7684\u5DE5\u4E1A\u63A7\u5236\u7CFB\u7EDF\uFF0C\u5E94\u80FD\u8BC6\u522B\u5176\u7269\u7406\u73AF\u5883\u4E2D\u53D1\u5C04\u7684\u672A\u7ECF\u6388\u6743\u7684\u65E0\u7EBF\u8BBE\u5907\uFF0C\u62A5\u544A\u672A\u7ECF\u6388\u6743\u8BD5\u56FE\u63A5\u5165\u6216\u5E72\u6270\u63A7\u5236\u7CFB\u7EDF\u7684\u884C\u4E3A",
    requirementEn: "Industrial control systems that use wireless communication technology should be able to identify unauthorized wireless devices transmitted in their physical environment and report unauthorized attempts to access or interfere with control systems.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES5-01",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u63A7\u5236\u8BBE\u5907\u5B89\u5168",
    controlEn: "Control Equipment Security",
    requirementCn: "\u63A7\u5236\u8BBE\u5907\u81EA\u8EAB\u5E94\u5B9E\u73B0\u76F8\u5E94\u7EA7\u522B\u5B89\u5168\u901A\u7528\u8981\u6C42\u63D0\u51FA\u7684\u8EAB\u4EFD\u9274\u522B\u3001\u8BBF\u95EE\u63A7\u5236\u548C\u5B89\u5168\u5BA1\u8BA1\u7B49\u5B89\u5168\u8981\u6C42\uFF0C\u5982\u53D7\u6761\u4EF6\u9650\u5236\u63A7\u5236\u8BBE\u5907\u65E0\u6CD5\u5B9E\u73B0\u4E0A\u8FF0\u8981\u6C42\uFF0C\u5E94\u7531\u5176\u4E0A\u4F4D\u63A7\u5236\u6216\u7BA1\u7406\u8BBE\u5907\u5B9E\u73B0\u540C\u7B49\u529F\u80FD\u6216\u901A\u8FC7\u7BA1\u7406\u624B\u6BB5\u63A7\u5236",
    requirementEn: "The control device itself shall implement the security requirements such as identity authentication, access control and security audit proposed by the corresponding level of security general requirements. If the above requirements cannot be implemented by restricted conditions, the equivalent function should be implemented by its upper class control or controlled by management means",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES5-02",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u63A7\u5236\u8BBE\u5907\u5B89\u5168",
    controlEn: "Control Equipment Security",
    requirementCn: "\u5E94\u5728\u7ECF\u8FC7\u5145\u5206\u6D4B\u8BD5\u8BC4\u4F30\u540E\uFF0C\u5728\u4E0D\u5F71\u54CD\u7CFB\u7EDF\u5B89\u5168\u7A33\u5B9A\u8FD0\u884C\u7684\u60C5\u51B5\u4E0B\u5BF9\u63A7\u5236\u8BBE\u5907\u8FDB\u884C\u8865\u4E01\u66F4\u65B0\u3001\u56FA\u4EF6\u66F4\u65B0\u7B49\u5DE5\u4F5C",
    requirementEn: "After sufficient testing and evaluation,  patches and firmware update can be applied to the control equipment which should not affect the safe and stable operation of the system.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES5-03",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u63A7\u5236\u8BBE\u5907\u5B89\u5168",
    controlEn: "Control Equipment Security",
    requirementCn: "\u5E94\u5173\u95ED\u6216\u62C6\u9664\u63A7\u5236\u8BBE\u5907\u7684\u8F6F\u76D8\u9A71\u52A8\u3001\u5149\u76D8\u9A71\u52A8\u3001USB \u63A5\u53E3\u3001\u4E32\u884C\u53E3\u6216\u591A\u4F59\u7F51\u53E3\u7B49\uFF0C\u786E\u9700\u4FDD\u7559\u7684\u5FC5\u987B\u901A\u8FC7\u76F8\u5173\u7684\u6280\u672F\u63AA\u65BD\u5B9E\u65BD\u4E25\u683C\u7684\u76D1\u63A7\u7BA1\u7406",
    requirementEn: "The floppy disk drive, CD-ROM drive, USB interface, serial port or redundant network port of the control device should be turned off or removed. It should be strictly monitored and managed through relevant technical measures if any of them are indeed to retain.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES5-04",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u63A7\u5236\u8BBE\u5907\u5B89\u5168",
    controlEn: "Control Equipment Security",
    requirementCn: "\u5E94\u4F7F\u7528\u4E13\u7528\u8BBE\u5907\u548C\u4E13\u7528\u8F6F\u4EF6\u5BF9\u63A7\u5236\u8BBE\u5907\u8FDB\u884C\u66F4\u65B0",
    requirementEn: "Control equipment should be updated with dedicated equipment and software",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  },
  {
    id: "L3-CES5-05",
    categoryCn: "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
    categoryEn: "Computing Environment Security",
    controlCn: "\u63A7\u5236\u8BBE\u5907\u5B89\u5168",
    controlEn: "Control Equipment Security",
    requirementCn: "\u5E94\u4FDD\u8BC1\u63A7\u5236\u8BBE\u5907\u5728\u4E0A\u7EBF\u524D\u7ECF\u8FC7\u5B89\u5168\u6027\u68C0\u6D4B\uFF0C\u907F\u514D\u63A7\u5236\u8BBE\u5907\u56FA\u4EF6\u4E2D\u5B58\u5728\u6076\u610F\u4EE3\u7801\u7A0B\u5E8F",
    requirementEn: "It should be ensured that the control device is tested for security before going online, and there is no malicious code program in the control device firmware.",
    referenceStatus: "\u4E0D\u9002\u7528 N/A",
    referenceComment: ""
  }
];

// src/data/mlps3-check-mapping.ts
var MLPS3_FULL_CHECKLIST = mlps3_full_checklist_default;
var MLPS3_CATEGORY_ORDER = [
  "\u5B89\u5168\u7269\u7406\u73AF\u5883",
  "\u5B89\u5168\u901A\u4FE1\u7F51\u7EDC",
  "\u5B89\u5168\u533A\u57DF\u8FB9\u754C",
  "\u5B89\u5168\u8BA1\u7B97\u73AF\u5883",
  "\u5B89\u5168\u7BA1\u7406\u4E2D\u5FC3"
];
var MLPS3_CHECK_MAPPING = [
  // =========================================================================
  // 安全物理环境 — L3-PES1-* (22 items) → cloud_provider
  // =========================================================================
  { id: "L3-PES1-01", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-02", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-03", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-04", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-05", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-06", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-07", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-08", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-09", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-10", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-11", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-12", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-13", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-14", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-15", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-16", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-17", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-18", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-19", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-20", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-21", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  { id: "L3-PES1-22", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u673A\u623F\u7269\u7406\u5B89\u5168" },
  // L3-PES2-01 (Cloud extension — physical infra in China)
  { id: "L3-PES2-01", type: "cloud_provider", note: "AWS \u4E2D\u56FD\u533A\u57FA\u7840\u8BBE\u65BD\u4F4D\u4E8E\u4E2D\u56FD\u5883\u5185" },
  // L3-PES3-01 (Wireless — N/A)
  { id: "L3-PES3-01", type: "not_applicable" },
  // L3-PES4-* (IoT sensor — N/A)
  { id: "L3-PES4-01", type: "not_applicable" },
  { id: "L3-PES4-02", type: "not_applicable" },
  { id: "L3-PES4-03", type: "not_applicable" },
  { id: "L3-PES4-04", type: "not_applicable" },
  // L3-PES5-* (Industrial control outdoor — N/A)
  { id: "L3-PES5-01", type: "not_applicable" },
  { id: "L3-PES5-02", type: "not_applicable" },
  // =========================================================================
  // 安全通信网络 — L3-CNS1-* (8 items)
  // =========================================================================
  { id: "L3-CNS1-01", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u7F51\u7EDC\u8BBE\u5907\u5904\u7406\u80FD\u529B" },
  { id: "L3-CNS1-02", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u7F51\u7EDC\u5E26\u5BBD" },
  {
    id: "L3-CNS1-03",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.2"]
  },
  {
    id: "L3-CNS1-04",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.2", "EC2.18", "EC2.19"]
  },
  { id: "L3-CNS1-05", type: "cloud_provider", note: "AWS \u591A\u53EF\u7528\u533A/\u591A\u533A\u57DF\u5197\u4F59" },
  {
    id: "L3-CNS1-06",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  {
    id: "L3-CNS1-07",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  { id: "L3-CNS1-08", type: "not_applicable" },
  // L3-CNS2-* (Cloud extension communication — 5 items)
  { id: "L3-CNS2-01", type: "cloud_provider", note: "AWS \u7B49\u4FDD\u6DB5\u76D6" },
  { id: "L3-CNS2-02", type: "cloud_provider", note: "VPC \u5B9E\u73B0\u865A\u62DF\u7F51\u7EDC\u9694\u79BB" },
  {
    id: "L3-CNS2-03",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "guardduty_findings"]
  },
  { id: "L3-CNS2-04", type: "cloud_provider", note: "AWS \u652F\u6301\u81EA\u4E3B\u5B89\u5168\u7B56\u7565\u914D\u7F6E" },
  { id: "L3-CNS2-05", type: "cloud_provider", note: "AWS Marketplace \u652F\u6301\u7B2C\u4E09\u65B9\u4EA7\u54C1" },
  // L3-CNS5-* (Industrial control communication — N/A)
  { id: "L3-CNS5-01", type: "not_applicable" },
  { id: "L3-CNS5-02", type: "not_applicable" },
  { id: "L3-CNS5-03", type: "not_applicable" },
  { id: "L3-CNS5-04", type: "not_applicable" },
  // =========================================================================
  // 安全区域边界 — L3-ABS1-* (20 items)
  // =========================================================================
  {
    id: "L3-ABS1-01",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS1-02",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS1-03",
    type: "manual",
    guidance: "\u9700\u786E\u8BA4 NAT Gateway\u3001VPC Endpoint \u914D\u7F6E\uFF0C\u9650\u5236\u5185\u90E8\u7528\u6237\u975E\u6388\u6743\u5916\u8054"
  },
  { id: "L3-ABS1-04", type: "not_applicable" },
  {
    id: "L3-ABS1-05",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS1-06",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS1-07",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS1-08",
    type: "manual",
    guidance: "\u9700\u542F\u7528 WAF \u6216\u90E8\u7F72\u7B2C\u4E09\u65B9\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\u5B9E\u73B0\u57FA\u4E8E\u4F1A\u8BDD\u72B6\u6001\u7684\u8BBF\u95EE\u63A7\u5236"
  },
  {
    id: "L3-ABS1-09",
    type: "manual",
    guidance: "\u9700\u542F\u7528 WAF \u6216\u90E8\u7F72\u7B2C\u4E09\u65B9\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\u5B9E\u73B0\u57FA\u4E8E\u5E94\u7528\u534F\u8BAE\u7684\u8BBF\u95EE\u63A7\u5236"
  },
  {
    id: "L3-ABS1-10",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"]
  },
  {
    id: "L3-ABS1-11",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"]
  },
  {
    id: "L3-ABS1-12",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"]
  },
  {
    id: "L3-ABS1-13",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"]
  },
  {
    id: "L3-ABS1-14",
    type: "manual",
    guidance: "\u9700\u5728\u64CD\u4F5C\u7CFB\u7EDF\u5B89\u88C5\u7B2C\u4E09\u65B9\u6740\u6BD2\u8F6F\u4EF6\uFF0C\u6216\u90E8\u7F72\u4E0B\u4E00\u4EE3\u9632\u706B\u5899\u8FDB\u884C\u6076\u610F\u4EE3\u7801\u68C0\u6D4B"
  },
  { id: "L3-ABS1-15", type: "not_applicable" },
  {
    id: "L3-ABS1-16",
    type: "auto",
    modules: ["service_detection", "config_rules_findings", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-ABS1-17",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-ABS1-18",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5", "CloudTrail.6", "CloudTrail.7"]
  },
  {
    id: "L3-ABS1-19",
    type: "manual",
    guidance: "\u9700\u914D\u7F6E S3 Access Log\u3001ALB Access Log\uFF0C\u6216\u90E8\u7F72\u4E0A\u7F51\u884C\u4E3A\u7BA1\u7406\u4EA7\u54C1\u8FDB\u884C\u8FDC\u7A0B\u8BBF\u95EE\u884C\u4E3A\u5BA1\u8BA1"
  },
  { id: "L3-ABS1-20", type: "not_applicable" },
  // L3-ABS2-* (Cloud extension boundary — 8 items)
  {
    id: "L3-ABS2-01",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS2-02",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-ABS2-03",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"]
  },
  {
    id: "L3-ABS2-04",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"]
  },
  {
    id: "L3-ABS2-05",
    type: "auto",
    modules: ["guardduty_findings"]
  },
  {
    id: "L3-ABS2-06",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"]
  },
  {
    id: "L3-ABS2-07",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-ABS2-08",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  // L3-ABS3-* (Wireless boundary — N/A)
  { id: "L3-ABS3-01", type: "not_applicable" },
  { id: "L3-ABS3-02", type: "not_applicable" },
  { id: "L3-ABS3-03", type: "not_applicable" },
  { id: "L3-ABS3-04", type: "not_applicable" },
  { id: "L3-ABS3-05", type: "not_applicable" },
  { id: "L3-ABS3-06", type: "not_applicable" },
  { id: "L3-ABS3-07", type: "not_applicable" },
  { id: "L3-ABS3-08", type: "not_applicable" },
  // L3-ABS4-* (IoT boundary — N/A)
  { id: "L3-ABS4-01", type: "not_applicable" },
  { id: "L3-ABS4-02", type: "not_applicable" },
  { id: "L3-ABS4-03", type: "not_applicable" },
  // L3-ABS5-* (Industrial control boundary — N/A)
  { id: "L3-ABS5-01", type: "not_applicable" },
  { id: "L3-ABS5-02", type: "not_applicable" },
  { id: "L3-ABS5-03", type: "not_applicable" },
  { id: "L3-ABS5-04", type: "not_applicable" },
  { id: "L3-ABS5-05", type: "not_applicable" },
  { id: "L3-ABS5-06", type: "not_applicable" },
  { id: "L3-ABS5-07", type: "not_applicable" },
  { id: "L3-ABS5-08", type: "not_applicable" },
  // =========================================================================
  // 安全计算环境 — L3-CES1-* (34 items, no CES1-16)
  // =========================================================================
  {
    id: "L3-CES1-01",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings", "security_hub_findings"],
    securityHubControlIds: ["IAM.7", "IAM.10", "IAM.11"]
  },
  {
    id: "L3-CES1-02",
    type: "manual",
    guidance: "\u9700\u914D\u7F6E\u5821\u5792\u673A\u6216\u901A\u8FC7 CloudTrail + CloudWatch Alarm + Lambda \u5B9E\u73B0\u767B\u5F55\u5931\u8D25\u5904\u7406"
  },
  {
    id: "L3-CES1-03",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  {
    id: "L3-CES1-04",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["IAM.5", "IAM.6"]
  },
  {
    id: "L3-CES1-05",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings"]
  },
  {
    id: "L3-CES1-06",
    type: "manual",
    guidance: "\u9700\u786E\u8BA4\u5DF2\u91CD\u547D\u540D\u6216\u5220\u9664\u9ED8\u8BA4\u8D26\u6237\uFF08\u5982 root \u76F4\u63A5\u767B\u5F55\uFF09\uFF0C\u4FEE\u6539\u9ED8\u8BA4\u53E3\u4EE4"
  },
  {
    id: "L3-CES1-07",
    type: "auto",
    modules: ["security_hub_findings", "access_analyzer_findings"],
    securityHubControlIds: ["IAM.3", "IAM.4", "IAM.22"]
  },
  {
    id: "L3-CES1-08",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"]
  },
  {
    id: "L3-CES1-09",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings"]
  },
  {
    id: "L3-CES1-10",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"]
  },
  {
    id: "L3-CES1-11",
    type: "manual",
    guidance: "\u9700\u5728\u5E94\u7528\u5C42\u5BF9\u654F\u611F\u4FE1\u606F\u8FDB\u884C\u5206\u7C7B\uFF0C\u5229\u7528 Tag \u6216 Metadata \u6807\u8BB0\u6570\u636E\uFF0C\u914D\u5408\u8BBF\u95EE\u63A7\u5236\u7B56\u7565\u7BA1\u63A7"
  },
  {
    id: "L3-CES1-12",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-CES1-13",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-CES1-14",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5", "CloudTrail.6", "CloudTrail.7"]
  },
  {
    id: "L3-CES1-15",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5"]
  },
  // Note: L3-CES1-16 does not exist in the standard
  {
    id: "L3-CES1-17",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-CES1-18",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-CES1-19",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  {
    id: "L3-CES1-20",
    type: "manual",
    guidance: "\u9700\u542F\u7528 WAF \u89C4\u5219\u8FDB\u884C\u8F93\u5165\u9A8C\u8BC1\uFF0C\u6216\u5728\u5E94\u7528\u5C42\u5B9E\u73B0\u6570\u636E\u6709\u6548\u6027\u68C0\u9A8C"
  },
  {
    id: "L3-CES1-21",
    type: "auto",
    modules: ["inspector_findings", "patch_compliance_findings"]
  },
  {
    id: "L3-CES1-22",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"]
  },
  {
    id: "L3-CES1-23",
    type: "manual",
    guidance: "\u9700\u5728\u64CD\u4F5C\u7CFB\u7EDF\u5C42\u5B89\u88C5\u7B2C\u4E09\u65B9\u6740\u6BD2\u4EA7\u54C1\uFF1B\u53EF\u7ED3\u5408 GuardDuty \u68C0\u6D4B\u6076\u610F\u884C\u4E3A"
  },
  { id: "L3-CES1-24", type: "not_applicable" },
  {
    id: "L3-CES1-25",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  {
    id: "L3-CES1-26",
    type: "manual",
    guidance: "\u9700\u5B89\u88C5\u7B2C\u4E09\u65B9\u9632\u7BE1\u6539\u8F6F\u4EF6\uFF1BS3 \u53EF\u5229\u7528\u5BF9\u8C61\u6821\u9A8C\u786E\u4FDD\u5B8C\u6574\u6027"
  },
  {
    id: "L3-CES1-27",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  {
    id: "L3-CES1-28",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["S3.4", "EC2.7", "RDS.3"]
  },
  {
    id: "L3-CES1-29",
    type: "auto",
    modules: ["disaster_recovery"]
  },
  {
    id: "L3-CES1-30",
    type: "auto",
    modules: ["disaster_recovery"]
  },
  {
    id: "L3-CES1-31",
    type: "auto",
    modules: ["disaster_recovery"]
  },
  { id: "L3-CES1-32", type: "cloud_provider", note: "AWS \u5B58\u50A8\u670D\u52A1\u6570\u636E\u6E05\u9664\u7B56\u7565\u8986\u76D6" },
  { id: "L3-CES1-33", type: "cloud_provider", note: "AWS \u5B58\u50A8\u670D\u52A1\u6570\u636E\u6E05\u9664\u7B56\u7565\u8986\u76D6" },
  {
    id: "L3-CES1-34",
    type: "manual",
    guidance: "\u5E94\u7528\u4FA7\u884C\u4E3A \u2014 \u9700\u786E\u8BA4\u4EC5\u91C7\u96C6\u548C\u4FDD\u5B58\u4E1A\u52A1\u5FC5\u9700\u7684\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F"
  },
  {
    id: "L3-CES1-35",
    type: "manual",
    guidance: "\u5E94\u7528\u4FA7\u884C\u4E3A \u2014 \u9700\u786E\u8BA4\u7981\u6B62\u672A\u6388\u6743\u8BBF\u95EE\u548C\u975E\u6CD5\u4F7F\u7528\u7528\u6237\u4E2A\u4EBA\u4FE1\u606F"
  },
  // L3-CES2-* (Cloud extension computing — 19 items)
  {
    id: "L3-CES2-01",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["IAM.5", "IAM.6"]
  },
  { id: "L3-CES2-02", type: "cloud_provider", note: "AWS \u786E\u4FDD VM \u8FC1\u79FB\u65F6\u8BBF\u95EE\u63A7\u5236\u968F\u8FC1" },
  {
    id: "L3-CES2-03",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"]
  },
  { id: "L3-CES2-04", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u865A\u62DF\u5316\u8D44\u6E90\u9694\u79BB" },
  {
    id: "L3-CES2-05",
    type: "auto",
    modules: ["guardduty_findings"]
  },
  {
    id: "L3-CES2-06",
    type: "manual",
    guidance: "\u9700\u90E8\u7F72\u7B2C\u4E09\u65B9\u5165\u4FB5\u9632\u8303\u548C\u6740\u6BD2\u4EA7\u54C1\u68C0\u6D4B\u865A\u62DF\u673A\u95F4\u6076\u610F\u4EE3\u7801\u8513\u5EF6"
  },
  {
    id: "L3-CES2-07",
    type: "manual",
    guidance: "\u82E5\u4E0D\u4F7F\u7528 AWS \u5B98\u65B9\u955C\u50CF\uFF0C\u9700\u81EA\u884C\u52A0\u56FA\u64CD\u4F5C\u7CFB\u7EDF"
  },
  {
    id: "L3-CES2-08",
    type: "manual",
    guidance: "\u82E5\u4E0D\u4F7F\u7528 AWS \u5B98\u65B9\u955C\u50CF\uFF0C\u9700\u81EA\u884C\u6821\u9A8C\u955C\u50CF\u548C\u5FEB\u7167\u5B8C\u6574\u6027"
  },
  {
    id: "L3-CES2-09",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["EC2.7"]
  },
  { id: "L3-CES2-10", type: "cloud_provider", note: "AWS \u4E2D\u56FD\u533A\u6570\u636E\u5B58\u50A8\u4E8E\u4E2D\u56FD\u5883\u5185" },
  { id: "L3-CES2-11", type: "cloud_provider", note: "AWS \u4EC5\u5728\u5BA2\u6237\u6388\u6743\u4E0B\u7BA1\u7406\u6570\u636E" },
  { id: "L3-CES2-12", type: "cloud_provider", note: "AWS \u786E\u4FDD VM \u8FC1\u79FB\u6570\u636E\u5B8C\u6574\u6027" },
  {
    id: "L3-CES2-13",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["KMS.4"]
  },
  { id: "L3-CES2-14", type: "not_applicable" },
  { id: "L3-CES2-15", type: "cloud_provider", note: "AWS \u652F\u6301\u67E5\u8BE2\u6570\u636E\u53CA\u5907\u4EFD\u5B58\u50A8\u4F4D\u7F6E" },
  { id: "L3-CES2-16", type: "cloud_provider", note: "AWS \u5B58\u50A8\u670D\u52A1\u4FDD\u8BC1\u591A\u526F\u672C\u4E00\u81F4" },
  { id: "L3-CES2-17", type: "not_applicable" },
  { id: "L3-CES2-18", type: "cloud_provider", note: "AWS \u786E\u4FDD VM \u5185\u5B58\u548C\u5B58\u50A8\u7A7A\u95F4\u56DE\u6536\u65F6\u5B8C\u5168\u6E05\u9664" },
  { id: "L3-CES2-19", type: "cloud_provider", note: "AWS \u786E\u4FDD\u5220\u9664\u6570\u636E\u65F6\u6E05\u9664\u6240\u6709\u526F\u672C" },
  // L3-CES3-* (Mobile — N/A)
  { id: "L3-CES3-01", type: "not_applicable" },
  { id: "L3-CES3-02", type: "not_applicable" },
  { id: "L3-CES3-03", type: "not_applicable" },
  { id: "L3-CES3-04", type: "not_applicable" },
  { id: "L3-CES3-05", type: "not_applicable" },
  // L3-CES4-* (IoT sensor/gateway — N/A)
  { id: "L3-CES4-01", type: "not_applicable" },
  { id: "L3-CES4-02", type: "not_applicable" },
  { id: "L3-CES4-03", type: "not_applicable" },
  { id: "L3-CES4-04", type: "not_applicable" },
  { id: "L3-CES4-05", type: "not_applicable" },
  { id: "L3-CES4-06", type: "not_applicable" },
  { id: "L3-CES4-07", type: "not_applicable" },
  { id: "L3-CES4-08", type: "not_applicable" },
  { id: "L3-CES4-09", type: "not_applicable" },
  { id: "L3-CES4-10", type: "not_applicable" },
  { id: "L3-CES4-11", type: "not_applicable" },
  // L3-CES5-* (Industrial control — N/A)
  { id: "L3-CES5-01", type: "not_applicable" },
  { id: "L3-CES5-02", type: "not_applicable" },
  { id: "L3-CES5-03", type: "not_applicable" },
  { id: "L3-CES5-04", type: "not_applicable" },
  { id: "L3-CES5-05", type: "not_applicable" },
  // =========================================================================
  // 安全管理中心 — L3-SMC1-* (12 items)
  // =========================================================================
  {
    id: "L3-SMC1-01",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"]
  },
  {
    id: "L3-SMC1-02",
    type: "auto",
    modules: ["security_hub_findings", "config_rules_findings"],
    securityHubControlIds: ["Config.1"]
  },
  {
    id: "L3-SMC1-03",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"]
  },
  {
    id: "L3-SMC1-04",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-SMC1-05",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"]
  },
  {
    id: "L3-SMC1-06",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"]
  },
  {
    id: "L3-SMC1-07",
    type: "auto",
    modules: ["service_detection"],
    findingPatterns: ["Security Hub"]
  },
  {
    id: "L3-SMC1-08",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"]
  },
  {
    id: "L3-SMC1-09",
    type: "manual",
    guidance: "\u9700\u914D\u7F6E CloudWatch \u96C6\u4E2D\u76D1\u63A7\u5E73\u53F0\uFF0C\u7ED3\u5408 SNS \u8FDB\u884C\u544A\u8B66\u901A\u77E5"
  },
  {
    id: "L3-SMC1-10",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"]
  },
  {
    id: "L3-SMC1-11",
    type: "manual",
    guidance: "\u9700\u90E8\u7F72\u7B2C\u4E09\u65B9\u9632\u5165\u4FB5\u548C\u9632\u75C5\u6BD2\u4EA7\u54C1\u8FDB\u884C\u5B89\u5168\u7B56\u7565\u3001\u6076\u610F\u4EE3\u7801\u3001\u8865\u4E01\u5347\u7EA7\u96C6\u4E2D\u7BA1\u7406"
  },
  {
    id: "L3-SMC1-12",
    type: "auto",
    modules: ["guardduty_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"]
  },
  // L3-SMC2-* (Cloud extension management center — 4 items)
  { id: "L3-SMC2-01", type: "cloud_provider", note: "AWS \u8D1F\u8D23\u7EDF\u4E00\u7BA1\u7406\u8C03\u5EA6\u548C\u5206\u914D" },
  { id: "L3-SMC2-02", type: "cloud_provider", note: "AWS \u786E\u4FDD\u7BA1\u7406\u6D41\u91CF\u4E0E\u4E1A\u52A1\u6D41\u91CF\u5206\u79BB" },
  { id: "L3-SMC2-03", type: "cloud_provider", note: "AWS \u57FA\u4E8E\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\u5B9E\u73B0\u96C6\u4E2D\u5BA1\u8BA1" },
  { id: "L3-SMC2-04", type: "cloud_provider", note: "AWS \u57FA\u4E8E\u8D23\u4EFB\u5171\u62C5\u6A21\u578B\u5B9E\u73B0\u96C6\u4E2D\u76D1\u6D4B" }
];
var _mappingIndex = /* @__PURE__ */ new Map();
for (const m of MLPS3_CHECK_MAPPING) {
  _mappingIndex.set(m.id, m);
}
function getMappingById(id) {
  return _mappingIndex.get(id);
}

// src/tools/mlps-report.ts
function evaluateFullCheck(item, mapping, allFindings, scanModules) {
  if (mapping.type === "cloud_provider") {
    return { item, mapping, status: "cloud_provider", relatedFindings: [] };
  }
  if (mapping.type === "not_applicable") {
    return { item, mapping, status: "not_applicable", relatedFindings: [] };
  }
  if (mapping.type === "manual") {
    return { item, mapping, status: "manual", relatedFindings: [] };
  }
  const mods = mapping.modules ?? [];
  const allModulesPresent = mods.every(
    (mod) => scanModules.some((m) => m.module === mod && m.status === "success")
  );
  if (!allModulesPresent) {
    return { item, mapping, status: "unknown", relatedFindings: [] };
  }
  let relatedFindings;
  if (mapping.securityHubControlIds?.length) {
    relatedFindings = allFindings.filter((f) => {
      if (!mods.includes(f.module ?? "")) return false;
      if (f.module === "security_hub_findings") {
        return mapping.securityHubControlIds.some((id) => f.title.includes(id));
      }
      return true;
    });
  } else if (mapping.findingPatterns?.length) {
    const patterns = mapping.findingPatterns;
    relatedFindings = allFindings.filter((f) => {
      if (!mods.includes(f.module ?? "")) return false;
      const text = `${f.title} ${f.description}`.toLowerCase();
      return patterns.some((pattern) => text.includes(pattern.toLowerCase()));
    });
  } else {
    relatedFindings = allFindings.filter((f) => mods.includes(f.module ?? ""));
  }
  const status = relatedFindings.length === 0 ? "clean" : "issues";
  return { item, mapping, status, relatedFindings };
}
function evaluateAllFullChecks(scanResults) {
  const allFindings = scanResults.modules.flatMap(
    (m) => m.findings.map((f) => ({ ...f, module: f.module ?? m.module }))
  );
  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status
  }));
  return MLPS3_FULL_CHECKLIST.map((item) => {
    const mapping = getMappingById(item.id);
    if (!mapping) {
      return {
        item,
        mapping: { id: item.id, type: "manual", guidance: "\u672A\u6620\u5C04\u7684\u68C0\u67E5\u9879" },
        status: "manual",
        relatedFindings: []
      };
    }
    return evaluateFullCheck(item, mapping, allFindings, scanModules);
  });
}
function generateMlps3Report(scanResults, lang) {
  const t = getI18n(lang ?? "zh");
  const isEn = (lang ?? "zh") === "en";
  const { accountId, region, scanStart } = scanResults;
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const results = evaluateAllFullChecks(scanResults);
  const autoResults = results.filter((r) => r.mapping.type === "auto");
  const autoClean = autoResults.filter((r) => r.status === "clean").length;
  const autoIssues = autoResults.filter((r) => r.status === "issues").length;
  const autoUnknown = autoResults.filter((r) => r.status === "unknown").length;
  const checkedTotal = autoClean + autoIssues;
  const cloudCount = results.filter((r) => r.status === "cloud_provider").length;
  const manualCount = results.filter((r) => r.status === "manual").length;
  const naCount = results.filter((r) => r.status === "not_applicable").length;
  const itemControl = (r) => isEn ? r.item.controlEn : r.item.controlCn;
  const itemReq = (r) => isEn ? r.item.requirementEn : r.item.requirementCn;
  const lines = [];
  lines.push(`# ${t.mlpsTitle}`);
  lines.push(`> **${t.mlpsDisclaimer}**`);
  lines.push("");
  lines.push(`## ${t.accountInfo}`);
  lines.push(`- ${t.account}: ${accountId} | ${t.region}: ${region} | ${t.scanTime}: ${scanTime}`);
  lines.push("");
  lines.push(`## ${t.preCheckOverview}`);
  lines.push(`- ${t.checkedCount(checkedTotal, autoClean, autoIssues)}`);
  if (autoUnknown > 0) {
    lines.push(`- ${t.uncheckedCount(autoUnknown)}`);
  }
  lines.push(`- ${t.cloudProviderCount(cloudCount)}`);
  lines.push(`- ${t.manualReviewCount(manualCount)}`);
  if (naCount > 0) {
    lines.push(`- ${t.naCount(naCount)}`);
  }
  lines.push("");
  for (const category of MLPS3_CATEGORY_ORDER) {
    const sectionTitle = t.mlpsCategorySection[category] ?? category;
    const catResults = results.filter(
      (r) => r.item.categoryCn === category && r.status !== "not_applicable"
    );
    if (catResults.length === 0) continue;
    lines.push(`## ${sectionTitle}`);
    lines.push("");
    const controlMap = /* @__PURE__ */ new Map();
    for (const r of catResults) {
      const key = r.item.controlCn;
      if (!controlMap.has(key)) controlMap.set(key, []);
      controlMap.get(key).push(r);
    }
    for (const [_controlKey, controlResults] of controlMap) {
      const controlName = itemControl(controlResults[0]);
      lines.push(`### ${controlName}`);
      for (const r of controlResults) {
        const icon = r.status === "clean" ? "\u2705" : r.status === "issues" ? "\u274C" : r.status === "unknown" ? "\u26A0\uFE0F" : r.status === "manual" ? "\u{1F4CB}" : "\u{1F3E2}";
        const suffix = r.status === "unknown" ? ` \u2014 ${t.notChecked}` : r.status === "manual" ? ` \u2014 ${r.mapping.guidance ?? t.manualReview}` : r.status === "cloud_provider" ? ` \u2014 ${r.mapping.note ?? t.cloudProvider}` : r.status === "clean" ? ` ${t.noIssues}` : ` ${t.issuesFound}`;
        const reqText = itemReq(r);
        lines.push(`- [${icon}] ${r.item.id} ${reqText.slice(0, 60)}${reqText.length > 60 ? "\u2026" : ""}${suffix}`);
        if (r.status === "issues" && r.relatedFindings.length > 0) {
          for (const f of r.relatedFindings.slice(0, 3)) {
            lines.push(`  - ${f.severity}: ${f.title}`);
          }
          if (r.relatedFindings.length > 3) {
            lines.push(`  - ${t.andMore(r.relatedFindings.length - 3)}`);
          }
        }
      }
      lines.push("");
    }
  }
  const failedResults = results.filter((r) => r.status === "issues");
  if (failedResults.length > 0) {
    lines.push(`## ${t.remediationByPriority}`);
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
  if (naCount > 0) {
    lines.push(`> ${t.naNote(naCount)}`);
    lines.push("");
  }
  return lines.join("\n");
}

// src/tools/html-report.ts
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function escWithLinks(s) {
  const parts = s.split(/(https?:\/\/\S+)/);
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      return `<a href="${esc(part)}" style="color:#60a5fa" target="_blank" rel="noopener">${esc(part)}</a>`;
    }
    return esc(part);
  }).join("");
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
function getRecommendationTemplate(rem) {
  return rem.replace(/\b(i-[0-9a-f]+)\b/g, "{instance}").replace(/\b(vol-[0-9a-f]+)\b/g, "{volume}").replace(/\b(sg-[0-9a-f]+)\b/g, "{sg}").replace(/\b(eipalloc-[0-9a-f]+)\b/g, "{eip}").replace(/\b(arn:aws[-\w]*:[^"\s]+)\b/g, "{arn}").replace(/"[^"]+"/g, "{name}").replace(/bucket \S+/g, "bucket {name}").replace(/instance \S+/g, "instance {id}").replace(/volume \S+/g, "volume {id}").replace(/rule \S+/g, "rule {name}");
}
function getSecurityHubSource(finding) {
  const impact = finding.impact ?? "";
  const match = impact.match(/^Source:\s*([^(]+)/);
  if (!match) return "Other";
  const product = match[1].trim();
  if (product === "Security Hub" || product.includes("Foundational")) return "FSBP";
  if (product === "Inspector" || product.includes("Inspector")) return "Inspector";
  if (product === "GuardDuty" || product.includes("GuardDuty")) return "GuardDuty";
  if (product === "Config" || product.includes("Config")) return "Config";
  if (product === "IAM Access Analyzer" || product.includes("Access Analyzer")) return "Access Analyzer";
  return "Other";
}
var SECURITY_HUB_SUB_CAT_ORDER = ["FSBP", "Inspector", "GuardDuty", "Config", "Access Analyzer", "Other"];
function scoreColor(score) {
  if (score >= 80) return "#22c55e";
  if (score >= 50) return "#eab308";
  return "#ef4444";
}
var SERVICE_NOT_ENABLED_PATTERNS = [
  "not enabled",
  "not found",
  "No IAM Access Analyzer",
  "No SSM-managed instances",
  "requires AWS Business or Enterprise Support",
  "not available",
  "is not enabled"
];
function getDisabledServices(modules, lang) {
  const t = getI18n(lang ?? "zh");
  const disabled = [];
  for (const mod of modules) {
    const rec = t.serviceRecommendations[mod.module];
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
function buildServiceReminderHtml(modules, lang) {
  const t = getI18n(lang ?? "zh");
  const disabled = getDisabledServices(modules, lang);
  if (disabled.length === 0) return "";
  const items = disabled.map((svc) => `
    <div style="margin-bottom:12px">
      <div style="font-weight:600;font-size:15px">${esc(svc.icon)} ${esc(svc.service)} ${esc(t.notEnabled)}</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">${esc(t.serviceImpact)}\uFF1A${esc(svc.impact)}</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">${esc(t.serviceAction)}\uFF1A${esc(svc.action)}</div>
    </div>`).join("\n");
  return `
  <section>
    <div style="background:#2d1f00;border:1px solid #b45309;border-radius:8px;padding:20px;margin-bottom:32px">
      <div style="font-size:17px;font-weight:700;margin-bottom:12px">${esc(t.serviceReminderTitle)}</div>
      ${items}
      <div style="margin-top:12px;font-size:13px;color:#fbbf24;font-weight:500">${esc(t.serviceReminderFooter)}</div>
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
    .filter-toolbar{display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-bottom:20px;padding:12px 16px;background:#1e293b;border:1px solid #334155;border-radius:8px}
    .filter-group{display:flex;align-items:center;gap:8px}
    .filter-label{color:#94a3b8;font-size:13px}
    .filter-btn{padding:4px 12px;border-radius:4px;border:1px solid #475569;background:transparent;color:#cbd5e1;cursor:pointer;font-size:13px}
    .filter-btn:hover{background:#334155}
    .filter-btn.active{background:#3b82f6;border-color:#3b82f6;color:#fff}
    .filter-select{padding:4px 8px;border-radius:4px;border:1px solid #475569;background:#0f172a;color:#cbd5e1;font-size:13px}
    .filter-count{color:#64748b;font-size:13px;margin-left:auto}
    @media print{
      .filter-toolbar{display:none !important}
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
function barChart(modules, allCleanLabel = "All modules clean") {
  const withFindings = modules.filter((m) => m.findingsCount > 0).sort((a, b) => b.findingsCount - a.findingsCount).slice(0, 12);
  if (withFindings.length === 0) {
    return [
      '<svg viewBox="0 0 400 50" width="100%">',
      `  <text x="200" y="30" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="600">${esc(allCleanLabel)}</text>`,
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
function generateHtmlReport(scanResults, history, lang) {
  const t = getI18n(lang ?? "zh");
  const htmlLang = (lang ?? "zh") === "zh" ? "zh-CN" : "en";
  const { summary, modules, accountId, region, scanStart, scanEnd } = scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration2(scanStart, scanEnd);
  const score = calcScore(summary);
  const allFindings = modules.flatMap(
    (m) => m.findings.map((f) => ({ ...f, module: f.module ?? m.module }))
  );
  const shModule = modules.find((m) => m.module === "security_hub_findings");
  const shSubCats = [];
  if (shModule && shModule.findingsCount > 0) {
    const catMap = {};
    for (const f of shModule.findings) {
      const cat = getSecurityHubSource(f);
      if (!catMap[cat]) catMap[cat] = [];
      catMap[cat].push(f);
    }
    for (const cat of SECURITY_HUB_SUB_CAT_ORDER) {
      const catFindings = catMap[cat];
      if (catFindings && catFindings.length > 0) {
        const meta = t.securityHubSubCategories[cat];
        const shLabel = t.moduleNames[`sh:${cat}`] ?? meta?.label ?? cat;
        shSubCats.push({
          key: cat,
          label: shLabel,
          count: catFindings.length,
          findings: catFindings
        });
      }
    }
  }
  const DETECTION_ONLY_MODULES = /* @__PURE__ */ new Set([
    "guardduty_findings",
    "inspector_findings",
    "config_rules_findings",
    "access_analyzer_findings"
  ]);
  const barChartModules = modules.flatMap((m) => {
    if (DETECTION_ONLY_MODULES.has(m.module)) return [];
    if (m.module === "security_hub_findings" && shSubCats.length > 0) {
      return shSubCats.map((sc) => ({
        ...m,
        module: t.moduleNames[`sh:${sc.key}`] ?? sc.key,
        findingsCount: sc.count,
        findings: sc.findings
      }));
    }
    return [{ ...m, module: t.moduleNames[m.module] ?? m.module }];
  });
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
          <div class="top5-detail"><strong>${t.resource}:</strong> ${esc(f.resourceId)}</div>
          <div class="top5-detail"><strong>${t.impact}:</strong> ${esc(f.impact)}</div>
          <div class="top5-detail"><strong>${t.riskScore}:</strong> ${f.riskScore}/10</div>
          <h4>${t.remediation}</h4>
          <ol class="top5-remediation">${f.remediationSteps.map((s) => `<li>${escWithLinks(s)}</li>`).join("")}</ol>
        </div>
      </div>`
    ).join("\n");
    top5Html = `
    <section>
      <h2>${esc(t.topHighestRiskFindings(top5.length))}</h2>
      ${cards}
    </section>`;
  }
  let findingsHtml;
  let filterToolbarHtml = "";
  if (summary.totalFindings === 0) {
    findingsHtml = `<div class="no-findings">${esc(t.noIssuesFound)}</div>`;
  } else {
    const FOLD_THRESHOLD = 20;
    const renderCard = (f, moduleKey) => {
      const sev = f.severity.toLowerCase();
      return `<div class="finding-card sev-${esc(sev)}" data-severity="${esc(f.severity)}" data-module="${esc(moduleKey)}">
        <span class="badge badge-${esc(sev)}">${esc(f.severity)}</span>
        <span class="finding-title-text">${esc(f.title)}</span>
        <span class="finding-resource">${esc(f.resourceArn || f.resourceId)}</span>
        <details><summary>${t.details}</summary><div class="finding-card-body">
          <p>${esc(f.description)}</p>
          <p><strong>${t.remediation}:</strong></p>
          <ol>${f.remediationSteps.map((s) => `<li>${escWithLinks(s)}</li>`).join("")}</ol>
        </div></details>
      </div>`;
    };
    const renderCards = (findings, moduleKey) => {
      if (findings.length <= FOLD_THRESHOLD) {
        return findings.map((f) => renderCard(f, moduleKey)).join("\n");
      }
      const first = findings.slice(0, FOLD_THRESHOLD).map((f) => renderCard(f, moduleKey)).join("\n");
      const rest = findings.slice(FOLD_THRESHOLD).map((f) => renderCard(f, moduleKey)).join("\n");
      return `${first}
<details><summary>${t.showRemainingFindings(findings.length - FOLD_THRESHOLD)}</summary>
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
    const expandedEntries = [];
    for (const [mod, findings] of moduleMap.entries()) {
      if (DETECTION_ONLY_MODULES.has(mod)) continue;
      if (mod === "security_hub_findings" && shSubCats.length > 0) {
        for (const sc of shSubCats) {
          expandedEntries.push([sc.key, sc.findings, sc.label]);
        }
      } else {
        expandedEntries.push([mod, findings, null]);
      }
    }
    const moduleEntries = expandedEntries.sort((a, b) => {
      const aHasCritHigh = a[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      const bHasCritHigh = b[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      if (aHasCritHigh !== bHasCritHigh) return aHasCritHigh ? -1 : 1;
      return b[1].length - a[1].length;
    });
    const renderSeverityGroups = (findings, moduleKey) => {
      return SEVERITY_ORDER2.map((sev) => {
        const sevFindings = findings.filter((f) => f.severity === sev);
        if (sevFindings.length === 0) return "";
        sevFindings.sort((a, b) => b.riskScore - a.riskScore);
        const emoji = SEV_EMOJI[sev] ?? "";
        const label = sev.charAt(0) + sev.slice(1).toLowerCase();
        return `<details class="severity-group-fold">
          <summary><h4>${emoji} ${label} (${sevFindings.length})</h4></summary>
          ${renderCards(sevFindings, moduleKey)}
        </details>`;
      }).filter(Boolean).join("\n");
    };
    const renderModuleBadges = (findings) => {
      const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      for (const f of findings) sevCounts[f.severity]++;
      return SEVERITY_ORDER2.filter((sev) => sevCounts[sev] > 0).map((sev) => `<span class="badge badge-${sev.toLowerCase()}">${sevCounts[sev]} ${sev.charAt(0) + sev.slice(1).toLowerCase()}</span>`).join(" ");
    };
    findingsHtml = moduleEntries.map(([modName, modFindings, subCatLabel]) => {
      const badges = renderModuleBadges(modFindings);
      const displayName = subCatLabel ?? (t.moduleNames[modName] ?? modName);
      return `<details class="module-fold" data-module="${esc(modName)}">
        <summary>
          <h3>&#128274; ${esc(displayName)} (${modFindings.length})</h3>
          <span class="module-badges">${badges}</span>
        </summary>
        <div class="module-body">
          ${renderSeverityGroups(modFindings, modName)}
        </div>
      </details>`;
    }).join("\n");
    const moduleOptions = moduleEntries.map(([modKey, , subCatLabel]) => {
      const label = subCatLabel ?? (t.moduleNames[modKey] ?? modKey);
      return `<option value="${esc(modKey)}">${esc(label)}</option>`;
    }).join("\n        ");
    filterToolbarHtml = `<div class="filter-toolbar" id="filterBar">
      <div class="filter-group">
        <span class="filter-label">${esc(t.filterSeverity)}</span>
        <button class="filter-btn active" data-severity="ALL">${esc(t.filterAll)}</button>
        <button class="filter-btn" data-severity="CRITICAL">Critical</button>
        <button class="filter-btn" data-severity="HIGH">High</button>
        <button class="filter-btn" data-severity="MEDIUM">Medium</button>
        <button class="filter-btn" data-severity="LOW">Low</button>
      </div>
      <div class="filter-group">
        <span class="filter-label">${esc(t.filterModule)}</span>
        <select class="filter-select" id="moduleFilter">
          <option value="ALL">${esc(t.filterAllModules)}</option>
          ${moduleOptions}
        </select>
      </div>
      <div class="filter-count" id="filterCount" data-tpl="${esc(t.filterCountTpl)}"></div>
    </div>`;
  }
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>${esc(t.trendTitle)}</h2>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.findingsBySeverity)}</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.securityScore)}</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }
  const isModuleDisabled = (m) => {
    if (!m.warnings?.length) return void 0;
    const w = m.warnings.find(
      (w2) => SERVICE_NOT_ENABLED_PATTERNS.some((p) => w2.includes(p))
    );
    return w;
  };
  const statsRows = modules.flatMap(
    (m) => {
      if (DETECTION_ONLY_MODULES.has(m.module)) return [];
      if (m.module === "security_hub_findings" && shSubCats.length > 0) {
        return shSubCats.map(
          (sc) => `<tr><td>${esc(sc.label)}</td><td>${m.resourcesScanned}</td><td>${sc.count}</td><td>&#10003;</td></tr>`
        );
      }
      const disabledWarning = isModuleDisabled(m);
      if (disabledWarning) {
        const rec = t.serviceRecommendations[m.module];
        const reason = rec ? rec.action : disabledWarning;
        return [`<tr><td>${esc(t.moduleNames[m.module] ?? m.module)}</td><td>-</td><td>-</td><td style="color:#eab308">&#9888; ${esc(reason)}</td></tr>`];
      }
      return [`<tr><td>${esc(t.moduleNames[m.module] ?? m.module)}</td><td>${m.resourcesScanned}</td><td>${m.findingsCount}</td><td>${m.status === "success" ? "&#10003;" : "&#10007;"}</td></tr>`];
    }
  ).join("\n");
  let recsHtml = "";
  if (summary.totalFindings > 0) {
    const recMap = /* @__PURE__ */ new Map();
    const kbPatches = [];
    let kbSeverity = "LOW";
    let kbUrl;
    const cveList = [];
    let cveSeverity = "LOW";
    let cveUrl;
    const genericPatterns = ["See References", "None Provided", "Review the finding", "Review and remediate."];
    for (const f of allFindings) {
      const rem = f.remediationSteps[0] ?? "Review and remediate.";
      const url = f.remediationSteps.find((s) => s.startsWith("Documentation:"))?.replace("Documentation: ", "");
      if (genericPatterns.some((p) => rem.startsWith(p))) continue;
      const kbMatch = f.title.match(/KB\d+/);
      if (kbMatch && (f.module === "security_hub_findings" || f.module === "inspector_findings")) {
        kbPatches.push(kbMatch[0]);
        if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(kbSeverity)) kbSeverity = f.severity;
        if (!kbUrl && url) kbUrl = url;
        continue;
      }
      const cveMatch = f.title.match(/CVE-[\d-]+/);
      if (cveMatch && (f.module === "security_hub_findings" || f.module === "inspector_findings")) {
        cveList.push(cveMatch[0]);
        if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(cveSeverity)) cveSeverity = f.severity;
        if (!cveUrl && url) cveUrl = url;
        continue;
      }
      if (f.module === "security_hub_findings") {
        const controlMatch = f.title.match(/^([A-Z][A-Za-z0-9]*\.\d+)\s/);
        if (controlMatch) {
          const controlId = controlMatch[1];
          const key = `ctrl:${controlId}`;
          const existing2 = recMap.get(key);
          if (existing2) {
            existing2.count++;
            if (!existing2.url && url) existing2.url = url;
            if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing2.severity)) existing2.severity = f.severity;
          } else {
            recMap.set(key, { text: `[${controlId}] ${rem}`, severity: f.severity, count: 1, url });
          }
          continue;
        }
      }
      if (f.module !== "security_hub_findings" && f.module !== "inspector_findings") {
        const template = getRecommendationTemplate(rem);
        if (template !== rem) {
          const templateKey = `tmpl:${f.module}:${template}`;
          const existingTmpl = recMap.get(templateKey);
          if (existingTmpl) {
            existingTmpl.count++;
            if (!existingTmpl.url && url) existingTmpl.url = url;
            if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existingTmpl.severity)) {
              existingTmpl.severity = f.severity;
            }
            continue;
          }
          recMap.set(templateKey, { text: rem, severity: f.severity, count: 1, url });
          continue;
        }
      }
      const existing = recMap.get(rem);
      if (existing) {
        existing.count++;
        if (!existing.url && url) existing.url = url;
        if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing.severity)) {
          existing.severity = f.severity;
        }
      } else {
        recMap.set(rem, { text: rem, severity: f.severity, count: 1, url });
      }
    }
    if (kbPatches.length > 0) {
      const unique = [...new Set(kbPatches)];
      const kbList = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      recMap.set("__kb__", { text: t.installWindowsPatches(unique.length, kbList), severity: kbSeverity, count: 1, url: kbUrl });
    }
    if (cveList.length > 0) {
      const unique = [...new Set(cveList)];
      const cveDisplay = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      const cveText = (lang ?? "zh") === "zh" ? `\u4FEE\u590D ${unique.length} \u4E2A\u8F6F\u4EF6\u6F0F\u6D1E (${cveDisplay})\uFF0C\u66F4\u65B0\u53D7\u5F71\u54CD\u7684\u8F6F\u4EF6\u5305\u5230\u6700\u65B0\u7248\u672C` : `Fix ${unique.length} software vulnerabilities (${cveDisplay}) \u2014 update affected packages to latest patched versions`;
      recMap.set("__cve__", { text: cveText, severity: cveSeverity, count: 1, url: cveUrl });
    }
    for (const [key, rec] of recMap) {
      if ((key.startsWith("ctrl:") || key.startsWith("tmpl:")) && rec.count > 1) {
        rec.text += ` \u2014 ${t.affectedResources(rec.count)}`;
        rec.count = 1;
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
      const linkHtml = r.url ? ` <a href="${esc(r.url)}" style="color:#60a5fa" target="_blank" rel="noopener">&#128214;</a>` : "";
      return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}${linkHtml}</li>`;
    };
    const TOP_N = 10;
    const topItems = uniqueRecs.slice(0, TOP_N).map(renderRec).join("\n");
    const remaining = uniqueRecs.slice(TOP_N);
    const moreHtml = remaining.length > 0 ? `
<details><summary>${t.showMoreCount(remaining.length)}</summary>
${remaining.map(renderRec).join("\n")}
</details>` : "";
    recsHtml = `
      <details class="rec-fold">
        <summary><h2 style="margin:0;border:0;display:inline">${esc(t.recommendations)} (${uniqueRecs.length} ${esc(t.unique)})</h2></summary>
        <div class="rec-body">
          <ol>${topItems}${moreHtml}</ol>
        </div>
      </details>`;
  }
  const filterScript = summary.totalFindings > 0 ? `<script>
(function(){
  var activeSev='ALL',activeMod='ALL';
  var countEl=document.getElementById('filterCount');
  var tpl=countEl?countEl.getAttribute('data-tpl'):'';
  function apply(){
    var cards=document.querySelectorAll('.finding-card[data-severity]');
    var shown=0,total=cards.length;
    cards.forEach(function(c){
      var sevOk=activeSev==='ALL'||c.getAttribute('data-severity')===activeSev;
      var modOk=activeMod==='ALL'||c.getAttribute('data-module')===activeMod;
      c.style.display=(sevOk&&modOk)?'':'none';
      if(sevOk&&modOk)shown++;
    });
    if(countEl)countEl.textContent=tpl.replace('{shown}',shown).replace('{total}',total);
    document.querySelectorAll('.module-fold').forEach(function(f){
      var mod=f.getAttribute('data-module');
      if(activeMod!=='ALL'&&mod!==activeMod){f.style.display='none';return;}
      f.style.display='';
    });
    document.querySelectorAll('.severity-group-fold').forEach(function(g){
      g.style.display=g.querySelectorAll('.finding-card:not([style*="display: none"])').length?'':'none';
    });
  }
  document.querySelectorAll('.filter-btn[data-severity]').forEach(function(b){
    b.addEventListener('click',function(){
      document.querySelectorAll('.filter-btn[data-severity]').forEach(function(x){x.classList.remove('active')});
      b.classList.add('active');
      activeSev=b.getAttribute('data-severity');
      apply();
    });
  });
  var sel=document.getElementById('moduleFilter');
  if(sel)sel.addEventListener('change',function(){activeMod=sel.value;apply();});
  apply();
})();
</script>` : "";
  return `<!DOCTYPE html>
<html lang="${htmlLang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(t.securityReportTitle)} &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; ${esc(t.securityReportTitle)}</h1>
  <div class="meta">${esc(t.account)}: ${esc(accountId)} | ${esc(t.region)}: ${esc(region)} | ${esc(date)} | ${esc(t.duration)}: ${esc(duration)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${scoreColor(score)}">${score}</div>
    <div class="score-label">${esc(t.securityScore)}</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card stat-critical"><div class="stat-count">${summary.critical}</div><div class="stat-label">${esc(t.critical)}</div></div>
    <div class="stat-card stat-high"><div class="stat-count">${summary.high}</div><div class="stat-label">${esc(t.high)}</div></div>
    <div class="stat-card stat-medium"><div class="stat-count">${summary.medium}</div><div class="stat-label">${esc(t.medium)}</div></div>
    <div class="stat-card stat-low"><div class="stat-count">${summary.low}</div><div class="stat-label">${esc(t.low)}</div></div>
  </div>
</section>

<section class="charts">
  <div class="chart-box">
    <div class="chart-title">${esc(t.severityDistribution)}</div>
    <div style="text-align:center">${donutChart(summary)}</div>
  </div>
  <div class="chart-box">
    <div class="chart-title">${esc(t.findingsByModule)}</div>
    ${barChart(barChartModules, t.allModulesClean)}
  </div>
</section>

${trendHtml}

${top5Html}

${buildServiceReminderHtml(modules, lang)}

<section>
  <h2>${esc(t.scanStatistics)}</h2>
  <table>
    <thead><tr><th>${esc(t.module)}</th><th>${esc(t.resources)}</th><th>${esc(t.findings)}</th><th>${esc(t.status)}</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
</section>

<section>
  <h2>${esc(t.allFindings)}</h2>
  ${filterToolbarHtml}
  ${findingsHtml}
</section>

${recsHtml}

<footer>
  <p>${esc(t.generatedBy)} v${VERSION}</p>
  <p>${esc(t.informationalOnly)}</p>
</footer>

</div>
${filterScript}
</body>
</html>`;
}
function generateMlps3HtmlReport(scanResults, history, lang) {
  const t = getI18n(lang ?? "zh");
  const htmlLang = (lang ?? "zh") === "zh" ? "zh-CN" : "en";
  const { accountId, region, scanStart } = scanResults;
  const date = scanStart.split("T")[0];
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const results = evaluateAllFullChecks(scanResults);
  const autoResults = results.filter((r) => r.mapping.type === "auto");
  const autoClean = autoResults.filter((r) => r.status === "clean").length;
  const autoIssues = autoResults.filter((r) => r.status === "issues").length;
  const autoUnknown = autoResults.filter((r) => r.status === "unknown").length;
  const checkedTotal = autoClean + autoIssues;
  const cloudCount = results.filter((r) => r.status === "cloud_provider").length;
  const manualCount = results.filter((r) => r.status === "manual").length;
  const naCount = results.filter((r) => r.status === "not_applicable").length;
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>${esc(t.trendTitle)}</h2>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.findingsBySeverity)}</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.securityScore)}</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }
  const isEn = (lang ?? "zh") === "en";
  const itemCat = (r) => isEn ? r.item.categoryEn : r.item.categoryCn;
  const itemControl = (r) => isEn ? r.item.controlEn : r.item.controlCn;
  const itemReq = (r) => isEn ? r.item.requirementEn : r.item.requirementCn;
  const categoryMap = /* @__PURE__ */ new Map();
  for (const r of results) {
    if (r.status === "not_applicable") continue;
    const cat = r.item.categoryCn;
    if (!categoryMap.has(cat)) categoryMap.set(cat, []);
    categoryMap.get(cat).push(r);
  }
  const categorySections = MLPS3_CATEGORY_ORDER.map((category) => {
    const sectionTitle = t.mlpsCategorySection[category] ?? category;
    const catResults = categoryMap.get(category);
    if (!catResults || catResults.length === 0) return "";
    const allCloud = catResults.every((r) => r.status === "cloud_provider");
    if (allCloud) {
      return `<details class="category-fold mlps-cloud-section">
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats"><span class="category-stat-cloud">\u{1F3E2} ${catResults.length} ${esc(t.cloudProvider)}</span></span>
  </summary>
  <div class="category-body">
    <div class="mlps-cloud-note">${esc(t.cloudItemsNote(catResults.length))}</div>
    ${catResults.map((r) => `<div class="check-item check-cloud"><span class="check-icon">\u{1F3E2}</span><span class="check-name">${esc(r.item.id)} ${esc(itemControl(r))}</span><span class="check-note">${esc(r.mapping.note ?? "")}</span></div>`).join("\n")}
  </div>
</details>`;
    }
    const catClean = catResults.filter((r) => r.status === "clean").length;
    const catIssues = catResults.filter((r) => r.status === "issues").length;
    const catUnknown = catResults.filter((r) => r.status === "unknown").length;
    const catCloud = catResults.filter((r) => r.status === "cloud_provider").length;
    const catManual = catResults.filter((r) => r.status === "manual").length;
    const statsHtml = [
      catClean > 0 ? `<span class="category-stat-clean">\u{1F7E2} ${catClean}</span>` : "",
      catIssues > 0 ? `<span class="category-stat-issues">\u{1F534} ${catIssues}</span>` : "",
      catUnknown > 0 ? `<span class="category-stat-unknown">? ${catUnknown}</span>` : "",
      catCloud > 0 ? `<span class="category-stat-cloud">\u{1F3E2} ${catCloud}</span>` : "",
      catManual > 0 ? `<span class="category-stat-manual">\u{1F4CB} ${catManual}</span>` : ""
    ].filter(Boolean).join("");
    const controlMap = /* @__PURE__ */ new Map();
    for (const r of catResults) {
      const key = r.item.controlCn;
      if (!controlMap.has(key)) controlMap.set(key, []);
      controlMap.get(key).push(r);
    }
    const controlGroups = [...controlMap.entries()].map(([_controlKey, controlResults]) => {
      const controlName = itemControl(controlResults[0]);
      const cloudItems = controlResults.filter((r) => r.status === "cloud_provider");
      const nonCloudItems = controlResults.filter((r) => r.status !== "cloud_provider");
      let itemsHtml = "";
      for (const r of nonCloudItems) {
        const icon = r.status === "clean" ? "\u{1F7E2}" : r.status === "issues" ? "\u{1F534}" : r.status === "unknown" ? "\u2B1C" : r.status === "manual" ? "\u{1F4CB}" : "\u{1F3E2}";
        const cls = `check-${r.status === "cloud_provider" ? "cloud" : r.status}`;
        const suffix = r.status === "unknown" ? ` \u2014 ${esc(t.notChecked)}` : r.status === "manual" ? ` \u2014 ${esc(r.mapping.guidance ?? t.manualReview)}` : "";
        let findingsDetail = "";
        if (r.status === "clean") {
          findingsDetail = `<div class="check-detail">${esc(t.noRelatedIssues)}</div>`;
        } else if (r.status === "issues" && r.relatedFindings.length > 0) {
          const fItems = r.relatedFindings.slice(0, 5).map((f) => `<li>${esc(f.severity)}: ${esc(f.title)}</li>`);
          if (r.relatedFindings.length > 5) {
            fItems.push(`<li>${esc(t.andMore(r.relatedFindings.length - 5))}</li>`);
          }
          const remediationHint = r.relatedFindings[0]?.remediationSteps?.[0] ? `<p style="color:#fbbf24;font-size:12px;margin-top:4px">${esc(t.remediation)}\uFF1A${escWithLinks(r.relatedFindings[0].remediationSteps[0])}</p>` : "";
          findingsDetail = `<div class="check-findings-wrap"><details><summary>${esc(t.issuesFoundCount(r.relatedFindings.length))}</summary><ul class="check-findings">${fItems.join("")}</ul>${remediationHint}</details></div>`;
        }
        const reqText = itemReq(r);
        itemsHtml += `<div class="check-item ${cls}"><span class="check-icon">${icon}</span><span class="check-name">${esc(r.item.id)} ${esc(reqText.slice(0, 60))}${reqText.length > 60 ? "\u2026" : ""}${suffix}</span></div>
${findingsDetail}`;
      }
      if (cloudItems.length > 0) {
        for (const r of cloudItems) {
          const reqText = itemReq(r);
          itemsHtml += `<div class="check-item check-cloud"><span class="check-icon">\u{1F3E2}</span><span class="check-name">${esc(r.item.id)} ${esc(reqText.slice(0, 50))}${reqText.length > 50 ? "\u2026" : ""}</span><span class="check-note">${esc(t.cloudProvider)}</span></div>
`;
        }
      }
      const grpClean = controlResults.filter((r) => r.status === "clean").length;
      const grpIssues = controlResults.filter((r) => r.status === "issues").length;
      const grpUnknown = controlResults.filter((r) => r.status === "unknown").length;
      const grpCloud = controlResults.filter((r) => r.status === "cloud_provider").length;
      const grpManual = controlResults.filter((r) => r.status === "manual").length;
      const grpStats = [
        grpClean > 0 ? `<span class="category-stat-clean">\u{1F7E2} ${grpClean}</span>` : "",
        grpIssues > 0 ? `<span class="category-stat-issues">\u{1F534} ${grpIssues}</span>` : "",
        grpUnknown > 0 ? `<span class="category-stat-unknown">? ${grpUnknown}</span>` : "",
        grpCloud > 0 ? `<span class="category-stat-cloud">\u{1F3E2} ${grpCloud}</span>` : "",
        grpManual > 0 ? `<span class="category-stat-manual">\u{1F4CB} ${grpManual}</span>` : ""
      ].filter(Boolean).join(" ");
      const hasFailures = grpIssues > 0;
      return `<details class="severity-group-fold"${hasFailures ? " open" : ""}><summary><h4>${esc(controlName)} <span class="category-stats">${grpStats}</span></h4></summary>
${itemsHtml}
</details>`;
    }).join("\n");
    return `<details class="category-fold">
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats">${statsHtml}</span>
  </summary>
  <div class="category-body">${controlGroups}</div>
</details>`;
  }).filter(Boolean).join("\n");
  const failedResults = results.filter((r) => r.status === "issues");
  let remediationHtml = "";
  if (failedResults.length > 0) {
    const mlpsRecMap = /* @__PURE__ */ new Map();
    const mlpsKbPatches = [];
    let mlpsKbSeverity = "LOW";
    let mlpsKbUrl;
    const mlpsCveList = [];
    let mlpsCveSeverity = "LOW";
    let mlpsCveUrl;
    const mlpsGenericPatterns = ["See References", "None Provided", "Review the finding", "Review and remediate."];
    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const rem = f.remediationSteps[0] ?? "Review and remediate.";
        const url = f.remediationSteps.find((s) => s.startsWith("Documentation:"))?.replace("Documentation: ", "");
        if (mlpsGenericPatterns.some((p) => rem.startsWith(p))) continue;
        const kbMatch = f.title.match(/KB\d+/);
        if (kbMatch && (f.module === "security_hub_findings" || f.module === "inspector_findings")) {
          mlpsKbPatches.push(kbMatch[0]);
          if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(mlpsKbSeverity)) mlpsKbSeverity = f.severity;
          if (!mlpsKbUrl && url) mlpsKbUrl = url;
          continue;
        }
        const cveMatch = f.title.match(/CVE-[\d-]+/);
        if (cveMatch) {
          mlpsCveList.push(cveMatch[0]);
          if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(mlpsCveSeverity)) mlpsCveSeverity = f.severity;
          if (!mlpsCveUrl && url) mlpsCveUrl = url;
          continue;
        }
        if (f.module === "security_hub_findings") {
          const controlMatch = f.title.match(/^([A-Z][A-Za-z0-9]*\.\d+)\s/);
          if (controlMatch) {
            const controlId = controlMatch[1];
            const key = `ctrl:${controlId}`;
            const existing2 = mlpsRecMap.get(key);
            if (existing2) {
              existing2.count++;
              if (!existing2.url && url) existing2.url = url;
              if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing2.severity)) existing2.severity = f.severity;
            } else {
              mlpsRecMap.set(key, { text: `[${controlId}] ${rem}`, severity: f.severity, count: 1, url });
            }
            continue;
          }
        }
        if (f.module !== "security_hub_findings" && f.module !== "inspector_findings") {
          const template = getRecommendationTemplate(rem);
          if (template !== rem) {
            const templateKey = `tmpl:${f.module}:${template}`;
            const existingTmpl = mlpsRecMap.get(templateKey);
            if (existingTmpl) {
              existingTmpl.count++;
              if (!existingTmpl.url && url) existingTmpl.url = url;
              if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existingTmpl.severity)) {
                existingTmpl.severity = f.severity;
              }
              continue;
            }
            mlpsRecMap.set(templateKey, { text: rem, severity: f.severity, count: 1, url });
            continue;
          }
        }
        const existing = mlpsRecMap.get(rem);
        if (existing) {
          existing.count++;
          if (!existing.url && url) existing.url = url;
          if (SEVERITY_ORDER2.indexOf(f.severity) < SEVERITY_ORDER2.indexOf(existing.severity)) {
            existing.severity = f.severity;
          }
        } else {
          mlpsRecMap.set(rem, { text: rem, severity: f.severity, count: 1, url });
        }
      }
    }
    if (mlpsKbPatches.length > 0) {
      const unique = [...new Set(mlpsKbPatches)];
      const kbList = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      mlpsRecMap.set("__kb__", { text: t.installWindowsPatches(unique.length, kbList), severity: mlpsKbSeverity, count: 1, url: mlpsKbUrl });
    }
    if (mlpsCveList.length > 0) {
      const unique = [...new Set(mlpsCveList)];
      const cveDisplay = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      const cveText = (lang ?? "zh") === "zh" ? `\u4FEE\u590D ${unique.length} \u4E2A\u8F6F\u4EF6\u6F0F\u6D1E (${cveDisplay})\uFF0C\u66F4\u65B0\u53D7\u5F71\u54CD\u7684\u8F6F\u4EF6\u5305\u5230\u6700\u65B0\u7248\u672C` : `Fix ${unique.length} software vulnerabilities (${cveDisplay}) \u2014 update affected packages to latest patched versions`;
      mlpsRecMap.set("__cve__", { text: cveText, severity: mlpsCveSeverity, count: 1, url: mlpsCveUrl });
    }
    for (const [key, rec] of mlpsRecMap) {
      if ((key.startsWith("ctrl:") || key.startsWith("tmpl:")) && rec.count > 1) {
        rec.text += ` \u2014 ${t.affectedResources(rec.count)}`;
        rec.count = 1;
      }
    }
    const mlpsUniqueRecs = [...mlpsRecMap.values()].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER2.indexOf(a.severity) - SEVERITY_ORDER2.indexOf(b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });
    if (mlpsUniqueRecs.length > 0) {
      const renderMlpsRec = (r) => {
        const sev = r.severity.toLowerCase();
        const countLabel = r.count > 1 ? ` (&times; ${r.count})` : "";
        const linkHtml = r.url ? ` <a href="${esc(r.url)}" style="color:#60a5fa" target="_blank" rel="noopener">&#128214;</a>` : "";
        return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}${linkHtml}</li>`;
      };
      const MLPS_TOP_N = 10;
      const mlpsTopItems = mlpsUniqueRecs.slice(0, MLPS_TOP_N).map(renderMlpsRec).join("\n");
      const mlpsRemaining = mlpsUniqueRecs.slice(MLPS_TOP_N);
      const mlpsMoreHtml = mlpsRemaining.length > 0 ? `
<details><summary>${esc(t.showRemaining(mlpsRemaining.length))}&hellip;</summary>
${mlpsRemaining.map(renderMlpsRec).join("\n")}
</details>` : "";
      remediationHtml = `
        <details class="rec-fold" open>
          <summary><h2 style="margin:0;border:0;display:inline">${esc(t.remediationItems(mlpsUniqueRecs.length))}</h2></summary>
          <div class="rec-body">
            <ol>${mlpsTopItems}${mlpsMoreHtml}</ol>
          </div>
        </details>`;
    }
  }
  const naNote = naCount > 0 ? `<p style="color:#64748b;font-size:13px;margin-top:24px">${esc(t.naNote(naCount))}</p>` : "";
  const unknownNote = autoUnknown > 0 ? `<div style="color:#94a3b8;font-size:12px;margin-top:8px">${esc(t.unknownNote(autoUnknown))}</div>` : "";
  const mlpsCss = `
    .mlps-cloud-section>summary{color:#94a3b8}
    .mlps-cloud-note{color:#94a3b8;font-size:13px;margin-bottom:12px;font-style:italic}
    .check-cloud{background:rgba(148,163,184,0.08)}
    .check-cloud .check-note{color:#64748b;font-size:12px;margin-left:auto;white-space:nowrap}
    .check-manual{background:rgba(148,163,184,0.06)}
    .check-clean{background:rgba(34,197,94,0.1);border-left:3px solid #22c55e}
    .check-issues{background:rgba(239,68,68,0.1);border-left:3px solid #ef4444}
    .check-unknown{background:rgba(148,163,184,0.1);border-left:3px solid #94a3b8}
    .check-findings-wrap{margin-left:28px;margin-bottom:4px}
    .check-detail{color:#94a3b8;font-size:13px;margin-left:28px;margin-top:2px}
    .category-stat-clean{color:#22c55e}
    .category-stat-issues{color:#ef4444}
    .category-stat-cloud{color:#94a3b8}
    .category-stat-manual{color:#94a3b8}
    .mlps-summary-cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px}
    .mlps-summary-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px 20px;text-align:center;min-width:100px;flex:1}
    .mlps-summary-card .stat-count{font-size:28px;font-weight:700}
    .mlps-summary-card .stat-label{font-size:12px;color:#94a3b8;margin-top:2px}
  `;
  return `<!DOCTYPE html>
<html lang="${htmlLang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(t.mlpsTitle)} &mdash; ${esc(date)}</title>
<style>${sharedCss()}${mlpsCss}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; ${esc(t.mlpsTitle)}</h1>
  <div class="disclaimer">${esc(t.mlpsDisclaimer)}</div>
  <div class="meta">${esc(t.account)}: ${esc(accountId)} | ${esc(t.region)}: ${esc(region)} | ${esc(t.scanTime)}: ${esc(scanTime)}</div>
</header>

<section class="summary" style="display:block;text-align:center">
  <div style="font-size:36px;font-weight:700;margin-bottom:12px">
    <span style="color:#22c55e">${autoClean}</span> <span style="color:#94a3b8;font-size:18px">${esc(t.noIssues)}</span>
    <span style="color:#475569;margin:0 16px">/</span>
    <span style="color:#ef4444">${autoIssues}</span> <span style="color:#94a3b8;font-size:18px">${esc(t.issuesFound)}</span>
  </div>
  <div class="mlps-summary-cards" style="justify-content:center">
    <div class="mlps-summary-card"><div class="stat-count" style="color:#60a5fa">${checkedTotal}</div><div class="stat-label">${esc(t.checkedItems)}</div></div>
    <div class="mlps-summary-card"><div class="stat-count" style="color:#94a3b8">${cloudCount}</div><div class="stat-label">\u{1F3E2} ${esc(t.cloudProvider)}</div></div>
    <div class="mlps-summary-card"><div class="stat-count" style="color:#eab308">${manualCount}</div><div class="stat-label">\u{1F4CB} ${esc(t.manualReview)}</div></div>
    ${naCount > 0 ? `<div class="mlps-summary-card"><div class="stat-count" style="color:#64748b">${naCount}</div><div class="stat-label">\u2796 ${esc(t.notApplicable)}</div></div>` : ""}
  </div>
</section>
${unknownNote}

${trendHtml}

${buildServiceReminderHtml(scanResults.modules, lang)}

${categorySections}

${remediationHtml}

${naNote}

<footer>
  <p>${esc(t.mlpsFooterGenerated(VERSION))}</p>
  <p>${esc(t.mlpsFooterDisclaimer)}</p>
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
- CloudTrail detection is included for coverage metrics.

### Maturity Levels
| Enabled Services | Level |
|------------------|-------|
| 0\u20131 | Basic |
| 2\u20133 | Intermediate |
| 4   | Advanced |
| 5   | Comprehensive |

## 2. Security Hub Findings (security_hub_findings)
Aggregates active findings from AWS Security Hub. Replaces individual config scanners (SG, S3, IAM, CloudTrail, RDS, EBS, VPC, etc.) with centralized compliance checks from FSBP, CIS, and PCI DSS standards.
- Findings are filtered to ACTIVE + NEW/NOTIFIED workflow status.
- Severity mapped: CRITICAL \u2192 9.5, HIGH \u2192 8.0, MEDIUM \u2192 5.5, LOW \u2192 3.0.
- INFORMATIONAL findings are skipped.

## 3. GuardDuty Findings (guardduty_findings)
Detection-only: checks if GuardDuty is enabled in the region.
- GuardDuty findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether GuardDuty detectors are active.

## 4. Inspector Findings (inspector_findings)
Detection-only: checks if Inspector is enabled in the region.
- Inspector findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether Inspector scanning (EC2/Lambda) is active.

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
Detection-only: checks if AWS Config Rules are configured.
- Config Rule compliance findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether Config is enabled and counts active rules.
- Gracefully handles regions where AWS Config is not enabled.

## 16. IAM Access Analyzer Findings (access_analyzer_findings)
Detection-only: checks if IAM Access Analyzer is configured.
- Access Analyzer findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether active analyzers exist.
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
  service_detection: "Detects which AWS security services (Security Hub, GuardDuty, Inspector, Config) are enabled and assesses security maturity.",
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
  guardduty_findings: "Checks if GuardDuty is enabled. Findings are aggregated via Security Hub.",
  inspector_findings: "Checks if Inspector is enabled. Findings are aggregated via Security Hub.",
  trusted_advisor_findings: "Aggregates security checks from AWS Trusted Advisor \u2014 requires Business or Enterprise Support plan.",
  config_rules_findings: "Checks if AWS Config Rules are configured. Findings are aggregated via Security Hub.",
  access_analyzer_findings: "Checks if IAM Access Analyzer is configured. Findings are aggregated via Security Hub.",
  patch_compliance_findings: "Checks SSM Patch Manager compliance \u2014 managed instances with missing or failed security and system patches.",
  imdsv2_enforcement: "Checks if EC2 instances enforce IMDSv2 (HttpTokens: required) \u2014 IMDSv1 allows credential theft via SSRF.",
  waf_coverage: "Checks if internet-facing ALBs have WAF Web ACL associated for protection against common web exploits."
};
function getHwDefenseChecklist(lang) {
  return getI18n(lang ?? "zh").hwChecklist;
}
var SERVICE_NOT_ENABLED_PATTERNS2 = [
  "not enabled",
  "not found",
  "No IAM Access Analyzer",
  "No SSM-managed instances",
  "requires AWS Business or Enterprise Support",
  "not available",
  "is not enabled"
];
function buildServiceReminder(modules, lang) {
  const t = getI18n(lang ?? "zh");
  const disabledServices = [];
  for (const mod of modules) {
    const rec = t.serviceRecommendations[mod.module];
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
    t.serviceReminderTitle,
    ""
  ];
  for (const svc of disabledServices) {
    lines.push(`${svc.icon} ${svc.service} ${t.notEnabled}`);
    lines.push(`   ${t.serviceImpact}: ${svc.impact}`);
    lines.push(`   ${t.serviceAction}: ${svc.action}`);
    lines.push("");
  }
  lines.push(t.serviceReminderFooter);
  return lines.join("\n");
}
function summarizeResult(result, lang) {
  const { summary } = result;
  const lines = [
    `Scan complete for account ${result.accountId} in ${result.region}.`,
    `Total findings: ${summary.totalFindings} (${summary.critical} Critical, ${summary.high} High, ${summary.medium} Medium, ${summary.low} Low)`,
    `Modules: ${summary.modulesSuccess} succeeded, ${summary.modulesError} errored`
  ];
  const reminder = buildServiceReminder(result.modules, lang);
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
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ region, org_mode, role_name, account_ids, lang }) => {
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
            { type: "text", text: summarizeResult(result, lang ?? "zh") },
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
      account_ids: z.array(z.string()).optional().describe("Specific account IDs to scan (default: all org accounts)"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ group, region, org_mode, role_name, account_ids, lang }) => {
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
          summarizeResult(result, lang ?? "zh")
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
            summaryContent.text += "\n\n" + getHwDefenseChecklist(lang ?? "zh");
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
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ scan_results, lang }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const report = generateMarkdownReport(parsed, lang ?? "zh");
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_mlps3_report",
    "Generate a GB/T 22239-2019 \u7B49\u4FDD\u4E09\u7EA7 compliance pre-check report from scan results. Best used with scan_group mlps3_precheck results. Read-only.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_group mlps3_precheck or scan_all"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ scan_results, lang }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const report = generateMlps3Report(parsed, lang ?? "zh");
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
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ scan_results, history, lang }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : void 0;
        const report = generateHtmlReport(parsed, historyData, lang ?? "zh");
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
      history: z.string().optional().describe("JSON string of DashboardHistoryEntry[] from dashboard data.json for 30-day trend charts"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
    async ({ scan_results, history, lang }) => {
      try {
        const parsed = JSON.parse(scan_results);
        const historyData = history ? JSON.parse(history) : void 0;
        const report = generateMlps3HtmlReport(parsed, historyData, lang ?? "zh");
        return { content: [{ type: "text", text: report }] };
      } catch (err) {
        return { content: [{ type: "text", text: `Error: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
      }
    }
  );
  server.tool(
    "generate_maturity_report",
    "Generate a security maturity assessment report from scan_all results. Requires service_detection module output. Read-only.",
    {
      scan_results: z.string().describe("JSON string of FullScanResult from scan_all"),
      lang: z.enum(["zh", "en"]).optional().describe("Report language (default: zh)")
    },
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
          "AWS Config": "Configuration tracking"
        };
        const serviceFreeTrials = {
          "Security Hub": true,
          "GuardDuty": true,
          "Inspector": true
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
          const priorityOrder = ["Security Hub", "GuardDuty", "Inspector", "AWS Config", "CloudTrail"];
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
            advanced: { level: "Comprehensive", target: 5, suggestions: ["CloudTrail"] }
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

${getHwDefenseChecklist("zh")}

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
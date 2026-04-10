/**
 * Integration smoke test — runs all 7 scanners against a real AWS account.
 * Usage: npx tsx tests/integration/smoke-test.ts
 */
import { writeFileSync } from "node:fs";

import { SgScanner } from "../../src/scanners/sg.js";
import { S3Scanner } from "../../src/scanners/s3.js";
import { IamScanner } from "../../src/scanners/iam.js";
import { CloudTrailScanner } from "../../src/scanners/cloudtrail.js";
import { RdsScanner } from "../../src/scanners/rds.js";
import { EbsScanner } from "../../src/scanners/ebs.js";
import { VpcScanner } from "../../src/scanners/vpc.js";
import { runAllScanners } from "../../src/scanners/runner.js";
import { generateMarkdownReport } from "../../src/tools/report-tool.js";

const REGION = "ap-northeast-1";
const REPORT_PATH = "/tmp/security-report.md";

async function main() {
  console.log(`\n=== AWS Security MCP — Integration Smoke Test ===`);
  console.log(`Region : ${REGION}`);
  console.log(`Time   : ${new Date().toISOString()}\n`);

  const scanners = [
    new SgScanner(),
    new S3Scanner(),
    new IamScanner(),
    new CloudTrailScanner(),
    new RdsScanner(),
    new EbsScanner(),
    new VpcScanner(),
  ];

  console.log(`Running ${scanners.length} scanners…\n`);

  const result = await runAllScanners(scanners, REGION);

  // Per-module status
  for (const m of result.modules) {
    const tag = m.status === "success" ? "OK" : "ERR";
    const detail =
      m.status === "success"
        ? `${m.resourcesScanned} resources, ${m.findingsCount} findings`
        : m.error;
    console.log(`  [${tag}] ${m.module.padEnd(16)} ${detail}`);
  }

  // Summary
  const s = result.summary;
  console.log(`\n--- Summary ---`);
  console.log(`Account          : ${result.accountId}`);
  console.log(`Total findings   : ${s.totalFindings}`);
  console.log(`  CRITICAL       : ${s.critical}`);
  console.log(`  HIGH           : ${s.high}`);
  console.log(`  MEDIUM         : ${s.medium}`);
  console.log(`  LOW            : ${s.low}`);
  console.log(`Modules OK       : ${s.modulesSuccess}/${scanners.length}`);
  console.log(`Modules error    : ${s.modulesError}/${scanners.length}`);

  // Generate markdown report
  const report = generateMarkdownReport(result);
  writeFileSync(REPORT_PATH, report, "utf-8");
  console.log(`\nReport saved to  : ${REPORT_PATH} (${report.length} chars)`);

  if (s.modulesError > 0) {
    console.log(`\n⚠  ${s.modulesError} module(s) returned errors — review output above.`);
  }

  console.log(`\nIntegration test PASSED`);
}

main().catch((err) => {
  console.error("\nIntegration test FAILED:", err);
  process.exit(1);
});

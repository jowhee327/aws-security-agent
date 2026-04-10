import { runAllScanners } from '../../src/scanners/runner.js';
import { SgScanner } from '../../src/scanners/sg.js';
import { S3Scanner } from '../../src/scanners/s3.js';
import { IamScanner } from '../../src/scanners/iam.js';
import { CloudTrailScanner } from '../../src/scanners/cloudtrail.js';
import { RdsScanner } from '../../src/scanners/rds.js';
import { EbsScanner } from '../../src/scanners/ebs.js';
import { VpcScanner } from '../../src/scanners/vpc.js';
import { ServiceDetectionScanner } from '../../src/scanners/service-detection.js';
import { saveResults } from '../../src/tools/save-results.js';
import { generateMarkdownReport } from '../../src/tools/report-tool.js';
import { writeFileSync } from 'node:fs';

const region = process.argv[2] || 'ap-northeast-1';

async function main() {
  console.log(`=== AWS Security MCP — China Region Test ===`);
  console.log(`Region : ${region}`);
  console.log(`Time   : ${new Date().toISOString()}\n`);
  console.log('Running 8 scanners (including service detection)…\n');

  const scanners = [new SgScanner(), new S3Scanner(), new IamScanner(), new CloudTrailScanner(), new RdsScanner(), new EbsScanner(), new VpcScanner(), new ServiceDetectionScanner()];
  const result = await runAllScanners(scanners, region);

  for (const m of result.modules) {
    const icon = m.status === 'success' ? '[OK] ' : '[ERR]';
    const detail = m.status === 'success'
      ? `${m.resourcesScanned} resources, ${m.findingsCount} findings`
      : m.error ?? 'unknown error';
    console.log(`  ${icon} ${m.module.padEnd(17)} ${detail}`);
    if (m.warnings?.length) {
      for (const w of m.warnings) console.log(`       ⚠ ${w}`);
    }
  }

  console.log(`\n--- Summary ---`);
  console.log(`Account          : ${result.accountId}`);
  console.log(`Region           : ${result.region}`);
  console.log(`Partition        : ${region.startsWith('cn-') ? 'aws-cn' : 'aws'}`);
  console.log(`Total findings   : ${result.summary.totalFindings}`);
  console.log(`  CRITICAL       : ${result.summary.critical}`);
  console.log(`  HIGH           : ${result.summary.high}`);
  console.log(`  MEDIUM         : ${result.summary.medium}`);
  console.log(`  LOW            : ${result.summary.low}`);
  console.log(`Modules OK       : ${result.summary.modulesSuccess}/8`);
  console.log(`Modules error    : ${result.summary.modulesError}/8`);

  // Check ARN partition
  const sampleFindings = result.modules.flatMap(m => m.findings).slice(0, 3);
  if (sampleFindings.length > 0) {
    console.log(`\n--- ARN Partition Check ---`);
    for (const f of sampleFindings) {
      const partOk = region.startsWith('cn-') ? f.resourceArn.includes('aws-cn') : f.resourceArn.includes('arn:aws:');
      console.log(`  ${partOk ? '✅' : '❌'} ${f.resourceArn.substring(0, 60)}...`);
    }
  }

  // Save results
  const dataPath = saveResults(result);
  console.log(`\nDashboard data: ${dataPath}`);

  // Generate report
  const report = generateMarkdownReport(result);
  writeFileSync('/tmp/china-security-report.md', report);
  console.log(`Report: /tmp/china-security-report.md (${report.length} chars)`);
}

main().catch(console.error);

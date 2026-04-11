import { runAllScanners } from '../../src/scanners/runner.js';
import { ServiceDetectionScanner } from '../../src/scanners/service-detection.js';
import { SecretExposureScanner } from '../../src/scanners/secret-exposure.js';
import { NetworkReachabilityScanner } from '../../src/scanners/network-reachability.js';
import { IamPrivilegeEscalationScanner } from '../../src/scanners/iam-privilege-escalation.js';
import { SecurityHubFindingsScanner } from '../../src/scanners/security-hub-findings.js';
import { GuardDutyFindingsScanner } from '../../src/scanners/guardduty-findings.js';
import { InspectorFindingsScanner } from '../../src/scanners/inspector-findings.js';
import { saveResults } from '../../src/tools/save-results.js';
import { generateMarkdownReport } from '../../src/tools/report-tool.js';
import { writeFileSync } from 'node:fs';

const region = process.argv[2] || 'cn-north-1';

async function main() {
  console.log(`=== AWS Security MCP — China Region Test ===`);
  console.log(`Region : ${region}`);
  console.log(`Time   : ${new Date().toISOString()}\n`);

  const scanners = [
    new ServiceDetectionScanner(),
    new SecretExposureScanner(),
    new NetworkReachabilityScanner(),
    new IamPrivilegeEscalationScanner(),
    new SecurityHubFindingsScanner(),
    new GuardDutyFindingsScanner(),
    new InspectorFindingsScanner(),
  ];

  console.log(`Running ${scanners.length} scanners…\n`);
  const result = await runAllScanners(scanners, region);

  for (const m of result.modules) {
    const icon = m.status === 'success' ? '[OK] ' : '[ERR]';
    const detail = m.status === 'success'
      ? `${m.resourcesScanned} resources, ${m.findingsCount} findings`
      : m.error ?? 'unknown error';
    console.log(`  ${icon} ${m.module.padEnd(28)} ${detail}`);
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
  console.log(`Modules OK       : ${result.summary.modulesSuccess}/${scanners.length}`);
  console.log(`Modules error    : ${result.summary.modulesError}/${scanners.length}`);

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

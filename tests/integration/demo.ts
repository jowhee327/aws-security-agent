import { runAllScanners } from '../../src/scanners/runner.js';
import { ServiceDetectionScanner } from '../../src/scanners/service-detection.js';
import { SecretExposureScanner } from '../../src/scanners/secret-exposure.js';
import { NetworkReachabilityScanner } from '../../src/scanners/network-reachability.js';
import { IamPrivilegeEscalationScanner } from '../../src/scanners/iam-privilege-escalation.js';
import { SecurityHubFindingsScanner } from '../../src/scanners/security-hub-findings.js';
import { GuardDutyFindingsScanner } from '../../src/scanners/guardduty-findings.js';
import { saveResults } from '../../src/tools/save-results.js';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';

async function demo() {
  console.log('=== AWS Security MCP — Full Demo ===\n');

  console.log('Step 1: Running full security scan...');
  const scanners = [
    new ServiceDetectionScanner(),
    new SecretExposureScanner(),
    new NetworkReachabilityScanner(),
    new IamPrivilegeEscalationScanner(),
    new SecurityHubFindingsScanner(),
    new GuardDutyFindingsScanner(),
  ];
  const results = await runAllScanners(scanners, 'ap-northeast-1');

  console.log(`\nScan complete!`);
  console.log(`  Account: ${results.accountId}`);
  console.log(`  Region: ${results.region}`);
  console.log(`  Duration: ${new Date(results.scanEnd).getTime() - new Date(results.scanStart).getTime()}ms`);
  console.log(`  Findings: ${results.summary.totalFindings}`);
  console.log(`    Critical: ${results.summary.critical}`);
  console.log(`    High: ${results.summary.high}`);
  console.log(`    Medium: ${results.summary.medium}`);
  console.log(`    Low: ${results.summary.low}`);
  console.log(`  Modules: ${results.summary.modulesSuccess}/${scanners.length} success\n`);

  for (const m of results.modules) {
    const icon = m.status === 'success' ? 'OK' : 'ERR';
    console.log(`  [${icon}] ${m.module}: ${m.findingsCount} findings (${m.resourcesScanned} resources)`);
  }

  console.log('\nStep 2: Saving results for Dashboard...');
  const dataPath = saveResults(results);
  console.log(`  Dashboard data saved to: ${dataPath}`);

  console.log('\nStep 3: Copying data to Dashboard...');
  const dashboardDev = join(dirname(new URL(import.meta.url).pathname), '..', 'dashboard', 'public', 'data.json');
  const dashboardDist = join(dirname(new URL(import.meta.url).pathname), '..', 'dashboard', 'dist', 'data.json');

  copyFileSync(dataPath, dashboardDev);
  if (existsSync(dirname(dashboardDist))) {
    copyFileSync(dataPath, dashboardDist);
  }
  console.log('  Data copied to dashboard/public/ and dashboard/dist/');

  console.log('\n=== Demo Complete! ===');
  console.log('Run: node dist/bin/aws-security-mcp.js dashboard');
  console.log('Then open: http://localhost:3000');
}

demo().catch(console.error);

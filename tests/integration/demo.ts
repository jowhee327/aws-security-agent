import { runAllScanners } from '../../src/scanners/runner.js';
import { SgScanner } from '../../src/scanners/sg.js';
import { S3Scanner } from '../../src/scanners/s3.js';
import { IamScanner } from '../../src/scanners/iam.js';
import { CloudTrailScanner } from '../../src/scanners/cloudtrail.js';
import { RdsScanner } from '../../src/scanners/rds.js';
import { EbsScanner } from '../../src/scanners/ebs.js';
import { VpcScanner } from '../../src/scanners/vpc.js';
import { saveResults } from '../../src/tools/save-results.js';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';

async function demo() {
  console.log('=== AWS Security MCP — Full Demo ===\n');
  
  console.log('Step 1: Running full security scan...');
  const scanners = [new SgScanner(), new S3Scanner(), new IamScanner(), new CloudTrailScanner(), new RdsScanner(), new EbsScanner(), new VpcScanner()];
  const results = await runAllScanners(scanners, 'ap-northeast-1');
  
  console.log(`\nScan complete!`);
  console.log(`  Account: ${results.accountId}`);
  console.log(`  Region: ${results.region}`);
  console.log(`  Duration: ${new Date(results.scanEnd).getTime() - new Date(results.scanStart).getTime()}ms`);
  console.log(`  Findings: ${results.summary.totalFindings}`);
  console.log(`    🔴 Critical: ${results.summary.critical}`);
  console.log(`    🟠 High: ${results.summary.high}`);
  console.log(`    🟡 Medium: ${results.summary.medium}`);
  console.log(`    🟢 Low: ${results.summary.low}`);
  console.log(`  Modules: ${results.summary.modulesSuccess}/7 success\n`);
  
  for (const m of results.modules) {
    const icon = m.status === 'success' ? '✅' : '❌';
    console.log(`  ${icon} ${m.module}: ${m.findingsCount} findings (${m.resourcesScanned} resources)`);
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

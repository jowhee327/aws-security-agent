import { generateMlps3Report } from '../../src/tools/mlps-report.js';
import { readFileSync, writeFileSync } from 'node:fs';

const dataJson = readFileSync('/home/ubuntu/.aws-security/dashboard/data.json', 'utf-8');
const data = JSON.parse(dataJson);

const fakeResult = {
  scanStart: data.lastScan.scanStart,
  scanEnd: data.lastScan.scanEnd,
  region: data.lastScan.region,
  accountId: data.lastScan.accountId,
  modules: data.lastScan.modules.map((m: any) => ({
    ...m,
    scanTimeMs: 0,
    resourcesScanned: 0,
    findings: data.lastScan.findings.filter((f: any) => f.module === m.module),
  })),
  summary: data.lastScan.summary,
};

const report = generateMlps3Report(fakeResult as any);
writeFileSync('/tmp/mlps3-report.md', report);
console.log('MLPS report generated:', report.length, 'chars');
console.log('---');
console.log(report);

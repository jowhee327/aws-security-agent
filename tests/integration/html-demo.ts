import { generateHtmlReport } from '../../src/tools/html-report.js';
import { readFileSync, writeFileSync } from 'node:fs';

const dataJson = readFileSync('/home/ubuntu/.aws-security/dashboard/data.json', 'utf-8');
const data = JSON.parse(dataJson);

const result = {
  scanStart: data.lastScan.scanStart,
  scanEnd: data.lastScan.scanEnd,
  region: data.lastScan.region,
  accountId: data.lastScan.accountId,
  modules: data.lastScan.modules.map((m: any) => ({
    ...m,
    scanTimeMs: 100,
    resourcesScanned: m.findingsCount || 1,
    findings: data.lastScan.findings.filter((f: any) => f.module === m.module),
  })),
  summary: data.lastScan.summary,
};

const html = generateHtmlReport(result as any);
writeFileSync('/tmp/security-report.html', html);
console.log('HTML report:', html.length, 'chars');

import { FullScanResult, ScanResult, ScanContext } from "../types.js";
import { Scanner } from "./base.js";
import { getAccountId, getPartition } from "../utils/aws-client.js";

export async function runAllScanners(
  scanners: Scanner[],
  region: string,
): Promise<FullScanResult> {
  const scanStart = new Date().toISOString();

  // Best-effort accountId retrieval — don't let STS failure break the whole scan
  let accountId: string;
  try {
    accountId = await getAccountId(region);
  } catch {
    accountId = "unknown";
  }

  const partition = getPartition(region);
  const ctx: ScanContext = { region, partition, accountId };

  const settled = await Promise.allSettled(scanners.map((s) => s.scan(ctx)));

  const modules: ScanResult[] = settled.map((result, i) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    return {
      module: scanners[i].moduleName,
      status: "error" as const,
      error: result.reason instanceof Error ? result.reason.message : String(result.reason),
      resourcesScanned: 0,
      findingsCount: 0,
      scanTimeMs: 0,
      findings: [],
    };
  });

  const scanEnd = new Date().toISOString();

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
        case "CRITICAL": critical++; break;
        case "HIGH": high++; break;
        case "MEDIUM": medium++; break;
        case "LOW": low++; break;
      }
    }
  }

  return {
    scanStart,
    scanEnd,
    region,
    accountId,
    modules,
    summary: {
      totalFindings: critical + high + medium + low,
      critical,
      high,
      medium,
      low,
      modulesSuccess,
      modulesError,
    },
  };
}

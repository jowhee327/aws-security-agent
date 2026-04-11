import type { FullScanResult, Finding } from "../types.js";
import {
  MLPS3_FULL_CHECKLIST,
  MLPS3_CHECK_MAPPING,
  MLPS3_CATEGORY_ORDER,
  MLPS3_CATEGORY_SECTION,
  getMappingById,
  type MlpsChecklistItem,
  type MlpsCheckMapping,
} from "../data/mlps3-check-mapping.js";

// Re-export for use by html-report and tests
export {
  MLPS3_FULL_CHECKLIST,
  MLPS3_CHECK_MAPPING,
  MLPS3_CATEGORY_ORDER,
  MLPS3_CATEGORY_SECTION,
  getMappingById,
  type MlpsChecklistItem,
  type MlpsCheckMapping,
} from "../data/mlps3-check-mapping.js";

// ---------------------------------------------------------------------------
// Full-checklist evaluation result
// ---------------------------------------------------------------------------

export type FullCheckStatus = "clean" | "issues" | "unknown" | "cloud_provider" | "manual" | "not_applicable";

export interface FullCheckResult {
  item: MlpsChecklistItem;
  mapping: MlpsCheckMapping;
  status: FullCheckStatus;
  relatedFindings: Finding[];
}

/**
 * Evaluate a single checklist item against scan results.
 */
export function evaluateFullCheck(
  item: MlpsChecklistItem,
  mapping: MlpsCheckMapping,
  allFindings: Finding[],
  scanModules: Array<{ module: string; status: string }>,
): FullCheckResult {
  if (mapping.type === "cloud_provider") {
    return { item, mapping, status: "cloud_provider", relatedFindings: [] };
  }
  if (mapping.type === "not_applicable") {
    return { item, mapping, status: "not_applicable", relatedFindings: [] };
  }
  if (mapping.type === "manual") {
    return { item, mapping, status: "manual", relatedFindings: [] };
  }

  // Type "auto" — check modules present and evaluate findings
  const mods = mapping.modules ?? [];

  const allModulesPresent = mods.every((mod) =>
    scanModules.some((m) => m.module === mod && m.status === "success"),
  );

  if (!allModulesPresent) {
    return { item, mapping, status: "unknown", relatedFindings: [] };
  }

  let relatedFindings: Finding[];

  if (mapping.securityHubControlIds?.length) {
    // Hybrid: security_hub_findings filtered by specific control IDs,
    // other scanner modules matched at module level (all findings count)
    relatedFindings = allFindings.filter((f) => {
      if (!mods.includes(f.module ?? "")) return false;
      if (f.module === "security_hub_findings") {
        return mapping.securityHubControlIds!.some((id) => f.title.includes(id));
      }
      return true;
    });
  } else if (mapping.findingPatterns?.length) {
    // Pattern-based matching (for service_detection or other special cases)
    const patterns = mapping.findingPatterns;
    relatedFindings = allFindings.filter((f) => {
      if (!mods.includes(f.module ?? "")) return false;
      const text = `${f.title} ${f.description}`.toLowerCase();
      return patterns.some((pattern) => text.includes(pattern.toLowerCase()));
    });
  } else {
    // Module-level: any findings from mapped modules = fail
    relatedFindings = allFindings.filter((f) => mods.includes(f.module ?? ""));
  }

  // Evidence collection: clean (0 findings) or issues (1+ findings)
  const status: FullCheckStatus = relatedFindings.length === 0 ? "clean" : "issues";

  return { item, mapping, status, relatedFindings };
}

/**
 * Evaluate all 184 checks from the full GB/T 22239-2019 checklist.
 */
export function evaluateAllFullChecks(
  scanResults: FullScanResult,
): FullCheckResult[] {
  const allFindings: Finding[] = scanResults.modules.flatMap((m) =>
    m.findings.map((f) => ({ ...f, module: f.module ?? m.module })),
  );
  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status,
  }));

  return MLPS3_FULL_CHECKLIST.map((item) => {
    const mapping = getMappingById(item.id);
    if (!mapping) {
      // Unmapped check — treat as manual
      return {
        item,
        mapping: { id: item.id, type: "manual" as const, guidance: "未映射的检查项" },
        status: "manual" as FullCheckStatus,
        relatedFindings: [],
      };
    }
    return evaluateFullCheck(item, mapping, allFindings, scanModules);
  });
}

// ---------------------------------------------------------------------------
// Legacy types and exports (kept for backward compatibility)
// ---------------------------------------------------------------------------

export interface MlpsCheck {
  id: string;
  category: string;
  name: string;
  modules: string[];
  findingPatterns: string[];
}

export const MLPS_CHECKS: MlpsCheck[] = [
  // 一、身份鉴别
  {
    id: "8.1.4.1a",
    category: "身份鉴别",
    name: "密码策略",
    modules: ["security_hub_findings"],
    findingPatterns: ["password policy", "password length", "complexity", "password expiry", "reuse prevention", "IAM.7", "IAM.10"],
  },
  {
    id: "8.1.4.1a",
    category: "身份鉴别",
    name: "密钥轮换",
    modules: ["security_hub_findings"],
    findingPatterns: ["access key older", "access key rotated", "IAM.3", "IAM.4"],
  },
  {
    id: "8.1.4.1d",
    category: "身份鉴别",
    name: "双因素认证",
    modules: ["security_hub_findings"],
    findingPatterns: ["MFA", "IAM.5", "IAM.6"],
  },
  // 二、访问控制
  {
    id: "8.1.4.2c",
    category: "访问控制",
    name: "最小权限",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    findingPatterns: [
      "AdministratorAccess", "PowerUserAccess", "IAMFullAccess",
      "over-permissive", "privilege escalation",
      "self-grant", "iam:*", "create admin", "Lambda role passing",
      "CreateAccessKey", "AssumeRole",
    ],
  },
  {
    id: "8.1.4.2",
    category: "访问控制",
    name: "安全组",
    modules: ["network_reachability", "security_hub_findings"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP", "MySQL", "PostgreSQL", "MongoDB", "Redis", "high-risk port", "security group", "EC2.18", "EC2.19"],
  },
  // 三、安全审计
  {
    id: "8.1.4.3a",
    category: "安全审计",
    name: "审计功能",
    modules: ["security_hub_findings"],
    findingPatterns: ["CloudTrail", "not enabled", "multi-region", "not logging", "CloudTrail.1"],
  },
  {
    id: "8.1.4.3b",
    category: "安全审计",
    name: "审计完整性",
    modules: ["security_hub_findings"],
    findingPatterns: ["log file validation", "log integrity", "log validation", "CloudTrail.4", "CloudTrail.5"],
  },
  {
    id: "8.1.4.3c",
    category: "安全审计",
    name: "审计保护",
    modules: ["security_hub_findings"],
    findingPatterns: ["CloudTrail", "S3 bucket", "encryption", "versioning", "Block Public Access", "CloudTrail.6", "CloudTrail.7"],
  },
  // 四、入侵防范
  {
    id: "8.1.4.4a",
    category: "入侵防范",
    name: "GuardDuty 威胁检测",
    modules: ["service_detection", "guardduty_findings"],
    findingPatterns: ["GuardDuty"],
  },
  {
    id: "8.1.4.4a",
    category: "入侵防范",
    name: "Inspector 漏洞扫描",
    modules: ["service_detection", "inspector_findings"],
    findingPatterns: ["Inspector", "CVE-"],
  },
  // 五、数据安全
  {
    id: "8.1.4.5a",
    category: "数据安全",
    name: "传输加密",
    modules: ["ssl_certificate", "security_hub_findings"],
    findingPatterns: ["HTTPS", "TLS", "HTTP listener", "certificate", "ELB.1"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "S3 存储加密",
    modules: ["security_hub_findings"],
    findingPatterns: ["no default encryption", "not encrypted", "S3.4"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "EBS 默认加密",
    modules: ["security_hub_findings"],
    findingPatterns: ["EBS default encryption", "EC2.7"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "RDS 存储加密",
    modules: ["security_hub_findings"],
    findingPatterns: ["storage is not encrypted", "RDS.3"],
  },
  // 六、网络安全
  {
    id: "8.1.3.1a",
    category: "网络安全",
    name: "网络架构",
    modules: ["security_hub_findings"],
    findingPatterns: ["default VPC", "EC2.2"],
  },
  {
    id: "8.1.3.2a",
    category: "网络安全",
    name: "边界防护",
    modules: ["network_reachability", "security_hub_findings"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP", "security group", "EC2.18", "EC2.19"],
  },
];

export const CATEGORY_ORDER = [
  "身份鉴别",
  "访问控制",
  "安全审计",
  "入侵防范",
  "数据安全",
  "网络安全",
];

export const CATEGORY_SECTION: Record<string, string> = {
  "身份鉴别": "一、身份鉴别",
  "访问控制": "二、访问控制",
  "安全审计": "三、安全审计",
  "入侵防范": "四、入侵防范",
  "数据安全": "五、数据安全",
  "网络安全": "六、网络安全",
};

export interface CheckResult {
  check: MlpsCheck;
  status: "clean" | "issues" | "unknown";
  relatedFindings: Finding[];
}

export function evaluateCheck(
  check: MlpsCheck,
  allFindings: Finding[],
  scanModules: Array<{ module: string; status: string }>,
): CheckResult {
  // Verify all required modules ran successfully
  const allModulesPresent = check.modules.every((mod) =>
    scanModules.some((m) => m.module === mod && m.status === "success"),
  );

  if (!allModulesPresent) {
    return { check, status: "unknown", relatedFindings: [] };
  }

  // Find findings from the relevant modules that match any of the patterns
  const relatedFindings = allFindings.filter((f) => {
    const moduleMatch = check.modules.some((mod) => f.module === mod);
    if (!moduleMatch) return false;

    const text = `${f.title} ${f.description}`.toLowerCase();
    return check.findingPatterns.some((pattern) =>
      text.includes(pattern.toLowerCase()),
    );
  });

  return {
    check,
    status: relatedFindings.length === 0 ? "clean" : "issues",
    relatedFindings,
  };
}

export function generateMlps3Report(scanResults: FullScanResult): string {
  const { accountId, region, scanStart } = scanResults;
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");

  // Evaluate all 184 checks from the full GB/T 22239-2019 checklist
  const results = evaluateAllFullChecks(scanResults);

  // Summary counts by type
  const autoResults = results.filter((r) => r.mapping.type === "auto");
  const autoClean = autoResults.filter((r) => r.status === "clean").length;
  const autoIssues = autoResults.filter((r) => r.status === "issues").length;
  const autoUnknown = autoResults.filter((r) => r.status === "unknown").length;
  const checkedTotal = autoClean + autoIssues;
  const cloudCount = results.filter((r) => r.status === "cloud_provider").length;
  const manualCount = results.filter((r) => r.status === "manual").length;
  const naCount = results.filter((r) => r.status === "not_applicable").length;

  const lines: string[] = [];

  // Header
  lines.push("# 等保三级预检报告");
  lines.push("> **本报告为等保三级预检参考，提供云平台配置检查数据与建议。合规判定（符合/部分符合/不符合）需由持证测评机构根据实际情况确认。**");
  lines.push("> **（GB/T 22239-2019 完整检查清单 184 项）**");
  lines.push("");

  // Account info
  lines.push("## 账户信息");
  lines.push(`- Account: ${accountId} | Region: ${region} | 扫描时间: ${scanTime}`);
  lines.push("");

  // Summary
  lines.push("## 预检总览");
  lines.push(`- 已检查: ${checkedTotal} 项（未发现问题: ${autoClean} 项 | 发现问题: ${autoIssues} 项）`);
  if (autoUnknown > 0) {
    lines.push(`- 未检查: ${autoUnknown} 项（对应扫描模块未运行）`);
  }
  lines.push(`- 云平台负责: ${cloudCount} 项`);
  lines.push(`- 需人工评估: ${manualCount} 项`);
  if (naCount > 0) {
    lines.push(`- 不适用: ${naCount} 项`);
  }
  lines.push("");

  // Group results by categoryCn (skip N/A items)
  for (const category of MLPS3_CATEGORY_ORDER) {
    const sectionTitle = MLPS3_CATEGORY_SECTION[category];
    const catResults = results.filter(
      (r) => r.item.categoryCn === category && r.status !== "not_applicable",
    );
    if (catResults.length === 0) continue;

    lines.push(`## ${sectionTitle}`);
    lines.push("");

    // Group by controlCn within category
    const controlMap = new Map<string, FullCheckResult[]>();
    for (const r of catResults) {
      const key = r.item.controlCn;
      if (!controlMap.has(key)) controlMap.set(key, []);
      controlMap.get(key)!.push(r);
    }

    for (const [controlName, controlResults] of controlMap) {
      lines.push(`### ${controlName}`);
      for (const r of controlResults) {
        const icon = r.status === "clean" ? "\u2705"
          : r.status === "issues" ? "\u274c"
          : r.status === "unknown" ? "\u26a0\ufe0f"
          : r.status === "manual" ? "\ud83d\udccb"
          : "\ud83c\udfe2";
        const suffix = r.status === "unknown" ? " — 未检查"
          : r.status === "manual" ? ` — ${r.mapping.guidance ?? "需人工评估"}`
          : r.status === "cloud_provider" ? ` — ${r.mapping.note ?? "云平台负责"}`
          : r.status === "clean" ? " 未发现问题"
          : " 发现问题";

        lines.push(`- [${icon}] ${r.item.id} ${r.item.requirementCn.slice(0, 60)}${r.item.requirementCn.length > 60 ? "\u2026" : ""}${suffix}`);
        if (r.status === "issues" && r.relatedFindings.length > 0) {
          for (const f of r.relatedFindings.slice(0, 3)) {
            lines.push(`  - ${f.severity}: ${f.title}`);
          }
          if (r.relatedFindings.length > 3) {
            lines.push(`  - ... 及其他 ${r.relatedFindings.length - 3} 项`);
          }
        }
      }
      lines.push("");
    }
  }

  // Remediation recommendations sorted by priority
  const failedResults = results.filter((r) => r.status === "issues");
  if (failedResults.length > 0) {
    lines.push("## 建议整改项（按优先级）");
    lines.push("");

    // Collect all related findings from failed checks, deduplicate, sort by riskScore
    const allFailedFindings = new Map<string, Finding>();
    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const key = `${f.resourceId}:${f.title}`;
        if (!allFailedFindings.has(key)) {
          allFailedFindings.set(key, f);
        }
      }
    }

    const sorted = [...allFailedFindings.values()].sort(
      (a, b) => b.riskScore - a.riskScore,
    );

    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      const priority = f.riskScore >= 9.0 ? "P0" : f.riskScore >= 7.0 ? "P1" : f.riskScore >= 4.0 ? "P2" : "P3";
      const remediation = f.remediationSteps[0] ?? "Review and remediate.";
      lines.push(`${i + 1}. [${priority}] ${f.title} — ${remediation}`);
    }
    lines.push("");
  }

  // N/A note
  if (naCount > 0) {
    lines.push(`> 不适用项: ${naCount} 项（物联网/无线网络/移动终端/工控系统/可信验证等）`);
    lines.push("");
  }

  return lines.join("\n");
}

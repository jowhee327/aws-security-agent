import type { FullScanResult, Finding } from "../types.js";

interface MlpsCheck {
  id: string;
  category: string;
  name: string;
  modules: string[];
  findingPatterns: string[];
}

const MLPS_CHECKS: MlpsCheck[] = [
  // 一、身份鉴别
  {
    id: "8.1.4.1a",
    category: "身份鉴别",
    name: "密码策略",
    modules: ["iam_password_policy"],
    findingPatterns: ["password policy", "password length", "complexity", "password expiry", "reuse prevention"],
  },
  {
    id: "8.1.4.1a",
    category: "身份鉴别",
    name: "密钥轮换",
    modules: ["iam"],
    findingPatterns: ["access key older"],
  },
  {
    id: "8.1.4.1d",
    category: "身份鉴别",
    name: "双因素认证",
    modules: ["iam_mfa_audit", "iam"],
    findingPatterns: ["MFA"],
  },
  // 二、访问控制
  {
    id: "8.1.4.2c",
    category: "访问控制",
    name: "最小权限",
    modules: ["iam", "iam_privilege_escalation"],
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
    modules: ["security_group", "network_reachability"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP", "MySQL", "PostgreSQL", "MongoDB", "Redis", "high-risk port"],
  },
  // 三、安全审计
  {
    id: "8.1.4.3a",
    category: "安全审计",
    name: "审计功能",
    modules: ["cloudtrail"],
    findingPatterns: ["CloudTrail", "not enabled", "multi-region", "not logging"],
  },
  {
    id: "8.1.4.3b",
    category: "安全审计",
    name: "审计完整性",
    modules: ["cloudtrail", "log_integrity_audit"],
    findingPatterns: ["log file validation", "log integrity", "log validation"],
  },
  {
    id: "8.1.4.3c",
    category: "安全审计",
    name: "审计保护",
    modules: ["cloudtrail_protection"],
    findingPatterns: ["CloudTrail", "S3 bucket", "encryption", "versioning", "Block Public Access"],
  },
  // 四、入侵防范
  {
    id: "8.1.4.4a",
    category: "入侵防范",
    name: "GuardDuty 威胁检测",
    modules: ["service_detection"],
    findingPatterns: ["GuardDuty"],
  },
  {
    id: "8.1.4.4a",
    category: "入侵防范",
    name: "Inspector 漏洞扫描",
    modules: ["service_detection"],
    findingPatterns: ["Inspector"],
  },
  // 五、数据安全
  {
    id: "8.1.4.5a",
    category: "数据安全",
    name: "传输加密",
    modules: ["elb_https", "ssl_certificate"],
    findingPatterns: ["HTTPS", "TLS", "HTTP listener", "certificate"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "S3 存储加密",
    modules: ["s3"],
    findingPatterns: ["no default encryption", "not encrypted"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "EBS 默认加密",
    modules: ["ebs"],
    findingPatterns: ["EBS default encryption"],
  },
  {
    id: "8.1.4.5b",
    category: "数据安全",
    name: "RDS 存储加密",
    modules: ["rds"],
    findingPatterns: ["storage is not encrypted"],
  },
  // 六、网络安全
  {
    id: "8.1.3.1a",
    category: "网络安全",
    name: "网络架构",
    modules: ["vpc"],
    findingPatterns: ["default VPC"],
  },
  {
    id: "8.1.3.2a",
    category: "网络安全",
    name: "边界防护",
    modules: ["security_group"],
    findingPatterns: ["allows all ports", "allows SSH", "allows RDP"],
  },
];

const CATEGORY_ORDER = [
  "身份鉴别",
  "访问控制",
  "安全审计",
  "入侵防范",
  "数据安全",
  "网络安全",
];

const CATEGORY_SECTION: Record<string, string> = {
  "身份鉴别": "一、身份鉴别",
  "访问控制": "二、访问控制",
  "安全审计": "三、安全审计",
  "入侵防范": "四、入侵防范",
  "数据安全": "五、数据安全",
  "网络安全": "六、网络安全",
};

interface CheckResult {
  check: MlpsCheck;
  status: "pass" | "fail" | "unknown";
  relatedFindings: Finding[];
}

function evaluateCheck(
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
    status: relatedFindings.length === 0 ? "pass" : "fail",
    relatedFindings,
  };
}

export function generateMlps3Report(scanResults: FullScanResult): string {
  const { accountId, region, scanStart } = scanResults;
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");

  // Collect all findings with module info
  const allFindings: Finding[] = scanResults.modules.flatMap((m) =>
    m.findings.map((f) => ({ ...f, module: f.module ?? m.module })),
  );

  // Evaluate all checks (pass scan module info for missing-module detection)
  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status,
  }));
  const results = MLPS_CHECKS.map((check) =>
    evaluateCheck(check, allFindings, scanModules),
  );

  const passCount = results.filter((r) => r.status === "pass").length;
  const failCount = results.filter((r) => r.status === "fail").length;
  const unknownCount = results.filter((r) => r.status === "unknown").length;
  const checkedTotal = passCount + failCount;
  const total = results.length;
  const percent = checkedTotal > 0 ? Math.round((passCount / checkedTotal) * 100) : 0;

  const lines: string[] = [];

  // Header
  lines.push("# 等保三级预检报告");
  lines.push("> **本报告为等保预检参考，仅覆盖 AWS 云平台配置检查。完整等保测评需由持证测评机构执行。**");
  lines.push("");

  // Account info
  lines.push("## 账户信息");
  lines.push(`- Account: ${accountId} | Region: ${region} | 扫描时间: ${scanTime}`);
  lines.push("");

  // Summary
  lines.push("## 预检总览");
  lines.push(`- 检查项: ${total} | 通过: ${passCount} | 不通过: ${failCount}${unknownCount > 0 ? ` | 未检查: ${unknownCount}` : ""}`);
  lines.push(`- 通过率: ${percent}%${unknownCount > 0 ? "（未检查项不计入通过率）" : ""}`);
  lines.push("");

  // Group results by category
  for (const category of CATEGORY_ORDER) {
    const sectionTitle = CATEGORY_SECTION[category];
    const categoryResults = results.filter((r) => r.check.category === category);
    if (categoryResults.length === 0) continue;

    lines.push(`## ${sectionTitle}`);
    lines.push("");

    // Group by check ID within category
    const byId = new Map<string, CheckResult[]>();
    for (const r of categoryResults) {
      const existing = byId.get(r.check.id) ?? [];
      existing.push(r);
      byId.set(r.check.id, existing);
    }

    for (const [checkId, checkResults] of byId) {
      lines.push(`### ${checkId} ${checkResults[0].check.name}`);
      for (const r of checkResults) {
        const icon = r.status === "pass" ? "\u2705" : r.status === "fail" ? "\u274c" : "\u26a0\ufe0f";
        const label = r.status === "unknown" ? " 未检查" : "";
        lines.push(`- [${icon}] ${r.check.name}${label}`);
        if (r.status === "fail" && r.relatedFindings.length > 0) {
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
  const failedResults = results.filter((r) => r.status === "fail");
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

  return lines.join("\n");
}

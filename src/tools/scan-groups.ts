export interface FindingsFilter {
  /** Filter Security Hub findings by category keywords (case-insensitive match on title/description/impact) */
  securityHubCategories?: string[];
  /** Filter GuardDuty findings by type prefix (matched against impact field) */
  guardDutyTypes?: string[];
  /** Filter Inspector findings by type (matched against impact field) */
  inspectorTypes?: string[];
  /** Filter by minimum severity */
  minSeverity?: string;
}

const SEVERITY_ORDER: Record<string, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export function applyFindingsFilter(
  moduleName: string,
  findings: import("../types.js").Finding[],
  filter: FindingsFilter,
): import("../types.js").Finding[] {
  let result = findings;

  // Apply severity filter
  if (filter.minSeverity) {
    const minLevel = SEVERITY_ORDER[filter.minSeverity.toUpperCase()] ?? 0;
    result = result.filter((f) => (SEVERITY_ORDER[f.severity] ?? 0) >= minLevel);
  }

  // Apply module-specific category filters
  if (moduleName === "security_hub_findings" && filter.securityHubCategories?.length) {
    const keywords = filter.securityHubCategories;
    result = result.filter((f) =>
      keywords.some((kw) => {
        const lower = kw.toLowerCase();
        return (
          f.title.toLowerCase().includes(lower) ||
          f.description.toLowerCase().includes(lower) ||
          f.impact.toLowerCase().includes(lower)
        );
      }),
    );
  }

  if (moduleName === "guardduty_findings" && filter.guardDutyTypes?.length) {
    const prefixes = filter.guardDutyTypes;
    result = result.filter((f) =>
      prefixes.some((prefix) => f.impact.includes(prefix)),
    );
  }

  if (moduleName === "inspector_findings" && filter.inspectorTypes?.length) {
    const types = filter.inspectorTypes;
    result = result.filter((f) =>
      types.some((t) => f.impact.includes(t)),
    );
  }

  return result;
}

export const SCAN_GROUPS: Record<string, {
  name: string;
  description: string;
  modules: string[];
  reportType?: string;
  findingsFilter?: FindingsFilter;
}> = {
  mlps3_precheck: {
    name: "等保三级预检",
    description: "GB/T 22239-2019 等保三级 AWS 云租户层配置检查",
    modules: ["service_detection", "secret_exposure", "ssl_certificate", "dns_dangling", "network_reachability", "iam_privilege_escalation", "tag_compliance", "disaster_recovery", "security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings"],
    reportType: "mlps3",
  },
  hw_defense: {
    name: "护网蓝队加固",
    description: "护网前安全自查 — 攻击面+弱点评估",
    modules: ["service_detection", "secret_exposure", "network_reachability", "iam_privilege_escalation", "security_hub_findings", "guardduty_findings", "inspector_findings"],
    findingsFilter: {
      guardDutyTypes: ["Backdoor", "Trojan", "PenTest", "CryptoCurrency"],
      minSeverity: "MEDIUM",
    },
  },
  exposure: {
    name: "公网暴露面评估",
    description: "评估公网可达的资源和端口",
    modules: ["network_reachability", "dns_dangling", "public_access_verify", "ssl_certificate", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["network", "public", "exposure", "port"],
    },
  },
  pre_launch: {
    name: "生产上线前检查",
    description: "上线前全面安全评估",
    modules: ["ALL"],
  },
  data_encryption: {
    name: "数据加密审计",
    description: "全面检查存储和传输加密状态",
    modules: ["ssl_certificate", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["encryption", "Encryption"],
    },
  },
  least_privilege: {
    name: "最小权限审计",
    description: "IAM 权限最小化评估",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["IAM", "iam", "access", "privilege"],
    },
  },
  log_integrity: {
    name: "日志完整性审计",
    description: "审计日志完整性和保护",
    modules: ["service_detection", "security_hub_findings"],
    findingsFilter: {
      securityHubCategories: ["logging", "CloudTrail", "audit"],
    },
  },
  disaster_recovery: {
    name: "灾备评估",
    description: "备份和灾备能力评估",
    modules: ["disaster_recovery", "security_hub_findings"],
  },
  idle_resources: {
    name: "闲置资源清理",
    description: "发现未使用的资源",
    modules: ["idle_resources", "trusted_advisor_findings"],
  },
  tag_compliance: {
    name: "资源标签合规",
    description: "检查必需标签",
    modules: ["tag_compliance"],
  },
  public_access_verify: {
    name: "公网可达性验证",
    description: "验证标记为公开的资源是否真正可从互联网访问",
    modules: ["public_access_verify"],
  },
  new_account_baseline: {
    name: "新账户基线检查",
    description: "新 AWS 账户安全基线",
    modules: ["service_detection", "secret_exposure", "iam_privilege_escalation", "security_hub_findings", "guardduty_findings"],
  },
  aggregation: {
    name: "安全服务聚合",
    description: "从 Security Hub / GuardDuty / Inspector / Trusted Advisor 聚合所有安全发现",
    modules: ["security_hub_findings", "guardduty_findings", "inspector_findings", "trusted_advisor_findings"],
  },
};

export const SCAN_GROUPS: Record<string, {
  name: string;
  description: string;
  modules: string[];
  reportType?: string;
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
  },
  exposure: {
    name: "公网暴露面评估",
    description: "评估公网可达的资源和端口",
    modules: ["network_reachability", "dns_dangling", "public_access_verify", "ssl_certificate", "security_hub_findings"],
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
  },
  least_privilege: {
    name: "最小权限审计",
    description: "IAM 权限最小化评估",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
  },
  log_integrity: {
    name: "日志完整性审计",
    description: "审计日志完整性和保护",
    modules: ["service_detection", "security_hub_findings"],
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

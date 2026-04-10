export const SCAN_GROUPS: Record<string, {
  name: string;
  description: string;
  modules: string[];
  reportType?: string;
}> = {
  mlps3_precheck: {
    name: "等保三级预检",
    description: "GB/T 22239-2019 等保三级 AWS 云租户层配置检查",
    modules: ["security_group", "s3", "iam", "cloudtrail", "rds", "ebs", "vpc", "service_detection", "iam_password_policy", "iam_mfa_audit", "cloudtrail_protection", "elb_https", "secret_exposure", "ssl_certificate", "dns_dangling", "network_reachability", "iam_privilege_escalation", "log_integrity_audit", "tag_compliance", "disaster_recovery"],
    reportType: "mlps3",
  },
  hw_defense: {
    name: "护网蓝队加固",
    description: "护网前安全自查 — 攻击面+弱点评估",
    modules: ["security_group", "s3", "iam", "ebs", "vpc", "service_detection", "secret_exposure", "network_reachability", "iam_privilege_escalation"],
  },
  exposure: {
    name: "公网暴露面评估",
    description: "评估公网可达的资源和端口",
    modules: ["security_group", "vpc", "s3", "rds", "elb_https", "network_reachability", "dns_dangling", "public_access_verify"],
  },
  pre_launch: {
    name: "生产上线前检查",
    description: "上线前全面安全评估",
    modules: ["ALL"],
  },
  data_encryption: {
    name: "数据加密审计",
    description: "全面检查存储和传输加密状态",
    modules: ["s3", "ebs", "rds", "elb_https", "ssl_certificate"],
  },
  least_privilege: {
    name: "最小权限审计",
    description: "IAM 权限最小化评估",
    modules: ["iam", "iam_password_policy", "iam_mfa_audit", "iam_privilege_escalation"],
  },
  log_integrity: {
    name: "日志完整性审计",
    description: "审计日志完整性和保护",
    modules: ["cloudtrail", "cloudtrail_protection", "vpc", "service_detection", "log_integrity_audit"],
  },
  disaster_recovery: {
    name: "灾备评估",
    description: "备份和灾备能力评估",
    modules: ["rds", "ebs", "s3", "disaster_recovery"],
  },
  idle_resources: {
    name: "闲置资源清理",
    description: "发现未使用的资源",
    modules: ["iam", "ebs", "security_group", "idle_resources"],
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
    modules: ["iam", "iam_password_policy", "iam_mfa_audit", "cloudtrail", "service_detection", "vpc", "security_group", "secret_exposure"],
  },
};

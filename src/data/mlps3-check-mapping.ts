/**
 * MLPS Level 3 (等保三级) GB/T 22239-2019 full checklist mapping.
 *
 * Each of the 184 checks is classified into one of four types:
 *   auto           — scanner modules can evaluate pass/fail automatically
 *   cloud_provider — the cloud platform (AWS, or Huawei Cloud when provider=huaweicloud) is responsible; compliant by default
 *   manual         — requires manual verification or third-party tools
 *   not_applicable — N/A for cloud-only environments (IoT, ICS, wireless, mobile, trusted verification)
 */

import checklistJson from "./mlps3-full-checklist.json";
import type { ProviderId } from "../types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MlpsChecklistItem {
  id: string;
  categoryCn: string;
  categoryEn: string;
  controlCn: string;
  controlEn: string;
  requirementCn: string;
  requirementEn: string;
  referenceStatus: string;
  referenceComment: string;
}

export interface MlpsCheckMapping {
  id: string;
  type: "auto" | "cloud_provider" | "manual" | "not_applicable";
  /** For auto: which scanner modules to check */
  modules?: string[];
  /** For auto: specific Security Hub control IDs to match (e.g. "EC2.2", "IAM.7") */
  securityHubControlIds?: string[];
  /** For auto: keywords to match in finding title/description (use securityHubControlIds when possible) */
  findingPatterns?: string[];
  /** For manual: guidance text */
  guidance?: string;
  /** For cloud_provider: brief note (AWS wording) */
  note?: string;
  /** For cloud_provider: Huawei Cloud wording; falls back to `note` when absent (see cloudProviderNote) */
  noteHuawei?: string;
  /**
   * For auto (provider=huaweicloud): Huawei Cloud Config (RMS) built-in policy
   * assignment names whose NonCompliant states satisfy this check, matched
   * against `rms_compliance_findings` finding titles/impact. The Security Hub
   * control IDs above are AWS-only; RMS names are the Huawei counterpart.
   */
  rmsPolicyAssignmentNames?: string[];
}

/** Cloud-provider note for a `cloud_provider` mapping, in the wording of `provider` (AWS when absent). */
export function cloudProviderNote(mapping: MlpsCheckMapping, provider?: ProviderId): string | undefined {
  if (provider === "huaweicloud" && mapping.noteHuawei) return mapping.noteHuawei;
  return mapping.note;
}

// ---------------------------------------------------------------------------
// Full checklist data (imported from JSON, bundled by tsup/esbuild)
// ---------------------------------------------------------------------------

export const MLPS3_FULL_CHECKLIST: MlpsChecklistItem[] =
  checklistJson as MlpsChecklistItem[];

// ---------------------------------------------------------------------------
// Category ordering for the report
// ---------------------------------------------------------------------------

export const MLPS3_CATEGORY_ORDER = [
  "安全物理环境",
  "安全通信网络",
  "安全区域边界",
  "安全计算环境",
  "安全管理中心",
] as const;

export const MLPS3_CATEGORY_SECTION: Record<string, string> = {
  "安全物理环境": "一、安全物理环境",
  "安全通信网络": "二、安全通信网络",
  "安全区域边界": "三、安全区域边界",
  "安全计算环境": "四、安全计算环境",
  "安全管理中心": "五、安全管理中心",
};

// ---------------------------------------------------------------------------
// Mapping: 184 checks → type + modules/patterns/guidance
// ---------------------------------------------------------------------------

export const MLPS3_CHECK_MAPPING: MlpsCheckMapping[] = [
  // =========================================================================
  // 安全物理环境 — L3-PES1-* (22 items) → cloud_provider
  // =========================================================================
  { id: "L3-PES1-01", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-02", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-03", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-04", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-05", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-06", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-07", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-08", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-09", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-10", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-11", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-12", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-13", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-14", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-15", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-16", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-17", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-18", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-19", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-20", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-21", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },
  { id: "L3-PES1-22", type: "cloud_provider", note: "AWS 负责机房物理安全", noteHuawei: "华为云负责机房物理安全" },

  // L3-PES2-01 (Cloud extension — physical infra in China)
  { id: "L3-PES2-01", type: "cloud_provider", note: "AWS 中国区基础设施位于中国境内", noteHuawei: "华为云中国区基础设施位于中国境内" },

  // L3-PES3-01 (Wireless — N/A)
  { id: "L3-PES3-01", type: "not_applicable" },

  // L3-PES4-* (IoT sensor — N/A)
  { id: "L3-PES4-01", type: "not_applicable" },
  { id: "L3-PES4-02", type: "not_applicable" },
  { id: "L3-PES4-03", type: "not_applicable" },
  { id: "L3-PES4-04", type: "not_applicable" },

  // L3-PES5-* (Industrial control outdoor — N/A)
  { id: "L3-PES5-01", type: "not_applicable" },
  { id: "L3-PES5-02", type: "not_applicable" },

  // =========================================================================
  // 安全通信网络 — L3-CNS1-* (8 items)
  // =========================================================================
  { id: "L3-CNS1-01", type: "cloud_provider", note: "AWS 负责网络设备处理能力", noteHuawei: "华为云负责网络设备处理能力" },
  { id: "L3-CNS1-02", type: "cloud_provider", note: "AWS 负责网络带宽", noteHuawei: "华为云负责网络带宽" },
  {
    id: "L3-CNS1-03",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.2"],
  },
  {
    id: "L3-CNS1-04",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.2", "EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  { id: "L3-CNS1-05", type: "cloud_provider", note: "AWS 多可用区/多区域冗余", noteHuawei: "华为云多可用区/多区域冗余" },
  {
    id: "L3-CNS1-06",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  {
    id: "L3-CNS1-07",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  { id: "L3-CNS1-08", type: "not_applicable" },

  // L3-CNS2-* (Cloud extension communication — 5 items)
  { id: "L3-CNS2-01", type: "cloud_provider", note: "AWS 等保涵盖", noteHuawei: "华为云等保涵盖" },
  { id: "L3-CNS2-02", type: "cloud_provider", note: "VPC 实现虚拟网络隔离" },
  {
    id: "L3-CNS2-03",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "guardduty_findings"],
  },
  { id: "L3-CNS2-04", type: "cloud_provider", note: "AWS 支持自主安全策略配置", noteHuawei: "华为云支持自主安全策略配置" },
  { id: "L3-CNS2-05", type: "cloud_provider", note: "AWS Marketplace 支持第三方产品", noteHuawei: "华为云云市场 支持第三方产品" },

  // L3-CNS5-* (Industrial control communication — N/A)
  { id: "L3-CNS5-01", type: "not_applicable" },
  { id: "L3-CNS5-02", type: "not_applicable" },
  { id: "L3-CNS5-03", type: "not_applicable" },
  { id: "L3-CNS5-04", type: "not_applicable" },

  // =========================================================================
  // 安全区域边界 — L3-ABS1-* (20 items)
  // =========================================================================
  {
    id: "L3-ABS1-01",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS1-02",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS1-03",
    type: "manual",
    guidance: "需确认 NAT Gateway、VPC Endpoint 配置，限制内部用户非授权外联",
  },
  { id: "L3-ABS1-04", type: "not_applicable" },
  {
    id: "L3-ABS1-05",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS1-06",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS1-07",
    type: "auto",
    modules: ["network_reachability", "waf_coverage", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS1-08",
    type: "manual",
    guidance: "需启用 WAF 或部署第三方下一代防火墙实现基于会话状态的访问控制",
  },
  {
    id: "L3-ABS1-09",
    type: "manual",
    guidance: "需启用 WAF 或部署第三方下一代防火墙实现基于应用协议的访问控制",
  },
  {
    id: "L3-ABS1-10",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"],
  },
  {
    id: "L3-ABS1-11",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"],
  },
  {
    id: "L3-ABS1-12",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage", "inspector_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"],
  },
  {
    id: "L3-ABS1-13",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"],
  },
  {
    id: "L3-ABS1-14",
    type: "manual",
    guidance: "需在操作系统安装第三方杀毒软件，或部署下一代防火墙进行恶意代码检测",
  },
  { id: "L3-ABS1-15", type: "not_applicable" },
  {
    id: "L3-ABS1-16",
    type: "auto",
    modules: ["service_detection", "config_rules_findings", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-ABS1-17",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-ABS1-18",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5", "CloudTrail.6", "CloudTrail.7"],
  },
  {
    id: "L3-ABS1-19",
    type: "manual",
    guidance: "需配置 S3 Access Log、ALB Access Log，或部署上网行为管理产品进行远程访问行为审计",
  },
  { id: "L3-ABS1-20", type: "not_applicable" },

  // L3-ABS2-* (Cloud extension boundary — 8 items)
  {
    id: "L3-ABS2-01",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS2-02",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-ABS2-03",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"],
  },
  {
    id: "L3-ABS2-04",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"],
  },
  {
    id: "L3-ABS2-05",
    type: "auto",
    modules: ["guardduty_findings"],
  },
  {
    id: "L3-ABS2-06",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"],
  },
  {
    id: "L3-ABS2-07",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-ABS2-08",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },

  // L3-ABS3-* (Wireless boundary — N/A)
  { id: "L3-ABS3-01", type: "not_applicable" },
  { id: "L3-ABS3-02", type: "not_applicable" },
  { id: "L3-ABS3-03", type: "not_applicable" },
  { id: "L3-ABS3-04", type: "not_applicable" },
  { id: "L3-ABS3-05", type: "not_applicable" },
  { id: "L3-ABS3-06", type: "not_applicable" },
  { id: "L3-ABS3-07", type: "not_applicable" },
  { id: "L3-ABS3-08", type: "not_applicable" },

  // L3-ABS4-* (IoT boundary — N/A)
  { id: "L3-ABS4-01", type: "not_applicable" },
  { id: "L3-ABS4-02", type: "not_applicable" },
  { id: "L3-ABS4-03", type: "not_applicable" },

  // L3-ABS5-* (Industrial control boundary — N/A)
  { id: "L3-ABS5-01", type: "not_applicable" },
  { id: "L3-ABS5-02", type: "not_applicable" },
  { id: "L3-ABS5-03", type: "not_applicable" },
  { id: "L3-ABS5-04", type: "not_applicable" },
  { id: "L3-ABS5-05", type: "not_applicable" },
  { id: "L3-ABS5-06", type: "not_applicable" },
  { id: "L3-ABS5-07", type: "not_applicable" },
  { id: "L3-ABS5-08", type: "not_applicable" },

  // =========================================================================
  // 安全计算环境 — L3-CES1-* (34 items, no CES1-16)
  // =========================================================================
  {
    id: "L3-CES1-01",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings", "security_hub_findings"],
    securityHubControlIds: ["IAM.7", "IAM.10", "IAM.11"],
  },
  {
    id: "L3-CES1-02",
    type: "manual",
    guidance: "需配置堡垒机或通过 CloudTrail + CloudWatch Alarm + Lambda 实现登录失败处理",
  },
  {
    id: "L3-CES1-03",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  {
    id: "L3-CES1-04",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["IAM.5", "IAM.6"],
    rmsPolicyAssignmentNames: ["iam-user-mfa-enabled"],
  },
  {
    id: "L3-CES1-05",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings"],
  },
  {
    id: "L3-CES1-06",
    type: "manual",
    guidance: "需确认已重命名或删除默认账户（如 root 直接登录），修改默认口令",
  },
  {
    id: "L3-CES1-07",
    type: "auto",
    modules: ["security_hub_findings", "access_analyzer_findings"],
    securityHubControlIds: ["IAM.3", "IAM.4", "IAM.22"],
    rmsPolicyAssignmentNames: ["access-keys-rotated", "iam-root-access-key-check"],
  },
  {
    id: "L3-CES1-08",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"],
  },
  {
    id: "L3-CES1-09",
    type: "auto",
    modules: ["iam_privilege_escalation", "access_analyzer_findings"],
  },
  {
    id: "L3-CES1-10",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"],
  },
  {
    id: "L3-CES1-11",
    type: "manual",
    guidance: "需在应用层对敏感信息进行分类，利用 Tag 或 Metadata 标记数据，配合访问控制策略管控",
  },
  {
    id: "L3-CES1-12",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-CES1-13",
    type: "auto",
    modules: ["service_detection", "security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-CES1-14",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5", "CloudTrail.6", "CloudTrail.7"],
  },
  {
    id: "L3-CES1-15",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.4", "CloudTrail.5"],
  },
  // Note: L3-CES1-16 does not exist in the standard
  {
    id: "L3-CES1-17",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-CES1-18",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-CES1-19",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  {
    id: "L3-CES1-20",
    type: "manual",
    guidance: "需启用 WAF 规则进行输入验证，或在应用层实现数据有效性检验",
  },
  {
    id: "L3-CES1-21",
    type: "auto",
    modules: ["inspector_findings", "patch_compliance_findings"],
  },
  {
    id: "L3-CES1-22",
    type: "auto",
    modules: ["guardduty_findings", "waf_coverage"],
  },
  {
    id: "L3-CES1-23",
    type: "manual",
    guidance: "需在操作系统层安装第三方杀毒产品；可结合 GuardDuty 检测恶意行为",
  },
  { id: "L3-CES1-24", type: "not_applicable" },
  {
    id: "L3-CES1-25",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  {
    id: "L3-CES1-26",
    type: "manual",
    guidance: "需安装第三方防篡改软件；S3 可利用对象校验确保完整性",
  },
  {
    id: "L3-CES1-27",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  {
    id: "L3-CES1-28",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["S3.4", "EC2.7", "RDS.3"],
    rmsPolicyAssignmentNames: ["volumes-encrypted-check"],
  },
  {
    id: "L3-CES1-29",
    type: "auto",
    modules: ["disaster_recovery"],
  },
  {
    id: "L3-CES1-30",
    type: "auto",
    modules: ["disaster_recovery"],
  },
  {
    id: "L3-CES1-31",
    type: "auto",
    modules: ["disaster_recovery"],
  },
  { id: "L3-CES1-32", type: "cloud_provider", note: "AWS 存储服务数据清除策略覆盖", noteHuawei: "华为云存储服务数据清除策略覆盖" },
  { id: "L3-CES1-33", type: "cloud_provider", note: "AWS 存储服务数据清除策略覆盖", noteHuawei: "华为云存储服务数据清除策略覆盖" },
  {
    id: "L3-CES1-34",
    type: "manual",
    guidance: "应用侧行为 — 需确认仅采集和保存业务必需的用户个人信息",
  },
  {
    id: "L3-CES1-35",
    type: "manual",
    guidance: "应用侧行为 — 需确认禁止未授权访问和非法使用用户个人信息",
  },

  // L3-CES2-* (Cloud extension computing — 19 items)
  {
    id: "L3-CES2-01",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["IAM.5", "IAM.6"],
    rmsPolicyAssignmentNames: ["iam-user-mfa-enabled"],
  },
  { id: "L3-CES2-02", type: "cloud_provider", note: "AWS 确保 VM 迁移时访问控制随迁", noteHuawei: "华为云确保 VM 迁移时访问控制随迁" },
  {
    id: "L3-CES2-03",
    type: "auto",
    modules: ["network_reachability", "security_hub_findings"],
    securityHubControlIds: ["EC2.18", "EC2.19"],
    rmsPolicyAssignmentNames: ["vpc-sg-ports-check"],
  },
  { id: "L3-CES2-04", type: "cloud_provider", note: "AWS 负责虚拟化资源隔离", noteHuawei: "华为云负责虚拟化资源隔离" },
  {
    id: "L3-CES2-05",
    type: "auto",
    modules: ["guardduty_findings"],
  },
  {
    id: "L3-CES2-06",
    type: "manual",
    guidance: "需部署第三方入侵防范和杀毒产品检测虚拟机间恶意代码蔓延",
  },
  {
    id: "L3-CES2-07",
    type: "manual",
    guidance: "若不使用 AWS 官方镜像，需自行加固操作系统",
  },
  {
    id: "L3-CES2-08",
    type: "manual",
    guidance: "若不使用 AWS 官方镜像，需自行校验镜像和快照完整性",
  },
  {
    id: "L3-CES2-09",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["EC2.7"],
    rmsPolicyAssignmentNames: ["volumes-encrypted-check"],
  },
  { id: "L3-CES2-10", type: "cloud_provider", note: "AWS 中国区数据存储于中国境内", noteHuawei: "华为云中国区数据存储于中国境内" },
  { id: "L3-CES2-11", type: "cloud_provider", note: "AWS 仅在客户授权下管理数据", noteHuawei: "华为云仅在客户授权下管理数据" },
  { id: "L3-CES2-12", type: "cloud_provider", note: "AWS 确保 VM 迁移数据完整性", noteHuawei: "华为云确保 VM 迁移数据完整性" },
  {
    id: "L3-CES2-13",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["KMS.4"],
  },
  { id: "L3-CES2-14", type: "not_applicable" },
  { id: "L3-CES2-15", type: "cloud_provider", note: "AWS 支持查询数据及备份存储位置", noteHuawei: "华为云支持查询数据及备份存储位置" },
  { id: "L3-CES2-16", type: "cloud_provider", note: "AWS 存储服务保证多副本一致", noteHuawei: "华为云存储服务保证多副本一致" },
  { id: "L3-CES2-17", type: "not_applicable" },
  { id: "L3-CES2-18", type: "cloud_provider", note: "AWS 确保 VM 内存和存储空间回收时完全清除", noteHuawei: "华为云确保 VM 内存和存储空间回收时完全清除" },
  { id: "L3-CES2-19", type: "cloud_provider", note: "AWS 确保删除数据时清除所有副本", noteHuawei: "华为云确保删除数据时清除所有副本" },

  // L3-CES3-* (Mobile — N/A)
  { id: "L3-CES3-01", type: "not_applicable" },
  { id: "L3-CES3-02", type: "not_applicable" },
  { id: "L3-CES3-03", type: "not_applicable" },
  { id: "L3-CES3-04", type: "not_applicable" },
  { id: "L3-CES3-05", type: "not_applicable" },

  // L3-CES4-* (IoT sensor/gateway — N/A)
  { id: "L3-CES4-01", type: "not_applicable" },
  { id: "L3-CES4-02", type: "not_applicable" },
  { id: "L3-CES4-03", type: "not_applicable" },
  { id: "L3-CES4-04", type: "not_applicable" },
  { id: "L3-CES4-05", type: "not_applicable" },
  { id: "L3-CES4-06", type: "not_applicable" },
  { id: "L3-CES4-07", type: "not_applicable" },
  { id: "L3-CES4-08", type: "not_applicable" },
  { id: "L3-CES4-09", type: "not_applicable" },
  { id: "L3-CES4-10", type: "not_applicable" },
  { id: "L3-CES4-11", type: "not_applicable" },

  // L3-CES5-* (Industrial control — N/A)
  { id: "L3-CES5-01", type: "not_applicable" },
  { id: "L3-CES5-02", type: "not_applicable" },
  { id: "L3-CES5-03", type: "not_applicable" },
  { id: "L3-CES5-04", type: "not_applicable" },
  { id: "L3-CES5-05", type: "not_applicable" },

  // =========================================================================
  // 安全管理中心 — L3-SMC1-* (12 items)
  // =========================================================================
  {
    id: "L3-SMC1-01",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"],
    rmsPolicyAssignmentNames: ["iam-root-access-key-check", "iam-user-mfa-enabled"],
  },
  {
    id: "L3-SMC1-02",
    type: "auto",
    modules: ["security_hub_findings", "config_rules_findings"],
    securityHubControlIds: ["Config.1"],
  },
  {
    id: "L3-SMC1-03",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"],
    rmsPolicyAssignmentNames: ["iam-root-access-key-check", "iam-user-mfa-enabled"],
  },
  {
    id: "L3-SMC1-04",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-SMC1-05",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.4", "IAM.6"],
    rmsPolicyAssignmentNames: ["iam-root-access-key-check", "iam-user-mfa-enabled"],
  },
  {
    id: "L3-SMC1-06",
    type: "auto",
    modules: ["iam_privilege_escalation", "security_hub_findings"],
    securityHubControlIds: ["IAM.1", "IAM.21"],
  },
  {
    id: "L3-SMC1-07",
    type: "auto",
    modules: ["service_detection"],
    findingPatterns: ["Security Hub"],
  },
  {
    id: "L3-SMC1-08",
    type: "auto",
    modules: ["ssl_certificate", "security_hub_findings"],
    securityHubControlIds: ["ELB.1"],
  },
  {
    id: "L3-SMC1-09",
    type: "manual",
    guidance: "需配置 CloudWatch 集中监控平台，结合 SNS 进行告警通知",
  },
  {
    id: "L3-SMC1-10",
    type: "auto",
    modules: ["security_hub_findings"],
    securityHubControlIds: ["CloudTrail.1"],
  },
  {
    id: "L3-SMC1-11",
    type: "manual",
    guidance: "需部署第三方防入侵和防病毒产品进行安全策略、恶意代码、补丁升级集中管理",
  },
  {
    id: "L3-SMC1-12",
    type: "auto",
    modules: ["guardduty_findings", "security_hub_findings"],
    securityHubControlIds: ["GuardDuty.1"],
  },

  // L3-SMC2-* (Cloud extension management center — 4 items)
  { id: "L3-SMC2-01", type: "cloud_provider", note: "AWS 负责统一管理调度和分配", noteHuawei: "华为云负责统一管理调度和分配" },
  { id: "L3-SMC2-02", type: "cloud_provider", note: "AWS 确保管理流量与业务流量分离", noteHuawei: "华为云确保管理流量与业务流量分离" },
  { id: "L3-SMC2-03", type: "cloud_provider", note: "AWS 基于责任共担模型实现集中审计", noteHuawei: "华为云基于责任共担模型实现集中审计" },
  { id: "L3-SMC2-04", type: "cloud_provider", note: "AWS 基于责任共担模型实现集中监测", noteHuawei: "华为云基于责任共担模型实现集中监测" },
];

// ---------------------------------------------------------------------------
// Lookup helper — build an index for fast access
// ---------------------------------------------------------------------------

const _mappingIndex = new Map<string, MlpsCheckMapping>();
for (const m of MLPS3_CHECK_MAPPING) {
  _mappingIndex.set(m.id, m);
}

export function getMappingById(id: string): MlpsCheckMapping | undefined {
  return _mappingIndex.get(id);
}

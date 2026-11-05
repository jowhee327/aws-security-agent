import type { Priority, ProviderId, RationaleCode, Reachability } from "../types.js";

export type Lang = "zh" | "en";

export interface I18n {
  // HTML Security Report
  securityReportTitle: string;
  securityScore: string;
  critical: string;
  high: string;
  medium: string;
  low: string;
  scanStatistics: string;
  module: string;
  resources: string;
  findings: string;
  status: string;
  allFindings: string;
  recommendations: string;
  unique: string;
  showMore: string;
  noIssuesFound: string;
  allModulesClean: string;
  generatedBy: string;
  informationalOnly: string;

  // MLPS Report
  mlpsTitle: string;
  mlpsDisclaimer: string;
  checkedItems: string;
  noIssues: string;
  issuesFound: string;
  notChecked: string;
  cloudProvider: string;
  manualReview: string;
  notApplicable: string;
  checkResult: string;
  noRelatedIssues: string;
  issuesFoundCount: (n: number) => string;
  remediation: string;
  remediationItems: (n: number) => string;
  showRemaining: (n: number) => string;

  // HW Defense Checklist
  hwChecklistTitle: string;
  hwChecklistSubtitle: string;
  hwEmergencyIsolation: string;
  hwTestEnvShutdown: string;
  hwDutyTeam: string;
  hwNetworkDiagram: string;
  hwPentest: string;
  hwWarRoom: string;
  hwCredentials: string;
  hwPostOptimization: string;
  hwReference: string;

  // Service Reminders
  serviceReminderTitle: string;
  serviceReminderFooter: string;
  serviceImpact: string;
  serviceAction: string;

  // Common
  account: string;
  region: string;
  scanTime: string;
  duration: string;
  severityDistribution: string;
  findingsByModule: string;
  details: string;

  // ---------------------------------------------------------------------------
  // Extended fields (beyond the base interface spec) needed for full coverage
  // ---------------------------------------------------------------------------

  // HTML Security Report extras
  topHighestRiskFindings: (n: number) => string;
  resource: string;
  impact: string;
  riskScore: string;
  showRemainingFindings: (n: number) => string;
  trendTitle: string;
  findingsBySeverity: string;
  showMoreCount: (n: number) => string;

  // Filter toolbar
  filterSeverity: string;
  filterModule: string;
  filterAll: string;
  filterAllModules: string;
  filterCountTpl: string;

  // Markdown report
  executiveSummary: string;
  aiSummaryTitle: string;
  totalFindingsLabel: string;
  description: string;
  priority: string;
  noFindingsForSeverity: (severity: string) => string;

  // MLPS extras
  preCheckOverview: string;
  accountInfo: string;
  checkedCount: (total: number, clean: number, issues: number) => string;
  uncheckedCount: (n: number) => string;
  cloudProviderCount: (n: number) => string;
  manualReviewCount: (n: number) => string;
  naCount: (n: number) => string;
  naNote: (n: number) => string;
  unknownNote: (n: number) => string;
  cloudItemsNote: (n: number) => string;
  mlpsFooterGenerated: (version: string) => string;
  mlpsFooterDisclaimer: string;
  andMore: (n: number) => string;
  remediationByPriority: string;
  affectedResources: (n: number) => string;
  installWindowsPatches: (n: number, kbs: string) => string;
  mlpsCategorySection: Record<string, string>;

  // Module display names (unified across all report formats)
  moduleNames: Record<string, string>;

  // Security Hub sub-categories
  securityHubSubCategories: Record<string, { label: string }>;

  // Service recommendations (per service)
  notEnabled: string;
  serviceRecommendations: Record<
    string,
    { icon: string; service: string; impact: string; action: string }
  >;

  // HW Checklist (full composite text)
  hwChecklist: string;

  // HW Defense HTML Report
  hwReportTitle: string;
  hwAutoCheck: string;
  hwManualCheck: string;
  hwNoAutoCheck: string;
  hwClean: string;
  hwTotalFindings: string;
  hwSectionsChecked: string;
  hwAutoVerified: string;
  hwManualPending: string;
  hwSectionNames: Record<string, { name: string; icon: string }>;
  hwManualItems: Record<string, string[]>;
  hwManualCount: (n: number) => string;
  hwAffectedResources: (n: number) => string;
  hwRemediation: string;

  // CVE exploitability prioritization (AWS; rendered only when findings carry `exploitability`)
  exploitability: ExploitabilityI18n;
}

/** Funnel layer keys — mirrors FUNNEL_LAYERS in src/exploitability/funnel.ts. */
export type ExploitFunnelLayer = "total" | "exploitAvailable" | "epssHigh" | "kev" | "reachable" | "p0";

export interface ExploitabilityI18n {
  sectionTitle: string;
  funnelTitle: string;
  funnelLayers: Record<ExploitFunnelLayer, string>;
  funnelFindings: string;
  funnelCves: string;
  funnelNote: string;
  byPriority: string;
  priorityLabels: Record<Priority, string>;
  priorityTableTitle: string;
  noUrgent: string;
  moreRows: (n: number) => string;
  colPriority: string;
  colCve: string;
  colResource: string;
  colResourceType: string;
  colExploit: string;
  colEpss: string;
  colKev: string;
  colReachability: string;
  colRationale: string;
  colAffectedResources: string;
  colFindings: string;
  colHighestPriority: string;
  yes: string;
  no: string;
  notAvailable: string;
  reachability: Record<Reachability, string>;
  rationale: Record<RationaleCode, string>;
  exploitPriority: string;
  disclaimer: string;
  kevSnapshot: (date: string) => string;
  kevStale: (days: number) => string;
  cveSummaryTitle: (findings: number, cves: number) => string;
  cveSummaryNote: (shown: number) => string;
  /** Note under the inspector module when findings overflow the individual-entry cap. */
  inspectorOverflow: (n: number) => string;
  hwUrgentTitle: string;
  hwOthersTitle: string;
  hwMoreGroups: (n: number) => string;
  mdTopTitle: (n: number) => string;
}

import { zhI18n } from "./zh.js";
import { enI18n } from "./en.js";

const translations: Record<Lang, I18n> = {
  zh: zhI18n,
  en: enI18n,
};

const PROVIDER_NAMES: Record<ProviderId, Record<Lang, string>> = {
  aws: { zh: "AWS", en: "AWS" },
  huaweicloud: { zh: "\u534e\u4e3a\u4e91", en: "Huawei Cloud" },
  alicloud: { zh: "\u963f\u91cc\u4e91", en: "Alibaba Cloud" },
  azure: { zh: "Azure", en: "Azure" },
};

/** Human-readable cloud provider name for report titles / notes. Absent provider means AWS. */
export function providerName(provider: ProviderId | undefined, lang: Lang = "zh"): string {
  const names = provider ? PROVIDER_NAMES[provider] : undefined;
  if (!names) return "AWS";
  return lang === "en" ? names.en : names.zh;
}

/** Alias of {@link providerName}: display name of a provider ("Alibaba Cloud" / "阿里云" for alicloud, "Azure" for azure). */
export const providerDisplayName = providerName;

/**
 * Text overrides applied on top of the AWS strings when the report describes a
 * Huawei Cloud scan. Only labels where "AWS" would be factually wrong are
 * replaced; product-name strings ("AWS Security MCP Server") are kept.
 */
const HUAWEI_OVERRIDES: Record<Lang, Partial<I18n>> = {
  zh: {
    securityReportTitle: "\u534e\u4e3a\u4e91\u5b89\u5168\u626b\u63cf\u62a5\u544a",
    cloudItemsNote: (n: number) =>
      `\u4ee5\u4e0b ${n} \u9879\u7531\u534e\u4e3a\u4e91\u5e73\u53f0\u8d1f\u8d23\uff0c\u6839\u636e\u5b89\u5168\u8d23\u4efb\u5171\u62c5\u6a21\u578b\u4e0d\u5728\u672c\u62a5\u544a\u68c0\u67e5\u8303\u56f4\u5185\u3002`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "\u534e\u4e3a\u4e91 Config (RMS)",
        impact: "\u65e0\u6cd5\u68c0\u67e5\u8d44\u6e90\u914d\u7f6e\u5408\u89c4\u72b6\u6001",
        action: "\u542f\u7528\u534e\u4e3a\u4e91 Config (RMS) \u8d44\u6e90\u8bb0\u5f55\u5668\u5e76\u914d\u7f6e\u5408\u89c4\u89c4\u5219\uff08\u53ef\u9009\u7528\u201c\u7b49\u4fdd\u5408\u89c4\u68c0\u67e5\u201d\u5408\u89c4\u89c4\u5219\u5305\uff09",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "\u534e\u4e3a\u4e91 HSS\uff08\u4e3b\u673a\u5b89\u5168\uff09",
        impact: "\u65e0\u6cd5\u626b\u63cf ECS \u4e3b\u673a\u7684\u8f6f\u4ef6\u6f0f\u6d1e\uff08CVE\uff09",
        action: "\u5728 ECS \u5b89\u88c5 HSS Agent \u5e76\u5f00\u542f\u9632\u62a4\u7248\u672c\uff0c\u542f\u7528\u6f0f\u6d1e\u68c0\u6d4b",
      },
      patch_compliance_findings: {
        icon: "\ud83d\udfe1",
        service: "\u534e\u4e3a\u4e91 HSS \u6f0f\u6d1e\u7ba1\u7406",
        impact: "\u65e0\u6cd5\u68c0\u67e5\u4e3b\u673a\u64cd\u4f5c\u7cfb\u7edf\u8865\u4e01\u5408\u89c4\u72b6\u6001",
        action: "\u5728 ECS \u5b89\u88c5 HSS Agent \u5e76\u5f00\u542f\u9632\u62a4\uff0c\u901a\u8fc7 HSS \u6f0f\u6d1e\u7ba1\u7406\u4fee\u590d Linux / Windows \u7cfb\u7edf\u6f0f\u6d1e",
      },
    },
  },
  en: {
    securityReportTitle: "Huawei Cloud Security Scan Report",
    cloudItemsNote: (n: number) =>
      `The following ${n} items are the responsibility of the Huawei Cloud platform and are outside the scope of this report per the shared responsibility model.`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "Huawei Cloud Config (RMS)",
        impact: "Cannot check resource configuration compliance status",
        action: "Enable the Huawei Cloud Config (RMS) resource recorder and configure compliance rules (e.g. the MLPS conformance package)",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "Huawei Cloud HSS (Host Security Service)",
        impact: "Cannot scan ECS hosts for software vulnerabilities (CVEs)",
        action: "Install the HSS agent on ECS instances, enable a protection edition and turn on vulnerability detection",
      },
      patch_compliance_findings: {
        icon: "\ud83d\udfe1",
        service: "Huawei Cloud HSS vulnerability management",
        impact: "Cannot check host operating system patch compliance status",
        action: "Install the HSS agent on ECS instances, enable protection and fix Linux / Windows OS vulnerabilities via HSS vulnerability management",
      },
    },
  },
};

/**
 * Alibaba Cloud overrides (EXPERIMENTAL provider). Same rule as Huawei: only labels
 * where "AWS" would be wrong. Config (配置审计) replaces AWS Config / Security Hub,
 * Security Center (SAS, 云安全中心) replaces GuardDuty / Inspector / SSM Patch Manager.
 */
const ALICLOUD_OVERRIDES: Record<Lang, Partial<I18n>> = {
  zh: {
    securityReportTitle: "阿里云安全扫描报告",
    cloudItemsNote: (n: number) =>
      `以下 ${n} 项由阿里云平台负责，根据安全责任共担模型不在本报告检查范围内。`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "阿里云配置审计（Config）",
        impact: "无法检查资源配置合规状态",
        action: "开通阿里云配置审计（Config）并启用规则（可选用“等保三级预检合规包”）",
      },
      config_compliance_findings: {
        icon: "\ud83d\udd34",
        service: "阿里云配置审计（Config）合规包",
        impact: "无法获取托管规则 / 合规包的不合规资源评估结果",
        action: "开通阿里云配置审计（Config），启用托管规则或“等保三级预检合规包”",
      },
      guardduty_findings: {
        icon: "\ud83d\udd34",
        service: "阿里云云安全中心（SAS）告警",
        impact: "无法检测威胁活动（异常登录、恶意进程、挖矿程序等）",
        action: "开通云安全中心付费版本并在 ECS 安装安全中心 Agent，启用安全告警",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "阿里云云安全中心（SAS）漏洞管理",
        impact: "无法扫描 ECS 主机的软件漏洞（CVE）",
        action: "开通云安全中心付费版本并在 ECS 安装安全中心 Agent，启用漏洞检测",
      },
      patch_compliance_findings: {
        icon: "\ud83d\udfe1",
        service: "阿里云云安全中心（SAS）漏洞管理",
        impact: "无法检查主机操作系统补丁合规状态",
        action: "开通云安全中心付费版本并在 ECS 安装安全中心 Agent，通过漏洞管理修复 Linux / Windows 系统漏洞",
      },
    },
  },
  en: {
    securityReportTitle: "Alibaba Cloud Security Scan Report",
    cloudItemsNote: (n: number) =>
      `The following ${n} items are the responsibility of the Alibaba Cloud platform and are outside the scope of this report per the shared responsibility model.`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "Alibaba Cloud Config",
        impact: "Cannot check resource configuration compliance status",
        action: "Activate Alibaba Cloud Config and enable rules (e.g. the MLPS Level 3 pre-check compliance pack)",
      },
      config_compliance_findings: {
        icon: "\ud83d\udd34",
        service: "Alibaba Cloud Config compliance packs",
        impact: "Cannot obtain non-compliant resource evaluations from managed rules / compliance packs",
        action: "Activate Alibaba Cloud Config and enable managed rules or the MLPS Level 3 pre-check compliance pack",
      },
      guardduty_findings: {
        icon: "\ud83d\udd34",
        service: "Alibaba Cloud Security Center (SAS) alerts",
        impact: "Cannot detect threat activity (unusual logins, malicious processes, crypto mining, etc.)",
        action: "Purchase a paid Security Center edition, install the Security Center agent on ECS instances and enable security alerts",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "Alibaba Cloud Security Center (SAS) vulnerability management",
        impact: "Cannot scan ECS hosts for software vulnerabilities (CVEs)",
        action: "Purchase a paid Security Center edition, install the Security Center agent on ECS instances and enable vulnerability detection",
      },
      patch_compliance_findings: {
        icon: "\ud83d\udfe1",
        service: "Alibaba Cloud Security Center (SAS) vulnerability management",
        impact: "Cannot check host operating system patch compliance status",
        action: "Purchase a paid Security Center edition, install the Security Center agent on ECS instances and fix Linux / Windows OS vulnerabilities via vulnerability management",
      },
    },
  },
};

/**
 * Azure overrides (EXPERIMENTAL provider; China / 21Vianet is the default cloud). Same
 * rule: only labels where "AWS" would be wrong. Azure Policy replaces AWS Config,
 * Microsoft Defender for Cloud replaces Security Hub (assessments), GuardDuty (alerts)
 * and Inspector (vulnerability assessment sub-assessments).
 */
const AZURE_OVERRIDES: Record<Lang, Partial<I18n>> = {
  zh: {
    securityReportTitle: "Azure 安全扫描报告",
    cloudItemsNote: (n: number) =>
      `以下 ${n} 项由 Azure 平台负责，根据安全责任共担模型不在本报告检查范围内。`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "Azure Policy",
        impact: "无法检查资源配置合规状态",
        action: "为订阅分配 Azure Policy 策略或策略集（如 Microsoft 云安全基准），并注册 Microsoft.PolicyInsights 资源提供程序",
      },
      defender_assessment_findings: {
        icon: "\ud83d\udd34",
        service: "Microsoft Defender for Cloud 安全建议",
        impact: "无法获取 Defender for Cloud 安全建议（assessments）的不健康资源评估结果",
        action: "注册 Microsoft.Security 资源提供程序并启用 Defender for Cloud（基础 CSPM 免费），为审计主体授予 Security Reader 角色",
      },
      disk_encryption_findings: {
        icon: "\ud83d\udfe1",
        service: "Azure 托管磁盘加密",
        impact: "无法检查托管磁盘 / 虚拟机的加密状态",
        action: "为审计主体授予订阅级 Reader 角色，以读取磁盘与虚拟机的加密配置",
      },
      guardduty_findings: {
        icon: "\ud83d\udd34",
        service: "Microsoft Defender for Cloud 安全警报",
        impact: "无法检测威胁活动（异常登录、恶意进程、挖矿程序等）",
        action: "启用 Defender for Cloud 工作负载保护计划（如 Defender for Servers），并为审计主体授予 Security Reader 角色",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "Microsoft Defender for Cloud 漏洞评估",
        impact: "无法扫描虚拟机 / 容器镜像的软件漏洞（CVE）",
        action: "启用 Defender for Servers / Defender for Containers 并开启漏洞评估（中国区部分计划可能不可用）",
      },
    },
  },
  en: {
    securityReportTitle: "Azure Security Scan Report",
    cloudItemsNote: (n: number) =>
      `The following ${n} items are the responsibility of the Azure platform and are outside the scope of this report per the shared responsibility model.`,
    serviceRecommendations: {
      config_rules_findings: {
        icon: "\ud83d\udfe1",
        service: "Azure Policy",
        impact: "Cannot check resource configuration compliance status",
        action: "Assign Azure Policy definitions or initiatives (e.g. the Microsoft cloud security benchmark) to the subscription and register the Microsoft.PolicyInsights resource provider",
      },
      defender_assessment_findings: {
        icon: "\ud83d\udd34",
        service: "Microsoft Defender for Cloud recommendations",
        impact: "Cannot obtain unhealthy resource evaluations from Defender for Cloud recommendations (assessments)",
        action: "Register the Microsoft.Security resource provider, enable Defender for Cloud (foundational CSPM is free) and grant the audit principal the Security Reader role",
      },
      disk_encryption_findings: {
        icon: "\ud83d\udfe1",
        service: "Azure managed disk encryption",
        impact: "Cannot check the encryption state of managed disks / virtual machines",
        action: "Grant the audit principal the Reader role on the subscription so disk and VM encryption settings can be read",
      },
      guardduty_findings: {
        icon: "\ud83d\udd34",
        service: "Microsoft Defender for Cloud security alerts",
        impact: "Cannot detect threat activity (unusual logins, malicious processes, crypto mining, etc.)",
        action: "Enable a Defender for Cloud workload protection plan (e.g. Defender for Servers) and grant the audit principal the Security Reader role",
      },
      inspector_findings: {
        icon: "\ud83d\udfe1",
        service: "Microsoft Defender for Cloud vulnerability assessment",
        impact: "Cannot scan virtual machines / container images for software vulnerabilities (CVEs)",
        action: "Enable Defender for Servers / Defender for Containers with vulnerability assessment (some plans may be unavailable in Azure China)",
      },
    },
  },
};

/** Per-provider overrides; providers without an entry (aws) use the base tables as-is. */
const PROVIDER_OVERRIDES: Partial<Record<ProviderId, Record<Lang, Partial<I18n>>>> = {
  huaweicloud: HUAWEI_OVERRIDES,
  alicloud: ALICLOUD_OVERRIDES,
  azure: AZURE_OVERRIDES,
};

const derivedI18nCache = new Map<string, I18n>();

/**
 * Translations for `lang`. For providers with overrides (huaweicloud, alicloud, azure) a
 * derived table with provider-specific labels is returned (cached); for aws /
 * undefined the original object is returned unchanged (identity-preserving, so
 * AWS output is byte-identical).
 */
export function getI18n(lang: Lang = "zh", provider?: ProviderId): I18n {
  const key: Lang = translations[lang] ? lang : "zh";
  const base = translations[key];
  const overrides = provider ? PROVIDER_OVERRIDES[provider]?.[key] : undefined;
  if (!overrides) return base;
  const cacheKey = `${provider}:${key}`;
  let derived = derivedI18nCache.get(cacheKey);
  if (!derived) {
    derived = {
      ...base,
      ...overrides,
      serviceRecommendations: { ...base.serviceRecommendations, ...(overrides.serviceRecommendations ?? {}) },
    };
    derivedI18nCache.set(cacheKey, derived);
  }
  return derived;
}

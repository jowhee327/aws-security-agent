import type { ProviderId } from "../types.js";

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
}

import { zhI18n } from "./zh.js";
import { enI18n } from "./en.js";

const translations: Record<Lang, I18n> = {
  zh: zhI18n,
  en: enI18n,
};

/** Human-readable cloud provider name for report titles / notes. Absent provider means AWS. */
export function providerName(provider: ProviderId | undefined, lang: Lang = "zh"): string {
  if (provider === "huaweicloud") return lang === "en" ? "Huawei Cloud" : "\u534e\u4e3a\u4e91";
  return "AWS";
}

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

const huaweiI18nCache: Partial<Record<Lang, I18n>> = {};

/**
 * Translations for `lang`. When `provider` is "huaweicloud" a derived table with
 * Huawei-specific labels is returned; for aws / undefined the original object is
 * returned unchanged (identity-preserving, so AWS output is byte-identical).
 */
export function getI18n(lang: Lang = "zh", provider?: ProviderId): I18n {
  const key: Lang = translations[lang] ? lang : "zh";
  const base = translations[key];
  if (provider !== "huaweicloud") return base;
  let derived = huaweiI18nCache[key];
  if (!derived) {
    const overrides = HUAWEI_OVERRIDES[key];
    derived = {
      ...base,
      ...overrides,
      serviceRecommendations: { ...base.serviceRecommendations, ...(overrides.serviceRecommendations ?? {}) },
    };
    huaweiI18nCache[key] = derived;
  }
  return derived;
}

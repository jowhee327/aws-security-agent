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
  hwReportDisclaimer: string;
}

import { zhI18n } from "./zh.js";
import { enI18n } from "./en.js";

const translations: Record<Lang, I18n> = {
  zh: zhI18n,
  en: enI18n,
};

export function getI18n(lang: Lang = "zh"): I18n {
  return translations[lang] ?? translations.zh;
}

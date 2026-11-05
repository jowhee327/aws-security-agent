import { createContext, useState, useCallback, type ReactNode } from 'react';

type Lang = 'en' | 'zh';

const translations: Record<Lang, Record<string, string>> = {
  en: {
    'nav.title': 'AWS Security',
    'nav.overview': 'Overview',
    'nav.trends': 'Trends',
    'nav.findings': 'Findings',
    'nav.lastScan': 'Last scan',
    'nav.account': 'Account',

    'overview.title': 'Overview',
    'overview.severity': 'Severity Distribution',
    'overview.topFindings': 'Top Findings',
    'overview.aiSummary': 'AI Security Summary',
    'overview.moduleBreakdown': 'Findings by Module',
    'overview.totalFindings': 'Total Findings',
    'overview.modulesScanned': 'Modules Scanned',
    'overview.scanTime': 'Scan Time',
    'overview.disabledServices': 'Disabled Services',

    'findings.title': 'Findings',
    'findings.all': 'ALL',
    'findings.search': 'Search...',
    'findings.allModules': 'All Modules',
    'findings.severity': 'Severity',
    'findings.titleCol': 'Title',
    'findings.module': 'Module',
    'findings.resource': 'Resource',
    'findings.riskScore': 'Risk Score',
    'findings.priority': 'Exploit Priority',
    'findings.description': 'Description',
    'findings.impact': 'Impact',
    'findings.remediation': 'Remediation Steps',
    'findings.showing': 'Showing',
    'findings.of': 'of',
    'findings.findingsLabel': 'findings',
    'findings.page': 'Page',
    'findings.noFindings': 'No findings match the current filters.',
    'findings.prev': 'Prev',
    'findings.next': 'Next',

    'exploit.title': 'Exploitability Assessment',
    'exploit.layer.total': 'CVE findings',
    'exploit.layer.exploitAvailable': 'Public exploit',
    'exploit.layer.epssHigh': 'EPSS high (≥ 0.1)',
    'exploit.layer.kev': 'CISA KEV',
    'exploit.layer.reachable': 'Publicly exposed (0.0.0.0/0 or allow-listed)',
    'exploit.layer.p0': 'P0',
    'exploit.cves': 'CVEs',
    'exploit.funnelNote': 'Each layer is counted independently (not a strict subset).',
    'exploit.urgent': 'P0 / P1 to fix first',
    'exploit.disclaimer': 'Prioritization from threat intel (exploit, EPSS, CISA KEV) and configured exposure (public IP, SG, NACL, running state). Not penetration testing; read-only, no active probing.',
    'exploit.priority': 'Priority',
    'exploit.reach.internet_open': 'Open to the internet',
    'exploit.reach.allowlist': 'Allow-listed public IPs only',
    'exploit.reach.internal': 'Internal only',
    'exploit.reach.not_running': 'Not running',
    'exploit.reach.unknown': 'Reachability unknown',

    'trends.title': 'Trends',
    'trends.findingsTrend': 'Findings Trend (30 days)',
    'trends.scoreTrend': 'Score Trend (30 days)',

    'severity.critical': 'Critical',
    'severity.high': 'High',
    'severity.medium': 'Medium',
    'severity.low': 'Low',
    'severity.CRITICAL': 'Critical',
    'severity.HIGH': 'High',
    'severity.MEDIUM': 'Medium',
    'severity.LOW': 'Low',

    'module.service_detection': 'Security Service Detection',
    'module.secret_exposure': 'Secret Exposure',
    'module.ssl_certificate': 'SSL Certificate',
    'module.dns_dangling': 'Dangling DNS',
    'module.network_reachability': 'Network Reachability',
    'module.iam_privilege_escalation': 'IAM Privilege Escalation',
    'module.public_access_verify': 'Public Access Verification',
    'module.tag_compliance': 'Tag Compliance',
    'module.idle_resources': 'Idle Resources',
    'module.disaster_recovery': 'Disaster Recovery',
    'module.security_hub_findings': 'Security Hub',
    'module.guardduty_findings': 'GuardDuty',
    'module.inspector_findings': 'Inspector',
    'module.trusted_advisor_findings': 'Trusted Advisor',
    'module.config_rules_findings': 'Config Rules',
    'module.access_analyzer_findings': 'Access Analyzer',
    'module.patch_compliance_findings': 'Patch Compliance',
    'module.imdsv2_enforcement': 'IMDSv2 Enforcement',
    'module.waf_coverage': 'WAF Coverage',

    'grade': 'Grade',
    'findings': 'findings',
    'seconds': 's',
  },
  zh: {
    'nav.title': 'AWS 安全',
    'nav.overview': '概览',
    'nav.trends': '趋势',
    'nav.findings': '发现',
    'nav.lastScan': '最近扫描',
    'nav.account': '账户',

    'overview.title': '概览',
    'overview.severity': '严重性分布',
    'overview.topFindings': '高风险发现',
    'overview.aiSummary': 'AI 安全态势总结',
    'overview.moduleBreakdown': '按模块分类',
    'overview.totalFindings': '总发现数',
    'overview.modulesScanned': '扫描模块数',
    'overview.scanTime': '扫描耗时',
    'overview.disabledServices': '未启用服务',

    'findings.title': '发现',
    'findings.all': '全部',
    'findings.search': '搜索...',
    'findings.allModules': '全部模块',
    'findings.severity': '严重性',
    'findings.titleCol': '标题',
    'findings.module': '模块',
    'findings.resource': '资源',
    'findings.riskScore': '风险评分',
    'findings.priority': '可利用性优先级',
    'findings.description': '描述',
    'findings.impact': '影响',
    'findings.remediation': '修复步骤',
    'findings.showing': '显示',
    'findings.of': '/',
    'findings.findingsLabel': '条发现',
    'findings.page': '页',
    'findings.noFindings': '没有符合当前筛选条件的发现。',
    'findings.prev': '上一页',
    'findings.next': '下一页',

    'exploit.title': '可利用性研判',
    'exploit.layer.total': 'CVE 漏洞',
    'exploit.layer.exploitAvailable': '有公开 exploit',
    'exploit.layer.epssHigh': 'EPSS 高（≥ 0.1）',
    'exploit.layer.kev': 'CISA KEV',
    'exploit.layer.reachable': '有公网暴露面（全开或白名单）',
    'exploit.layer.p0': 'P0',
    'exploit.cves': '个 CVE',
    'exploit.funnelNote': '各层独立统计，非严格子集。',
    'exploit.urgent': '优先修复（P0 / P1）',
    'exploit.disclaimer': '基于威胁情报（exploit、EPSS、CISA KEV）与配置暴露面（公网 IP、安全组、NACL、运行状态）的优先级排序，不是渗透测试；全程只读，不做主动探测。',
    'exploit.priority': '优先级',
    'exploit.reach.internet_open': '对全网开放',
    'exploit.reach.allowlist': '仅白名单公网 IP',
    'exploit.reach.internal': '仅内网',
    'exploit.reach.not_running': '未运行',
    'exploit.reach.unknown': '可达性未知',

    'trends.title': '趋势',
    'trends.findingsTrend': '发现趋势 (30天)',
    'trends.scoreTrend': '评分趋势 (30天)',

    'severity.critical': '严重',
    'severity.high': '高',
    'severity.medium': '中',
    'severity.low': '低',
    'severity.CRITICAL': '严重/Critical',
    'severity.HIGH': '高/High',
    'severity.MEDIUM': '中/Medium',
    'severity.LOW': '低/Low',

    'module.service_detection': '安全服务检测',
    'module.secret_exposure': '密钥暴露',
    'module.ssl_certificate': 'SSL 证书',
    'module.dns_dangling': '悬挂 DNS',
    'module.network_reachability': '网络可达性',
    'module.iam_privilege_escalation': 'IAM 提权分析',
    'module.public_access_verify': '公网访问验证',
    'module.tag_compliance': '标签合规',
    'module.idle_resources': '闲置资源',
    'module.disaster_recovery': '灾备评估',
    'module.security_hub_findings': 'Security Hub',
    'module.guardduty_findings': 'GuardDuty',
    'module.inspector_findings': 'Inspector',
    'module.trusted_advisor_findings': 'Trusted Advisor',
    'module.config_rules_findings': 'Config Rules',
    'module.access_analyzer_findings': 'Access Analyzer',
    'module.patch_compliance_findings': '补丁合规',
    'module.imdsv2_enforcement': 'IMDSv2 强制',
    'module.waf_coverage': 'WAF 覆盖',

    'grade': '等级',
    'findings': '发现',
    'seconds': '秒',
  },
};

interface I18nContextType {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: string) => string;
}

export const I18nContext = createContext<I18nContextType>(null!);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const saved = localStorage.getItem('dashboard-lang');
    return saved === 'zh' ? 'zh' : 'en';
  });

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    localStorage.setItem('dashboard-lang', l);
  }, []);

  const t = useCallback(
    (key: string) => translations[lang][key] ?? key,
    [lang],
  );

  return (
    <I18nContext value={{ lang, setLang, t }}>
      {children}
    </I18nContext>
  );
}

export { useI18n } from './hooks/useI18n';

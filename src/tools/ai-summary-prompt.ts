import type { FullScanResult, Finding } from "../types.js";
import type { Lang } from "../i18n/index.js";

export type ReportType = "dashboard" | "html" | "hw_defense" | "mlps3";

/**
 * Build a compact, token-friendly digest of the scan result that the calling
 * AI can ground its summary on. We deliberately keep this small: counts by
 * severity, top modules by finding count, and the top-N highest-risk findings.
 */
function buildFindingsDigest(scan: FullScanResult, lang: Lang, topN = 12): string {
  const zh = lang === "zh";
  const all: Finding[] = scan.modules.flatMap((m) =>
    m.findings.map((f) => ({ ...f, module: f.module ?? m.module })),
  );
  const s = scan.summary;

  // Module breakdown (desc by findings). Limit generously so no module with
  // findings is silently dropped from the grounding digest.
  const byModule = [...scan.modules]
    .filter((m) => m.findingsCount > 0)
    .sort((a, b) => b.findingsCount - a.findingsCount)
    .slice(0, 19)
    .map((m) => `${m.module}=${m.findingsCount}`)
    .join(", ");

  // Top findings by riskScore
  const top = [...all].sort((a, b) => b.riskScore - a.riskScore).slice(0, topN);
  const topLines = top
    .map(
      (f, i) =>
        `${i + 1}. [${f.severity}/${f.priority}] ${f.title} — ${f.resourceType} ${f.resourceId} (${f.region}) risk=${f.riskScore}`,
    )
    .join("\n");

  const head = zh
    ? `账号: ${scan.accountId} | 区域: ${scan.region}\n风险总数: ${s.totalFindings} (CRITICAL ${s.critical} / HIGH ${s.high} / MEDIUM ${s.medium} / LOW ${s.low})\n模块分布: ${byModule || "无"}\n\n高风险 Top ${top.length}:\n${topLines || "无"}`
    : `Account: ${scan.accountId} | Region: ${scan.region}\nTotal findings: ${s.totalFindings} (CRITICAL ${s.critical} / HIGH ${s.high} / MEDIUM ${s.medium} / LOW ${s.low})\nModule breakdown: ${byModule || "none"}\n\nTop ${top.length} by risk:\n${topLines || "none"}`;

  return head;
}

interface Profile {
  persona: string;
  focus: string;
  format: string;
}

/** Report-type-specific instructions (bilingual). */
function getProfile(type: ReportType, lang: Lang): Profile {
  const zh = lang === "zh";
  switch (type) {
    case "dashboard":
      return zh
        ? {
            persona: "你在为安全运营仪表盘写一段高管速览。读者是 CISO / 管理层，时间很少。",
            focus: "整体安全态势一句话定调 + 安全评分解读 + 此刻最该关注的 3 件事（按业务影响排序）。不要罗列所有 finding。",
            format: "3-5 句话，开头一句结论先行。中文。不用 Markdown 标题，可用简短分号或换行。语气专业、克制、可执行。",
          }
        : {
            persona: "You are writing an executive at-a-glance summary for a security operations dashboard. Readers are CISO/leadership with little time.",
            focus: "One-line overall posture verdict + interpretation of the security score + the top 3 things to focus on right now (ordered by business impact). Do NOT list every finding.",
            format: "3-5 sentences, conclusion first. English. No Markdown headings; short line breaks ok. Professional, restrained, actionable tone.",
          };
    case "html":
      return zh
        ? {
            persona: "你在为一份完整的 AWS 安全扫描报告写执行摘要。读者既有管理层也有技术负责人。",
            focus: "整体风险全景 + Top 风险的共性根因（如公网暴露面、IAM 过权、加密/日志缺失等）+ 分优先级(P0→P2)的修复路线建议。点出系统性问题而非逐条复述。",
            format: "1 段概述 + 3-5 条要点。中文。可用要点列表。技术与管理双视角，给出可落地的下一步。",
          }
        : {
            persona: "You are writing the executive summary for a full AWS security scan report. Readers include both management and technical leads.",
            focus: "Overall risk landscape + common root causes behind the top risks (public exposure, over-privileged IAM, missing encryption/logging, etc.) + a prioritized (P0→P2) remediation roadmap. Surface systemic issues rather than restating each finding.",
            format: "1 overview paragraph + 3-5 bullet points. English. Bullet list ok. Both technical and management lens, with concrete next steps.",
          };
    case "hw_defense":
      return zh
        ? {
            persona: "你是护网行动(网络安全攻防演练)的蓝队指挥。这是一份护网备战评估报告。注意：HW=护网，与华为无关。",
            focus: "从攻击者视角串联 findings 成攻击链(kill-chain)：哪些是外部可达的初始突破口、横向移动/提权路径、可能的影响面；然后给出备战收敛清单(先关什么、先盯什么)。强调暴露面收敛与监控加固。",
            format: "先一句研判结论(当前暴露面/被打穿风险)，再给『攻击链视角』和『备战整改优先级』两块。中文。语气贴护网实战语境，紧迫但不夸张。",
          }
        : {
            persona: "You are the blue-team lead for an HW Defense exercise (cybersecurity attack-defense drill). This is a pre-exercise readiness report. Note: HW = HuWang/护网, unrelated to Huawei.",
            focus: "From an attacker's perspective, chain findings into a kill-chain: external initial footholds, lateral movement/privilege-escalation paths, likely blast radius; then a hardening checklist (what to close/watch first). Emphasize attack-surface reduction and monitoring.",
            format: "Lead with a one-line verdict (current exposure / breach risk), then two blocks: 'Attack-chain view' and 'Readiness remediation priorities'. English. Combat-readiness tone, urgent but not alarmist.",
          };
    case "mlps3":
      return zh
        ? {
            persona: "你是等保测评顾问。这是一份等保三级(GB/T 22239-2019)合规预检报告。",
            focus: "从合规视角总结：当前对照等保三级控制项的总体达标情况、哪些控制域存在明显不达标项(如访问控制、安全审计、入侵防范、数据完整性/保密性等)、整改紧迫度与过保建议。把技术 finding 映射到合规语言。",
            format: "1 段合规结论 + 按控制域分组的不达标要点 + 整改优先级。中文。引用控制域名称。语气严谨、面向测评。",
          }
        : {
            persona: "You are an MLPS assessment advisor. This is an MLPS Level 3 (GB/T 22239-2019) compliance pre-check report.",
            focus: "Summarize from a compliance lens: overall conformance against MLPS L3 controls, which control domains have clear gaps (access control, security audit, intrusion prevention, data integrity/confidentiality, etc.), remediation urgency, and certification-readiness advice. Map technical findings to compliance language.",
            format: "1 compliance verdict paragraph + non-conformance points grouped by control domain + remediation priority. English. Reference control-domain names. Rigorous, assessment-oriented tone.",
          };
  }
}

const TYPE_LABEL: Record<ReportType, { zh: string; en: string }> = {
  dashboard: { zh: "安全运营仪表盘", en: "Security Operations Dashboard" },
  html: { zh: "AWS 安全扫描报告", en: "AWS Security Scan Report" },
  hw_defense: { zh: "护网行动评估报告", en: "HW Defense (护网) Readiness Report" },
  mlps3: { zh: "等保三级合规预检报告", en: "MLPS Level 3 Compliance Pre-check" },
};

/**
 * Build a ready-to-run prompt for the calling client AI to produce a
 * report-type-tailored AI summary. The server never calls an LLM itself —
 * it only assembles this prompt + a grounded findings digest.
 */
export function buildAiSummaryPrompt(
  type: ReportType,
  scan: FullScanResult,
  lang: Lang,
): string {
  const zh = lang === "zh";
  const p = getProfile(type, lang);
  const label = TYPE_LABEL[type][zh ? "zh" : "en"];
  const digest = buildFindingsDigest(scan, lang);

  if (zh) {
    return [
      `# 任务：为「${label}」生成针对性的 AI 安全总结`,
      ``,
      `## 角色`,
      p.persona,
      ``,
      `## 总结重点`,
      p.focus,
      ``,
      `## 输出格式`,
      p.format,
      ``,
      `## 约束`,
      `- 只依据下面的扫描数据，不要编造不存在的资源或 finding。`,
      `- 不要逐条复述所有 finding；提炼模式与优先级。`,
      `- 直接输出总结正文本身（不要带「以下是总结」之类的前言，不要 code fence）。`,
      `- 语言：中文。`,
      ``,
      `## 扫描数据摘要`,
      digest,
      ``,
      `请现在输出总结正文。生成后，把这段文本通过对应报告工具的 ai_summary 参数回传即可。`,
    ].join("\n");
  }

  return [
    `# Task: Produce a tailored AI security summary for the "${label}"`,
    ``,
    `## Role`,
    p.persona,
    ``,
    `## Summary focus`,
    p.focus,
    ``,
    `## Output format`,
    p.format,
    ``,
    `## Constraints`,
    `- Base it ONLY on the scan data below; do not invent resources or findings.`,
    `- Do not restate every finding; distill patterns and priorities.`,
    `- Output the summary body itself (no preamble like "Here is the summary", no code fences).`,
    `- Language: English.`,
    ``,
    `## Scan data digest`,
    digest,
    ``,
    `Now output the summary body. After generating it, pass the text back via the ai_summary parameter of the corresponding report tool.`,
  ].join("\n");
}

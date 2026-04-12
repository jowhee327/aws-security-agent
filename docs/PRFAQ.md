# AWS Security MCP Agent — PRFAQ

---

# 中文版

## Press Release

### 标题
**AWS Security MCP Agent：让 AI 助手直接执行 AWS 安全检查的开源工具**

### 副标题
业界首个基于 MCP 协议的 AWS 安全扫描 Agent，19 个检查模块、11 个预置场景、等保三级全覆盖，让 Kiro/Claude Code 等 AI 编程助手成为你的安全工程师。

### 正文

**为什么做这个项目？**

AWS 客户面临一个普遍困境：安全服务很多（Security Hub、GuardDuty、Inspector、Config、Access Analyzer、Trusted Advisor），但每个服务各自为政。安全工程师需要登录多个控制台，手动拼凑分散在不同服务中的安全发现，才能回答一个简单的问题——"我的 AWS 环境安全吗？"

与此同时，AI 编程助手（Kiro、Claude Code、Cursor 等）正在改变开发者的工作方式，但它们只能写代码，不能理解你的 AWS 安全状态。**工具和智能之间存在断层。**

AWS Security MCP Agent 通过 Model Context Protocol (MCP) 打通这个断层：让 AI 助手直接调用安全扫描工具，获取实时安全数据，进行深度分析，给出具体建议。

**解决了什么问题？**

1. **安全服务碎片化**：6+ 个 AWS 安全服务的数据分散在不同控制台，没有统一视图。Agent 将所有安全发现聚合到一处。

2. **Security Hub 检查盲区**：Security Hub 只检查"配置是否合规"，无法发现 IAM 提权路径、Lambda 中的硬编码密钥、DNS 悬挂导致的子域名接管、ALB 是否实际启用了 WAF 等深层风险。Agent 的 12 个自有 scanner 专门填补这些盲区。

3. **等保合规负担重**：等保三级（GB/T 22239-2019）有 184 项检查要求，安全团队需要数天手动整理。Agent 自动将扫描结果映射到等保检查项，生成证据收集报告。

4. **安全发现看得到但看不懂**：Security Hub 告诉你"EC2.6 VPC Flow Logs 未开启"，但不告诉你这意味着什么、影响范围多大、应该怎么修。AI 分析补上这一环。

5. **护网准备耗时长**：每年护网行动前的安全自查需要 1-2 周。Agent 提供 `hw_defense` 一键扫描 + 人工 checklist，将准备周期从周级压缩到天级。

**核心价值**

| 价值 | 说明 |
|------|------|
| **聚合入口** | Security Hub + GuardDuty + Inspector + Config + Access Analyzer + Trusted Advisor，一次 `scan_all` 全拉到 |
| **独有深度检查** | IAM 提权链分析、密钥泄露、公网暴露验证、DNS 悬挂、WAF 覆盖率、IMDSv2 强制 — Security Hub 做不到的事 |
| **场景化预置** | 11 个开箱即用分组：护网、等保预检、公网暴露、最小权限、新账号基线… |
| **AI 原生** | MCP 协议让 AI 助手直接调用工具 + 分析结果，不是"生成报告让人看"，而是"AI 看完告诉你该怎么办" |
| **中国区完整支持** | aws-cn partition、无 root user、无 Macie，19 个 scanner 全部中国区验证通过 |

**AI 怎么参与？**

AWS Security MCP Agent 的设计理念是**"工具做检测，AI 做理解"**：

- **工具层**（不需要 AI）：19 个 scanner 执行只读 API 调用、风险评分算法打分、HTML/Markdown/等保报告模板渲染、Dashboard 前端展示。这些是确定性的、可审计的、可复现的。

- **AI 层**（MCP 协议连接）：
  - **编排**：AI 根据用户需求选择调用哪些工具、以什么顺序执行（MCP prompt: `security-scan`）
  - **分析**：AI 解读单个 finding 的风险、攻击路径、影响范围、修复步骤（MCP prompt: `analyze-finding`）
  - **关联**：AI 跨 findings 发现模式——"这 5 个 findings 组合起来说明你有一条从公网到数据库的攻击路径"
  - **规划**：AI 基于护网 checklist 制定具体准备计划（MCP prompt: `hw_defense_checklist`）
  - **对话**：用户可以用自然语言问任何问题——"帮我看看哪些是最紧急的"、"这个 finding 怎么修"

关键设计决策：**检测不依赖 AI，分析借力 AI。** 扫描结果是确定性的（同样的环境 = 同样的 findings），AI 负责把结构化数据转化为可执行的洞察。

**交付物**

| 交付物 | 形式 | 说明 |
|--------|------|------|
| MCP Server | npm 包 (`aws-security-mcp`) | 13 个 tools + 3 个 prompts + 2 个 resources |
| 安全报告 | 单文件 HTML | 暗色主题、交互过滤、SVG 图表、打印友好 |
| 等保报告 | 单文件 HTML | 184 项 GB/T 22239-2019 证据收集 |
| React Dashboard | 本地/S3 部署 | 30 天趋势、SH 子分类、i18n、交互过滤 |
| StackSet 模板 | CloudFormation YAML/JSON | 多账号审计角色一键部署 |
| Markdown 报告 | 纯文本 | 适合 AI 进一步分析 |
| 安全成熟度评估 | Markdown | 基于扫描结果的成熟度打分 |

**技术规格**

- 19 个 scanner（12 独有 + 5 检测 + 2 聚合）
- 11 个预置扫描分组
- 多账号支持（Organizations + AssumeRole）
- 中英文双语
- 146 个测试
- 100% 只读（无写入 API）
- MIT 开源

---

## FAQ

### Q1: 和 Security Hub 是什么关系？
Security Hub 是我们的数据源之一。Agent 通过 `security_hub_findings` scanner 聚合 Security Hub 的 FSBP、Inspector、GuardDuty、Config、Access Analyzer 发现，并按来源分类展示。但 Agent 的独有 scanner 检查的是 Security Hub 做不到的事（IAM 提权链、密钥泄露、公网验证等）。不是替代 Security Hub，是补充 + 聚合。

### Q2: 需要开哪些 AWS 安全服务？
不需要全开。Agent 会自动检测哪些服务已开启（`service_detection` scanner），未开启的会给出提醒和影响说明。核心推荐开启 Security Hub（获取最完整的聚合数据），但即使没开，12 个独有 scanner 仍然可以独立运行。

### Q3: 支持中国区吗？
完整支持。19 个 scanner 全部在 cn-north-1 / cn-northwest-1 验证通过。自动识别 aws-cn partition，无 root user 假设，已移除中国区不可用的 Macie。

### Q4: 会不会修改我的 AWS 资源？
不会。所有 scanner 只使用 Describe/Get/List API，代码级强制只读。凭证不会出现在 findings 或日志中。

### Q5: 怎么和 AI 助手配合使用？
安装 npm 包后，在 Kiro/Claude Code/Cursor 的 MCP 配置中添加 server。AI 助手会自动发现可用的 tools、prompts、resources。你可以直接说"帮我做一次安全扫描"或"分析这个 finding"。

### Q6: 多账号怎么用？
三步：1) 用提供的 StackSet 模板在所有子账号部署审计角色；2) 扫描时设 `org_mode: true`；3) Agent 自动发现 Organizations 子账号并逐个 AssumeRole 扫描。

### Q7: 等保报告可以直接交给测评机构吗？
不能。Agent 生成的是"证据收集报告"，自动将扫描结果映射到 184 项检查要求，标注哪些已自动验证、哪些需人工确认、哪些由云服务商保障。这是给安全团队的准备材料，不是最终测评报告。

### Q8: 和 Prowler / ScoutSuite 有什么区别？
三个关键差异：1) MCP 原生——可以和 AI 助手直接交互，不只是生成报告；2) 中国区优先——全部功能中国区验证，等保报告是独有的；3) 聚合层——不重做 Security Hub 已有的检查，而是聚合 + 补充独有检查。

### Q9: 扫描需要多长时间？
取决于资源规模。典型单账号扫描 30-60 秒（所有 scanner 并行执行）。多账号按子账号数线性增长。

### Q10: 是否免费？
完全免费开源（MIT License）。AWS API 调用本身可能产生少量费用（主要是 Security Hub 按 finding 计费），但 Agent 本身不收费。

---
---

# English Version

## Press Release

### Title
**AWS Security MCP Agent: Let AI Assistants Run Your AWS Security Checks**

### Subtitle
The first open-source AWS security scanner built on the MCP protocol — 19 modules, 11 preset scenarios, MLPS Level 3 compliance coverage. Turn Kiro, Claude Code, and other AI coding assistants into your security engineer.

### Body

**Why this project?**

AWS customers face a universal challenge: there are many security services (Security Hub, GuardDuty, Inspector, Config, Access Analyzer, Trusted Advisor), but each operates in isolation. Security engineers must log into multiple consoles and manually piece together findings scattered across different services to answer a simple question — "Is my AWS environment secure?"

Meanwhile, AI coding assistants (Kiro, Claude Code, Cursor, etc.) are transforming how developers work, but they can only write code — they can't understand your AWS security posture. **There's a gap between tools and intelligence.**

AWS Security MCP Agent bridges this gap through the Model Context Protocol (MCP): it lets AI assistants directly invoke security scanning tools, access real-time security data, perform deep analysis, and provide specific recommendations.

**What problems does it solve?**

1. **Fragmented security services**: 6+ AWS security services with data scattered across different consoles, no unified view. The Agent aggregates all security findings in one place.

2. **Security Hub blind spots**: Security Hub only checks "is the configuration compliant?" — it can't detect IAM privilege escalation paths, hardcoded secrets in Lambda, dangling DNS leading to subdomain takeover, or whether ALBs actually have WAF enabled. The Agent's 12 proprietary scanners fill these gaps.

3. **Compliance burden**: China's MLPS Level 3 (GB/T 22239-2019) has 184 check requirements that take security teams days to compile. The Agent automatically maps scan results to MLPS items and generates evidence collection reports.

4. **Findings are visible but not understandable**: Security Hub tells you "EC2.6 VPC Flow Logs not enabled" but doesn't explain what it means, how big the blast radius is, or how to fix it. AI analysis fills this gap.

5. **HW Defense preparation takes too long**: The annual HW (red-blue team exercise) security self-assessment takes 1-2 weeks. The Agent provides one-click `hw_defense` scanning plus a manual checklist, compressing preparation from weeks to days.

**Core Value**

| Value | Description |
|-------|-------------|
| **Aggregation Hub** | Security Hub + GuardDuty + Inspector + Config + Access Analyzer + Trusted Advisor — one `scan_all` gets everything |
| **Proprietary Deep Checks** | IAM privilege escalation chains, secret exposure, public access verification, dangling DNS, WAF coverage, IMDSv2 enforcement — things Security Hub can't do |
| **Scenario Presets** | 11 ready-to-use scan groups: HW Defense, MLPS pre-check, exposure, least privilege, new account baseline... |
| **AI-Native** | MCP protocol lets AI assistants directly invoke tools + analyze results — not "generate a report for humans to read" but "AI reads it and tells you what to do" |
| **Full China Region Support** | aws-cn partition, no root user, no Macie — all 19 scanners verified in China regions |

**How does AI participate?**

The AWS Security MCP Agent is designed around the principle: **"Tools detect, AI understands."**

- **Tool Layer** (no AI needed): 19 scanners execute read-only API calls, risk scoring algorithms assign scores, HTML/Markdown/MLPS report templates render, Dashboard frontend displays data. These are deterministic, auditable, and reproducible.

- **AI Layer** (connected via MCP):
  - **Orchestration**: AI chooses which tools to call and in what order based on user needs (MCP prompt: `security-scan`)
  - **Analysis**: AI interprets individual findings — risk level, attack vectors, blast radius, remediation steps (MCP prompt: `analyze-finding`)
  - **Correlation**: AI discovers patterns across findings — "these 5 findings together mean there's an attack path from the internet to your database"
  - **Planning**: AI creates specific preparation plans based on the HW Defense checklist (MCP prompt: `hw_defense_checklist`)
  - **Conversation**: Users can ask anything in natural language — "show me the most urgent issues", "how do I fix this finding?"

Key design decision: **Detection doesn't depend on AI; analysis leverages AI.** Scan results are deterministic (same environment = same findings), while AI transforms structured data into actionable insights.

**Deliverables**

| Deliverable | Format | Description |
|-------------|--------|-------------|
| MCP Server | npm package (`aws-security-mcp`) | 13 tools + 3 prompts + 2 resources |
| Security Report | Single-file HTML | Dark theme, interactive filtering, SVG charts, print-friendly |
| MLPS Report | Single-file HTML | 184-item GB/T 22239-2019 evidence collection |
| React Dashboard | Local or S3 deployment | 30-day trends, SH sub-categories, i18n, interactive filtering |
| StackSet Template | CloudFormation YAML/JSON | One-click multi-account audit role deployment |
| Markdown Report | Plain text | Suitable for further AI analysis |
| Security Maturity Assessment | Markdown | Maturity scoring based on scan results |

**Technical Specifications**

- 19 scanners (12 proprietary + 5 detection + 2 aggregation)
- 11 preset scan groups
- Multi-account support (Organizations + AssumeRole)
- Bilingual (Chinese/English)
- 146 tests
- 100% read-only (no write APIs)
- MIT open-source

---

## FAQ

### Q1: What's the relationship with Security Hub?
Security Hub is one of our data sources. The Agent aggregates Security Hub findings (FSBP, Inspector, GuardDuty, Config, Access Analyzer) through the `security_hub_findings` scanner and categorizes them by source. But the Agent's proprietary scanners check things Security Hub can't (IAM escalation chains, secret exposure, public access verification, etc.). It's not a replacement — it's augmentation + aggregation.

### Q2: Which AWS security services need to be enabled?
None are strictly required. The Agent auto-detects which services are enabled (`service_detection` scanner) and alerts you about disabled ones with impact explanations. We recommend enabling Security Hub for the most complete aggregated data, but even without it, 12 proprietary scanners run independently.

### Q3: Does it support China regions?
Full support. All 19 scanners verified in cn-north-1 / cn-northwest-1. Auto-detects aws-cn partition, no root user assumptions, removed China-unavailable Macie.

### Q4: Will it modify my AWS resources?
No. All scanners use only Describe/Get/List APIs — read-only enforced at code level. Credentials never appear in findings or logs.

### Q5: How do I use it with AI assistants?
Install the npm package, add the server to your Kiro/Claude Code/Cursor MCP configuration. The AI assistant auto-discovers available tools, prompts, and resources. Just say "run a security scan" or "analyze this finding."

### Q6: How does multi-account work?
Three steps: 1) Deploy audit roles across member accounts using the provided StackSet template; 2) Set `org_mode: true` when scanning; 3) The Agent auto-discovers Organizations member accounts and scans each via AssumeRole.

### Q7: Can the MLPS report be submitted directly to assessors?
No. The Agent generates an "evidence collection report" that maps scan results to 184 check requirements, marking which were auto-verified, which need manual confirmation, and which are covered by the cloud provider. It's preparation material for your security team, not the final assessment report.

### Q8: How is it different from Prowler / ScoutSuite?
Three key differences: 1) MCP-native — can interact with AI assistants directly, not just generate reports; 2) China-region first — all features verified in China regions, MLPS report is unique; 3) Aggregation layer — doesn't redo Security Hub checks, but aggregates them + adds proprietary checks.

### Q9: How long does a scan take?
Depends on resource scale. Typical single-account scan: 30-60 seconds (all scanners run in parallel). Multi-account scales linearly with member account count.

### Q10: Is it free?
Completely free and open-source (MIT License). AWS API calls themselves may incur minor costs (mainly Security Hub per-finding charges), but the Agent itself is free.

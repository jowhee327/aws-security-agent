# AWS Security Agent 🛡️

> 面向 **AWS 中国区企业客户** 的自助式安全基线扫描 Agent —— 通过 MCP 协议接入 Kiro CLI / Claude Code，几分钟内产出等保 2.0 / 护网行动级别的中文安全评估报告。

---

## 1. 这个 Agent 是什么？

**AWS Security Agent** 是一个基于 **MCP（Model Context Protocol）** 协议的只读安全扫描服务，以 npm 包 `aws-security-mcp` 的形式分发。

- **形态**：本地运行的 Node.js MCP Server（Windows / macOS / Linux / 客户自有 EC2 都可）
- **调用方式**：通过支持 MCP 的 AI 客户端（**Kiro CLI**、**Claude Code**）用自然语言指令触发
- **产出**：单文件 HTML 报告 + Markdown 报告（中英双语），可直接用于内部评审或审计佐证
- **许可**：MIT 开源，GitHub 可审计，无商业授权、无使用费、无注册
- **定位**：**社区项目**，由 AWS 中国区 TAM / CSE / NWCD 共同贡献，**不是 AWS 官方服务**

一句话：**客户自己装、自己跑、数据不出门，几分钟出一份等保能用的安全报告。**

---

## 2. 这个 Agent 解决什么问题？

AWS 中国区企业客户每年都要面对两件周期性的安全合规工作，但目前基本靠人工：

| 痛点 | 现状 | Agent 解决方式 |
|---|---|---|
| **等保 2.0 三级评估**（GB/T 22239-2019） | 工程师手工拼 Trusted Advisor / IAM Access Analyzer / Security Hub / Config 输出，再手动映射到控制项 | `mlps3` profile 直接按 8.1.2–8.1.11 控制族输出证据 |
| **护网行动备战**（每年 5–8 月） | 红蓝对抗前临时扫互联网暴露面、特权 IAM、未加密数据、日志盲区 | `hw_defense` profile 聚焦 11 项护网高优先级检查 |
| **中国区服务差异** | Macie 不提供、GuardDuty 分类不同、Security Hub standards pack 滞后 | 原生支持 `aws-cn` partition，自动适配 `cn-north-1` / `cn-northwest-1` |
| **审计交接困难** | 每次评估都从零开始，依赖工程师个人脚本和隐性知识 | 标准化 20 个扫描模块 + 结构化 JSON + 可复现的单文件报告 |
| **缺乏官方中文审计产出物** | 现有 AWS 工具报告都是英文，交付监管还要翻译 | 报告默认中文，可切英文，格式对齐国内审计习惯 |

E2E 实测：在中等规模 AWS 中国区账号上一次 `scan_all` 返回 **831 条发现**（41 Critical / 343 High / 268 Medium / 179 Low），大部分是 Trusted Advisor 等单一工具无法覆盖的配置漂移。

---

## 3. Agent 都支持哪些场景？

### 三大扫描 Profile

| Profile | 扫描模块数 | 用途 | 耗时 |
|---|---|---|---|
| **`scan_all`** | 20 | 全面安全态势评估，覆盖 IAM / EC2 / VPC / S3 / RDS / Lambda / CloudTrail / KMS / Config / ECR 等 | 5–15 分钟 |
| **`hw_defense`** | 11 | 护网行动备战，聚焦互联网暴露面 + 特权路径 + 数据 + 日志 | 3–8 分钟 |
| **`mlps3`** | 按控制族分组 | 等保 2.0 三级证据映射，输出对齐 GB/T 22239-2019 | 5–10 分钟 |

### 典型使用场景

- ✅ **合规周期** — 等保三级自评 / 复测，一次扫描出证据
- ✅ **护网前体检** — 5 月前跑一次，锁定需要修的高危暴露
- ✅ **发布前 baseline** — DevOps 团队接入 CI/CD（v0.9.0 规划），每次发布前自动扫
- ✅ **Account handoff** — 接手新账号时快速摸底
- ✅ **TAM / CSE 协助** — AWS 技术支持快速生成客户账号体检报告
- ✅ **第三方审计配合** — 把 HTML 报告作为内部工作稿，Markdown 作为正式交付物原料

### 环境矩阵

- **AWS partition**：`aws`（全球）+ `aws-cn`（中国区）全支持，自动识别
- **Region**：按调用时参数决定，单次单 region（多账号多 region 在 v1.0.0 roadmap 上）
- **操作系统**：Windows / macOS / Linux
- **部署位置**：工程师工作站 / 内网 bastion / EC2 / CI runner 都行

---

## 4. Agent 的数据源都有哪些？

**所有数据全部来自 AWS 公开 API**——只用 `Describe*`、`Get*`、`List*`、`Head*` 四类只读调用。下表列出 20 个扫描模块覆盖的 AWS 服务与 API：

| 类别 | 扫描模块 | 主要数据源（AWS API / 服务） |
|---|---|---|
| **IAM / 身份** | IAM Users、IAM Roles、IAM Policies、IAM Access Keys、IAM MFA、Password Policy | IAM `ListUsers/Roles/Policies/AccessKeys`、`GetAccountPasswordPolicy`、`GetAccountSummary` |
| **计算 / 网络** | EC2 Instances、EC2 Security Groups、EBS Snapshots、VPC Flow Logs | EC2 `DescribeInstances/SecurityGroups/Snapshots`、`DescribeFlowLogs` |
| **存储** | S3 Buckets、S3 Bucket Policies | S3 `ListBuckets`、`GetBucketPolicy/Acl/Encryption/PublicAccessBlock` |
| **数据库** | RDS Instances | RDS `DescribeDBInstances`、`DescribeDBSnapshots` |
| **应用 / Serverless** | Lambda Functions | Lambda `ListFunctions`、`GetFunctionConfiguration` |
| **审计 / 加密** | CloudTrail、KMS Keys、Config Recorders | CloudTrail `DescribeTrails/GetTrailStatus`、KMS `ListKeys/GetKeyRotationStatus`、Config `DescribeConfigurationRecorders` |
| **暴露面** | Public Endpoints | 跨服务聚合（EC2 + ELB + RDS + API Gateway 等公网可达资源） |
| **治理** | Tag Compliance | Resource Groups Tagging API |
| **容器 / 镜像** | ECR Image CVE（官方扫描差距分析：非包管理二进制、发行版 secdb 缺口、EOL 系统） | ECR `DescribeRepositories/DescribeImages/BatchGetImage/GetDownloadUrlForLayer/DescribeImageScanFindings`、Inspector2 `ListFindings/ListCoverage` |
| **漏洞可利用性** | Inspector Findings（直拉 + [可利用性研判](#cve-可利用性研判)） | Inspector2 `BatchGetAccountStatus/ListFindings`、EC2 `DescribeInstances/SecurityGroups/NetworkAcls/NetworkInterfaces`、ECS `ListClusters/ListTasks/DescribeTasks/DescribeContainerInstances`、EKS `ListClusters`、Lambda `GetFunctionUrlConfig`、CISA KEV 离线快照 |

**可选增强数据源**（如果客户启用了这些服务，Agent 会自动消费）：

- **AWS Security Hub** — 拉取已有 findings 做交叉验证
- **AWS Config** — 读取 compliance 状态做对照
- **AWS Trusted Advisor** — 只对 Business / Enterprise Support 客户可见的检查项
- **AWS Inspector**（EC2 / ECR / Lambda 漏洞） — 中国区已 GA，支持 **agentless 混合扫描**（没装 SSM Agent 的机器自动走 EBS 快照扫描）。`inspector_findings` 现在**直接从 Inspector2 拉取**漏洞（不再只是“探测是否开通”），并做可利用性研判；拉取失败时退回 Security Hub
- **AWS GuardDuty** — 行为检测 findings

> ⚠️ **不支持 Macie**：中国区未提供，相关扫描器在 `aws-cn` 下自动禁用。

### 数据隐私承诺 🔒

- 凭证**只在进程内存**，不落盘、不进日志、不进报告
- 除必要的 AWS API 调用外，**零出站网络**
- 报告内容只含资源 ARN、region、发现描述，不含 access key / session token
- 所有报告 **XSS 安全**：资源名里的恶意字符不会在 HTML 里被执行

---

## 5. AI 在里面都起到了哪些作用？

Agent 本身是**确定性扫描器**——扫描逻辑、阈值、控制项映射都是工程代码，**不是 AI 决策**。AI 主要在三个层面提供价值：

### 🎯 场景 1：自然语言驱动的扫描编排

传统做法：工程师写 shell 脚本串起 AWS CLI / boto3 / IAM Access Analyzer 调用。

AI 做法：工程师直接对 Kiro CLI / Claude Code 说：

> **"帮我在 cn-north-1 跑一次护网备战扫描，输出中文报告"**

MCP 客户端（LLM）自动理解意图 → 调用 `hw_defense` 工具 → 填入 `region=cn-north-1` `language=zh` 参数 → 触发扫描。

**AI 角色**：意图理解 + 工具选择 + 参数填充。

### 🎯 场景 2：发现的智能解读与优先级建议

扫描产出的原始 JSON 有几百上千条 finding。AI 客户端可以进一步：

- **归因分析** — 把 20 个"Security Group 0.0.0.0/0"合并成"同一个 web tier 被多条规则重复暴露"
- **优先级排序** — 结合业务上下文（生产 tag、面向互联网）调整严重性
- **修复脚本建议** — 根据 finding 的 ARN + remediation hint，生成具体的 Terraform / CloudFormation / CLI 修复命令
- **跨 finding 关联** — 发现"IAM User 有 AdministratorAccess + Access Key 180 天未轮换 + MFA 未启用"是同一个人，打包成一条"高危身份"

**AI 角色**：语义聚合 + 上下文推理 + 修复代码生成。

### 🎯 场景 3：合规控制项的语义映射（`mlps3` profile 核心）

等保 2.0 控制项用的是描述性语言（例："应对重要节点进行入侵行为检测"），AWS findings 用的是技术语言（例："CloudTrail trail lacks log file validation"）。

AI 帮助：
- 把自然语言描述的等保条款**拆解为可验证的技术条件**
- 将扫描 findings **映射回对应的控制项 ID**（如 8.1.3.a、8.1.4.c）
- 对齐不清晰的控制项时提示"这里需要人工佐证"

**AI 角色**：规则翻译 + 控制项映射 + 证据完整性检查。

### 不是 AI 做的事情 ⚠️

- ❌ 扫描规则本身不是 LLM 推理（避免不确定性、幻觉）
- ❌ API 调用列表不是动态生成（静态 allowlist，避免越权）
- ❌ 严重性评级不是 AI 打分（固定 schema）
- ❌ 客户数据不会被送给第三方 AI 训练

**设计哲学**：**扫描确定性 + 解读智能化**。事实层靠工程，洞察层靠 AI。

---

## 6. 用户需要准备什么？怎么装？

### 前置条件清单 ✅

| 项 | 要求 | 说明 |
|---|---|---|
| **运行环境** | Node.js **20.x+** | 工程师本机 / bastion / EC2 / CI runner 任意之一 |
| **MCP 客户端** | Kiro CLI 或 Claude Code | 任选一个，都支持 MCP 协议 |
| **AWS 凭证** | IAM Role / User / SSO session / EC2 instance profile | 任何标准 SDK credential chain 能解析的形式都行 |
| **IAM 权限** | 推荐 `SecurityAudit`（AWS 托管策略） | `ReadOnlyAccess` 也行但更宽；也可以用最小权限自定义策略（仓库里有 action 清单） |
| **网络** | 能访问 AWS API endpoint | 内网需要配好 AWS 出站代理；**无需**任何出到 AWS 以外的网络 |
| **EC2 端** | **什么都不用装** ❌ | Agent 只读 API，EC2 上**不需要装 SSM Agent、不需要装任何 Agent 二进制**；即使要扫 EC2 OS 漏洞，Inspector 中国区也支持 agentless（EBS 快照）|

### 不需要准备什么 🚫

- ❌ AWS 官方账号 / 合作协议
- ❌ 付费订阅 / license key
- ❌ 提供生产数据
- ❌ 开放任何外部网络入站
- ❌ 修改 EC2 / 容器镜像
- ❌ 提前 enable Security Hub / Config（有更好，没有也能跑）

### 安装部署（5 分钟搞定）

#### Step 1. 安装 Agent

```bash
npm install -g aws-security-mcp
```

验证：

```bash
aws-security-mcp --version
# 应输出 0.10.0 或更高
```

#### Step 2. 配置 AWS 凭证

任选一种：

```bash
# 方式 A：命名 profile
aws configure --profile prod-cn
export AWS_PROFILE=prod-cn
export AWS_REGION=cn-north-1

# 方式 B：SSO
aws sso login --profile my-sso
export AWS_PROFILE=my-sso

# 方式 C：EC2 instance role（部署在 EC2 上时完全自动，什么都不用配）
```

给这个身份附加 **`SecurityAudit`** 托管策略即可。

#### Step 3. 在 MCP 客户端里登记 Agent

**Kiro CLI** — 编辑 `~/.kiro/mcp.json`：

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "aws-security-mcp"
    }
  }
}
```

**Claude Code** — 编辑 `~/.config/claude-code/mcp.json`（或用 `claude mcp add` 命令）：

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "aws-security-mcp"
    }
  }
}
```

#### Step 4. 跑第一次扫描

在客户端里用自然语言直接说：

> **"在 cn-north-1 跑一次全量安全扫描，生成中文报告"**

或

> **"帮我做护网行动备战扫描"**

或

> **"生成等保三级合规评估报告"**

客户端自动调用对应的 MCP 工具 → 5–15 分钟后生成：

- `aws-security-report-YYYYMMDD-HHMMSS.html` — 单文件 HTML 报告（内联 CSS/JS，可直接发邮件 / 交审计）
- `aws-security-report-YYYYMMDD-HHMMSS.md` — Markdown 版本（方便贴 Confluence / 飞书 Wiki）
- `aws-security-report-YYYYMMDD-HHMMSS.json` — 结构化数据（方便二次处理）

#### Step 5. （可选）启动本地 Dashboard

Dashboard 的数据来自每次扫描自动落盘的本地文件（`scan_and_report` 或 `save_results` 写入）：

```
~/.aws-security/
├── scans/YYYY-MM-DD/scan.json   # 每天的原始扫描结果存档
├── dashboard/data.json          # Dashboard 数据：最近一次扫描 + 滚动 30 天历史（趋势图数据源）
└── reports/                     # HTML / 等保 / 护网 / Markdown 报告
```

启动本地 Dashboard 只要一条命令（npm 包里已带构建好的前端，无需 build）：

```bash
aws-security-mcp dashboard --port 3000
# 自动加载 ~/.aws-security/dashboard/data.json（没扫过就用内置示例数据）
# 浏览器打开 http://localhost:3000，聚合查看历史扫描趋势
```

支持严重度过滤、模块分布、30 天趋势图；同一天重复扫描会覆盖当天记录而不是重复累加。

#### Step 6. （可选）把 Dashboard 部署到自己账号的 S3

团队共享 / 长期留档场景，可以把 Dashboard（含最新 data.json）上传到自己账号的私有 bucket —— 数据依然**不离开客户账号**：

```bash
aws-security-mcp deploy-dashboard --bucket <你的bucket> --region cn-north-1
```

bucket **保持私有**（不加公开策略、不开静态网站托管），访问控制走 IAM（预签名 URL / CloudFront + OAC / 内部代理均可）。

---

## 运行示意

```
┌─────────────────────────┐        ┌───────────────────────┐
│ 工程师工作站 / EC2       │        │  AWS 账号 (aws-cn)    │
│                         │        │                       │
│  ┌─────────────────┐    │  AWS   │  ┌─────────────────┐  │
│  │ Kiro CLI /      │    │  API   │  │ IAM / EC2 / S3  │  │
│  │ Claude Code     │◄───┼────────┼──┤ RDS / Lambda... │  │
│  └────────┬────────┘    │ Read   │  └─────────────────┘  │
│           │ MCP          │  only  │                       │
│  ┌────────▼────────┐    │        │  ┌─────────────────┐  │
│  │ aws-security-   │────┼────────┼─►│ Security Hub*   │  │
│  │ mcp (本地)       │    │        │  │ Config*/Inspect*│  │
│  └────────┬────────┘    │        │  └─────────────────┘  │
│           │             │        │   * 可选数据源        │
│  ┌────────▼────────┐    │        └───────────────────────┘
│  │ HTML/MD 报告     │    │
│  │ (本地，不外传)    │    │
│  └─────────────────┘    │
└─────────────────────────┘
```

---

## CVE 可利用性研判

> **定位声明**：本功能是**基于威胁情报（exploit 可得性、EPSS、CISA KEV）与暴露面（公网 IP、安全组、NACL、运行状态）的可利用性优先级排序**，**不是渗透测试或漏洞验证**。工具全程只读，不对任何资源做主动探测（不发包、不扫端口、不连接目标 IP）。“internet_open（对全网开放）”表示配置上对全网开放，不代表已被证实可利用。

只按 CVSS 排序时，几百条 CRITICAL + 几千条 HIGH 全挤在前面，真正“有公开 exploit / 在野利用 / 暴露在公网”的少数漏洞被淹没。现在每条 Inspector CVE finding 带一个 `exploitability` 对象，按四层信号定级 P0–P3：

| 层 | 信号 | 来源 |
|---|---|---|
| L1 | 公开 exploit | Inspector `exploitAvailable` / ASFF `Vulnerabilities[].ExploitAvailable` |
| L2 | 利用概率 EPSS | `epss.score`：高 ≥ 0.1，中 ≥ 0.01 |
| L3 | 在野利用 | CISA KEV（随包离线快照） |
| L4 | 可达性 | EC2 公网 IP + 安全组 + NACL；ECR 镜像 → 运行中 ECS task 的 ENI；Lambda Function URL |

定级规则（按顺序首条命中；每条结果带机器可读的 `rationaleCode` 与英文 `rationale`，报告按 code 做中英文渲染）：

| # | 条件 | 优先级 | `rationaleCode` |
|---|---|---|---|
| 1 | 在 KEV 且 `internet_open` | **P0** | `KEV_INTERNET` |
| 2 | 公开 exploit 且 `internet_open` | **P0** | `EXPLOIT_INTERNET` |
| 3 | EPSS 高且 `internet_open` | **P0** | `EPSS_HIGH_INTERNET` |
| 4 | 在 KEV 但不是 `internet_open`（`not_running` → `KEV_NOT_RUNNING`，重新部署前必须修复；`allowlist` / `internal` / `unknown` → `KEV_NOT_EXPOSED`） | P1 | `KEV_NOT_RUNNING` / `KEV_NOT_EXPOSED` |
| 5 | 公开 exploit 且 EPSS 高 | P1 | `EXPLOIT_EPSS_HIGH` |
| 6 | 公开 exploit 且 `allowlist` | P1 | `EXPLOIT_ALLOWLIST` |
| 7 | 公开 exploit（无公网暴露） | P2 | `EXPLOIT_LIMITED` |
| 8 | EPSS 高 | P2 | `EPSS_HIGH` |
| 9 | EPSS 中 | P2 | `EPSS_MEDIUM` |
| 10 | 其他 | P3 | `BASELINE` |

可达性 5 态：`internet_open`（有公网地址，且安全组有 `0.0.0.0/0` / `::/0` 入站、子网 NACL 也放行）、`allowlist`（有公网地址，但只对具体公网 CIDR / prefix list 开放——`/32` 白名单永远不会算成 internet_open）、`internal`、`not_running`（ECR 镜像未在运行中的 ECS task 里观察到）、`unknown`（未评估；永远不会升到 P0）。P0 必须是 `internet_open`；`allowlist` 不算公网可达。

**向后兼容**：`Finding.severity` 与按严重级别派生的 `Finding.priority` 不变；可利用性优先级放在 `exploitability.priority`。`riskScore` 按优先级分带（P0 9.0–10.0、P1 7.0–8.9、P2 4.0–6.9、P3 0.1–3.9，带内保持原顺序，原值存 `exploitability.originalRiskScore`），因此“按 riskScore 排序”即“按可利用性优先级排序”。没有 exploit 信号的 CRITICAL 漏洞仍显示 CRITICAL 徽章，只是排在 P0/P1 之后。不含 CVE 的 finding 输出逐字节不变。

**数据源与去重**：`inspector_findings` 直接调用 `ListFindings`（ACTIVE、PACKAGE_VULNERABILITY），按资源类型分区、3 路并发，上限 20,000 条且保证 exploit/EPSS 信号子集完整。`scan_all` / `scan_group` 中会删除 Security Hub 里与之重复的 Inspector finding（先按 finding ARN，再按 CVE + 资源），并写 warning `Deduplicated N Inspector findings…`。Inspector2 不可读时退回“仅检测”，Security Hub 的 Inspector CVE 用 ASFF 自带信号做同样研判。

**展示位置**：HTML 报告（Top 5 按可利用性优先级；“🎯 可利用性研判”区块：漏斗 + P0/P1 清单 + KEV 快照日期；Inspector 模块最多渲染 200 张卡片，其余按 CVE 汇总）、护网报告（“漏洞与补丁管理”先列 P0/P1）、Markdown 报告、AI 摘要 prompt、Dashboard（可利用性卡片、优先级列），以及下面的新工具。

### 相关 MCP 工具

| 工具 | 说明 |
|---|---|
| `prioritize_vulnerabilities` | **新增**。“先修哪几个”：按可利用性优先级（P0 在前）返回 CVE 清单 + 漏斗 + 研判依据 + 可达性。参数：`priorities`（默认 `["P0","P1"]`）、`limit`（默认 20，上限 200）、`resource_type`（`ec2`/`ecr`/`lambda`）、`include_reachability`（默认 true；false 时跳过 L4，全部 `unknown`，更快）。仅 AWS（任何非 aws 的 `provider` 均返回明确错误） |
| `scan_inspector_findings` | 检测 Inspector 开通状态，并**直接从 Inspector2 拉取**活跃的软件包漏洞，每条带可利用性研判（不再是“仅检测”）；无 `inspector2:ListFindings` 权限时退回“仅检测”+ Security Hub |

返回 JSON 结构（示例，资源 ID 为占位符）：

```text
{
  "dataSource": "inspector2",
  "funnel": { "total": {...}, "exploitAvailable": {...}, "epssHigh": {...}, "kev": {...}, "reachable": {...}, "p0": {...}, "byPriority": {...} },
  "kevSnapshotDate": "2026-11-03",
  "disclaimer": "This is exploitability prioritization ... NOT penetration testing ...",
  "matched": 132,
  "items": [
    { "cveId": "CVE-YYYY-NNNNN", "priority": "P0", "rationaleCode": "KEV_INTERNET", "rationale": "In CISA KEV ...",
      "resourceType": "AwsEc2Instance", "resourceId": "i-0123456789abcdef0", "severity": "HIGH",
      "exploitAvailable": true, "epss": 0.42, "kev": true, "reachability": "internet_open", "fixAvailable": "YES" }
  ],
  "truncated": true
}
```

### 实测示例（cn-north-1 真实账号，只读）

| 层 | 条数 |
|---|---|
| Inspector2 直拉 | 9,914 条 / 6,671 个 CVE |
| 有公开 exploit | 1,311 |
| EPSS 高（≥ 0.1） | 38 |
| CISA KEV | 29 |
| 公网可达（`internet_open` + `allowlist`） | 888 |
| **P0 / P1 / P2 / P3** | **9 / 123 / 1,449 / 8,333** |
| 去重删除的 Security Hub Inspector 重复项 | 9,888 |

两台有公网 IP 的 EC2（安全组只有 `/32` 白名单规则）判为 `allowlist`；5 个运行中的 ECS Fargate 镜像判为 `internal`（ENI 有公网 IP，但安全组只放行 VPC 网段与安全组引用）。“先修清单”从几千条 CRITICAL/HIGH 收敛到 9 条 P0 + 123 条 P1。

### IAM 权限

新增的只读动作：`inspector2:BatchGetAccountStatus`、`inspector2:ListFindings`、`ecs:ListClusters`、`ecs:ListTasks`、`ecs:DescribeTasks`、`ecs:DescribeContainerInstances`、`ec2:DescribeNetworkInterfaces`、`eks:ListClusters`、`lambda:GetFunctionUrlConfig`（另需已有的 `ec2:DescribeInstances`、`ec2:DescribeSecurityGroups`、`ec2:DescribeNetworkAcls`）。全部为 List/Describe/Get；已于 2026-11-04 核实：`aws-cn` 分区的 AWS 托管策略 **SecurityAudit**（v92）与 **ReadOnlyAccess**（v187）**均已全部包含**。权限不足时优雅降级（可达性 `unknown` + 1 条 warning，模块不报错）。

如果使用自定义最小权限策略，请追加以下语句（完整推荐策略见英文 [README](README.md#recommended-iam-policy)）：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CveExploitabilityReadOnly",
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListFindings",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:DescribeContainerInstances",
        "eks:ListClusters",
        "lambda:GetFunctionUrlConfig"
      ],
      "Resource": "*"
    }
  ]
}
```

### CISA KEV 快照更新

KEV 目录以离线快照随包分发（`src/data/kev.json`；CISA KEV 为美国联邦政府作品，属公共领域；来源 <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>）。默认扫描时 **KEV 零网络调用**。报告会显示快照日期，超过 90 天提示过期。更新方法：

```bash
npx tsx scripts/update-kev.ts                    # 下载官方 feed
npx tsx scripts/update-kev.ts --from feed.json   # 或使用本地已下载的文件
```

设置环境变量 `AWS_SECURITY_MCP_KEV_REFRESH=1` 时，扫描时会尝试在内存中在线刷新（5 秒超时；失败则静默沿用离线快照并记一条 warning；绝不写文件）。

### 已知局限

- 可达性只看配置（公网 IP、安全组、NACL），**不评估** ALB/NLB/CloudFront 前置以及路由表 / IGW。
- **EKS 未评估**：账号里有 EKS 集群时，未在 ECS 中观察到的镜像判为 `unknown` 而不是 `not_running`。
- ECS 运行状态是扫描时刻的**时点快照**。
- **中国区不支持 Lambda Function URL**：`GetFunctionUrlConfig` 在中国区被拒绝，Lambda 可达性为 `unknown`（只出 1 条 warning）；API Gateway / ALB 触发器未评估。
- org 模式下 **member 账号资源的可达性为 `unknown`**（只解析扫描账号自身的资源）。
- 仅覆盖 AWS provider；华为云结果不带可利用性数据。

---

## 多云支持：华为云（Phase 1）

同一套工具与报告也可以扫描 **华为云** 账号。默认仍是 AWS，不传 `provider` 时行为与以往完全一致。

**选择云厂商**

- 所有扫描工具（`scan_all`、`scan_group`、`scan_<module>`、`scan_and_report`、`detect_services`、`list_modules`、`list_org_accounts`）新增可选参数 `provider: "aws" | "huaweicloud"`（默认 `aws`）。
- 服务级默认值：启动参数 `--provider huaweicloud`，或环境变量 `CLOUD_PROVIDER=huaweicloud`（别名 `AWS_SECURITY_MCP_PROVIDER`）。
- `provider: "huaweicloud"` 时 `region` 为华为云 region ID（如 `cn-north-4`）；不传或传 `"all"` 则扫描账号下全部 region 项目（通过 IAM `keystoneListProjects` 发现）。账号级模块（RMS）只跑一次，区域级模块逐 region 执行。

**凭据**（只读 AK/SK；华为 SDK 不会自动读取凭据文件，由本服务解析）

1. 环境变量：`HUAWEICLOUD_SDK_AK` / `HUAWEICLOUD_SDK_SK`（可选 `HUAWEICLOUD_SDK_SECURITY_TOKEN`、`HUAWEICLOUD_SDK_PROJECT_ID`、`HUAWEICLOUD_SDK_DOMAIN_ID`）。
2. 文件：`~/.huaweicloud/credentials`（可用 `HUAWEICLOUD_CREDENTIALS_FILE` 覆盖路径），INI 格式：

```ini
[basic]
ak = <区域服务使用的 AK>
sk = <SK>

[global]
ak = <全局服务（IAM / RMS / Organizations）使用的 AK>
sk = <SK>
```

各 region 的 project ID 与账号 domain ID 通过 IAM 解析一次并缓存。凭据值绝不写日志；华为 SDK 自带的 log4js 输出已被关闭（否则会把含签名 `Authorization` 头的错误日志打到 stdout，即 MCP 通道）。

**支持的模块（11 个）**

| 模块 | 华为云服务 | 说明 |
|------|-----------|------|
| `service_detection` | CTS、RMS (Config)、HSS、SecMaster | 安全服务成熟度矩阵 |
| `config_rules_findings` | RMS 资源记录器 | 探测型（是否开启） |
| `rms_compliance_findings` | RMS 合规策略状态 | 华为云专有聚合模块；在扫描分组与报告中替代 `security_hub_findings`（工具 `scan_rms_compliance_findings`） |
| `public_access_verify` | OBS（ACL / 桶策略 / 公共访问阻止）、RDS 公网 IP | |
| `secret_exposure` | FunctionGraph 环境变量、ECS user data | |
| `ssl_certificate` | SCM、ELB 证书 | |
| `idle_resources` | EVS、EIP、ECS、VPC 安全组 | |
| `tag_compliance` | RMS 资源清单 | 必需标签 Environment / Project / Owner |
| `inspector_findings` | HSS 主机漏洞 | 探测 + 汇总：无防护主机 → “HSS 未启用” finding；否则未处理的 Critical/High 漏洞逐条输出（最多 50 条），Medium/Low 以 warning 汇总 |
| `patch_compliance_findings` | HSS 逐主机系统漏洞（`linux_vul` / `windows_vul`） | 华为云无 Patch Manager；每台存在未处理系统漏洞的防护主机一条 finding（含 Critical/High → 7.5，否则 5.5） |
| `imdsv2_enforcement` | ECS 元数据选项（`http_tokens`） | 逐台 `showMetadataOptions`（仅运行中实例，并发 5，上限 500）；`http_tokens != required` → 7.5 |

Finding 的 `resourceArn` 使用 URN `hws:<region>:<domainId>:<service>:<type>:<id>`，`accountId` 为 IAM domain ID。Markdown / HTML / 等保三级 / 护网 报告均接受华为云结果；等保“云平台负责”项按华为云措辞，Security Hub 控制号在已映射处替换为 RMS 内置策略名（如 `iam-user-mfa-enabled`、`volumes-encrypted-check`、`vpc-sg-ports-check`）。

**建议的只读 IAM 系统策略**（授予审计用户 / 委托）

`IAM ReadOnlyAccess`、`RMS ReadOnlyAccess`、`CTS ReadOnlyAccess`、`OBS ReadOnlyAccess`（或 `Tenant Guest`）、`ECS ReadOnlyAccess`、`EVS ReadOnlyAccess`、`VPC ReadOnlyAccess`（含 EIP）、`RDS ReadOnlyAccess`、`ELB ReadOnlyAccess`、`SCM Administrator`（无独立只读策略）、`FunctionGraph ReadOnlyAccess`、`HSS ReadOnlyAccess`、`SecMaster ReadOnlyAccess`；后续阶段还需 `WAF ReadOnlyAccess`、`DNS ReadOnlyAccess`、`CBR ReadOnlyAccess`、`CES ReadOnlyAccess`、`Organizations ReadOnlyAccess`。`Tenant Guest` 可覆盖多数读操作，但**不含 IAM 安全策略读取**。权限不足时优雅降级：模块给出 warning 并保持 `success`。

**已知限制（Phase 1）**

- 仅单账号。`org_mode` / `role_name` 会给出 warning 并只扫当前账号；基于 Organizations + STS `assumeAgency` 的多账号留待 Phase 2（`list_org_accounts` 对 `huaweicloud` 返回错误）。
- 暂无 IAM 提权检测（依赖 `IAM ReadOnlyAccess`，测试账号当前无此权限）；`dns_dangling`、`network_reachability`、`disaster_recovery`、`waf_coverage`、`guardduty_findings`、`trusted_advisor_findings`、`access_analyzer_findings` 与 `scan_ecr_image_cve` 目前仍为 AWS 专属（以 `provider: "huaweicloud"` 调用会返回明确错误；扫描分组会将其列为不可用）。
- 不按企业项目（EPS）拆分，结果覆盖整个账号。

---

## 常见问题快查

| 问题 | 答案 |
|---|---|
| 会影响生产吗？ | 不会。纯只读 API，SDK 层有 allowlist 强制。 |
| 凭证会上传吗？ | 不会。内存中用完即释放，零外部出站。 |
| EC2 上要装 agent 吗？ | **不用**。这是纯 API 扫描工具。 |
| 多账号怎么办？ | v0.7.5 单账号；v1.0.0 会加 StackSet 多账号支持；现阶段可以用脚本循环 assume-role。 |
| 和 Security Hub 是替代关系吗？ | 不是。**互补**。Agent 专注中国区合规映射 + 单文件报告 + 无前置依赖。 |
| 有官方 AWS 支持吗？ | 这是**社区项目**，MIT 开源；有 Enterprise Support 的客户可以在 case 里引用报告。 |

---

## 资源链接

- 📦 npm: https://www.npmjs.com/package/aws-security-mcp
- 💻 GitHub: https://github.com/jowhee327/aws-security-agent
- 📄 License: MIT
- 📘 完整 Narrative: `security-agent-narrative.docx`

---

**当前版本**：v0.8.0（2026 Q3）
**下一里程碑**：Dashboard PDF 导出 + 更多扫描器

---

## 附：第 20 个扫描器 `ecr-image-cve` 是怎么实现的？

**背景**：真实客户案例 —— 一个 `Alpine 3.21 + nginx 1.27` 的 ECR 镜像里有 HIGH 级 nginx CVE，但 **ECR Basic Scanning 和 Inspector Enhanced Scanning 都报不出来**。原因是结构性的：官方扫描器基于发行版安全数据库（secdb）+ 包管理器元数据，一旦二进制不是发行版官方仓库装的（edge/community 包、厂商仓库、源码编译），或者 secdb 没收录该分支的修复条目，就完全失明。这个扫描器就是为了补这个盲区，并且**只汇报和官方结果的差集（gap）**，不做重复劳动。

**实现流水线**（无需 Docker daemon，全程只读、流式处理）：

1. **枚举镜像** — `DescribeRepositories` / `DescribeImages`，每个 repo 取最近推送的 3 个 tag + `latest`（可配置），全程以镜像 **digest** 为唯一标识（tag 会漂移）。
2. **直接走 ECR Registry HTTP API 拉层** — `GetAuthorizationToken` 认证，`BatchGetImage` 取 manifest，`GetDownloadUrlForLayer` 下载层 blob；支持多架构 manifest list（优先 amd64，其次 arm64）。层数据 gzip+tar 流式解压逐条处理，不整层缓冲、不运行镜像。体积护栏：单层 512MB / 单镜像 2GB / 50 个 repo / 单次扫描 20GB（都可配），超限记为 `skipped` 并注明原因。
3. **双通道组件清单（核心设计）**：
   - **通道 A（包级）**：解析层内的包管理器数据库 — Alpine `/lib/apk/db/installed`、Debian/Ubuntu `/var/lib/dpkg/status`，加 `/etc/os-release` 识别发行版分支。这一路和官方扫描器看到的一样。
   - **通道 B（二进制级，ECR 做不到的）**：用 ELF 魔数 + 路径启发式定位常见服务端二进制（nginx / openssl / curl / redis / node / httpd / haproxy / php / python3 / java / envoy），直接在二进制字节里用签名正则抠出内嵌版本串（如 `nginx version: nginx/1.27.4`）。每个命中标注来源：`package-managed`（通道 A 能解释）或 **`unmanaged-binary`**（镜像里有但不属于任何已装的包 —— 就是那个客户案例，会重点标红）。
4. **CVE 匹配（只报 CRITICAL/HIGH）**，双层数据源：
   - **Tier 1（离线，默认）**：随包内置的人工维护 + 单测覆盖的 advisory 表，完全离线可用 —— 中国区 / 隔离网络环境友好。
   - **Tier 2（在线，可选）**：NVD API 2.0 查询 + 24 小时磁盘缓存，由 `onlineCveLookup` 开关控制（默认关）。
   - 版本比较会归一化非 semver 形态（Alpine 的 `-r0` 包修订号、OpenSSL 的 `1.0.2k` 字母后缀），输出保留原始字符串。
5. **官方结果差集分析（gap analysis）** — 对每个镜像拉官方结果（`ecr:DescribeImageScanFindings` + `inspector2:ListFindings`），把自己的发现分成三类：
   - **`gap`** — 我们发现、官方没报 → 报告头条，每条附机器判定的原因：`unmanaged-binary` / `distro-secdb-no-entry`（发行版 secdb 无条目）/ `eol-os` / `unsupported-os` / `unknown`；
   - **`confirmed`** — 双方都发现（折叠成计数）；
   - **`reverse-gap`** — 官方报了我们没报（自审清单）。
   报告同时注明每个镜像当时可用的官方基线（basic / enhanced / none）。
6. **误报控制** — 支持 `suppressions` 抑制清单（CVE ID + 可选 digest 前缀/组件 + 理由），被抑制的发现进 `suppressed[]` 段落，绝不静默丢弃。

**新增 IAM 权限（全部只读）**：`ecr:GetAuthorizationToken / DescribeRepositories / DescribeImages / BatchGetImage / GetDownloadUrlForLayer / DescribeImageScanFindings`、`inspector2:ListFindings / ListCoverage`。

**调用方式**：单独调 `scan_ecr_image_cve`，或走 `container_security` 扫描组，或包含在 `scan_all` / `scan_and_report` 全量扫描里。完整设计文档见 `docs/specs/ecr-image-cve-scanner-spec.md`。

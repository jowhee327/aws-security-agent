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

**可选增强数据源**（如果客户启用了这些服务，Agent 会自动消费）：

- **AWS Security Hub** — 拉取已有 findings 做交叉验证
- **AWS Config** — 读取 compliance 状态做对照
- **AWS Trusted Advisor** — 只对 Business / Enterprise Support 客户可见的检查项
- **AWS Inspector**（EC2 / ECR / Lambda 漏洞） — 中国区已 GA，支持 **agentless 混合扫描**（没装 SSM Agent 的机器自动走 EBS 快照扫描）
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
# 应输出 0.8.0 或更高
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

```bash
aws-security-mcp dashboard
# 浏览器打开 http://localhost:3000，聚合查看历史扫描趋势
```

#### Step 6. （可选）把报告归档到自己账号的 S3

配置一个 S3 bucket 作为长期留档，Dashboard 支持自动上传 —— 数据依然**不离开客户账号**。

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

# AWS 安全扫描报告 — 2026-05-01

## 执行摘要
- **账户:** 123456789012
- **区域:** us-east-1
- **耗时:** 2m 5s
- **发现总数:** 9 (🔴 2 严重 | 🟠 4 高 | 🟡 2 中 | 🟢 1 低)

## 按严重性分类的发现

### 🔴 严重

#### CVE-2024-4577 - php
- **资源:** arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003`)
- **描述:** PHP CGI argument injection <b>bold</b>
- **影响:** Source: Inspector (package vulnerability)
- **风险评分:** 9.8/10
- **建议:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **优先级:** P0

#### EC2 instance i-0legacy0001 has SSH (22) reachable from 0.0.0.0/0
- **资源:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Legacy impact
- **风险评分:** 9.4/10
- **建议:**
  1. Restrict port 22 on sg-0abc1234 to known IPs
- **优先级:** P0

### 🟠 高

#### EC2 instance i-0legacy0002 has RDP (3389) reachable
- **资源:** i-0legacy0002 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Legacy impact
- **风险评分:** 8.1/10
- **建议:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **优先级:** P1

#### Instance i-0legacy0004 missing critical patches
- **资源:** i-0legacy0004 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Legacy impact
- **风险评分:** 7.8/10
- **建议:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **优先级:** P1

#### CVE-2023-1111 - openssl
- **资源:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Source: Inspector (package vulnerability)
- **风险评分:** 7.5/10
- **建议:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **优先级:** P1

#### EC2.19 Security groups should not allow unrestricted access to ports with high risk
- **资源:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Source: Security Hub (Foundational Security Best Practices)
- **风险评分:** 7/10
- **建议:**
  1. Remove unrestricted rules
- **优先级:** P1

### 🟡 中

#### Unusual API call
- **资源:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Source: GuardDuty (threat detection)
- **风险评分:** 5.5/10
- **建议:**
  1. Investigate
- **优先级:** P2

#### KB5034441 - Windows security update
- **资源:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **描述:** Legacy finding description
- **影响:** Source: Inspector (package vulnerability)
- **风险评分:** 5/10
- **建议:**
  1. Install KB5034441
- **优先级:** P2

### 🟢 低

#### Role 'dev' can pass role
- **资源:** dev (`arn:aws:iam::123456789012:role/dev`)
- **描述:** Legacy finding description
- **影响:** Legacy impact
- **风险评分:** 2.5/10
- **建议:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **优先级:** P3

## 扫描统计
| 模块 | 资源 | 发现 | 状态 |
|--------|------------------|----------|--------|
| 网络可达性 | 7 | 2 | ✅ |
| Security Hub | 7 | 5 | ✅ |
| Inspector | 7 | 0 | ✅ |
| 补丁合规 | 7 | 1 | ✅ |
| IAM 提权分析 | 7 | 1 | ✅ |
| SSL 证书 | 7 | 0 | ❌ |

## 建议
1. [P0] CVE-2024-4577 - php: Review and fix
2. [P0] EC2 instance i-0legacy0001 has SSH (22) reachable from 0.0.0.0/0: Restrict port 22 on sg-0abc1234 to known IPs
3. [P1] EC2 instance i-0legacy0002 has RDP (3389) reachable: Review and fix
4. [P1] Instance i-0legacy0004 missing critical patches: Review and fix
5. [P1] CVE-2023-1111 - openssl: Review and fix
6. [P1] EC2.19 Security groups should not allow unrestricted access to ports with high risk: Remove unrestricted rules
7. [P2] Unusual API call: Investigate
8. [P2] KB5034441 - Windows security update: Install KB5034441
9. [P3] Role 'dev' can pass role: Review and fix

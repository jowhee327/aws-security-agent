# aws-security-mcp

MCP server for automated AWS security scanning — 19 modules, risk scoring, zero write operations.

<!-- badges -->
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)
![MCP Protocol](https://img.shields.io/badge/MCP-1.12-purple.svg)

## Features

- **19 Security Scan Modules** — 15 unique scanners + 4 aggregation scanners (Security Hub, GuardDuty, Inspector, Trusted Advisor, Config Rules, Access Analyzer, Patch Compliance)
- **Risk Scoring** — every finding scored 0-10 with severity (CRITICAL/HIGH/MEDIUM/LOW) and priority (P0-P3)
- **100% Read-Only** — uses only Describe/Get/List API calls; never modifies your AWS resources
- **Multi-Account Support** — scan all accounts in an AWS Organization via `org_mode` with cross-account role assumption
- **Parallel Execution** — all modules run concurrently via `Promise.allSettled`
- **Report Generation** — Markdown, professional HTML, and MLPS Level 3 compliance reports
- **React Dashboard** — local or S3-hosted dashboard with 30-day trend charts
- **MCP Resources** — embedded security rules and risk scoring model documentation
- **MCP Prompts** — pre-built workflows for full scans and finding analysis
- **China Region Support** — full support for aws-cn partition
- **CloudFormation StackSet Template** — one-click deployment of cross-account audit roles

## Quick Start

### 1. Install

```bash
npm install
npm run build
```

### 2. Configure AWS Credentials

The server uses the standard AWS SDK credential chain. Any of the following will work:

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=ap-northeast-1

# Or use an AWS profile
export AWS_PROFILE=your-profile

# Or run on an EC2 instance / ECS task with an IAM role attached
```

See [Recommended IAM Policy](#recommended-iam-policy) below for the minimum permissions required.

### 3. Configure Your AI Tool

Add the MCP server to your AI tool's configuration:

#### Kiro

`.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "aws-security-mcp",
      "args": ["--region", "ap-northeast-1"]
    }
  }
}
```

#### Claude Code

`.claude/settings.json`:

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "aws-security-mcp",
      "args": ["--region", "ap-northeast-1"]
    }
  }
}
```

#### Cursor

Add in Cursor MCP settings:

```json
{
  "mcpServers": {
    "aws-security": {
      "command": "aws-security-mcp",
      "args": ["--region", "ap-northeast-1"]
    }
  }
}
```

### 4. Use

Ask your AI tool to run a security scan:

> "Run a full AWS security scan and generate a report"

Or use the built-in `security-scan` prompt for a guided workflow.

For multi-account scanning across an AWS Organization:

> "Run a full scan across all org accounts using org_mode"

## Available Tools

| Tool | Description |
|------|-------------|
| `scan_all` | Run all 19 security scanners in parallel (supports org_mode) |
| `detect_services` | Detect enabled AWS security services and assess maturity |
| `scan_secret_exposure` | Check Lambda env vars and EC2 userData for exposed secrets |
| `scan_ssl_certificate` | Check ACM certificates for expiry and failed status |
| `scan_dns_dangling` | Detect dangling DNS records (subdomain takeover risk) |
| `scan_network_reachability` | Analyze true network reachability (SG + NACL rules) |
| `scan_iam_privilege_escalation` | Detect IAM privilege escalation paths |
| `scan_public_access_verify` | Verify actual public accessibility of resources |
| `scan_tag_compliance` | Check resources for required tags |
| `scan_idle_resources` | Find unused/idle resources |
| `scan_disaster_recovery` | Assess disaster recovery readiness |
| `scan_security_hub_findings` | Aggregate findings from AWS Security Hub |
| `scan_guardduty_findings` | Aggregate findings from Amazon GuardDuty |
| `scan_inspector_findings` | Aggregate findings from Amazon Inspector |
| `scan_trusted_advisor_findings` | Aggregate findings from AWS Trusted Advisor |
| `scan_config_rules_findings` | Aggregate findings from AWS Config Rules |
| `scan_access_analyzer_findings` | Aggregate findings from IAM Access Analyzer |
| `scan_patch_compliance_findings` | Aggregate findings from SSM Patch Compliance |
| `scan_imdsv2_enforcement` | Check EC2 instances for IMDSv2 enforcement |
| `scan_waf_coverage` | Check internet-facing ALBs for WAF Web ACL protection |
| `scan_group` | Run a predefined group of scanners for a specific scenario |
| `list_groups` | List available scan groups |
| `list_modules` | List available scan modules with descriptions |
| `list_org_accounts` | List all accounts in AWS Organization |
| `generate_report` | Generate a Markdown report from scan results |
| `generate_html_report` | Generate a professional HTML report |
| `generate_mlps3_report` | Generate a MLPS Level 3 compliance report |
| `generate_mlps3_html_report` | Generate a MLPS Level 3 HTML compliance report |
| `generate_maturity_report` | Generate a security maturity assessment |
| `save_results` | Save scan results for the dashboard |
| `get_setup_template` | Get CloudFormation StackSet template for cross-account audit role |

All tools accept an optional `region` parameter (defaults to the server's configured region).

## Recommended IAM Policy

Attach this policy to the IAM user or role running the scanner. All actions are read-only.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityScannerReadOnly",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindingsV2",

        "acm:DescribeCertificate",
        "acm:ListCertificates",

        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigurationRecorders",
        "config:GetComplianceDetailsByConfigRule",

        "elasticloadbalancing:DescribeLoadBalancers",

        "ec2:DescribeAddresses",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeVolumes",
        "ec2:GetEbsEncryptionByDefault",

        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",

        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",

        "inspector2:ListFindings",

        "lambda:ListFunctions",
        "lambda:GetFunction",

        "macie2:GetMacieSession",

        "organizations:ListAccounts",

        "rds:DescribeDBInstances",

        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",

        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketReplication",
        "s3:GetBucketTagging",
        "s3:ListAllMyBuckets",

        "securityhub:DescribeHub",
        "securityhub:GetFindings",

        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatchStates",

        "sts:GetCallerIdentity",

        "support:DescribeTrustedAdvisorChecks",
        "support:DescribeTrustedAdvisorCheckResult",

        "wafv2:GetWebACL",
        "wafv2:GetWebACLForResource"
      ],
      "Resource": "*"
    }
  ]
}
```

## Scan Modules

### Unique Scanners (15)

| Module | What It Checks | Risk Score Range |
|--------|---------------|-----------------|
| **Service Detection** | Enabled security services (Security Hub, GuardDuty, Inspector, Config, Macie, CloudTrail) and maturity level | 5.0 - 7.5 |
| **Secret Exposure** | Lambda env vars and EC2 userData for exposed secrets (AWS keys, private keys, passwords) | 7.0 - 9.5 |
| **SSL Certificate** | ACM certificate expiry, failed status, upcoming renewals | 5.5 - 9.0 |
| **Dangling DNS** | Route53 CNAME records pointing to non-existent resources (subdomain takeover) | 7.0 - 8.5 |
| **Network Reachability** | True network reachability combining Security Group + NACL rules for public EC2 instances | 5.5 - 9.5 |
| **IAM Privilege Escalation** | Privilege escalation paths via policy manipulation, role creation, or service abuse | 7.0 - 9.5 |
| **Public Access Verify** | Actual public accessibility of resources marked as public (S3 HTTP, RDS DNS) | 7.0 - 9.0 |
| **Tag Compliance** | Required tags (Environment, Project, Owner) on EC2, RDS, S3 resources | 3.0 - 5.0 |
| **Idle Resources** | Unused resources (unattached EBS, unused EIPs, stopped instances, unused SGs) | 3.0 - 5.0 |
| **Disaster Recovery** | RDS Multi-AZ & backups, EBS snapshot coverage, S3 versioning & replication | 4.0 - 7.5 |
| **Config Rules** | AWS Config Rules compliance status | 3.0 - 9.5 |
| **Access Analyzer** | IAM Access Analyzer external access findings | 3.0 - 9.5 |
| **Patch Compliance** | SSM Patch Manager compliance status for managed instances | 3.0 - 9.5 |
| **IMDSv2 Enforcement** | EC2 instances not enforcing IMDSv2 (HttpTokens != required) | 7.5 |
| **WAF Coverage** | Internet-facing ALBs without WAF Web ACL protection | 7.5 |

### Aggregation Scanners (4)

| Module | Source Service | Risk Score Range |
|--------|---------------|-----------------|
| **Security Hub Findings** | AWS Security Hub (FSBP, CIS, PCI DSS) | 3.0 - 9.5 |
| **GuardDuty Findings** | Amazon GuardDuty threat detection | 3.0 - 9.5 |
| **Inspector Findings** | Amazon Inspector vulnerability scanning | 3.0 - 9.5 |
| **Trusted Advisor Findings** | AWS Trusted Advisor security checks (requires Business/Enterprise Support) | 5.5 - 8.0 |

### Risk Scoring

| Score | Severity | Priority |
|-------|----------|----------|
| 9.0 - 10.0 | CRITICAL | P0 |
| 7.0 - 8.9 | HIGH | P1 |
| 4.0 - 6.9 | MEDIUM | P2 |
| 0.0 - 3.9 | LOW | P3 |

## Scan Groups

Pre-defined scanner groupings for common scenarios:

| Group | Description | Modules |
|-------|-------------|---------|
| `mlps3_precheck` | GB/T 22239-2019 等保三级预检 | 17 modules |
| `hw_defense` | 护网蓝队加固 | 14 modules |
| `exposure` | 公网暴露面评估 | 8 modules |
| `data_encryption` | 数据加密审计 | 2 modules |
| `least_privilege` | 最小权限审计 | 3 modules |
| `log_integrity` | 日志完整性审计 | 2 modules |
| `disaster_recovery` | 灾备评估 | 2 modules |
| `idle_resources` | 闲置资源清理 | 2 modules |
| `tag_compliance` | 资源标签合规 | 1 module |
| `new_account_baseline` | 新账户基线检查 | 7 modules |
| `aggregation` | 安全服务聚合 | 7 modules |

Use `list_groups` to see all available groups with their module lists.

## Multi-Account Support

For scanning across an AWS Organization:

1. **Deploy the audit role** — Use `get_setup_template` to retrieve the CloudFormation StackSet template, then deploy it from your Management Account to create the `AWSSecurityMCPAudit` role in all member accounts.

2. **Run with org_mode** — Pass `org_mode: true` to `scan_all` or `scan_group`. The scanner will discover accounts via `organizations:ListAccounts` and assume the audit role in each.

3. **Optional filtering** — Pass `account_ids` to scan specific accounts instead of the full organization.

The StackSet templates are available in the `templates/` directory in both YAML and JSON formats.

## Output Format

### Scan Results (JSON)

Each scan tool returns structured JSON:

```json
{
  "module": "network_reachability",
  "status": "success",
  "resourcesScanned": 12,
  "findingsCount": 3,
  "scanTimeMs": 1250,
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "EC2 instance i-abc123 has SSH (22) reachable from 0.0.0.0/0",
      "resourceType": "AWS::EC2::Instance",
      "resourceId": "i-abc123",
      "resourceArn": "arn:aws:ec2:ap-northeast-1:123456789012:instance/i-abc123",
      "region": "ap-northeast-1",
      "description": "...",
      "impact": "...",
      "riskScore": 9.0,
      "remediationSteps": ["..."],
      "priority": "P0"
    }
  ]
}
```

### Markdown Report

The `generate_report` tool produces a Markdown report with:

- **Executive Summary** — account, region, duration, finding counts by severity
- **Findings by Severity** — grouped and sorted by risk score
- **Scan Statistics** — per-module resource counts and status
- **Recommendations** — prioritized action items

## License

MIT

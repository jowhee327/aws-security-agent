# aws-security-mcp

MCP server for automated AWS security scanning — 7 modules, risk scoring, zero write operations.

<!-- badges -->
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)
![MCP Protocol](https://img.shields.io/badge/MCP-1.12-purple.svg)

## Features

- **7 Security Scan Modules** — Security Groups, S3, IAM, CloudTrail, RDS, EBS, VPC
- **Risk Scoring** — every finding scored 0-10 with severity (CRITICAL/HIGH/MEDIUM/LOW) and priority (P0-P3)
- **100% Read-Only** — uses only Describe/Get/List API calls; never modifies your AWS resources
- **Parallel Execution** — all 7 modules run concurrently via `Promise.allSettled`
- **Markdown Report Generation** — structured report with executive summary, findings by severity, and prioritized recommendations
- **MCP Resources** — embedded security rules and risk scoring model documentation
- **MCP Prompts** — pre-built workflows for full scans and finding analysis

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

## Available Tools

| Tool | Description |
|------|-------------|
| `scan_all` | Run all 7 security scanners in parallel |
| `scan_sg` | Scan EC2 security groups for overly permissive rules |
| `scan_s3` | Check S3 buckets for public access, encryption, versioning |
| `scan_iam` | Audit IAM users, root account, access keys, policies |
| `scan_cloudtrail` | Validate CloudTrail logging configuration |
| `scan_rds` | Scan RDS instances for public access, encryption, backups |
| `scan_ebs` | Check EBS volumes and snapshots for encryption and public sharing |
| `scan_vpc` | Review VPC flow logs, default VPC usage, default security groups |
| `generate_report` | Generate a Markdown report from scan results |
| `list_modules` | List available scan modules with descriptions |

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
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",

        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",

        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",

        "rds:DescribeDBInstances",

        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Scan Modules

| Module | What It Checks | Risk Score Range |
|--------|---------------|-----------------|
| **Security Groups** | Open ports to 0.0.0.0/0 (SSH, RDP, databases), all-ports rules | 7.5 - 9.5 |
| **S3** | Public ACLs, public bucket policies, Block Public Access, encryption, versioning | 3.0 - 9.5 |
| **IAM** | Root MFA, root access keys, inactive users, old access keys, over-permissive policies | 5.0 - 10.0 |
| **CloudTrail** | Trail existence, multi-region logging, log validation, CloudWatch integration, management events | 5.5 - 9.5 |
| **RDS** | Public accessibility, storage encryption, backup retention, deletion protection | 4.0 - 8.0 |
| **EBS** | Default encryption, unencrypted volumes, unencrypted snapshots, public snapshots | 5.5 - 9.5 |
| **VPC** | Default VPC usage, VPC Flow Logs, default security group rules | 5.5 - 7.0 |

### Risk Scoring

| Score | Severity | Priority |
|-------|----------|----------|
| 9.0 - 10.0 | CRITICAL | P0 |
| 7.0 - 8.9 | HIGH | P1 |
| 4.0 - 6.9 | MEDIUM | P2 |
| 0.0 - 3.9 | LOW | P3 |

## Output Format

### Scan Results (JSON)

Each scan tool returns structured JSON:

```json
{
  "module": "security_group",
  "status": "success",
  "resourcesScanned": 12,
  "findingsCount": 3,
  "scanTimeMs": 1250,
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "Security group sg-abc123 allows SSH (22) from 0.0.0.0/0",
      "resourceType": "AWS::EC2::SecurityGroup",
      "resourceId": "sg-abc123",
      "resourceArn": "arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-abc123",
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

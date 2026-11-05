# AWS Security Scan Report — 2026-05-01

## Executive Summary
- **Account:** 123456789012
- **Region:** us-east-1
- **Duration:** 2m 5s
- **Total Findings:** 9 (🔴 2 Critical | 🟠 4 High | 🟡 2 Medium | 🟢 1 Low)

## Findings by Severity

### 🔴 Critical

#### CVE-2024-4577 - php
- **Resource:** arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0003`)
- **Description:** PHP CGI argument injection <b>bold</b>
- **Impact:** Source: Inspector (package vulnerability)
- **Risk Score:** 9.8/10
- **Remediation:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **Priority:** P0

#### EC2 instance i-0legacy0001 has SSH (22) reachable from 0.0.0.0/0
- **Resource:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Legacy impact
- **Risk Score:** 9.4/10
- **Remediation:**
  1. Restrict port 22 on sg-0abc1234 to known IPs
- **Priority:** P0

### 🟠 High

#### EC2 instance i-0legacy0002 has RDP (3389) reachable
- **Resource:** i-0legacy0002 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Legacy impact
- **Risk Score:** 8.1/10
- **Remediation:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **Priority:** P1

#### Instance i-0legacy0004 missing critical patches
- **Resource:** i-0legacy0004 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Legacy impact
- **Risk Score:** 7.8/10
- **Remediation:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **Priority:** P1

#### CVE-2023-1111 - openssl
- **Resource:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Source: Inspector (package vulnerability)
- **Risk Score:** 7.5/10
- **Remediation:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **Priority:** P1

#### EC2.19 Security groups should not allow unrestricted access to ports with high risk
- **Resource:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Source: Security Hub (Foundational Security Best Practices)
- **Risk Score:** 7/10
- **Remediation:**
  1. Remove unrestricted rules
- **Priority:** P1

### 🟡 Medium

#### Unusual API call
- **Resource:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Source: GuardDuty (threat detection)
- **Risk Score:** 5.5/10
- **Remediation:**
  1. Investigate
- **Priority:** P2

#### KB5034441 - Windows security update
- **Resource:** i-0legacy0001 (`arn:aws:ec2:us-east-1:123456789012:instance/i-0legacy0001`)
- **Description:** Legacy finding description
- **Impact:** Source: Inspector (package vulnerability)
- **Risk Score:** 5/10
- **Remediation:**
  1. Install KB5034441
- **Priority:** P2

### 🟢 Low

#### Role 'dev' can pass role
- **Resource:** dev (`arn:aws:iam::123456789012:role/dev`)
- **Description:** Legacy finding description
- **Impact:** Legacy impact
- **Risk Score:** 2.5/10
- **Remediation:**
  1. Review and fix
  2. Documentation: https://docs.aws.amazon.com/x
- **Priority:** P3

## Scan Statistics
| Module | Resources | Findings | Status |
|--------|------------------|----------|--------|
| Network Reachability | 7 | 2 | ✅ |
| Security Hub | 7 | 5 | ✅ |
| Inspector | 7 | 0 | ✅ |
| Patch Compliance | 7 | 1 | ✅ |
| IAM Privilege Escalation | 7 | 1 | ✅ |
| SSL Certificate | 7 | 0 | ❌ |

## Recommendations
1. [P0] CVE-2024-4577 - php: Review and fix
2. [P0] EC2 instance i-0legacy0001 has SSH (22) reachable from 0.0.0.0/0: Restrict port 22 on sg-0abc1234 to known IPs
3. [P1] EC2 instance i-0legacy0002 has RDP (3389) reachable: Review and fix
4. [P1] Instance i-0legacy0004 missing critical patches: Review and fix
5. [P1] CVE-2023-1111 - openssl: Review and fix
6. [P1] EC2.19 Security groups should not allow unrestricted access to ports with high risk: Remove unrestricted rules
7. [P2] Unusual API call: Investigate
8. [P2] KB5034441 - Windows security update: Install KB5034441
9. [P3] Role 'dev' can pass role: Review and fix

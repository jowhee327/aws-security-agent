export const SECURITY_RULES_CONTENT = `# AWS Security Scan Modules & Rules

## 1. Security Groups (security_group)
Scans EC2 security groups for overly permissive inbound rules.
- **All ports open to 0.0.0.0/0** — Risk 9.5: Full port range exposed to the internet.
- **SSH (22) exposed to 0.0.0.0/0** — Risk 9.0: Remote shell access open to all.
- **RDP (3389) exposed to 0.0.0.0/0** — Risk 9.0: Windows remote desktop open to all.
- **Database ports (3306/5432/1433/27017) exposed** — Risk 8.0: Database access from internet.
- **Cache/search ports (6379/9200/11211) exposed** — Risk 7.5: Service ports reachable externally.

## 2. S3 Buckets (s3)
Checks S3 bucket security configuration.
- **Public ACL grants** — Risk 9.5: Bucket allows public read/write via ACL.
- **Public bucket policy** — Risk 9.0: Bucket policy permits public access.
- **Block Public Access incomplete** — Risk 8.0: Account or bucket-level BPA not fully enabled.
- **Missing encryption** — Risk 6.0: Server-side encryption not configured.
- **Versioning not enabled** — Risk 3.0: No object versioning for data protection.

## 3. IAM (iam)
Audits IAM users, credentials, and policies.
- **Root account without MFA** — Risk 10.0: Root has no multi-factor authentication.
- **Root account has access keys** — Risk 9.5: Programmatic access on root account.
- **Old access keys (90+ days)** — Risk 7.5: Access keys not rotated.
- **Over-permissive policies** — Risk 7.0: AdministratorAccess or similar attached to users.
- **Inactive users (90+ days)** — Risk 5.0: Unused IAM users still active.

## 4. CloudTrail (cloudtrail)
Validates CloudTrail logging configuration.
- **No trails configured** — Risk 9.5: No API logging in the account.
- **Trail not multi-region** — Risk 7.5: Activity outside home region is unlogged.
- **Not logging management events** — Risk 7.0: Management API calls not captured.
- **No log file validation** — Risk 6.0: Log integrity cannot be verified.
- **No CloudWatch Logs integration** — Risk 5.5: Logs not forwarded for alerting.

## 5. RDS (rds)
Scans RDS instances for security misconfigurations.
- **Publicly accessible** — Risk 8.0: DB instance reachable from the internet.
- **Storage not encrypted** — Risk 7.0: Data at rest is unencrypted.
- **No automated backups** — Risk 6.0: No point-in-time recovery available.
- **No deletion protection** — Risk 4.0: Instance can be accidentally deleted.

## 6. EBS (ebs)
Checks EBS volumes and snapshots.
- **Publicly shared snapshots** — Risk 9.5: Snapshot accessible to any AWS account.
- **Default encryption not enabled** — Risk 7.0: New volumes not encrypted by default.
- **Unencrypted volumes** — Risk 6.0: Existing volumes without encryption.
- **Unencrypted snapshots** — Risk 5.5: Snapshots without encryption.

## 7. VPC (vpc)
Reviews VPC network configuration.
- **Instances in default VPC** — Risk 7.0: Resources in the default VPC lack proper isolation.
- **Missing VPC Flow Logs** — Risk 7.0: No network traffic logging enabled.
- **Default SG with custom inbound rules** — Risk 5.5: Default security group modified with open rules.

## 8. Service Detection (service_detection)
Detects which AWS security services are enabled and assesses overall security maturity.
- **Security Hub not enabled** — Risk 7.5: Provides 300+ automated security checks.
- **GuardDuty not enabled** — Risk 7.5: Provides continuous threat detection.
- **Inspector not enabled** — Risk 6.0: Scans for software vulnerabilities.
- **AWS Config not enabled** — Risk 6.0: Tracks configuration changes.
- **Macie not enabled** — Risk 5.0: Detects sensitive data in S3 (not available in China regions).
- CloudTrail detection is included for coverage metrics; findings handled by the CloudTrail module.

### Maturity Levels
| Enabled Services | Level |
|------------------|-------|
| 0–1 | Basic |
| 2–3 | Intermediate |
| 4–5 | Advanced |
| 6   | Comprehensive |
`;

export const RISK_SCORING_CONTENT = `# Risk Scoring Model

## Score Ranges
Each finding is assigned a risk score from 0.0 to 10.0 based on potential impact and exploitability.

| Score Range | Severity | Priority | Description |
|-------------|----------|----------|-------------|
| 9.0 – 10.0 | CRITICAL | P0 | Immediate action required. Active exploitation risk. |
| 7.0 – 8.9  | HIGH     | P1 | Address within 24-48 hours. Significant exposure. |
| 4.0 – 6.9  | MEDIUM   | P2 | Address within 1-2 weeks. Moderate risk. |
| 0.0 – 3.9  | LOW      | P3 | Address in next maintenance cycle. Minor risk. |

## Severity Mapping
\`\`\`
score >= 9.0  → CRITICAL
score >= 7.0  → HIGH
score >= 4.0  → MEDIUM
score <  4.0  → LOW
\`\`\`

## Priority Mapping
\`\`\`
CRITICAL → P0 (Immediate)
HIGH     → P1 (Urgent)
MEDIUM   → P2 (Normal)
LOW      → P3 (Low)
\`\`\`

## Scoring Factors
- **Exploitability**: How easily can this misconfiguration be exploited?
- **Blast radius**: What data or systems are at risk?
- **Public exposure**: Is the resource internet-facing?
- **Compliance**: Does this violate common compliance frameworks (CIS, SOC2)?
- **Data sensitivity**: Could sensitive data be exposed or lost?

## Examples
- Root account without MFA → 10.0 (total account compromise risk)
- Public S3 ACL → 9.5 (data breach via public access)
- Missing encryption at rest → 6.0 (data exposure if storage is compromised)
- Versioning disabled → 3.0 (data loss risk, low exploitability)
`;

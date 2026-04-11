export const SECURITY_RULES_CONTENT = `# AWS Security Scan Modules & Rules

## 1. Service Detection (service_detection)
Detects which AWS security services are enabled and assesses overall security maturity.
- **Security Hub not enabled** — Risk 7.5: Provides 300+ automated security checks.
- **GuardDuty not enabled** — Risk 7.5: Provides continuous threat detection.
- **Inspector not enabled** — Risk 6.0: Scans for software vulnerabilities.
- **AWS Config not enabled** — Risk 6.0: Tracks configuration changes.
- **Macie not enabled** — Risk 5.0: Detects sensitive data in S3 (not available in China regions).
- CloudTrail detection is included for coverage metrics.

### Maturity Levels
| Enabled Services | Level |
|------------------|-------|
| 0–1 | Basic |
| 2–3 | Intermediate |
| 4–5 | Advanced |
| 6   | Comprehensive |

## 2. Security Hub Findings (security_hub_findings)
Aggregates active findings from AWS Security Hub. Replaces individual config scanners (SG, S3, IAM, CloudTrail, RDS, EBS, VPC, etc.) with centralized compliance checks from FSBP, CIS, and PCI DSS standards.
- Findings are filtered to ACTIVE + NEW/NOTIFIED workflow status.
- Severity mapped: CRITICAL → 9.5, HIGH → 8.0, MEDIUM → 5.5, LOW → 3.0.
- INFORMATIONAL findings are skipped.

## 3. GuardDuty Findings (guardduty_findings)
Aggregates threat detection findings from Amazon GuardDuty.
- Covers account compromise, instance compromise, and reconnaissance.
- Severity mapped from GuardDuty 0–10 scale: ≥7 → HIGH, ≥4 → MEDIUM, <4 → LOW.
- Only non-archived findings are included.

## 4. Inspector Findings (inspector_findings)
Aggregates vulnerability findings from Amazon Inspector v2.
- Covers CVEs in EC2 instances, Lambda functions, and container images.
- Severity mapped: CRITICAL → 9.5, HIGH → 8.0, MEDIUM → 5.5, LOW → 3.0.
- CVE IDs are included in finding titles when available.

## 5. Trusted Advisor Findings (trusted_advisor_findings)
Aggregates security checks from AWS Trusted Advisor.
- Requires AWS Business or Enterprise Support plan.
- Not available in AWS China regions.
- Status mapped: error (RED) → 8.0, warning (YELLOW) → 5.5, ok (GREEN) → skip.

## 6. Secret Exposure (secret_exposure)
Checks Lambda env vars and EC2 userData for exposed secrets (AWS keys, private keys, passwords).

## 7. SSL Certificate (ssl_certificate)
Checks ACM certificates for expiry, failed status, and upcoming renewals.

## 8. Dangling DNS (dns_dangling)
Checks Route53 CNAME records for dangling DNS (subdomain takeover risk).

## 9. Network Reachability (network_reachability)
Analyzes true network reachability by combining Security Group + NACL rules for public EC2 instances.

## 10. IAM Privilege Escalation (iam_privilege_escalation)
Detects IAM privilege escalation paths — users/roles that can escalate to admin via policy manipulation, role creation, or service abuse.

## 11. Public Access Verify (public_access_verify)
Verifies actual public accessibility of resources marked as public (S3 HTTP check, RDS DNS resolution).

## 12. Tag Compliance (tag_compliance)
Checks EC2, RDS, and S3 resources for required tags (Environment, Project, Owner).

## 13. Idle Resources (idle_resources)
Finds unused/idle AWS resources (unattached EBS volumes, unused EIPs, stopped instances, unused security groups).

## 14. Disaster Recovery (disaster_recovery)
Assesses disaster recovery readiness — RDS Multi-AZ & backups, EBS snapshot coverage, S3 versioning & cross-region replication.
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

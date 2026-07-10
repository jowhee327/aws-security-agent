export const SECURITY_RULES_CONTENT = `# AWS Security Scan Modules & Rules (20 modules)

## 1. Service Detection (service_detection)
Detects which AWS security services are enabled and assesses overall security maturity.
- **Security Hub not enabled** — Risk 7.5: Provides 300+ automated security checks.
- **GuardDuty not enabled** — Risk 7.5: Provides continuous threat detection.
- **Inspector not enabled** — Risk 6.0: Scans for software vulnerabilities.
- **AWS Config not enabled** — Risk 6.0: Tracks configuration changes.
- CloudTrail detection is included for coverage metrics.

### Maturity Levels
| Enabled Services | Level |
|------------------|-------|
| 0–1 | Basic |
| 2–3 | Intermediate |
| 4   | Advanced |
| 5   | Comprehensive |

## 2. Security Hub Findings (security_hub_findings)
Aggregates active findings from AWS Security Hub. Replaces individual config scanners (SG, S3, IAM, CloudTrail, RDS, EBS, VPC, etc.) with centralized compliance checks from FSBP, CIS, and PCI DSS standards.
- Findings are filtered to ACTIVE + NEW/NOTIFIED workflow status.
- Severity mapped: CRITICAL → 9.5, HIGH → 8.0, MEDIUM → 5.5, LOW → 3.0.
- INFORMATIONAL findings are skipped.

## 3. GuardDuty Findings (guardduty_findings)
Detection-only: checks if GuardDuty is enabled in the region.
- GuardDuty findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether GuardDuty detectors are active.

## 4. Inspector Findings (inspector_findings)
Detection-only: checks if Inspector is enabled in the region.
- Inspector findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether Inspector scanning (EC2/Lambda) is active.

## 5. Trusted Advisor Findings (trusted_advisor_findings)
Aggregates security checks from AWS Trusted Advisor.
- Requires AWS Business or Enterprise Support plan.
- In China regions, uses cn-north-1 as the Support API endpoint.
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

## 15. Config Rules Findings (config_rules_findings)
Detection-only: checks if AWS Config Rules are configured.
- Config Rule compliance findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether Config is enabled and counts active rules.
- Gracefully handles regions where AWS Config is not enabled.

## 16. IAM Access Analyzer Findings (access_analyzer_findings)
Detection-only: checks if IAM Access Analyzer is configured.
- Access Analyzer findings are aggregated via Security Hub (security_hub_findings module).
- Reports whether active analyzers exist.
- Returns warning if no analyzer is configured.

## 17. SSM Patch Compliance (patch_compliance_findings)
Checks patch compliance status for SSM-managed instances.
- Lists all managed instances via SSM.
- Retrieves patch compliance state for each instance.
- Missing security patches or failed patches → HIGH (7.5).
- Missing non-security patches → MEDIUM (5.5).
- Instances without patch data flagged as LOW (3.0) for visibility.
- Includes platform info, missing/failed counts, and last scan time.

## 18. IMDSv2 Enforcement (imdsv2_enforcement)
Checks if EC2 instances enforce IMDSv2 (Instance Metadata Service v2).
- Lists all running EC2 instances and checks MetadataOptions.HttpTokens.
- **HttpTokens != "required"** — Risk 7.5: IMDSv1 allows credential theft via SSRF attacks.
- Also checks HttpPutResponseHopLimit — values >1 on containerized workloads noted as warning.
- Remediation: Set HttpTokens to "required" via modify-instance-metadata-options.

## 19. WAF Coverage (waf_coverage)
Checks if internet-facing ALBs have WAF Web ACL associated for protection.
- Lists all ELBv2 load balancers, filters to internet-facing only.
- For each internet-facing ALB, checks WAFv2 Web ACL association.
- **No WAF Web ACL** — Risk 7.5: ALB exposed to SQL injection, XSS, and OWASP Top 10 attacks.
- NLBs (L4) are skipped as WAF does not apply — noted in warnings.
- Gracefully handles WAFv2 access denied or unavailable regions.

## 20. ECR Image CVE (ecr_image_cve)
Deep-scans ECR image layers for critical/high CVEs that ECR Basic / Inspector Enhanced scanning structurally miss.
- Pulls manifests and layers via the ECR API (no Docker daemon); streams tar+gzip layers.
- Dual-channel inventory: package metadata (apk/dpkg) + binary version signatures (nginx, openssl, curl, redis, node, httpd, haproxy, php, python3, java, envoy).
- Flags unmanaged binaries (present with no matching installed package) — the class official scanners cannot see.
- Matches against a curated offline advisory table (optional NVD API 2.0 online lookup, cached 24h).
- Diffs our findings vs official scan results: **gap** (we found, official missed), confirmed, reverse-gap.
- Gap reasons: unmanaged-binary | distro-secdb-no-entry | eol-os | unsupported-os | unknown.
- rpm-based images: rpm parsing unsupported in v1 (noted as warning); whiteout semantics not applied (last-writer-wins).
- Suppression list supported; suppressed findings reported in a dedicated section, never dropped.
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

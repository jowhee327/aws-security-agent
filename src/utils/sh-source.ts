import type { Finding } from "../types.js";

/** Extract source sub-category from a Security Hub finding's impact field. */
export function getSecurityHubSource(finding: Finding): string {
  const impact = finding.impact ?? "";
  const match = impact.match(/^Source:\s*([^(]+)/);
  if (!match) return "Other";
  const product = match[1].trim();
  if (product === "Security Hub" || product.includes("Foundational")) return "FSBP";
  if (product === "Inspector" || product.includes("Inspector")) return "Inspector";
  if (product === "GuardDuty" || product.includes("GuardDuty")) return "GuardDuty";
  if (product === "Config" || product.includes("Config")) return "Config";
  if (product === "IAM Access Analyzer" || product.includes("Access Analyzer")) return "Access Analyzer";
  return "Other";
}

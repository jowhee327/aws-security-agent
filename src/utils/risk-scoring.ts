import { Severity, Priority } from "../types.js";

export function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

export function priorityFromSeverity(severity: Severity): Priority {
  switch (severity) {
    case "CRITICAL": return "P0";
    case "HIGH": return "P1";
    case "MEDIUM": return "P2";
    case "LOW": return "P3";
  }
}

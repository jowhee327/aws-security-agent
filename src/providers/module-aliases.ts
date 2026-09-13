import type { ProviderId } from "../types.js";

/**
 * Module-name substitutions applied when a scan group / report mapping written
 * for AWS is evaluated for another provider. Huawei Cloud has no Security Hub;
 * `rms_compliance_findings` (RMS / Config compliance states) is the aggregation
 * module that stands in for it. AWS has no aliases (byte-identical behaviour).
 */
export const PROVIDER_MODULE_ALIASES: Readonly<Record<ProviderId, Readonly<Record<string, string>>>> = {
  aws: {},
  huaweicloud: {
    security_hub_findings: "rms_compliance_findings",
  },
};

/** Resolve `module` for `provider`; returns the input unchanged when no alias exists (always for aws). */
export function resolveModuleAlias(module: string, provider: ProviderId | undefined): string {
  if (!provider || provider === "aws") return module;
  return PROVIDER_MODULE_ALIASES[provider]?.[module] ?? module;
}

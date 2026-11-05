/**
 * Resolution of the optional {@link CloudProviderHooks} into concrete values for
 * the orchestration layer (`scanners/runner.ts`, `index.ts`).
 *
 * Precedence: the hook on the registered provider object → the built-in hook
 * table below → a generic default. The built-in table keeps behaviour identical
 * when a provider object lacks hooks (e.g. a test double that only implements
 * the core interface); it only references dependency-light hook modules.
 */
import type { ProviderId, ScanContext } from "../types.js";
import type { CloudProvider, CloudProviderHooks, RegionScope, RegionalProviderMessages } from "./types.js";
import { getProvider } from "./registry.js";
import { huaweiCloudHooks } from "./huaweicloud/hooks.js";

const BUILTIN_HOOKS: Partial<Record<ProviderId, CloudProviderHooks>> = {
  huaweicloud: huaweiCloudHooks,
};

export interface ResolvedProviderHooks {
  displayName: string;
  partitionFor(region: string): string;
  /** Undefined only for providers that declare none (the regional runner then requires an explicit region). */
  defaultRegion?: string;
  globalModules: ReadonlySet<string>;
  redactDiagnostic(text: string): string;
  contextFor(scope: RegionScope, accountId: string): Partial<ScanContext>;
  supportsMultiAccount: boolean;
  messages: RegionalProviderMessages;
}

const EMPTY_SET: ReadonlySet<string> = new Set<string>();
const identity = (text: string): string => text;

function genericMessages(displayName: string, id: string): RegionalProviderMessages {
  return {
    noRegions: (fallback) => `${displayName} region discovery returned no regions; scanning ${fallback} only.`,
    unknownRegion: (requested, known) =>
      `${displayName} region "${requested}" is not among this account's regions (known: ${known}); scanning it anyway.`,
    discoveryFailed: (reason, fallback) => `${displayName} region discovery failed: ${reason}. Scanning ${fallback} only.`,
    multiAccountUnsupported: `org_mode requested but multi-account scanning is not yet supported for ${id}. Scanning the current account only.`,
  };
}

export function resolveProviderHooks(provider: CloudProvider): ResolvedProviderHooks {
  const builtin = BUILTIN_HOOKS[provider.id] ?? {};
  const pick = <K extends keyof CloudProviderHooks>(key: K): CloudProviderHooks[K] => provider[key] ?? builtin[key];

  const displayName = pick("displayName") ?? provider.id;
  const partitionFor = pick("partitionFor");
  const redactDiagnostic = pick("redactDiagnostic") ?? identity;
  const contextFor = pick("contextFor");
  return {
    displayName,
    partitionFor: (region) => (partitionFor ? partitionFor(region) : provider.id),
    defaultRegion: pick("defaultRegion"),
    globalModules: pick("globalModules") ?? EMPTY_SET,
    redactDiagnostic: (text) => redactDiagnostic(text),
    contextFor: (scope, accountId) => (contextFor ? contextFor(scope, accountId) : {}),
    supportsMultiAccount: pick("supportsMultiAccount") ?? false,
    messages: {
      ...genericMessages(displayName, provider.id),
      ...builtin.regionalMessages,
      ...provider.regionalMessages,
    },
  };
}

/**
 * Redact error / warning text for a provider. `undefined` (legacy AWS contexts) and
 * providers without a redactor return the text verbatim.
 */
export function redactProviderDiagnostic(provider: ProviderId | undefined, text: string): string {
  if (!provider) return text;
  return resolveProviderHooks(getProvider(provider)).redactDiagnostic(text);
}

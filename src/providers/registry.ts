import type { ProviderId } from "../types.js";
import type { CloudProvider } from "./types.js";
import { awsProvider } from "./aws/index.js";
import { huaweiCloudProvider } from "./huaweicloud/index.js";
import { alibabaCloudProvider } from "./alicloud/index.js";

/** Every registered provider ID as a literal tuple (zod enums need one). Order = display order. */
export const PROVIDER_IDS = ["aws", "huaweicloud", "alicloud"] as const;

// Compile-time guard: PROVIDER_IDS and the ProviderId union must list the same IDs.
type _ProviderIdsCoverUnion = [ProviderId] extends [(typeof PROVIDER_IDS)[number]] ? true : never;
const _providerIdsCoverUnion: _ProviderIdsCoverUnion = true;
void _providerIdsCoverUnion;

const PROVIDERS: Record<(typeof PROVIDER_IDS)[number], CloudProvider> = {
  aws: awsProvider,
  huaweicloud: huaweiCloudProvider,
  alicloud: alibabaCloudProvider,
};

export const DEFAULT_PROVIDER_ID: ProviderId = "aws";

export function isProviderId(id: string): id is ProviderId {
  return Object.prototype.hasOwnProperty.call(PROVIDERS, id);
}

/**
 * Providers flagged experimental (not yet validated against a live account). They are
 * fully registered (`getProvider` / `isProviderId` accept them) but omitted from the
 * default {@link listProviderIds} listing so that callers enumerating the stable
 * provider set are unaffected; pass `includeExperimental` to get every registered ID.
 */
export const EXPERIMENTAL_PROVIDER_IDS: ReadonlySet<ProviderId> = new Set<ProviderId>(["alicloud"]);

export interface ListProviderIdsOptions {
  /** Include experimental providers (default false). */
  includeExperimental?: boolean;
}

export function listProviderIds(opts: ListProviderIdsOptions = {}): ProviderId[] {
  return PROVIDER_IDS.filter((id) => opts.includeExperimental || !EXPERIMENTAL_PROVIDER_IDS.has(id));
}

/** Look up a registered cloud provider. Unknown IDs throw (callers validate via zod / isProviderId). */
export function getProvider(id: ProviderId | string = DEFAULT_PROVIDER_ID): CloudProvider {
  if (!isProviderId(id)) {
    throw new Error(`Unknown cloud provider "${id}". Supported: ${PROVIDER_IDS.join(", ")}`);
  }
  return PROVIDERS[id];
}

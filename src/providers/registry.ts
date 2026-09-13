import type { ProviderId } from "../types.js";
import type { CloudProvider } from "./types.js";
import { awsProvider } from "./aws/index.js";
import { huaweiCloudProvider } from "./huaweicloud/index.js";

const PROVIDERS: Record<ProviderId, CloudProvider> = {
  aws: awsProvider,
  huaweicloud: huaweiCloudProvider,
};

export const DEFAULT_PROVIDER_ID: ProviderId = "aws";

export function isProviderId(id: string): id is ProviderId {
  return Object.prototype.hasOwnProperty.call(PROVIDERS, id);
}

export function listProviderIds(): ProviderId[] {
  return Object.keys(PROVIDERS) as ProviderId[];
}

/** Look up a registered cloud provider. Unknown IDs throw (callers validate via zod / isProviderId). */
export function getProvider(id: ProviderId | string = DEFAULT_PROVIDER_ID): CloudProvider {
  if (!isProviderId(id)) {
    throw new Error(`Unknown cloud provider "${id}". Supported: ${listProviderIds().join(", ")}`);
  }
  return PROVIDERS[id];
}

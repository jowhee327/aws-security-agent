/**
 * Azure subscription enumeration seam (plan §3.3).
 *
 * The provider's `listRegions` turns each visible subscription into one scan scope
 * (`RegionScope { region: subscriptionId, domainId: tenantId }`). Everything that
 * talks to ARM lives behind {@link listAzureSubscriptions} so the provider can be
 * unit-tested by mocking this module (no SDK, no network).
 */
import type { AzureCredentials } from "../../types.js";

/** One subscription visible to the service principal. */
export interface AzureSubscriptionRef {
  subscriptionId: string;
  /** Home tenant of the subscription (falls back to the credentials' tenant when absent). */
  tenantId?: string;
  displayName?: string;
  /** ARM `state`: Enabled / Warned / PastDue / Disabled / Deleted. */
  state?: string;
}

export class AzureSubscriptionEnumerationUnavailableError extends Error {
  constructor() {
    super(
      "Azure subscription enumeration is not implemented yet; set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region",
    );
    this.name = "AzureSubscriptionEnumerationUnavailableError";
  }
}

/**
 * List every subscription visible to `creds`.
 *
 * TODO(T1, plan §3.3/§3.4): implement via a lazily imported
 * `@azure/arm-resources-subscriptions` `SubscriptionClient(azureCredential(creds),
 * { endpoint: armEndpoint, credentialScopes: [armScope] }).subscriptions.list()`
 * (PagedAsyncIterableIterator through `azurePaginate`, capped), mapping
 * `subscriptionId` / `tenantId` / `displayName` / `state`. Errors must surface through
 * `describeAzureError` (never the raw RestError — it carries the Bearer token).
 * Until then this always throws, and the provider falls back to the requested
 * subscription / `AZURE_SUBSCRIPTION_ID`.
 */
export async function listAzureSubscriptions(_creds: AzureCredentials): Promise<AzureSubscriptionRef[]> {
  throw new AzureSubscriptionEnumerationUnavailableError();
}

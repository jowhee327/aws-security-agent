/**
 * Azure subscription enumeration seam (plan §3.3).
 *
 * The provider's `listRegions` turns each visible subscription into one scan scope
 * (`RegionScope { region: subscriptionId, domainId: tenantId }`). The provider imports
 * {@link listAzureSubscriptions} from THIS module so it can be unit-tested by mocking it
 * (no SDK, no network). The implementation — `SubscriptionClient(azureCredential(creds),
 * { endpoint: armEndpoint, credentialScopes: [armScope] }).subscriptions.list()`, paginated
 * and capped — lives in ./client.ts and throws only redacted `AzureCloudError`s.
 */
export { listAzureSubscriptions } from "./client.js";

/** One subscription visible to the service principal. */
export interface AzureSubscriptionRef {
  subscriptionId: string;
  /** Home tenant of the subscription (falls back to the credentials' tenant when absent). */
  tenantId?: string;
  displayName?: string;
  /** ARM `state`: Enabled / Warned / PastDue / Disabled / Deleted. */
  state?: string;
}

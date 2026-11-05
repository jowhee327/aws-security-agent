/**
 * Azure resource URNs (plan §3.6): the native ARM resource ID is used as-is
 * (`/subscriptions/<sub>/resourceGroups/<rg>/providers/<rp>/<type>/<name>`); tenant-level
 * resources use `/tenants/<tenantId>/providers/…`. When a resource carries no `id`, a
 * template is built from its parts. Resource IDs are identifiers, not secrets — but they
 * are server-sourced, so every part still passes through the diagnostic redactor.
 */
import { redactAzureDiagnostic } from "./errors.js";

export interface AzureUrnParts {
  /** Native ARM resource ID — returned (redacted, trimmed) when present. */
  id?: string;
  subscriptionId?: string;
  resourceGroup?: string;
  /** `<namespace>/<type>[/<childType>]`, e.g. `Microsoft.Storage/storageAccounts`. */
  resourceType: string;
  /** Resource name (`<name>` or `<parent>/<child>` for nested types). */
  name: string;
  /** Used for tenant-level resources when there is no subscription. */
  tenantId?: string;
}

function seg(v: string | undefined): string {
  return redactAzureDiagnostic((v ?? "").trim().replace(/^\/+|\/+$/g, ""));
}

/**
 * Native ID passthrough, else
 * `/subscriptions/<sub>[/resourceGroups/<rg>]/providers/<resourceType>/<name>`,
 * `/tenants/<tenant>/providers/<resourceType>/<name>` (no subscription) or
 * `/providers/<resourceType>/<name>` (neither).
 */
export function toAzureUrn(parts: AzureUrnParts): string {
  const id = typeof parts.id === "string" ? parts.id.trim() : "";
  if (id.startsWith("/")) return redactAzureDiagnostic(id);

  const sub = seg(parts.subscriptionId);
  const rg = seg(parts.resourceGroup);
  const tenant = seg(parts.tenantId);
  let prefix = "";
  if (sub) prefix = `/subscriptions/${sub}${rg ? `/resourceGroups/${rg}` : ""}`;
  else if (tenant) prefix = `/tenants/${tenant}`;
  return `${prefix}/providers/${seg(parts.resourceType)}/${seg(parts.name || id)}`;
}

export interface ParsedAzureResourceId {
  subscriptionId?: string;
  resourceGroup?: string;
  tenantId?: string;
  /** Provider namespace of the (innermost) resource, e.g. `Microsoft.Storage`. */
  providerNamespace?: string;
  /** Full type `<namespace>/<type>[/<childType>]`, e.g. `Microsoft.Sql/servers/databases`. */
  resourceType?: string;
  /** Resource name (`<parent>/<child>` for nested types). */
  name?: string;
}

/**
 * Parse an ARM resource ID (case-insensitive keywords). For extension resources
 * (`…/providers/Microsoft.Storage/storageAccounts/sa/providers/Microsoft.Authorization/roleAssignments/x`)
 * the innermost (last) `providers/` segment wins. Returns undefined for non-ID input.
 */
export function parseAzureResourceId(id: string): ParsedAzureResourceId | undefined {
  if (typeof id !== "string") return undefined;
  const trimmed = id.trim();
  if (!trimmed.startsWith("/")) return undefined;
  const parts = trimmed.split("/").filter((p) => p.length > 0);
  if (parts.length < 2) return undefined;

  const out: ParsedAzureResourceId = {};
  let providersAt = -1;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i].toLowerCase();
    if (key === "subscriptions" && out.subscriptionId === undefined) out.subscriptionId = parts[i + 1];
    else if (key === "resourcegroups" && out.resourceGroup === undefined) out.resourceGroup = parts[i + 1];
    else if (key === "tenants" && out.tenantId === undefined) out.tenantId = parts[i + 1];
    if (key === "providers") providersAt = i;
  }
  if (providersAt >= 0) {
    const namespace = parts[providersAt + 1];
    const rest = parts.slice(providersAt + 2);
    out.providerNamespace = namespace;
    const types: string[] = [];
    const names: string[] = [];
    for (let i = 0; i < rest.length; i += 2) {
      types.push(rest[i]);
      if (rest[i + 1] !== undefined) names.push(rest[i + 1]);
    }
    if (types.length > 0) out.resourceType = [namespace, ...types].join("/");
    if (names.length > 0) out.name = names.join("/");
  } else if (out.resourceGroup !== undefined && parts.length === 4) {
    out.name = out.resourceGroup;
  } else if (out.subscriptionId !== undefined && parts.length === 2) {
    out.name = out.subscriptionId;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

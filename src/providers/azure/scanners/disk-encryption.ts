/**
 * Azure disk encryption scanner (moduleName `disk_encryption_findings`, new Azure-only module,
 * plan §2 / §4.1 P1 / T4). EXPERIMENTAL — not yet validated against a live account; field
 * names follow the `@azure/arm-compute` 25.x d.ts (TypeSpec client: `properties` flattened;
 * a nested `properties` object is also accepted).
 *
 * Decision rules (plan §6.4 Q3 is still open — orchestrator default until Will decides):
 *  - Managed disk (`disks.list()`) whose `encryption.type` is missing — and Azure Disk
 *    Encryption (`encryptionSettingsCollection.enabled`) is not on — or explicitly
 *    unencrypted → HIGH (7.0).
 *  - `EncryptionAtRestWithPlatformKey` only → NO finding (platform-managed keys are the
 *    Azure default; flagging them would be noise); the disk is just counted.
 *  - `EncryptionAtRestWithCustomerKey` / `EncryptionAtRestWithPlatformAndCustomerKeys`
 *    (CMK / double encryption) → fine. Any other, unrecognised `encryption.type` value is
 *    treated as encrypted (no finding) so a new Azure encryption mode does not raise noise.
 *  - Unmanaged (VHD in a storage account) OS / data disk on a VM (`storageProfile.*.vhd`
 *    without `managedDisk`) and no ADE on the VM (`osDisk.encryptionSettings.enabled`) →
 *    HIGH (7.0), one finding per VM listing the disk names (VHD URIs are not emitted).
 *  - VM whose `securityProfile.encryptionAtHost` is not `true` → LOW (2.0): temp disk and
 *    disk caches are not encrypted at the host. At most
 *    {@link AZURE_DISK_HOST_MAX_FINDINGS} such findings; the remainder is summarised in a
 *    warning.
 *
 * Sub-services (independent; a failure in one never hides the other's results):
 * `ComputeManagementClient.disks.list()` (capped at {@link AZURE_DISK_MAX_DISKS}) and
 * `virtualMachines.listAll()` (capped at {@link AZURE_DISK_MAX_VMS}). resourcesScanned =
 * disks + VMs. resourceArn = the native ARM resource ID; region = the resource `location`.
 *
 * Errors: access denied / RP not registered / throttled / network → warning and skip that
 * sub-service; **auth_failed or api_misuse in either → module `status: "error"`**.
 */
import type { ComputeManagementClient } from "@azure/arm-compute";
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azLastSegment,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureErrorResult,
  azureNoSubscriptionResult,
  azureSafeFinding,
  azureSafeWarnings,
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

export const AZURE_DISK_MAX_DISKS = 5000;
export const AZURE_DISK_MAX_VMS = 5000;
export const AZURE_DISK_HOST_MAX_FINDINGS = 100;

export const AZURE_DISK_UNENCRYPTED_RISK = 7.0;
export const AZURE_VM_UNMANAGED_DISK_RISK = 7.0;
export const AZURE_VM_NO_HOST_ENCRYPTION_RISK = 2.0;

const DISK_TYPE = "Microsoft.Compute/disks";
const VM_TYPE = "Microsoft.Compute/virtualMachines";
const DISK_SERVICE = "Compute disks.list";
const VM_SERVICE = "Compute virtualMachines.listAll";

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

export type AzureDiskEncryptionState = "platform" | "customer" | "double" | "ade" | "other" | "unencrypted";

/** Resource property: flattened (TypeSpec SDK) or nested under `properties` (raw ARM). */
function prop(resource: unknown, key: string): unknown {
  const direct = azField(resource, key);
  return direct !== undefined ? direct : azField(azField(resource, "properties"), key);
}

/** Encryption state of a managed disk (see the decision rules in the file header). */
export function azureDiskEncryptionState(disk: unknown): AzureDiskEncryptionState {
  const type = azString(azField(prop(disk, "encryption"), "type"))?.toLowerCase();
  const ade = azField(prop(disk, "encryptionSettingsCollection"), "enabled") === true;
  if (type === "encryptionatrestwithplatformkey") return ade ? "ade" : "platform";
  if (type === "encryptionatrestwithcustomerkey") return "customer";
  if (type === "encryptionatrestwithplatformandcustomerkeys") return "double";
  if (type === undefined || /unencrypted|^none$|^disabled$/.test(type)) return ade ? "ade" : "unencrypted";
  return "other";
}

/** Names of a VM's unmanaged (VHD) OS / data disks; raw (redact before emitting). */
export function azureUnmanagedVmDisks(vm: unknown): string[] {
  const storage = prop(vm, "storageProfile");
  const isUnmanaged = (d: unknown) => azString(azField(azField(d, "vhd"), "uri")) !== undefined && !azField(d, "managedDisk");
  const out: string[] = [];
  const os = azField(storage, "osDisk");
  if (os && isUnmanaged(os)) out.push(azString(azField(os, "name")) ?? "OS disk");
  for (const d of azArray(azField(storage, "dataDisks"))) {
    if (isUnmanaged(d)) out.push(azString(azField(d, "name")) ?? `data disk LUN ${String(azField(d, "lun") ?? "?")}`);
  }
  return out;
}

/** Azure Disk Encryption enabled on the VM (`storageProfile.osDisk.encryptionSettings.enabled`). */
function vmHasAde(vm: unknown): boolean {
  return azField(azField(azField(prop(vm, "storageProfile"), "osDisk"), "encryptionSettings"), "enabled") === true;
}

export function azureVmEncryptionAtHost(vm: unknown): boolean {
  return azField(prop(vm, "securityProfile"), "encryptionAtHost") === true;
}

interface ResourceRef {
  name: string;
  arn: string;
  region: string;
  resourceGroup?: string;
}

function resourceRef(resource: unknown, resourceType: string, env: AzureScanEnv): ResourceRef {
  const rawId = azString(azField(resource, "id"));
  const parsed = rawId ? parseAzureResourceId(rawId) : undefined;
  const rawName = azString(azField(resource, "name")) ?? parsed?.name ?? "unknown";
  return {
    name: aztUntrusted(rawName),
    arn: toAzureUrn({ id: rawId, subscriptionId: env.subscriptionId, resourceGroup: parsed?.resourceGroup, resourceType, name: rawName }),
    region: aztUntrustedOpt(azField(resource, "location")) ?? "global",
    resourceGroup: aztUntrustedOpt(parsed?.resourceGroup),
  };
}

function where(ref: ResourceRef, env: AzureScanEnv): string {
  return `${ref.resourceGroup ? `resource group ${ref.resourceGroup}, ` : ""}subscription ${aztUntrusted(env.subscriptionId)}`;
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/** Finding for one managed disk (or none). Exported for unit tests. */
export function azureDiskFinding(disk: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  if (azureDiskEncryptionState(disk) !== "unencrypted") return undefined;
  const ref = resourceRef(disk, DISK_TYPE, env);
  const vm = aztUntrustedOpt(azLastSegment(azString(prop(disk, "managedBy"))));
  const state = aztUntrustedOpt(prop(disk, "diskState"));
  return makeFinding({
    riskScore: AZURE_DISK_UNENCRYPTED_RISK,
    title: `Managed disk ${ref.name} is not encrypted at rest`,
    resourceType: DISK_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Managed disk ${ref.name} (${where(ref, env)}${vm ? `, attached to VM ${vm}` : ""}${state ? `, state ${state}` : ""}) reports no server-side encryption type and Azure Disk Encryption is not enabled.`,
    impact: "Disk contents (including snapshots and exports made from it) are not protected by encryption at rest.",
    remediationSteps: [
      `Verify the encryption settings of disk ${ref.name} (Disks → Encryption); re-create or migrate it with server-side encryption (platform-managed or customer-managed key via a disk encryption set).`,
      "For workloads with key-control requirements, use a customer-managed key (disk encryption set backed by Key Vault).",
      "Assign the Azure Policy \"Managed disks should be double encrypted with both platform-managed and customer-managed keys\" or \"Disk encryption should be applied on virtual machines\" to monitor regressions.",
    ],
    accountId: env.tenantId,
    module,
  });
}

/** Unmanaged-disk finding for one VM (or none). Exported for unit tests. */
export function azureVmUnmanagedDiskFinding(vm: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  const disks = azureUnmanagedVmDisks(vm);
  if (disks.length === 0 || vmHasAde(vm)) return undefined;
  const ref = resourceRef(vm, VM_TYPE, env);
  const names = disks.map((d) => aztUntrusted(d)).join(", ");
  return makeFinding({
    riskScore: AZURE_VM_UNMANAGED_DISK_RISK,
    title: `VM ${ref.name} has unmanaged (VHD) disks without Azure Disk Encryption`,
    resourceType: VM_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Virtual machine ${ref.name} (${where(ref, env)}) uses ${disks.length} unmanaged (VHD in a storage account) disk(s) — ${names} — and Azure Disk Encryption is not enabled on the VM. Their encryption depends solely on the storage account's service-side encryption, which this scan cannot verify.`,
    impact: "VHD disk data may be unencrypted at rest, and anyone with access to the storage account (keys / SAS) can copy the disk blobs.",
    remediationSteps: [
      `Migrate VM ${ref.name} to managed disks (ConvertTo-AzVMManagedDisk / az vm convert); managed disks are encrypted at rest by default.`,
      "Alternatively enable Azure Disk Encryption (BitLocker / dm-crypt) on the VM.",
      "Unmanaged disks are being retired by Azure; plan the migration regardless of encryption.",
    ],
    accountId: env.tenantId,
    module,
  });
}

/** Encryption-at-host finding for one VM (or none). Exported for unit tests. */
export function azureVmHostEncryptionFinding(vm: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  if (azureVmEncryptionAtHost(vm)) return undefined;
  const ref = resourceRef(vm, VM_TYPE, env);
  return makeFinding({
    riskScore: AZURE_VM_NO_HOST_ENCRYPTION_RISK,
    title: `VM ${ref.name} does not use encryption at host`,
    resourceType: VM_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Virtual machine ${ref.name} (${where(ref, env)}) does not have securityProfile.encryptionAtHost enabled: its temporary disk and OS / data disk caches are not encrypted on the host.`,
    impact: "Data on the VM temp disk and disk caches is stored unencrypted on the physical host.",
    remediationSteps: [
      "Register the EncryptionAtHost feature for the subscription (Microsoft.Compute provider), deallocate the VM and set securityProfile.encryptionAtHost=true.",
      "Assign the Azure Policy \"Virtual machines and virtual machine scale sets should have encryption at host enabled\" to monitor new VMs.",
    ],
    accountId: env.tenantId,
    module,
  });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface SubResult {
  findings: Finding[];
  scanned: number;
  warnings: string[];
  /** auth_failed / api_misuse: the whole module fails. */
  fatal?: unknown;
}

export class AzureDiskEncryptionScanner implements Scanner {
  readonly moduleName = "disk_encryption_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure disk encryption scan failed", err);
    }
    if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);

    let client: ComputeManagementClient;
    try {
      client = await this.client(env);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure disk encryption scan failed", err);
    }

    const parts = await Promise.all([this.scanDisks(client, env), this.scanVms(client, env)]);
    const warnings = parts.flatMap((p) => p.warnings);
    const fatal = parts.find((p) => p.fatal !== undefined);
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure disk encryption scan failed", fatal.fatal, warnings);

    const findings = parts.flatMap((p) => p.findings);
    return {
      module: this.moduleName,
      status: "success",
      ...(warnings.length > 0 ? { warnings: azureSafeWarnings(warnings) } : {}),
      resourcesScanned: parts.reduce((n, p) => n + p.scanned, 0),
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }

  private async client(env: AzureScanEnv): Promise<ComputeManagementClient> {
    const { ComputeManagementClient } = await import("@azure/arm-compute");
    return armClient(ComputeManagementClient, env.credentials, env.subscriptionId);
  }

  private async scanDisks(client: ComputeManagementClient, env: AzureScanEnv): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    try {
      const page = await azurePaginate(client.disks.list(), {
        max: AZURE_DISK_MAX_DISKS,
        collect: false,
        onItem: (d) => {
          const f = azureDiskFinding(d, env, this.moduleName);
          if (f) out.findings.push(f);
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(DISK_SERVICE, AZURE_DISK_MAX_DISKS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(DISK_SERVICE, err)} — managed disk encryption not verified.`);
    }
    return out;
  }

  private async scanVms(client: ComputeManagementClient, env: AzureScanEnv): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    let hostFindings = 0;
    let hostOverflow = 0;
    try {
      const page = await azurePaginate(client.virtualMachines.listAll(), {
        max: AZURE_DISK_MAX_VMS,
        collect: false,
        onItem: (vm) => {
          const unmanaged = azureVmUnmanagedDiskFinding(vm, env, this.moduleName);
          if (unmanaged) out.findings.push(unmanaged);
          const host = azureVmHostEncryptionFinding(vm, env, this.moduleName);
          if (!host) return;
          if (hostFindings < AZURE_DISK_HOST_MAX_FINDINGS) {
            out.findings.push(host);
            hostFindings++;
          } else {
            hostOverflow++;
          }
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(VM_SERVICE, AZURE_DISK_MAX_VMS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(VM_SERVICE, err)} — VM unmanaged disk / encryption at host not verified.`);
    }
    if (hostOverflow > 0) {
      out.warnings.push(
        `${VM_SERVICE}: ${hostOverflow} more VM(s) without encryption at host were not reported individually (limit ${AZURE_DISK_HOST_MAX_FINDINGS} findings).`,
      );
    }
    return out;
  }
}

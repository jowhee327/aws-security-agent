/**
 * Azure idle resources scanner (moduleName `idle_resources`, plan §2 #9 / §4.1 P1 / T5).
 * EXPERIMENTAL — not yet validated against a live account; field names follow the
 * `@azure/arm-compute` 25.x / `@azure/arm-network` 39.x d.ts (TypeSpec clients: `properties`
 * flattened; a nested `properties` object is also accepted).
 *
 * Mirrors `src/scanners/idle-resources.ts` (EBS / EIP / stopped EC2 / unused SG):
 *  - Compute `disks.list()` with `diskState=Unattached` (and no `managedBy`) → 3.0 (AWS
 *    unattached EBS). `Reserved` disks (attached to a deallocated VM) are covered by the VM
 *    category instead.
 *  - Network `publicIPAddresses.listAll()` without `ipConfiguration` and without `natGateway`
 *    → 2.0 (AWS unused EIP).
 *  - Compute `virtualMachines.listAll({ statusOnly: "true" })` → `instanceView.statuses[]`
 *    `PowerState/stopped` (stopped from the OS / without deallocation: compute is still billed)
 *    → 3.0; `PowerState/deallocated` (only disks / reserved public IPs billed) → 2.0. The
 *    power-state `time` is shown when present but not used as a threshold (AWS flags > 30
 *    days; Azure exposes no reliable stop timestamp), so every stopped VM is reported.
 *  - Network `networkSecurityGroups.listAll()` whose `networkInterfaces[]` and `subnets[]` are
 *    both empty (associated with nothing) → 2.0 (AWS unused SG).
 * Every listing is a capped `PagedAsyncIterableIterator` (`azurePaginate`).
 *
 * Errors: access denied / RP not registered / throttled / network on a category → warning and
 * skip that category; **auth_failed or api_misuse in any → module `status: "error"`**.
 */
import type { ComputeManagementClient } from "@azure/arm-compute";
import type { NetworkManagementClient } from "@azure/arm-network";
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azNumber,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureEmptyResult,
  azureErrorResult,
  azureNoSubscriptionWarning,
  azureSafeFinding,
  azureSafeWarnings,
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

export const AZURE_IDLE_MAX_ITEMS = 5000;

/** riskScores aligned with the AWS idle-resources scanner. */
export const AZURE_IDLE_DISK_RISK = 3.0;
export const AZURE_IDLE_PUBLIC_IP_RISK = 2.0;
export const AZURE_IDLE_VM_STOPPED_RISK = 3.0;
export const AZURE_IDLE_VM_DEALLOCATED_RISK = 2.0;
export const AZURE_IDLE_NSG_RISK = 2.0;

const DISK_TYPE = "Microsoft.Compute/disks";
const PIP_TYPE = "Microsoft.Network/publicIPAddresses";
const VM_TYPE = "Microsoft.Compute/virtualMachines";
const NSG_TYPE = "Microsoft.Network/networkSecurityGroups";
const DISK_SERVICE = "Compute disks.list";
const PIP_SERVICE = "Network publicIPAddresses.listAll";
const VM_SERVICE = "Compute virtualMachines.listAll";
const NSG_SERVICE = "Network networkSecurityGroups.listAll";

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/** Resource property: flattened (TypeSpec SDK) or nested under `properties` (raw ARM). */
function prop(resource: unknown, key: string): unknown {
  const direct = azField(resource, key);
  return direct !== undefined ? direct : azField(azField(resource, "properties"), key);
}

/** Unattached managed disk (`diskState=Unattached`, no `managedBy`). */
export function azureDiskIsUnattached(disk: unknown): boolean {
  return (azString(prop(disk, "diskState")) ?? "").toLowerCase() === "unattached" && !azString(prop(disk, "managedBy"));
}

/** Public IP associated with nothing (no IP configuration, no NAT gateway). */
export function azurePublicIpIsUnassociated(pip: unknown): boolean {
  return !azField(prop(pip, "ipConfiguration"), "id") && !azField(prop(pip, "natGateway"), "id");
}

/** NSG associated with no NIC and no subnet. */
export function azureNsgIsUnassociated(nsg: unknown): boolean {
  return azArray(prop(nsg, "networkInterfaces")).length === 0 && azArray(prop(nsg, "subnets")).length === 0;
}

export interface AzureVmPowerState {
  /** Lower-cased power state (`running`, `stopped`, `deallocated`, …). */
  state: string;
  /** Status `time`, when reported. */
  time?: Date;
}

/** `PowerState/<state>` from `instanceView.statuses[]`; undefined when not reported. */
export function azureVmPowerState(vm: unknown): AzureVmPowerState | undefined {
  for (const s of azArray(azField(prop(vm, "instanceView"), "statuses"))) {
    const code = azString(azField(s, "code"));
    const m = code ? /^PowerState\/(.+)$/i.exec(code) : null;
    if (!m) continue;
    const t = azField(s, "time");
    const time = t instanceof Date ? t : typeof t === "string" ? new Date(t) : undefined;
    return { state: m[1].toLowerCase(), ...(time && !Number.isNaN(time.getTime()) ? { time } : {}) };
  }
  return undefined;
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

/* ------------------------------------------------------------------------ */
/* Per-resource findings (exported for unit tests)                          */
/* ------------------------------------------------------------------------ */

export function azureIdleDiskFinding(disk: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  if (!azureDiskIsUnattached(disk)) return undefined;
  const ref = resourceRef(disk, DISK_TYPE, env);
  const size = azNumber(prop(disk, "diskSizeGB"));
  const sku = aztUntrustedOpt(azField(azField(disk, "sku"), "name"));
  return makeFinding({
    riskScore: AZURE_IDLE_DISK_RISK,
    title: `Managed disk ${ref.name} is unattached`,
    resourceType: DISK_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Managed disk ${ref.name} (${where(ref, env)}; ${size ?? "?"} GiB${sku ? `, ${sku}` : ""}) is in "Unattached" state and not attached to any virtual machine.`,
    impact: "Unattached disks incur storage costs and may contain sensitive data that is no longer actively managed.",
    remediationSteps: [
      "Determine if the disk is still needed.",
      "If not needed, create a snapshot for archival and delete the disk.",
      "If needed, attach it to the appropriate virtual machine.",
    ],
    accountId: env.tenantId,
    module,
  });
}

export function azureIdlePublicIpFinding(pip: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  if (!azurePublicIpIsUnassociated(pip)) return undefined;
  const ref = resourceRef(pip, PIP_TYPE, env);
  const ip = aztUntrustedOpt(prop(pip, "ipAddress"));
  const sku = aztUntrustedOpt(azField(azField(pip, "sku"), "name"));
  const method = aztUntrustedOpt(prop(pip, "publicIPAllocationMethod"));
  return makeFinding({
    riskScore: AZURE_IDLE_PUBLIC_IP_RISK,
    title: `Public IP ${ip ?? ref.name} is not associated`,
    resourceType: PIP_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Public IP address ${ref.name}${ip ? ` (${ip})` : ""} (${where(ref, env)}${sku ? `; SKU ${sku}` : ""}${method ? `, ${method} allocation` : ""}) is not associated with any network interface, load balancer, application gateway or NAT gateway.`,
    impact: "Unused (especially Static / Standard SKU) public IPs keep incurring charges and represent unnecessary spend.",
    remediationSteps: [
      "Associate the public IP with a resource if it is still needed.",
      "Delete the public IP if it is no longer required.",
    ],
    accountId: env.tenantId,
    module,
  });
}

export function azureIdleVmFinding(vm: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  const power = azureVmPowerState(vm);
  if (!power || (power.state !== "stopped" && power.state !== "deallocated")) return undefined;
  const ref = resourceRef(vm, VM_TYPE, env);
  const stopped = power.state === "stopped";
  const size = aztUntrustedOpt(azField(prop(vm, "hardwareProfile"), "vmSize"));
  const since = power.time ? ` since ${power.time.toISOString()}` : "";
  return makeFinding({
    riskScore: stopped ? AZURE_IDLE_VM_STOPPED_RISK : AZURE_IDLE_VM_DEALLOCATED_RISK,
    title: stopped ? `VM ${ref.name} is stopped but not deallocated (still billed)` : `VM ${ref.name} is deallocated`,
    resourceType: VM_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Virtual machine ${ref.name} (${where(ref, env)}${size ? `; ${size}` : ""}) is in power state "${power.state}"${since}. ${
      stopped
        ? "A VM stopped from inside the OS (or without deallocation) keeps its compute allocation and is still billed for it, in addition to its disks."
        : "Its OS / data disks (and any static public IP) continue to incur charges."
    }${power.time ? "" : " The stop time is not reported; review how long it has been stopped."}`,
    impact: stopped
      ? "The stopped VM is still billed for compute and storage, and may run stale configurations or unpatched images when restarted."
      : "Deallocated VMs still incur disk storage costs and may contain stale configurations or unpatched images.",
    remediationSteps: [
      "Determine if the VM is still needed.",
      "If not needed, capture an image / snapshot for archival and delete the VM and its disks.",
      ...(stopped ? ["If it must be kept, stop it from the Azure portal / CLI (az vm deallocate) to release the compute allocation."] : []),
      "If needed temporarily, consider an image or template for on-demand recreation.",
    ],
    accountId: env.tenantId,
    module,
  });
}

export function azureIdleNsgFinding(nsg: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  if (!azureNsgIsUnassociated(nsg)) return undefined;
  const ref = resourceRef(nsg, NSG_TYPE, env);
  const rules = azArray(prop(nsg, "securityRules")).length;
  return makeFinding({
    riskScore: AZURE_IDLE_NSG_RISK,
    title: `Network security group ${ref.name} is not attached to any resource`,
    resourceType: NSG_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Network security group ${ref.name} (${where(ref, env)}; ${rules} custom rule(s)) is not associated with any network interface or subnet.`,
    impact: "Unused network security groups add clutter and may cause confusion during security reviews.",
    remediationSteps: [
      "Verify the NSG is not referenced by templates / automation that will associate it later.",
      "Delete the network security group if it is no longer needed.",
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

type FindingFn = (item: unknown, env: AzureScanEnv, module: string) => Finding | undefined;

export class AzureIdleResourcesScanner implements Scanner {
  readonly moduleName = "idle_resources";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure idle resources scan failed", err);
    }
    if (!env) return azureEmptyResult(this.moduleName, startMs, { warnings: [azureNoSubscriptionWarning(this.moduleName)] });

    let compute: ComputeManagementClient;
    let network: NetworkManagementClient;
    try {
      [compute, network] = await this.clients(env);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure idle resources scan failed", err);
    }

    const scanEnv = env;
    const parts = await Promise.all([
      this.category(() => compute.disks.list(), DISK_SERVICE, "unattached disks not checked", azureIdleDiskFinding, scanEnv),
      this.category(() => network.publicIPAddresses.listAll(), PIP_SERVICE, "unassociated public IPs not checked", azureIdlePublicIpFinding, scanEnv),
      this.category(() => compute.virtualMachines.listAll({ statusOnly: "true" }), VM_SERVICE, "stopped / deallocated VMs not checked", azureIdleVmFinding, scanEnv),
      this.category(() => network.networkSecurityGroups.listAll(), NSG_SERVICE, "unassociated NSGs not checked", azureIdleNsgFinding, scanEnv),
    ]);
    const warnings = parts.flatMap((p) => p.warnings);
    const fatal = parts.find((p) => p.fatal !== undefined);
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure idle resources scan failed", fatal.fatal, warnings);

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

  private async clients(env: AzureScanEnv): Promise<[ComputeManagementClient, NetworkManagementClient]> {
    const [{ ComputeManagementClient }, { NetworkManagementClient }] = await Promise.all([import("@azure/arm-compute"), import("@azure/arm-network")]);
    return Promise.all([
      armClient(ComputeManagementClient, env.credentials, env.subscriptionId),
      armClient(NetworkManagementClient, env.credentials, env.subscriptionId),
    ]);
  }

  private async category(iter: () => AsyncIterable<unknown>, service: string, consequence: string, toFinding: FindingFn, env: AzureScanEnv): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    try {
      const page = await azurePaginate(iter(), {
        max: AZURE_IDLE_MAX_ITEMS,
        collect: false,
        onItem: (item) => {
          const f = toFinding(item, env, this.moduleName);
          if (f) out.findings.push(f);
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(service, AZURE_IDLE_MAX_ITEMS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(service, err)} — ${consequence}.`);
    }
    return out;
  }
}

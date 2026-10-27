/**
 * Azure network reachability scanner (moduleName `network_reachability`, plan §2 #5 / §4.1 P1 /
 * T5). EXPERIMENTAL — not yet validated against a live account; field names follow the
 * `@azure/arm-network` 39.x d.ts (TypeSpec client: `properties` flattened; a nested
 * `properties` object is also accepted).
 *
 * Sub-services (all `listAll()` on `NetworkManagementClient`, capped):
 *  - `networkSecurityGroups` → `securityRules` + `defaultSecurityRules`, and the NSG's
 *    `networkInterfaces[]` / `subnets[]` association references;
 *  - `networkInterfaces` → per NIC `networkSecurityGroup`, `virtualMachine`,
 *    `ipConfigurations[].subnet` / `.publicIPAddress`;
 *  - `publicIPAddresses` → `ipAddress`, `sku.name` and `ipConfiguration.id` (a NIC IP
 *    configuration ID also links the public IP to its NIC when the NIC listing failed).
 *
 * NSG evaluation (exact for one NSG, per address family): inbound rules (custom + default) are
 * walked in priority order (lower number first; first match wins). For a high-risk port
 * ({@link HIGH_RISK_PORTS}, the AWS table) and protocol TCP / UDP / `*`:
 *  - a rule whose source (`sourceAddressPrefix` / `sourceAddressPrefixes[]`) covers the whole
 *    internet of that family (`*`, `Internet`, `0.0.0.0/0` for IPv4; `*`, `Internet`, `::/0`
 *    for IPv6) decides: Allow → open, Deny → closed;
 *  - rules with a partial source (CIDRs, other service tags, application security groups) are
 *    skipped: a partial Allow does not open the port to the whole internet and a partial Deny
 *    does not close it (conservative — a world Allow that is only partly blocked is still
 *    reported);
 *  - `destinationAddressPrefix(es)` / destination ASGs are not evaluated (assumed to match);
 *  - no matching rule → closed (the implicit `DenyAllInBound`). Equal priorities (invalid in
 *    Azure) sort Allow first so a malformed collection never hides an Allow.
 *
 * Internet exposure: a NIC is internet-exposed when one of its IP configurations has a public
 * IP. Its effective result is open only when BOTH the subnet NSG and the NIC NSG allow the
 * port (Azure evaluates both for inbound traffic); a layer without an NSG passes everything
 * through. A public NIC with no NSG on either layer is open on every port when its public IP
 * is Basic SKU (or the SKU is unknown); Standard SKU public IPs are closed by default.
 * Exposure through load balancers / application gateways (public IP on a frontend) is not
 * traced to backend NICs.
 *
 * Findings (riskScores aligned with the AWS scanner):
 *  - internet-exposed NIC (or its VM) with a high-risk port open → {@link AZURE_NET_PORT_OPEN_RISK} per port;
 *  - internet-exposed NIC open on every port (an all-ports world Allow decides on every layer,
 *    or no NSG + Basic SKU) → {@link AZURE_NET_ALL_PORTS_RISK};
 *  - NSG associated with a NIC / subnet, allowing a high-risk port from the internet but with
 *    no public-IP association found → {@link AZURE_NET_NSG_OPEN_RISK} (one finding per NSG
 *    listing the ports: still reachable through a load balancer / future public IP). NSGs
 *    associated with nothing are left to `idle_resources`.
 *
 * Errors: access denied / RP not registered / throttled / network → warning and skip that
 * sub-service (NSG listing failure → no evaluation; NIC listing failure → NICs known only via
 * public IPs, subnet layer unknown and the no-NSG check skipped); **auth_failed or api_misuse
 * in any → module `status: "error"`**.
 */
import type { NetworkManagementClient } from "@azure/arm-network";
import type { Scanner } from "../../../scanners/base.js";
import { HIGH_RISK_PORTS } from "../../../scanners/network-reachability.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azLastSegment,
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

export { HIGH_RISK_PORTS };

export const AZURE_NET_MAX_NSGS = 5000;
export const AZURE_NET_MAX_NICS = 5000;
export const AZURE_NET_MAX_PUBLIC_IPS = 5000;

export const AZURE_NET_PORT_OPEN_RISK = 9.5;
export const AZURE_NET_ALL_PORTS_RISK = 8.0;
export const AZURE_NET_NSG_OPEN_RISK = 5.0;

/** Priority for a custom rule without one (lowest custom priority). */
const DEFAULT_CUSTOM_PRIORITY = 4096;
/** Priority for a default rule without one (`DenyAllInBound`). */
const DEFAULT_RULE_PRIORITY = 65500;

const NSG_TYPE = "Microsoft.Network/networkSecurityGroups";
const NIC_TYPE = "Microsoft.Network/networkInterfaces";
const VM_TYPE = "Microsoft.Compute/virtualMachines";
const NSG_SERVICE = "Network networkSecurityGroups.listAll";
const NIC_SERVICE = "Network networkInterfaces.listAll";
const PIP_SERVICE = "Network publicIPAddresses.listAll";

/** Ports sampled for the all-ports check (as the AWS NACL proxy: 80 + every high-risk port). */
const ALL_PORTS_SAMPLE = [80, ...Object.keys(HIGH_RISK_PORTS).map(Number)];

/* ------------------------------------------------------------------------ */
/* Rule parsing                                                             */
/* ------------------------------------------------------------------------ */

export interface PortSpan {
  from: number;
  to: number;
}

const ALL_PORTS: PortSpan = Object.freeze({ from: 0, to: 65535 });

/** Resource property: flattened (TypeSpec SDK) or nested under `properties` (raw ARM). */
function prop(resource: unknown, key: string): unknown {
  const direct = azField(resource, key);
  return direct !== undefined ? direct : azField(azField(resource, "properties"), key);
}

/**
 * One NSG port expression: `*` → every port, `n` → [n, n], `a-b` → [a, b]. Out-of-range,
 * reversed or unparsable values → undefined.
 */
export function parseAzurePortRange(raw: unknown): PortSpan | undefined {
  const s = azString(raw);
  if (!s) return undefined;
  if (s === "*") return ALL_PORTS;
  const m = /^(\d{1,5})\s*(?:-\s*(\d{1,5}))?$/.exec(s);
  if (!m) return undefined;
  const from = Number(m[1]);
  const to = m[2] !== undefined ? Number(m[2]) : from;
  if (from > 65535 || to > 65535 || from > to) return undefined;
  return { from, to };
}

/** Port spans of a rule: `destinationPortRange` plus every `destinationPortRanges[]` entry. */
export function azureRulePortSpans(rule: unknown): PortSpan[] {
  const raws = [prop(rule, "destinationPortRange"), ...azArray(prop(rule, "destinationPortRanges"))];
  return raws.flatMap((r) => {
    const span = parseAzurePortRange(r);
    return span ? [span] : [];
  });
}

export function isAllPortSpan(span: PortSpan): boolean {
  return span.from <= 1 && span.to >= 65535;
}

const V4_WORLD = new Set(["*", "internet", "0.0.0.0/0"]);
const V6_WORLD = new Set(["*", "internet", "::/0"]);

export interface AzureNsgRule {
  /** Already redacted. */
  name: string;
  access: "allow" | "deny";
  priority: number;
  spans: PortSpan[];
  ipv4World: boolean;
  ipv6World: boolean;
}

/**
 * Inbound TCP / UDP / `*` rule → normalised rule, or undefined (outbound, other protocol, no
 * parsable port, unknown access). Sources: `sourceAddressPrefix` + `sourceAddressPrefixes[]`.
 */
export function parseAzureNsgRule(rule: unknown, isDefault = false): AzureNsgRule | undefined {
  if ((azString(prop(rule, "direction")) ?? "").toLowerCase() !== "inbound") return undefined;
  const protocol = (azString(prop(rule, "protocol")) ?? "").toLowerCase();
  if (protocol !== "tcp" && protocol !== "udp" && protocol !== "*") return undefined;
  const accessRaw = (azString(prop(rule, "access")) ?? "").toLowerCase();
  if (accessRaw !== "allow" && accessRaw !== "deny") return undefined;
  const spans = azureRulePortSpans(rule);
  if (spans.length === 0) return undefined;
  const sources = [prop(rule, "sourceAddressPrefix"), ...azArray(prop(rule, "sourceAddressPrefixes"))].flatMap((s) => {
    const v = azString(s);
    return v ? [v.toLowerCase()] : [];
  });
  return {
    name: aztUntrusted(azString(azField(rule, "name")) ?? "unnamed rule"),
    access: accessRaw,
    priority: azNumber(prop(rule, "priority")) ?? (isDefault ? DEFAULT_RULE_PRIORITY : DEFAULT_CUSTOM_PRIORITY),
    spans,
    ipv4World: sources.some((s) => V4_WORLD.has(s)),
    ipv6World: sources.some((s) => V6_WORLD.has(s)),
  };
}

/** Inbound rules of an NSG (custom + default), sorted by priority; Allow first on ties. */
export function azureNsgRules(nsg: unknown): AzureNsgRule[] {
  const custom = azArray(prop(nsg, "securityRules")).flatMap((r) => {
    const p = parseAzureNsgRule(r);
    return p ? [p] : [];
  });
  const defaults = azArray(prop(nsg, "defaultSecurityRules")).flatMap((r) => {
    const p = parseAzureNsgRule(r, true);
    return p ? [p] : [];
  });
  return [...custom, ...defaults].sort((a, b) => a.priority - b.priority || (a.access === b.access ? 0 : a.access === "allow" ? -1 : 1));
}

export type AddressFamily = "v4" | "v6";

/** First rule deciding internet traffic of `family` to `port` (undefined = implicit deny). */
export function azureDecidingRule(rules: readonly AzureNsgRule[], port: number, family: AddressFamily): AzureNsgRule | undefined {
  return rules.find(
    (r) => (family === "v4" ? r.ipv4World : r.ipv6World) && r.spans.some((s) => port >= s.from && port <= s.to),
  );
}

/** World Allow rule deciding `port` for `family`, if the port is open from the internet. */
export function azureOpenRule(rules: readonly AzureNsgRule[], port: number, family: AddressFamily): AzureNsgRule | undefined {
  const r = azureDecidingRule(rules, port, family);
  return r?.access === "allow" ? r : undefined;
}

/* ------------------------------------------------------------------------ */
/* Inventory                                                                */
/* ------------------------------------------------------------------------ */

const key = (id: string) => id.toLowerCase();

/** Lower-cased ARM ID of a `{ id }` sub-resource reference. */
function refId(ref: unknown): string | undefined {
  const id = azString(azField(ref, "id"));
  return id ? key(id) : undefined;
}

/** NIC ID part of a NIC IP configuration ID (`…/networkInterfaces/<nic>/ipConfigurations/<cfg>`). */
export function azureNicIdFromIpConfigId(ipConfigId: string | undefined): string | undefined {
  if (!ipConfigId) return undefined;
  const m = /^(.*\/providers\/microsoft\.network\/networkinterfaces\/[^/]+)\/ipconfigurations\/[^/]+$/i.exec(ipConfigId.trim());
  return m ? key(m[1]) : undefined;
}

interface NsgInfo {
  /** Raw resource (for resourceRef). */
  raw: unknown;
  rules: AzureNsgRule[];
  nicIds: string[];
  subnetIds: string[];
}

interface PipInfo {
  /** Already redacted. */
  address?: string;
  /** Lower-cased SKU name (`basic` / `standard` / …); undefined when unknown. */
  sku?: string;
}

interface NicInfo {
  raw?: unknown;
  /** Lower-cased NIC ID. */
  id: string;
  nsgId?: string;
  subnetIds: string[];
  pipIds: string[];
  vmId?: string;
}

/* ------------------------------------------------------------------------ */
/* Findings                                                                 */
/* ------------------------------------------------------------------------ */

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

/** Reference for an ID-only resource (a NIC known only from a public IP / a VM reference). */
function idRef(id: string, resourceType: string, env: AzureScanEnv, region: string): ResourceRef {
  const parsed = parseAzureResourceId(id);
  return {
    name: aztUntrusted(azLastSegment(id) ?? "unknown"),
    arn: toAzureUrn({ id, subscriptionId: env.subscriptionId, resourceType, name: azLastSegment(id) ?? "unknown" }),
    region,
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

/** One layer of a NIC's inbound path: an evaluated NSG, or pass-through (no NSG). */
interface Layer {
  /** Already redacted; undefined = no NSG on this layer. */
  nsgName?: string;
  rules?: AzureNsgRule[];
}

interface LayerHit {
  nsgName: string;
  rule: AzureNsgRule;
}

/** Open through every layer for `family`? Returns the deciding Allow rules (per NSG layer). */
function openThroughLayers(layers: readonly Layer[], port: number, family: AddressFamily): LayerHit[] | undefined {
  const hits: LayerHit[] = [];
  for (const layer of layers) {
    if (!layer.rules || layer.nsgName === undefined) continue;
    const rule = azureOpenRule(layer.rules, port, family);
    if (!rule) return undefined;
    hits.push({ nsgName: layer.nsgName, rule });
  }
  return hits;
}

/** Open for either family (IPv6 is evaluated even without a public IPv6 address, as AWS / Alibaba Cloud do). */
function openEither(layers: readonly Layer[], port: number): LayerHit[] | undefined {
  return openThroughLayers(layers, port, "v4") ?? openThroughLayers(layers, port, "v6");
}

const describeHits = (hits: readonly LayerHit[]) =>
  hits.map((h) => `NSG ${h.nsgName} rule ${h.rule.name} (priority ${h.rule.priority})`).join(" and ");

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface ListResult<T> {
  items: T[];
  ok: boolean;
  warnings: string[];
  fatal?: unknown;
}

export class AzureNetworkReachabilityScanner implements Scanner {
  readonly moduleName = "network_reachability";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure network reachability scan failed", err);
    }
    if (!env) return azureEmptyResult(this.moduleName, startMs, { warnings: [azureNoSubscriptionWarning(this.moduleName)] });

    let client: NetworkManagementClient;
    try {
      client = await this.client(env);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure network reachability scan failed", err);
    }

    const [nsgs, nics, pips] = await Promise.all([
      this.list(() => client.networkSecurityGroups.listAll(), AZURE_NET_MAX_NSGS, NSG_SERVICE, "NSG rules not evaluated"),
      this.list(() => client.networkInterfaces.listAll(), AZURE_NET_MAX_NICS, NIC_SERVICE, "NIC ↔ subnet / public IP associations incomplete"),
      this.list(() => client.publicIPAddresses.listAll(), AZURE_NET_MAX_PUBLIC_IPS, PIP_SERVICE, "public IP addresses / SKUs not resolved"),
    ]);
    const warnings = [...nsgs.warnings, ...nics.warnings, ...pips.warnings];
    const fatal = [nsgs, nics, pips].find((p) => p.fatal !== undefined);
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure network reachability scan failed", fatal.fatal, warnings);

    const findings = nsgs.ok ? this.evaluate(env, nsgs.items, nics, pips.items, warnings) : [];
    return {
      module: this.moduleName,
      status: "success",
      ...(warnings.length > 0 ? { warnings: azureSafeWarnings(warnings) } : {}),
      resourcesScanned: nsgs.items.length + nics.items.length,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }

  private async client(env: AzureScanEnv): Promise<NetworkManagementClient> {
    const { NetworkManagementClient } = await import("@azure/arm-network");
    return armClient(NetworkManagementClient, env.credentials, env.subscriptionId);
  }

  private async list(iter: () => AsyncIterable<unknown>, max: number, service: string, consequence: string): Promise<ListResult<unknown>> {
    try {
      const page = await azurePaginate(iter(), { max });
      return { items: page.items, ok: true, warnings: page.truncated ? [azureTruncationWarning(service, max)] : [] };
    } catch (err) {
      if (isAzureFatal(err)) return { items: [], ok: false, warnings: [], fatal: err };
      return { items: [], ok: false, warnings: [`${azureSoftWarning(service, err)} — ${consequence}.`] };
    }
  }

  private evaluate(env: AzureScanEnv, rawNsgs: unknown[], nics: ListResult<unknown>, rawPips: unknown[], warnings: string[]): Finding[] {
    // NSGs by ID, plus subnet → NSG from the NSG's own association references.
    const nsgById = new Map<string, NsgInfo>();
    const subnetNsg = new Map<string, string>();
    const nicNsgFromNsg = new Map<string, string>();
    for (const raw of rawNsgs) {
      const id = refId(raw);
      if (!id) continue;
      const info: NsgInfo = {
        raw,
        rules: azureNsgRules(raw),
        nicIds: azArray(prop(raw, "networkInterfaces")).flatMap((r) => refId(r) ?? []),
        subnetIds: azArray(prop(raw, "subnets")).flatMap((r) => refId(r) ?? []),
      };
      nsgById.set(id, info);
      for (const s of info.subnetIds) subnetNsg.set(s, id);
      for (const n of info.nicIds) nicNsgFromNsg.set(n, id);
    }

    const pipById = new Map<string, PipInfo>();
    const nicById = new Map<string, NicInfo>();
    for (const raw of nics.items) {
      const id = refId(raw);
      if (!id) continue;
      const cfgs = azArray(prop(raw, "ipConfigurations"));
      nicById.set(id, {
        raw,
        id,
        nsgId: refId(prop(raw, "networkSecurityGroup")),
        subnetIds: cfgs.flatMap((c) => refId(prop(c, "subnet")) ?? []),
        pipIds: cfgs.flatMap((c) => refId(prop(c, "publicIPAddress")) ?? []),
        vmId: azString(azField(prop(raw, "virtualMachine"), "id")),
      });
    }
    for (const raw of rawPips) {
      const id = refId(raw);
      if (!id) continue;
      pipById.set(id, { address: aztUntrustedOpt(prop(raw, "ipAddress")), sku: azString(azField(prop(raw, "sku"), "name"))?.toLowerCase() });
      // Public IP → NIC link (covers NICs missing from a failed / truncated NIC listing).
      const nicId = azureNicIdFromIpConfigId(azString(azField(prop(raw, "ipConfiguration"), "id")));
      if (!nicId) continue;
      const nic = nicById.get(nicId) ?? { id: nicId, subnetIds: [], pipIds: [] };
      if (!nic.pipIds.includes(id)) nic.pipIds.push(id);
      nicById.set(nicId, nic);
    }

    const nsgName = (id: string) => resourceRef(nsgById.get(id)?.raw, NSG_TYPE, env).name;
    const findings: Finding[] = [];
    const nsgsOnPublicNics = new Set<string>();
    const subnetLayerKnown = nics.ok;
    if (!subnetLayerKnown && [...nicById.values()].some((n) => n.pipIds.length > 0)) {
      warnings.push(`${NIC_SERVICE}: subnet NSGs of internet-exposed NICs could not be resolved; only NIC-level NSGs were evaluated (results may over-report).`);
    }

    for (const nic of nicById.values()) {
      if (nic.pipIds.length === 0) continue;
      const nicNsgId = nic.nsgId ?? nicNsgFromNsg.get(nic.id);
      const subnetNsgIds = [...new Set(nic.subnetIds.flatMap((s) => subnetNsg.get(s) ?? []))];
      const layerIds = [...subnetNsgIds, ...(nicNsgId ? [nicNsgId] : [])];
      // An NSG referenced but missing from the (possibly truncated) listing → unknown, skip.
      if (layerIds.some((id) => !nsgById.has(id))) {
        warnings.push(`${NIC_SERVICE}: NSG of NIC ${aztUntrusted(azLastSegment(nic.id) ?? "unknown")} was not in the NSG listing; not evaluated.`);
        continue;
      }
      for (const id of layerIds) nsgsOnPublicNics.add(id);
      const layers: Layer[] = layerIds.map((id) => ({ nsgName: nsgName(id), rules: nsgById.get(id)?.rules }));
      findings.push(...this.nicFindings(env, nic, layers, pipById, subnetLayerKnown));
    }

    // NSGs that open high-risk ports to the internet, are in use, but front no public NIC.
    for (const [id, info] of nsgById) {
      if (nsgsOnPublicNics.has(id) || (info.nicIds.length === 0 && info.subnetIds.length === 0)) continue;
      const open = Object.entries(HIGH_RISK_PORTS).flatMap(([p, label]) => {
        const port = Number(p);
        const rule = azureOpenRule(info.rules, port, "v4") ?? azureOpenRule(info.rules, port, "v6");
        return rule ? [{ port, label, rule }] : [];
      });
      if (open.length === 0) continue;
      const ref = resourceRef(info.raw, NSG_TYPE, env);
      const portList = open.map((o) => `${o.label} (${o.port}) via rule ${o.rule.name}`).join(", ");
      findings.push(
        makeFinding({
          riskScore: AZURE_NET_NSG_OPEN_RISK,
          title: `NSG ${ref.name} allows high-risk ports from the internet (no public IP association found)`,
          resourceType: NSG_TYPE,
          resourceId: ref.name,
          resourceArn: ref.arn,
          region: ref.region,
          description: `Network security group ${ref.name} (${where(ref, env)}; associated with ${info.nicIds.length} NIC(s) and ${info.subnetIds.length} subnet(s)) allows inbound ${portList} from the internet (*, Internet, 0.0.0.0/0 or ::/0). No public IP was found on the associated NICs, but the rule takes effect as soon as one is attached, and traffic through a public load balancer / application gateway is not traced by this scan.`,
          impact: "Any resource behind this NSG that becomes internet-reachable exposes these services to brute-force and exploitation.",
          remediationSteps: [
            `Restrict the source of the listed rules in NSG ${ref.name} to specific IP ranges or service tags.`,
            "Use Azure Bastion or just-in-time VM access (Defender for Cloud) instead of open management ports.",
            "Assign the Azure Policy \"Management ports should be closed on your virtual machines\" to monitor regressions.",
          ],
          accountId: env.tenantId,
          module: this.moduleName,
        }),
      );
    }
    return findings;
  }

  private nicFindings(env: AzureScanEnv, nic: NicInfo, layers: Layer[], pipById: Map<string, PipInfo>, subnetLayerKnown: boolean): Finding[] {
    const pips = nic.pipIds.map((id) => pipById.get(id));
    const addresses = pips.flatMap((p) => p?.address ?? []);
    const ipText = addresses.length > 0 ? addresses.join(", ") : "public IP";
    const nicRef = nic.raw ? resourceRef(nic.raw, NIC_TYPE, env) : idRef(nic.id, NIC_TYPE, env, "global");
    const target = nic.vmId ? idRef(nic.vmId, VM_TYPE, env, nicRef.region) : nicRef;
    const label = nic.vmId ? `VM ${target.name} (NIC ${nicRef.name}, ${ipText})` : `NIC ${nicRef.name} (${ipText})`;
    const resourceType = nic.vmId ? VM_TYPE : NIC_TYPE;
    const base = { resourceType, resourceId: target.name, resourceArn: target.arn, region: target.region, accountId: env.tenantId, module: this.moduleName };
    const findings: Finding[] = [];

    if (layers.length === 0) {
      // No NSG anywhere: Basic SKU (or unknown) public IPs are open on every port; Standard is closed by default.
      const open = subnetLayerKnown && pips.some((p) => !p?.sku || p.sku === "basic");
      if (!open) return findings;
      findings.push(
        makeFinding({
          ...base,
          riskScore: AZURE_NET_ALL_PORTS_RISK,
          title: `${label}: all ports reachable from internet (no NSG)`,
          description: `${label} (${where(target, env)}) has a Basic SKU (or unknown SKU) public IP and no network security group on either the NIC or its subnet, so every inbound port is reachable from the internet.`,
          impact: "All services on this resource are exposed to the internet, creating a large attack surface.",
          remediationSteps: [
            `Associate a network security group with NIC ${nicRef.name} or its subnet that allows only required ports from specific sources.`,
            "Upgrade Basic SKU public IPs to Standard SKU (closed to inbound traffic by default).",
          ],
        }),
      );
      return findings;
    }

    for (const [portStr, portName] of Object.entries(HIGH_RISK_PORTS)) {
      const port = Number(portStr);
      const hits = openEither(layers, port);
      if (!hits) continue;
      findings.push(
        makeFinding({
          ...base,
          riskScore: AZURE_NET_PORT_OPEN_RISK,
          title: `${label}: ${portName} (${port}) reachable from internet`,
          description: `${label} (${where(target, env)}) has public IP ${ipText} and ${describeHits(hits)} allow inbound ${portName} (port ${port}) from the internet (*, Internet, 0.0.0.0/0 or ::/0) with no higher-priority Deny.`,
          impact: `${portName} is directly reachable from the internet, enabling brute-force, exploitation, or unauthorized access.`,
          remediationSteps: [
            `Restrict NSG inbound rules for port ${port} to specific source IP ranges.`,
            "Use Azure Bastion or just-in-time VM access (Defender for Cloud) instead of direct access.",
            "Remove the public IP if the resource does not need to be reachable from the internet.",
            "Enable NSG / VNet flow logs to monitor connection attempts.",
          ],
        }),
      );
    }

    // Every port: each NSG layer's deciding Allow must be an all-ports rule on every sampled port.
    const sampled = ALL_PORTS_SAMPLE.map((p) => openEither(layers, p));
    if (sampled.every((hits) => hits !== undefined && hits.every((h) => h.rule.spans.some(isAllPortSpan)))) {
      findings.push(
        makeFinding({
          ...base,
          riskScore: AZURE_NET_ALL_PORTS_RISK,
          title: `${label}: all ports reachable from internet`,
          description: `${label} (${where(target, env)}) has public IP ${ipText} and ${describeHits(sampled[0] ?? [])} allow all ports from the internet (*, Internet, 0.0.0.0/0 or ::/0).`,
          impact: "All services on this resource are exposed to the internet, creating a large attack surface.",
          remediationSteps: [
            "Replace the all-ports NSG rule with specific port rules restricted to known sources.",
            "Audit all services running on the resource.",
          ],
        }),
      );
    }
    return findings;
  }
}

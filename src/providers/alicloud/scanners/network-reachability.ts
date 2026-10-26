/**
 * Alibaba Cloud network reachability scanner (moduleName `network_reachability`, plan §4.1 P2 / T5).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/network-reachability.ts`:
 *  - ECS `DescribeInstances` (PageNumber / PageSize, cap `ECS_MAX_INSTANCES`) → internet-exposed
 *    instances = `PublicIpAddress.IpAddress[]` or `EipAddress.IpAddress` present.
 *  - per distinct security group of those instances (concurrency {@link NET_SG_CONCURRENCY},
 *    cap {@link NET_MAX_SECURITY_GROUPS}) `DescribeSecurityGroupAttribute Direction=ingress`
 *    (NextToken / MaxResults) → ingress rules.
 *  - an `Accept` ingress rule whose source is `0.0.0.0/0` (`SourceCidrIp`) or `::/0`
 *    (`Ipv6SourceCidrIp`) and whose `IpProtocol` + `PortRange` cover a high-risk port
 *    ({@link HIGH_RISK_PORTS}, the AWS list) → 9.5 per port; covering every port
 *    (`IpProtocol=ALL`, `-1/-1`, `1/65535`) → additional 8.0 finding (AWS riskScores).
 *
 * Rule priority (simplified on purpose — Phase 2 does NOT do precise cross-rule evaluation):
 * the rules of all the instance's groups are pooled; an open `Accept` rule is suppressed only
 * when a `Drop` rule with the SAME OR HIGHER priority (`Priority` 1 = highest; same priority →
 * Drop wins) also matches the whole internet (`0.0.0.0/0` / `::/0`, same address family) and
 * covers the port. Partial-CIDR Drops, source security groups / prefix lists, enterprise
 * security group semantics and VPC network ACLs are not evaluated (AWS's NACL step has no
 * equivalent here), so results can over-report but never hide a world-open Accept that is
 * only partially blocked. IPv6 rules are evaluated even when the instance has no public IPv6
 * address (as the AWS scanner does).
 *
 * Errors: access denied / throttled / network on a lookup → warning and skip; **auth_failed
 * or api_misuse anywhere → module `status: "error"`**. Every cloud-sourced string in a
 * Finding / warning passes through redactAliDiagnostic.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { toAliUrn } from "../urn.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliSafeFinding,
  aliSafeWarnings,
  aliScanEnv,
  aliSoftWarning,
  aliString,
  aliUntrusted,
  isAliFatal,
  listAliEcsInstances,
  toAliError,
  type AliScanEnv,
} from "./shared.js";

/** Same list as the AWS network-reachability scanner. */
export const HIGH_RISK_PORTS: Readonly<Record<number, string>> = {
  22: "SSH",
  3389: "RDP",
  3306: "MySQL",
  5432: "PostgreSQL",
  1433: "MSSQL",
  27017: "MongoDB",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
};

export const NET_MAX_SECURITY_GROUPS = 500;
export const NET_SG_CONCURRENCY = 5;
/** DescribeSecurityGroupAttribute MaxResults (maximum 1000) and page cap. */
export const NET_SG_RULES_PAGE_SIZE = 1000;
export const NET_SG_RULES_MAX_PAGES = 10;

/** riskScores aligned with the AWS scanner. */
export const NET_PORT_OPEN_RISK = 9.5;
export const NET_ALL_PORTS_RISK = 8.0;

/** Ali SG priority range: 1 (highest) … 100 (lowest, default 1). */
const DEFAULT_PRIORITY = 1;

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

/* ------------------------------------------------------------------------ */
/* Rule parsing                                                             */
/* ------------------------------------------------------------------------ */

export interface PortSpan {
  from: number;
  to: number;
}

const ALL_PORTS: PortSpan = Object.freeze({ from: 1, to: 65535 });

/**
 * TCP / UDP port span of a rule. `IpProtocol=ALL` → every port (PortRange is `-1/-1`);
 * TCP / UDP `a/b` → [a, b], `-1/-1` → every port, a single `n` → [n, n]. ICMP / GRE /
 * ICMPv6 and unparsable ranges → undefined (no TCP / UDP port is reachable).
 */
export function parseAliPortRange(ipProtocol: unknown, portRange: unknown): PortSpan | undefined {
  const proto = (aliString(ipProtocol) ?? "").toLowerCase();
  if (proto === "all" || proto === "-1") return ALL_PORTS;
  if (proto !== "tcp" && proto !== "udp") return undefined;
  const raw = aliString(portRange);
  if (!raw) return undefined;
  const m = /^(-?\d+)\s*(?:\/\s*(-?\d+))?$/.exec(raw);
  if (!m) return undefined;
  const from = Number(m[1]);
  const to = m[2] !== undefined ? Number(m[2]) : from;
  if (from === -1 && to === -1) return ALL_PORTS;
  if (from < 0 || to < 0 || from > 65535 || to > 65535 || from > to) return undefined;
  return { from, to };
}

/** True when the span covers every port (`ALL`, `-1/-1`, `1/65535`, `0/65535`). */
export function isAllPortSpan(span: PortSpan | undefined): boolean {
  return !!span && span.from <= 1 && span.to >= 65535;
}

export interface AliSgRule {
  /** Already redacted. */
  groupId: string;
  policy: "accept" | "drop";
  priority: number;
  span: PortSpan;
  ipv4World: boolean;
  ipv6World: boolean;
}

/**
 * Ingress rule from `Permissions.Permission[]` → normalised rule, or undefined when it is not
 * an ingress TCP / UDP / ALL rule. `Policy` defaults to Accept, `Priority` to 1.
 */
export function parseAliSgRule(groupId: string, perm: unknown): AliSgRule | undefined {
  const direction = (aliString(aliField(perm, "Direction")) ?? "ingress").toLowerCase();
  if (direction !== "ingress") return undefined;
  const span = parseAliPortRange(aliField(perm, "IpProtocol"), aliField(perm, "PortRange"));
  if (!span) return undefined;
  const policy = (aliString(aliField(perm, "Policy")) ?? "accept").toLowerCase() === "drop" ? "drop" : "accept";
  const priority = aliNumber(aliField(perm, "Priority")) ?? DEFAULT_PRIORITY;
  return {
    groupId,
    policy,
    priority,
    span,
    ipv4World: aliString(aliField(perm, "SourceCidrIp")) === "0.0.0.0/0",
    ipv6World: aliString(aliField(perm, "Ipv6SourceCidrIp")) === "::/0",
  };
}

const covers = (span: PortSpan, port: number) => port >= span.from && port <= span.to;

/** Is `accept` (world-open, covering `port`) blocked by a world Drop of same / higher priority? */
function blockedByDrop(accept: AliSgRule, rules: readonly AliSgRule[], port: number, family: "v4" | "v6"): boolean {
  return rules.some(
    (d) =>
      d.policy === "drop" &&
      d.priority <= accept.priority &&
      (family === "v4" ? d.ipv4World : d.ipv6World) &&
      covers(d.span, port),
  );
}

/**
 * World-open Accept rules effective for `port` after the simplified Drop check
 * (see module comment). Returns the matching Accept rules (may be empty).
 */
export function worldOpenRulesForPort(rules: readonly AliSgRule[], port: number): AliSgRule[] {
  return rules.filter((a) => {
    if (a.policy !== "accept" || !covers(a.span, port)) return false;
    const v4 = a.ipv4World && !blockedByDrop(a, rules, port, "v4");
    const v6 = a.ipv6World && !blockedByDrop(a, rules, port, "v6");
    return v4 || v6;
  });
}

/** World-open Accept rules covering every port, not blocked on the sampled ports by a world Drop. */
export function worldOpenAllPortRules(rules: readonly AliSgRule[]): AliSgRule[] {
  // Proxy check with port 80 (as AWS's NACL proxy) plus every high-risk port: a world Drop on
  // any of them means the "all ports" exposure is at least partly mitigated → not reported.
  const sample = [80, ...Object.keys(HIGH_RISK_PORTS).map(Number)];
  return rules.filter((a) => {
    if (a.policy !== "accept" || !isAllPortSpan(a.span) || !(a.ipv4World || a.ipv6World)) return false;
    return sample.every((p) => worldOpenRulesForPort([a, ...rules.filter((r) => r.policy === "drop")], p).length > 0);
  });
}

/* ------------------------------------------------------------------------ */
/* Instances / security groups                                              */
/* ------------------------------------------------------------------------ */

export interface AliPublicInstance {
  /** Already redacted. */
  id: string;
  name?: string;
  publicIp: string;
  /** Raw (unredacted) group ids for API calls. */
  securityGroupIds: string[];
}

/** Public IPv4 of an instance: `PublicIpAddress.IpAddress[0]`, else `EipAddress.IpAddress`. */
export function aliInstancePublicIp(inst: unknown): string | undefined {
  const pub = aliArray(aliField(aliField(inst, "PublicIpAddress"), "IpAddress"))
    .map((v) => aliString(v))
    .find(Boolean);
  return pub ?? aliString(aliField(aliField(inst, "EipAddress"), "IpAddress"));
}

function toPublicInstance(inst: Record<string, unknown>): AliPublicInstance | undefined {
  const id = aliUntrusted(inst.InstanceId);
  const ip = aliInstancePublicIp(inst);
  if (!id || !ip) return undefined;
  const sgIds = aliArray(aliField(inst.SecurityGroupIds, "SecurityGroupId")).flatMap((v) => {
    const s = aliString(v);
    return s ? [s] : [];
  });
  return { id, name: aliUntrusted(inst.InstanceName), publicIp: aliUntrusted(ip) ?? "unknown", securityGroupIds: sgIds };
}

async function fetchSgRules(env: AliScanEnv, region: string, sgId: string): Promise<{ rules: AliSgRule[]; warnings: string[] }> {
  const shownId = aliUntrusted(sgId) ?? "unknown";
  const page = await aliPaginate<unknown, unknown>({
    style: "token",
    label: `ECS DescribeSecurityGroupAttribute (${shownId})`,
    pageSize: NET_SG_RULES_PAGE_SIZE,
    maxPages: NET_SG_RULES_MAX_PAGES,
    fetch: (q) =>
      aliCall(ALI_API.ecs.DescribeSecurityGroupAttribute, aliCallCtx(env, region), {
        RegionId: region,
        SecurityGroupId: sgId,
        Direction: "ingress",
        ...q,
      }),
    items: (body) => aliArray(aliField(aliField(body, "Permissions"), "Permission")),
  });
  const rules = page.items.flatMap((p) => {
    const r = parseAliSgRule(shownId, p);
    return r ? [r] : [];
  });
  return { rules, warnings: page.warnings.map((w) => aliUntrusted(w) ?? w) };
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliNetworkReachabilityScanner implements Scanner {
  readonly moduleName = "network_reachability";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);
      const region = ctx.region;

      let publicInstances: AliPublicInstance[];
      try {
        const list = await listAliEcsInstances(env, region);
        warnings.push(...list.warnings);
        publicInstances = list.instances.flatMap((i) => {
          const p = toPublicInstance(i);
          return p ? [p] : [];
        });
      } catch (err) {
        if (isAliFatal(err)) return aliErrorResult(this.moduleName, startMs, "ECS instance listing failed", err, warnings);
        warnings.push(aliSoftWarning("ECS DescribeInstances", err));
        return {
          module: this.moduleName,
          status: "success",
          warnings: aliSafeWarnings(warnings),
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings,
        };
      }

      let sgIds = [...new Set(publicInstances.flatMap((i) => i.securityGroupIds))];
      if (sgIds.length > NET_MAX_SECURITY_GROUPS) {
        warnings.push(
          `ECS security groups: ${sgIds.length} groups attached to internet-exposed instances in ${region}; only the first ${NET_MAX_SECURITY_GROUPS} were evaluated.`,
        );
        sgIds = sgIds.slice(0, NET_MAX_SECURITY_GROUPS);
      }

      const settled = await runWithConcurrency(
        sgIds.map((id) => () => fetchSgRules(env, region, id)),
        NET_SG_CONCURRENCY,
      );
      const sgRules = new Map<string, AliSgRule[]>();
      for (let i = 0; i < settled.length; i++) {
        const s = settled[i];
        const shownId = aliUntrusted(sgIds[i]) ?? "unknown";
        if (s.status === "rejected") {
          if (isAliFatal(s.reason)) {
            return aliErrorResult(this.moduleName, startMs, "Security group rule lookup failed", toAliError(s.reason, "ecs:DescribeSecurityGroupAttribute"), warnings);
          }
          warnings.push(aliSoftWarning(`ECS DescribeSecurityGroupAttribute (${shownId})`, s.reason));
          continue;
        }
        warnings.push(...s.value.warnings);
        sgRules.set(sgIds[i], s.value.rules);
      }

      for (const inst of publicInstances) {
        const known = inst.securityGroupIds.filter((id) => sgRules.has(id));
        if (inst.securityGroupIds.length > 0 && known.length < inst.securityGroupIds.length) {
          warnings.push(`ECS ${inst.id}: rules of ${inst.securityGroupIds.length - known.length} security group(s) could not be evaluated; results may be incomplete.`);
        }
        // Rules of all groups of the instance are pooled and evaluated by priority (module comment).
        const rules = known.flatMap((id) => sgRules.get(id) ?? []);
        const urn = toAliUrn("ecs", "instance", inst.id, region, env.accountId);
        const label = `ECS ${inst.id} (${inst.publicIp})`;

        for (const [portStr, portName] of Object.entries(HIGH_RISK_PORTS)) {
          const port = Number(portStr);
          const open = worldOpenRulesForPort(rules, port);
          if (open.length === 0) continue;
          const groups = [...new Set(open.map((r) => r.groupId))].join(", ");
          findings.push(
            makeFinding({
              riskScore: NET_PORT_OPEN_RISK,
              title: `${label}: ${portName} (${port}) reachable from internet`,
              resourceType: "ACS::ECS::Instance",
              resourceId: inst.id,
              resourceArn: urn,
              region,
              description: `ECS instance "${inst.id}"${inst.name ? ` (${inst.name})` : ""} has public IP ${inst.publicIp} and security group(s) ${groups} accept inbound ${portName} (port ${port}) from the internet (0.0.0.0/0 or ::/0) with no higher-or-equal priority Drop rule.`,
              impact: `${portName} is directly reachable from the internet, enabling brute-force, exploitation, or unauthorized access.`,
              remediationSteps: [
                `Restrict security group inbound rules for port ${port} to specific IPs.`,
                "Use Cloud Assistant / Session Manager or a bastion host instead of direct access.",
                "Add Drop rules or VPC network ACL entries for high-risk ports as an additional layer.",
                "Enable VPC flow logs to monitor connection attempts.",
              ],
            }),
          );
        }

        const allOpen = worldOpenAllPortRules(rules);
        if (allOpen.length > 0) {
          const groups = [...new Set(allOpen.map((r) => r.groupId))].join(", ");
          findings.push(
            makeFinding({
              riskScore: NET_ALL_PORTS_RISK,
              title: `${label}: all ports reachable from internet`,
              resourceType: "ACS::ECS::Instance",
              resourceId: inst.id,
              resourceArn: urn,
              region,
              description: `ECS instance "${inst.id}" has public IP ${inst.publicIp} and security group(s) ${groups} accept all ports from the internet (0.0.0.0/0 or ::/0).`,
              impact: "All services on this instance are exposed to the internet, creating a large attack surface.",
              remediationSteps: [
                "Replace the all-ports security group rule with specific port rules.",
                "Implement VPC network ACL rules to restrict inbound traffic as defense in depth.",
                "Audit all services running on the instance.",
              ],
            }),
          );
        }
      }

      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings: aliSafeWarnings(warnings) } : {}),
        resourcesScanned: publicInstances.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "Network reachability check failed", err, warnings);
    }
  }
}

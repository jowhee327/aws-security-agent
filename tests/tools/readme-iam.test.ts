/**
 * T6 — README IAM policy blocks (plan §2.11): every ```json block that is an IAM
 * policy must parse, stay read-only, and grant the actions the CVE exploitability
 * feature needs (Inspector2 direct pull + L4 reachability).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

const ROOT = join(__dirname, "..", "..");

const EXPLOITABILITY_ACTIONS = [
  "inspector2:BatchGetAccountStatus",
  "inspector2:ListFindings",
  "ec2:DescribeInstances",
  "ec2:DescribeSecurityGroups",
  "ec2:DescribeNetworkAcls",
  "ec2:DescribeNetworkInterfaces",
  "ecs:ListClusters",
  "ecs:ListTasks",
  "ecs:DescribeTasks",
  "ecs:DescribeContainerInstances",
  "eks:ListClusters",
  "lambda:GetFunctionUrlConfig",
];

interface PolicyDoc {
  Version: string;
  Statement: Array<{ Effect: string; Action: string | string[]; Resource: string | string[] }>;
}

function policyBlocks(file: string): PolicyDoc[] {
  const md = readFileSync(join(ROOT, file), "utf8");
  const blocks = [...md.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1]);
  return blocks
    .filter((b) => b.includes('"Statement"'))
    .map((b) => JSON.parse(b) as PolicyDoc);
}

function actionsOf(doc: PolicyDoc): string[] {
  return doc.Statement.flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
}

describe.each(["README.md", "README.zh-CN.md"])("%s IAM policy", (file) => {
  const docs = policyBlocks(file);

  it("has at least one IAM policy JSON block that parses", () => {
    expect(docs.length).toBeGreaterThan(0);
    for (const d of docs) {
      expect(d.Version).toBe("2012-10-17");
      for (const s of d.Statement) expect(s.Effect).toBe("Allow");
    }
  });

  it("grants every action the exploitability feature uses", () => {
    const actions = new Set(docs.flatMap(actionsOf));
    for (const a of EXPLOITABILITY_ACTIONS) expect(actions.has(a), `${file} grants ${a}`).toBe(true);
  });

  it("only grants read-only actions", () => {
    for (const a of docs.flatMap(actionsOf)) {
      expect(a).toMatch(/^[a-z0-9-]+:(List|Describe|Get|BatchGet)[A-Za-z0-9]*$/);
    }
  });

  it("documents the positioning disclaimer and the new tool", () => {
    const md = readFileSync(join(ROOT, file), "utf8");
    expect(md).toContain("prioritize_vulnerabilities");
    expect(md).toContain("scripts/update-kev.ts");
    expect(md).toMatch(file === "README.md" ? /not penetration testing/i : /不是渗透测试/);
  });
});

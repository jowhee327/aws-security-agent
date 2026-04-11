import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

const templatesDir = join(__dirname, "..", "..", "templates");

describe("StackSet audit role templates", () => {
  describe("YAML template", () => {
    it("exists and contains required elements", () => {
      const content = readFileSync(join(templatesDir, "stackset-audit-role.yaml"), "utf-8");

      expect(content).toContain("AWSTemplateFormatVersion");
      expect(content).toContain("AdminAccountId");
      expect(content).toContain("RoleName");
      expect(content).toContain("AWSSecurityMCPAudit");
      expect(content).toContain("SecurityAudit");
      expect(content).toContain("sts:AssumeRole");
      expect(content).toContain("aws-security-mcp-audit");
      expect(content).toContain("AWS::IAM::Role");
    });

    it("has external ID condition for security", () => {
      const content = readFileSync(join(templatesDir, "stackset-audit-role.yaml"), "utf-8");
      expect(content).toContain("sts:ExternalId");
      expect(content).toContain("aws-security-mcp-audit");
    });
  });

  describe("JSON template", () => {
    it("is valid JSON with required elements", () => {
      const content = readFileSync(join(templatesDir, "stackset-audit-role.json"), "utf-8");
      const template = JSON.parse(content);

      expect(template.AWSTemplateFormatVersion).toBe("2010-09-09");
      expect(template.Parameters.AdminAccountId).toBeDefined();
      expect(template.Parameters.RoleName).toBeDefined();
      expect(template.Parameters.RoleName.Default).toBe("AWSSecurityMCPAudit");
      expect(template.Resources.SecurityAuditRole).toBeDefined();
      expect(template.Resources.SecurityAuditRole.Type).toBe("AWS::IAM::Role");
      expect(template.Outputs.RoleArn).toBeDefined();
    });

    it("has matching structure with YAML template", () => {
      const jsonContent = readFileSync(join(templatesDir, "stackset-audit-role.json"), "utf-8");
      const template = JSON.parse(jsonContent);

      // Verify trust policy
      const statements = template.Resources.SecurityAuditRole.Properties.AssumeRolePolicyDocument.Statement;
      expect(statements).toHaveLength(1);
      expect(statements[0].Action).toBe("sts:AssumeRole");
      expect(statements[0].Condition.StringEquals["sts:ExternalId"]).toBe("aws-security-mcp-audit");
    });
  });
});

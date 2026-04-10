#!/usr/bin/env node

import { startServer } from "../src/index.js";

const args = process.argv.slice(2);
const subcommand = args[0];

const VERSION = "0.1.0";

const HELP = `Usage: aws-security-mcp [command] [options]

Commands:
  (default)            Start MCP server (stdio, for Kiro/Claude Code)
  dashboard            Start local HTTP server serving the security dashboard
  deploy-dashboard     Deploy dashboard to an S3 bucket as a static website

Options:
  --region <region>    AWS region (default: AWS_REGION env or us-east-1)
  --version            Print version and exit
  --help, -h           Show this help message

Dashboard options:
  --port <port>        Port for local dashboard server (default: 3000)

Deploy options:
  --bucket <name>      S3 bucket name (required)
  --region <region>    AWS region for the S3 bucket

Environment variables:
  AWS_REGION           Default AWS region
  AWS_DEFAULT_REGION   Fallback default region

The MCP server communicates over stdio using the MCP protocol.`;

if (args.includes("--help") || args.includes("-h")) {
  console.log(HELP);
  process.exit(0);
}

if (args.includes("--version")) {
  console.log(`aws-security-mcp ${VERSION}`);
  process.exit(0);
}

function getArg(name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return undefined;
}

function getRegion(): string {
  return (
    getArg("--region") ??
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION ??
    "us-east-1"
  );
}

if (subcommand === "dashboard") {
  const port = Number(getArg("--port")) || 3000;
  import("../src/commands/dashboard.js").then(({ startDashboard }) => {
    startDashboard(port);
  });
} else if (subcommand === "deploy-dashboard") {
  const bucket = getArg("--bucket");
  if (!bucket) {
    console.error("Error: --bucket <name> is required for deploy-dashboard");
    process.exit(1);
  }
  const region = getRegion();
  import("../src/commands/deploy-dashboard.js").then(({ deployDashboard }) => {
    deployDashboard(bucket, region).catch((err) => {
      console.error("Deploy failed:", err.message || err);
      process.exit(1);
    });
  });
} else if (subcommand && !subcommand.startsWith("--")) {
  console.error(`Unknown command: ${subcommand}`);
  console.error('Run "aws-security-mcp --help" for usage.');
  process.exit(1);
} else {
  // Default: start MCP server
  const region = getRegion();
  startServer(region).catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}

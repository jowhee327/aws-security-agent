import { readdirSync, readFileSync, existsSync, copyFileSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  S3Client,
  PutObjectCommand,
} from "@aws-sdk/client-s3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function collectFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full));
    } else {
      files.push(full);
    }
  }
  return files;
}

export async function deployDashboard(
  bucket: string,
  region: string,
): Promise<void> {
  const dashboardDir = join(__dirname, "../../dashboard/dist");

  if (!existsSync(dashboardDir)) {
    console.error(
      `Dashboard not built. Run "npm run build:dashboard" first.\n` +
        `Expected: ${dashboardDir}`,
    );
    process.exit(1);
  }

  // Copy real data.json if available
  const dataSource = join(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".aws-security/dashboard/data.json",
  );
  const dataDest = join(dashboardDir, "data.json");
  if (existsSync(dataSource)) {
    copyFileSync(dataSource, dataDest);
    console.log(`Loaded scan data from ${dataSource}`);
  } else {
    console.log(
      "No scan data at ~/.aws-security/dashboard/data.json — deploying with bundled sample data",
    );
  }

  const s3 = new S3Client({ region });

  // Upload all files (private — no public policy, no website hosting)
  const files = collectFiles(dashboardDir);
  console.log(`Uploading ${files.length} files to s3://${bucket}/ ...`);

  for (const filePath of files) {
    const key = relative(dashboardDir, filePath);
    const ext = extname(filePath);
    const contentType = CONTENT_TYPES[ext] || "application/octet-stream";
    const body = readFileSync(filePath);

    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
      }),
    );
    console.log(`  ${key}`);
  }

  console.log(`\n✅ Dashboard uploaded to s3://${bucket}/`);
  console.log(`\nS3 bucket remains private (Block Public Access enabled).`);
  console.log(`Access control is managed via IAM permissions.`);
  console.log(`\nTo view the dashboard locally:`);
  console.log(`  aws-security-mcp dashboard --port 3000`);
}

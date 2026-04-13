import { readdirSync, readFileSync, existsSync, copyFileSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  S3Client,
  PutObjectCommand,
  PutBucketWebsiteCommand,
  PutBucketPolicyCommand,
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
  opts: { public?: boolean } = {},
): Promise<void> {
  if (!opts.public) {
    console.error("Error: S3 deployment makes scan data publicly accessible.");
    console.error("Pass --public to confirm, or use CloudFront + OAI for private access.");
    process.exit(1);
  }

  console.warn("⚠️  WARNING: This will make scan results publicly accessible on the internet.");
  console.warn("   The dashboard will contain sensitive information including AWS account IDs,");
  console.warn("   resource ARNs, and security findings.");
  console.warn("   Consider using CloudFront + OAI for private access instead.\n");
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

  // Configure static website hosting
  console.log(`Configuring s3://${bucket} for static website hosting...`);
  await s3.send(
    new PutBucketWebsiteCommand({
      Bucket: bucket,
      WebsiteConfiguration: {
        IndexDocument: { Suffix: "index.html" },
        ErrorDocument: { Key: "index.html" }, // SPA fallback
      },
    }),
  );

  // Set bucket policy for public read access
  const partition = region.startsWith("cn-") ? "aws-cn" : "aws";
  console.log(`Setting public read bucket policy on s3://${bucket}...`);
  await s3.send(
    new PutBucketPolicyCommand({
      Bucket: bucket,
      Policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "PublicReadGetObject",
            Effect: "Allow",
            Principal: "*",
            Action: "s3:GetObject",
            Resource: `arn:${partition}:s3:::${bucket}/*`,
          },
        ],
      }),
    }),
  );

  // Upload all files
  const files = collectFiles(dashboardDir);
  console.log(`Uploading ${files.length} files to s3://${bucket}...`);

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

  const domain = region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com";
  const websiteUrl = `http://${bucket}.s3-website.${region}.${domain}`;
  console.log(`\nDashboard deployed successfully!`);
  console.log(`Website URL: ${websiteUrl}`);
  console.log(
    "\nNote: Ensure S3 Block Public Access is disabled on this bucket for the website to be accessible.\n",
  );
}

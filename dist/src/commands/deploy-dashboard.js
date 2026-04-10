// src/commands/deploy-dashboard.ts
import { readdirSync, readFileSync, existsSync, copyFileSync } from "fs";
import { join, extname, relative } from "path";
import { fileURLToPath } from "url";
import {
  S3Client,
  PutObjectCommand,
  PutBucketWebsiteCommand,
  PutBucketPolicyCommand
} from "@aws-sdk/client-s3";
var __filename = fileURLToPath(import.meta.url);
var __dirname = join(__filename, "..");
var CONTENT_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2"
};
function collectFiles(dir) {
  const files = [];
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
async function deployDashboard(bucket, region) {
  const dashboardDir = join(__dirname, "../../dashboard/dist");
  if (!existsSync(dashboardDir)) {
    console.error(
      `Dashboard not built. Run "npm run build:dashboard" first.
Expected: ${dashboardDir}`
    );
    process.exit(1);
  }
  const dataSource = join(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".aws-security/dashboard/data.json"
  );
  const dataDest = join(dashboardDir, "data.json");
  if (existsSync(dataSource)) {
    copyFileSync(dataSource, dataDest);
    console.log(`Loaded scan data from ${dataSource}`);
  } else {
    console.log(
      "No scan data at ~/.aws-security/dashboard/data.json \u2014 deploying with bundled sample data"
    );
  }
  const s3 = new S3Client({ region });
  console.log(`Configuring s3://${bucket} for static website hosting...`);
  await s3.send(
    new PutBucketWebsiteCommand({
      Bucket: bucket,
      WebsiteConfiguration: {
        IndexDocument: { Suffix: "index.html" },
        ErrorDocument: { Key: "index.html" }
        // SPA fallback
      }
    })
  );
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
            Resource: `arn:${partition}:s3:::${bucket}/*`
          }
        ]
      })
    })
  );
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
        ContentType: contentType
      })
    );
    console.log(`  ${key}`);
  }
  const websiteUrl = `http://${bucket}.s3-website-${region}.amazonaws.com`;
  console.log(`
Dashboard deployed successfully!`);
  console.log(`Website URL: ${websiteUrl}`);
  console.log(
    "\nNote: Ensure S3 Block Public Access is disabled on this bucket for the website to be accessible.\n"
  );
}
export {
  deployDashboard
};
//# sourceMappingURL=deploy-dashboard.js.map
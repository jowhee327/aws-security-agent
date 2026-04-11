import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname, resolve } from "node:path";
import { existsSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { exec } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = join(__filename, "..");

const MIME_TYPES: Record<string, string> = {
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

export function startDashboard(port = 3000): void {
  // dashboard/dist is two levels up from dist/src/commands/
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
      "No scan data found at ~/.aws-security/dashboard/data.json — using bundled sample data",
    );
  }

  const resolvedBase = resolve(dashboardDir);

  const server = createServer(async (req, res) => {
    const url = req.url?.split("?")[0] ?? "/";
    let filePath = resolve(
      join(dashboardDir, url === "/" ? "index.html" : url),
    );

    // Ensure the resolved path is within dashboardDir
    if (!filePath.startsWith(resolvedBase + "/") && filePath !== resolvedBase) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }

    // SPA fallback: if file doesn't exist and isn't a static asset, serve index.html
    if (!existsSync(filePath)) {
      filePath = join(dashboardDir, "index.html");
    }

    try {
      const content = await readFile(filePath);
      const ext = extname(filePath);
      res.writeHead(200, {
        "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
      });
      res.end(content);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
  });

  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(`\nAWS Security Dashboard: ${url}\n`);
    console.log("Press Ctrl+C to stop.\n");

    // Try to open browser
    const cmd =
      process.platform === "darwin"
        ? "open"
        : process.platform === "win32"
          ? "start"
          : "xdg-open";
    exec(`${cmd} ${url}`, () => {
      // ignore errors — browser open is best-effort
    });
  });

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${port} is already in use. Try --port <other>`);
      process.exit(1);
    }
    throw err;
  });
}

// src/commands/dashboard.ts
import { createServer } from "http";
import { readFile } from "fs/promises";
import { join, extname, resolve } from "path";
import { existsSync, copyFileSync } from "fs";
import { fileURLToPath } from "url";
import { exec } from "child_process";
var __filename = fileURLToPath(import.meta.url);
var __dirname = join(__filename, "..");
var MIME_TYPES = {
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
function startDashboard(port = 3e3) {
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
      "No scan data found at ~/.aws-security/dashboard/data.json \u2014 using bundled sample data"
    );
  }
  const resolvedBase = resolve(dashboardDir);
  const server = createServer(async (req, res) => {
    const url = req.url?.split("?")[0] ?? "/";
    let filePath = resolve(
      join(dashboardDir, url === "/" ? "index.html" : url)
    );
    if (!filePath.startsWith(resolvedBase + "/") && filePath !== resolvedBase) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }
    if (!existsSync(filePath)) {
      filePath = join(dashboardDir, "index.html");
    }
    try {
      const content = await readFile(filePath);
      const ext = extname(filePath);
      res.writeHead(200, {
        "Content-Type": MIME_TYPES[ext] || "application/octet-stream"
      });
      res.end(content);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
  });
  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(`
AWS Security Dashboard: ${url}
`);
    console.log("Press Ctrl+C to stop.\n");
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
    exec(`${cmd} ${url}`, () => {
    });
  });
  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${port} is already in use. Try --port <other>`);
      process.exit(1);
    }
    throw err;
  });
}
export {
  startDashboard
};
//# sourceMappingURL=dashboard.js.map
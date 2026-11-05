/**
 * Refresh the offline CISA KEV snapshot (src/data/kev.json).
 *
 *   npx tsx scripts/update-kev.ts                 # download the official feed
 *   npx tsx scripts/update-kev.ts --from feed.json  # use a local copy
 *   npx tsx scripts/update-kev.ts --out other.json  # write elsewhere
 *
 * This is the only code path that downloads the feed to disk, and it only
 * runs when invoked by hand. All diagnostics go to stderr.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  KEV_FEED_URL,
  serializeKevSnapshot,
  slimKevFeed,
  validateKevFeed,
} from "../src/exploitability/kev-feed.js";

export { KEV_FEED_URL, serializeKevSnapshot, slimKevFeed, validateKevFeed };

export const DEFAULT_OUT = fileURLToPath(new URL("../src/data/kev.json", import.meta.url));

export interface UpdateKevArgs {
  from?: string;
  out: string;
}

export function parseArgs(argv: string[]): UpdateKevArgs {
  const args: UpdateKevArgs = { out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--from" || a === "--out") {
      const v = argv[++i];
      if (!v) throw new Error(`${a} requires a path`);
      if (a === "--from") args.from = resolve(v);
      else args.out = resolve(v);
    } else {
      throw new Error(`Unknown argument: ${a}`);
    }
  }
  return args;
}

async function loadFeed(args: UpdateKevArgs): Promise<{ raw: unknown; source: string }> {
  if (args.from) {
    return { raw: JSON.parse(readFileSync(args.from, "utf8")), source: KEV_FEED_URL };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60_000);
  try {
    const res = await fetch(KEV_FEED_URL, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${KEV_FEED_URL}`);
    return { raw: await res.json(), source: KEV_FEED_URL };
  } finally {
    clearTimeout(timer);
  }
}

function previousCount(path: string): number | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const prev = JSON.parse(readFileSync(path, "utf8")) as { count?: unknown };
    return typeof prev.count === "number" ? prev.count : undefined;
  } catch {
    return undefined;
  }
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const { raw, source } = await loadFeed(args);
  const errors = validateKevFeed(raw);
  if (errors.length > 0) {
    process.stderr.write(`KEV feed failed validation:\n  ${errors.slice(0, 20).join("\n  ")}\n`);
    return 1;
  }
  const snap = slimKevFeed(raw, source);
  const before = previousCount(args.out);
  writeFileSync(args.out, serializeKevSnapshot(snap));
  process.stderr.write(
    `KEV snapshot written to ${args.out}: catalogVersion ${snap.catalogVersion}, ` +
      `snapshotDate ${snap.snapshotDate}, ${before ?? "(none)"} -> ${snap.count} entries\n`,
  );
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err: unknown) => {
      process.stderr.write(`update-kev failed: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    },
  );
}

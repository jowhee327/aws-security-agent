import { createGunzip } from "node:zlib";
import { pipeline } from "node:stream/promises";
import { extract } from "tar-stream";
import type { BinaryRecord, ImageInventory } from "./types.js";
import {
  candidateSignatures,
  extractBinaryVersions,
  SignatureStreamScanner,
  type BinarySignature,
} from "./binary-signatures.js";
import { parseApkInstalled, parseDpkgStatus, parseOsRelease } from "./parsers.js";

/**
 * Package-manager metadata files are buffered (they must be parsed as a whole)
 * but are small in practice; keep a hard stop against hostile layers.
 */
const DEFAULT_MAX_ENTRY_BYTES = 64 * 1024 * 1024;
/**
 * Candidate binaries are never buffered — they are scanned in a bounded
 * sliding window — but bytes fed through the scanner are still capped so a
 * gzip bomb named `nginx` cannot pin the decompressor indefinitely.
 */
const DEFAULT_MAX_BINARY_SCAN_BYTES = 64 * 1024 * 1024;

export interface LayerScanLimits {
  /** Cap on buffered metadata entries (apk db, dpkg status, os-release). */
  maxEntryBytes?: number;
  /** Cap on bytes stream-scanned per candidate binary. */
  maxBinaryScanBytes?: number;
}

const APK_DB_PATH = "lib/apk/db/installed";
const DPKG_STATUS_PATH = "var/lib/dpkg/status";
const OS_RELEASE_PATHS = ["etc/os-release", "usr/lib/os-release"];
const ALPINE_RELEASE_PATH = "etc/alpine-release";
const RPM_DB_PREFIX = "var/lib/rpm/";

function normalizePath(name: string): string {
  return name.replace(/^\.\//, "").replace(/^\//, "");
}

/**
 * Resolve a tar symlink's target to a normalized image path. Handles relative
 * (`../lib/foo`) and absolute (`/usr/lib/foo`) link targets; returns undefined
 * if the target escapes the image root. `linkname` is the tar `linkname` field.
 */
export function resolveLinkTarget(linkPath: string, linkname: string): string | undefined {
  if (!linkname) return undefined;
  const base: string[] = linkname.startsWith("/")
    ? []
    : normalizePath(linkPath).split("/").slice(0, -1); // directory of the link
  for (const seg of linkname.replace(/^\//, "").split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (base.length === 0) return undefined; // escapes root
      base.pop();
    } else {
      base.push(seg);
    }
  }
  return base.length > 0 ? base.join("/") : undefined;
}

/**
 * Resolve a tar hardlink's target. Unlike a symlink's content, a hardlink
 * `linkname` is a pathname relative to the archive root (it names another
 * archive member), so it is resolved from the root regardless of where the
 * link entry itself lives. Returns undefined if it escapes the root.
 */
export function resolveHardlinkTarget(linkname: string): string | undefined {
  if (!linkname) return undefined;
  return resolveLinkTarget("", linkname);
}

function isSpecialFile(p: string): boolean {
  return p === APK_DB_PATH || p === DPKG_STATUS_PATH || p === ALPINE_RELEASE_PATH || OS_RELEASE_PATHS.includes(p);
}

/**
 * Accumulates inventory across layers. Layers must be fed in order;
 * last-writer-wins per path (v1 simplification — whiteouts are not applied,
 * so files deleted by later layers may still appear in the inventory).
 */
export class InventoryCollector {
  private specialFiles = new Map<string, string>();
  private binariesByPath = new Map<string, BinaryRecord[]>();
  private rpmDbPresent = false;
  /**
   * Link (symlink/hardlink) target path → signatures to apply when that target
   * is scanned. Populated when a link whose basename is a candidate (e.g.
   * `python3 → python3.11`) points at a target whose own basename would not be
   * recognized, including through chains of intermediate links.
   */
  private symlinkTargets = new Map<string, BinarySignature[]>();

  isInteresting(entryPath: string): boolean {
    const p = normalizePath(entryPath);
    if (isSpecialFile(p)) return true;
    return this.signaturesForPath(p).length > 0;
  }

  noteEntry(entryPath: string): void {
    if (normalizePath(entryPath).startsWith(RPM_DB_PREFIX)) this.rpmDbPresent = true;
  }

  /**
   * Record a symlink or hardlink whose basename is a candidate so its target
   * is scanned with the same signatures even when the target's own basename is
   * not a candidate (e.g. `usr/bin/python3 → ../lib/cpython-3.11`). A hardlink
   * (`kind === "link"`) names another archive member relative to the archive
   * root; a symlink's linkname is resolved relative to the link's directory.
   * Signatures inherited from an earlier link are propagated, so a candidate
   * reachable through a chain (`python3 → alias → cpython`) still marks the
   * final target even when the intermediate link is not itself a candidate.
   * Best-effort: a target (or chain link) that appeared in an earlier entry
   * than the link pointing at it is not retroactively scanned.
   */
  noteLink(entryPath: string, linkname: string, kind: "symlink" | "link"): void {
    const p = normalizePath(entryPath);
    const sigs = this.signaturesForPath(p);
    if (sigs.length === 0) return;
    const target = kind === "link" ? resolveHardlinkTarget(linkname) : resolveLinkTarget(p, linkname);
    if (!target || target === p) return;
    const existing = this.symlinkTargets.get(target);
    this.symlinkTargets.set(target, existing ? [...existing, ...sigs] : sigs);
  }

  /**
   * Signatures applicable to a file path: those matched by its basename, plus
   * any inherited from a candidate symlink that points at this path.
   */
  signaturesForPath(entryPath: string): BinarySignature[] {
    const p = normalizePath(entryPath);
    const direct = candidateSignatures(p);
    const inherited = this.symlinkTargets.get(p);
    if (!inherited) return direct;
    const merged = [...direct];
    for (const sig of inherited) {
      if (!merged.includes(sig)) merged.push(sig);
    }
    return merged;
  }

  addFile(entryPath: string, content: Buffer, layerDigest: string): void {
    const p = normalizePath(entryPath);
    if (isSpecialFile(p)) {
      this.specialFiles.set(p, content.toString("utf8"));
      return;
    }
    const sigs = this.signaturesForPath(p);
    if (sigs.length > 0) {
      this.setBinaryRecords(p, extractBinaryVersions(p, content, layerDigest, sigs));
    }
  }

  /**
   * Record the outcome of a stream scan for a candidate binary path.
   * Overwrite per path even when no version was found — a later layer may
   * replace a detected binary with one we cannot fingerprint.
   */
  setBinaryRecords(entryPath: string, records: BinaryRecord[]): void {
    this.binariesByPath.set(normalizePath(entryPath), records);
  }

  /**
   * Drop anything previously recorded for a path. Called when a later layer
   * replaces the file with an entry we cannot scan (over a size cap) —
   * last-writer-wins means the stale earlier record must not survive.
   */
  clearFile(entryPath: string): void {
    const p = normalizePath(entryPath);
    if (isSpecialFile(p)) this.specialFiles.delete(p);
    else this.binariesByPath.delete(p);
  }

  build(): ImageInventory {
    const apkContent = this.specialFiles.get(APK_DB_PATH);
    const dpkgContent = this.specialFiles.get(DPKG_STATUS_PATH);
    const packages = [
      ...(apkContent ? parseApkInstalled(apkContent) : []),
      ...(dpkgContent ? parseDpkgStatus(dpkgContent) : []),
    ];

    const osReleaseContent = this.specialFiles.get(OS_RELEASE_PATHS[0]) ?? this.specialFiles.get(OS_RELEASE_PATHS[1]);
    const os = osReleaseContent ? parseOsRelease(osReleaseContent) : {};
    const alpineRelease = this.specialFiles.get(ALPINE_RELEASE_PATH)?.trim();

    return {
      packages,
      binaries: [...this.binariesByPath.values()].flat(),
      os: { ...os, alpineRelease },
      rpmDbPresent: this.rpmDbPresent,
    };
  }
}

/**
 * Stream a tar (already decompressed) into the collector.
 * Metadata files are buffered up to `maxEntryBytes` (size checked upfront via
 * the tar header); candidate binaries are stream-scanned in a bounded sliding
 * window — never buffered or decoded as one string — up to `maxBinaryScanBytes`.
 */
export async function scanTarStream(
  tarStream: NodeJS.ReadableStream,
  layerDigest: string,
  collector: InventoryCollector,
  limits: LayerScanLimits = {},
): Promise<void> {
  const maxEntryBytes = limits.maxEntryBytes ?? DEFAULT_MAX_ENTRY_BYTES;
  const maxBinaryScanBytes = limits.maxBinaryScanBytes ?? DEFAULT_MAX_BINARY_SCAN_BYTES;
  const extractor = extract();

  extractor.on("entry", (header, stream, next) => {
    collector.noteEntry(header.name);

    const drain = () => {
      stream.resume();
      stream.on("end", next);
    };

    if (header.type === "symlink" || header.type === "link") {
      // A symlink or hardlink whose basename is a candidate (e.g. `python3 →
      // python3.11`) points scanning at its target path; the ELF itself is
      // scanned when the target entry is reached. The two types resolve
      // differently: a hardlink's linkname is archive-root-relative, a
      // symlink's is relative to the link's own directory.
      if (header.linkname) collector.noteLink(header.name, header.linkname, header.type);
      drain();
      return;
    }

    if (header.type !== "file") {
      drain();
      return;
    }

    const p = normalizePath(header.name);
    const declaredSize = header.size ?? 0;

    if (isSpecialFile(p)) {
      // Size guard upfront: a hostile tar header cannot force a huge allocation.
      if (declaredSize > maxEntryBytes) {
        // Last-writer-wins: an over-cap replacement must also erase what an
        // earlier layer recorded for this path, not leave it stale.
        collector.clearFile(header.name);
        drain();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let overLimit = false;
      stream.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxEntryBytes) {
          overLimit = true;
          chunks.length = 0;
          return;
        }
        chunks.push(chunk);
      });
      stream.on("end", () => {
        if (overLimit) collector.clearFile(header.name);
        else collector.addFile(header.name, Buffer.concat(chunks), layerDigest);
        next();
      });
      stream.on("error", next);
      return;
    }

    const sigs = collector.signaturesForPath(p);
    if (sigs.length === 0) {
      drain();
      return;
    }

    if (declaredSize > maxBinaryScanBytes) {
      collector.clearFile(header.name);
      drain();
      return;
    }

    const scanner = new SignatureStreamScanner(p, layerDigest, sigs);
    let scanned = 0;
    let overLimit = false;
    stream.on("data", (chunk: Buffer) => {
      if (overLimit) return;
      scanned += chunk.length;
      if (scanned > maxBinaryScanBytes) {
        // Actual bytes exceed the declared header size — hostile entry; drop it.
        overLimit = true;
        return;
      }
      scanner.update(chunk);
    });
    stream.on("end", () => {
      collector.setBinaryRecords(p, overLimit ? [] : scanner.finish());
      next();
    });
    stream.on("error", next);
  });

  await new Promise<void>((resolve, reject) => {
    extractor.on("finish", resolve);
    extractor.on("error", reject);
    tarStream.on("error", reject);
    tarStream.pipe(extractor);
  });
}

export type LayerCompression = "gzip" | "tar" | "zstd" | "unknown";

/**
 * Classify a layer by its OCI/Docker media type. Docker's historical default
 * (and an absent media type) is gzip; zstd is emitted by newer buildkit/
 * containerd and is not decompressible with zlib.
 */
export function layerCompression(mediaType?: string): LayerCompression {
  const mt = mediaType?.toLowerCase() ?? "";
  if (mt.includes("+zstd") || mt.endsWith(".tar.zstd")) return "zstd";
  if (mt.includes("+gzip") || mt.endsWith(".tar.gzip")) return "gzip";
  // Plain, uncompressed tar layers (OCI `...tar`, Docker `...diff.tar`).
  if (mt.endsWith(".tar") || mt.endsWith("image.layer.v1.tar")) return "tar";
  return "unknown";
}

/** Thrown when a layer uses a compression we cannot decode; caught per-image. */
export class UnsupportedLayerCompressionError extends Error {
  constructor(compression: string) {
    super(`unsupported layer compression ${compression}`);
    this.name = "UnsupportedLayerCompressionError";
  }
}

/**
 * Scan one layer blob into the collector, decompressing according to its media
 * type. Plain tar layers stream directly; gzip (and media-type-absent) layers
 * are gunzipped; zstd layers throw UnsupportedLayerCompressionError so the
 * caller can skip the image with a clear reason instead of a cryptic zlib error.
 */
export async function scanLayerStream(
  blobStream: NodeJS.ReadableStream,
  layerDigest: string,
  mediaType: string | undefined,
  collector: InventoryCollector,
  limits?: LayerScanLimits,
): Promise<void> {
  const compression = layerCompression(mediaType);
  if (compression === "zstd") throw new UnsupportedLayerCompressionError("zstd");
  if (compression === "tar") {
    try {
      await scanTarStream(blobStream, layerDigest, collector, limits);
    } catch (err) {
      // Mirror the gzip path: a malformed layer must not leak the HTTP body.
      (blobStream as NodeJS.ReadableStream & { destroy?: (e?: Error) => void }).destroy?.(err as Error);
      throw err;
    }
    return;
  }
  await scanTarGzStream(blobStream, layerDigest, collector, limits);
}

/** Stream-decompress a gzipped layer tar into the collector. */
export async function scanTarGzStream(
  gzStream: NodeJS.ReadableStream,
  layerDigest: string,
  collector: InventoryCollector,
  limits?: LayerScanLimits,
): Promise<void> {
  const gunzip = createGunzip();
  const done = scanTarStream(gunzip, layerDigest, collector, limits);
  try {
    await Promise.all([pipeline(gzStream, gunzip), done]);
  } catch (err) {
    // On a corrupted/incomplete layer, tear down both the HTTP body and the
    // gunzip so a failed layer never leaks a socket or the decompressor.
    (gzStream as NodeJS.ReadableStream & { destroy?: (e?: Error) => void }).destroy?.(err as Error);
    gunzip.destroy(err as Error);
    throw err;
  }
}

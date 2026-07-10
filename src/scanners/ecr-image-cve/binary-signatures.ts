import type { BinaryRecord, ComponentName } from "./types.js";

/**
 * Channel B: version-signature extraction from binary bytes.
 * Candidate selection is path/name heuristics; version extraction scans the
 * bytes in a bounded sliding window (latin1 decode per chunk, never the whole
 * file as one string) for well-known version strings. A signature only
 * produces a record when the file is a real ELF binary, unless the signature
 * explicitly allows text files (e.g. the Java `release` metadata file).
 */

export interface BinarySignature {
  id: string;
  component: ComponentName;
  /** Basenames that make a file a candidate for this signature. */
  fileNames: string[];
  /**
   * Basename patterns that also make a file a candidate. Used for versioned
   * interpreter binaries whose real ELF is reached via a symlink from the bare
   * name (Debian `python3 → python3.11`, `php8.2`; Alpine `python3.12`, `php82`).
   */
  fileNamePatterns?: RegExp[];
  /** Regex applied to the binary's bytes; first capture group is the version. */
  pattern: RegExp;
  /**
   * When true the signature also matches non-ELF regular files. Reserved for
   * known text metadata files (Java `release`); server binaries must be ELF
   * so a text file named `usr/sbin/nginx` cannot fake an unmanaged binary.
   */
  allowTextFile?: boolean;
}

/** `python3`, `python3.11`, `python3.12` — the bare `python3` is often a symlink to a versioned ELF. */
const PYTHON3_BASENAME_RE = /^python3(\.\d+)?$/;
/** Debian `php8.2` / `php-fpm8.2` and Alpine `php82` / `php-fpm82` versioned interpreters. */
const PHP_BASENAME_RE = /^php(-fpm)?\d+(\.\d+)?$/;

/** Extensible signature table — v1 target list per spec R3. */
export const BINARY_SIGNATURES: BinarySignature[] = [
  { id: "nginx-version-string", component: "nginx", fileNames: ["nginx"], pattern: /nginx version: nginx\/(\d+\.\d+\.\d+)/ },
  { id: "nginx-server-string", component: "nginx", fileNames: ["nginx"], pattern: /nginx\/(\d+\.\d+\.\d+)/ },
  { id: "openssl-version-string", component: "openssl", fileNames: ["openssl", "libssl.so", "libcrypto.so"], pattern: /OpenSSL (\d+\.\d+\.\d+[a-z]?)/ },
  { id: "curl-version-string", component: "curl", fileNames: ["curl", "libcurl.so"], pattern: /curl\/(\d+\.\d+\.\d+)/ },
  { id: "redis-version-string", component: "redis", fileNames: ["redis-server"], pattern: /Redis server v=(\d+\.\d+\.\d+)/ },
  { id: "redis-embedded-version", component: "redis", fileNames: ["redis-server"], pattern: /redis_version:(\d+\.\d+\.\d+)/ },
  { id: "node-version-string", component: "node", fileNames: ["node", "nodejs"], pattern: /node\.js\/v(\d+\.\d+\.\d+)/i },
  { id: "httpd-version-string", component: "httpd", fileNames: ["httpd", "apache2"], pattern: /Apache\/(\d+\.\d+\.\d+)/ },
  { id: "haproxy-version-string", component: "haproxy", fileNames: ["haproxy"], pattern: /HA-?Proxy version (\d+\.\d+\.\d+)/i },
  // PHP interpreters are versioned in common layouts: Debian `php8.2`, `php-fpm8.2`; Alpine `php82`, `php-fpm82`.
  { id: "php-version-string", component: "php", fileNames: ["php", "php-fpm"], fileNamePatterns: [PHP_BASENAME_RE], pattern: /X-Powered-By: PHP\/(\d+\.\d+\.\d+)/ },
  { id: "php-embedded-version", component: "php", fileNames: ["php", "php-fpm"], fileNamePatterns: [PHP_BASENAME_RE], pattern: /PHP\/(\d+\.\d+\.\d+)/ },
  // Python interpreters are versioned: `python3`, `python3.11`, `python3.12`.
  { id: "python3-version-string", component: "python3", fileNames: ["python3", "python"], fileNamePatterns: [PYTHON3_BASENAME_RE], pattern: /Python (\d+\.\d+\.\d+)/ },
  // Java's `release` file is intentionally a text file (JDK metadata), so it opts out of the ELF requirement.
  { id: "java-release-string", component: "java", fileNames: ["release"], pattern: /JAVA_VERSION="(\d+[\d._]*)"/, allowTextFile: true },
  { id: "java-binary-version", component: "java", fileNames: ["java"], pattern: /JAVA_VERSION="(\d+[\d._]*)"/ },
  { id: "envoy-version-string", component: "envoy", fileNames: ["envoy"], pattern: /envoy\/(\d+\.\d+\.\d+)/i },
];

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // \x7fELF

export function isElf(buf: Buffer): boolean {
  return buf.length >= 4 && buf.subarray(0, 4).equals(ELF_MAGIC);
}

function baseName(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx >= 0 ? path.slice(idx + 1) : path;
}

/**
 * Signatures whose fileNames match this path's basename. Versioned `.so` names
 * match by prefix (`libssl.so.3`); versioned interpreter basenames
 * (`python3.11`, `php8.2`) match via the signature's `fileNamePatterns`.
 */
export function candidateSignatures(filePath: string): BinarySignature[] {
  const base = baseName(filePath);
  return BINARY_SIGNATURES.filter(
    (sig) =>
      sig.fileNames.some((n) => base === n || (n.endsWith(".so") && base.startsWith(n))) ||
      (sig.fileNamePatterns?.some((re) => re.test(base)) ?? false),
  );
}

/**
 * Overlap kept between consecutive windows; must exceed the longest possible
 * signature match so a match split across a chunk boundary is still seen.
 */
const WINDOW_OVERLAP_CHARS = 256;

/**
 * Incremental signature scanner: feed chunks with update(), collect records
 * with finish(). Memory is bounded by one chunk plus the overlap window —
 * the file is never held (or decoded) in memory as a whole.
 */
export class SignatureStreamScanner {
  private pending: BinarySignature[];
  private found: Array<{ record: BinaryRecord; allowTextFile: boolean }> = [];
  private seen = new Set<string>();
  private window = "";
  private head = Buffer.alloc(0);

  constructor(
    private readonly filePath: string,
    private readonly layerDigest: string,
    signatures?: BinarySignature[],
  ) {
    // Explicit signatures are used when scanning a symlink target whose own
    // basename is not a candidate but the symlink pointing at it is.
    this.pending = [...(signatures ?? candidateSignatures(filePath))];
  }

  update(chunk: Buffer): void {
    if (this.head.length < ELF_MAGIC.length) {
      this.head = Buffer.concat([this.head, chunk.subarray(0, ELF_MAGIC.length - this.head.length)]);
    }
    if (this.pending.length === 0) return;
    this.window += chunk.toString("latin1");
    this.scanWindow(false);
    if (this.window.length > WINDOW_OVERLAP_CHARS) {
      this.window = this.window.slice(-WINDOW_OVERLAP_CHARS);
    }
  }

  finish(): BinaryRecord[] {
    this.scanWindow(true);
    const elf = isElf(this.head);
    return this.found
      .filter((f) => elf || f.allowTextFile)
      .map((f) => f.record);
  }

  private scanWindow(final: boolean): void {
    const still: BinarySignature[] = [];
    // Table order = signature priority: the first signature to claim a
    // component@version wins the signatureId (e.g. nginx-version-string
    // over the looser nginx-server-string).
    for (const sig of this.pending) {
      const m = this.window.match(sig.pattern);
      if (!m || m.index === undefined) {
        still.push(sig);
        continue;
      }
      // A match ending exactly at the window edge may have a truncated version
      // (e.g. `nginx/1.27.` + `4` in the next chunk) — retry on the next window.
      if (!final && m.index + m[0].length === this.window.length) {
        still.push(sig);
        continue;
      }
      const key = `${sig.component}@${m[1]}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      this.found.push({
        record: {
          component: sig.component,
          version: m[1],
          filePath: this.filePath,
          signatureId: sig.id,
          layerDigest: this.layerDigest,
        },
        allowTextFile: sig.allowTextFile === true,
      });
    }
    this.pending = still;
  }
}

/** Scan a whole in-memory buffer for embedded version signatures (fixture/test convenience). */
export function extractBinaryVersions(
  filePath: string,
  content: Buffer,
  layerDigest: string,
  signatures?: BinarySignature[],
): BinaryRecord[] {
  const scanner = new SignatureStreamScanner(filePath, layerDigest, signatures);
  scanner.update(content);
  return scanner.finish();
}

import { describe, it, expect } from "vitest";
import { gzipSync } from "node:zlib";
import { Readable } from "node:stream";
import { pack } from "tar-stream";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  InventoryCollector,
  scanTarGzStream,
  scanLayerStream,
  layerCompression,
  resolveLinkTarget,
  resolveHardlinkTarget,
  UnsupportedLayerCompressionError,
} from "../../../src/scanners/ecr-image-cve/layer-scan.js";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures", "ecr-image-cve");

function fakeElf(embedded: string): Buffer {
  return Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    Buffer.alloc(16, 0),
    Buffer.from(embedded, "latin1"),
  ]);
}

interface LayerEntry {
  name: string;
  content?: Buffer | string;
  type?: string;
  linkname?: string;
}

/** Build an uncompressed tar of the given entries (plain tar layers, symlinks). */
async function makeTar(entries: LayerEntry[]): Promise<Buffer> {
  const p = pack();
  for (const e of entries) {
    if (e.type === "symlink" || e.type === "link") {
      p.entry({ name: e.name, type: e.type, linkname: e.linkname });
    } else {
      p.entry({ name: e.name }, e.content ?? "");
    }
  }
  p.finalize();
  const chunks: Buffer[] = [];
  for await (const chunk of p) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

async function makeLayer(entries: LayerEntry[]): Promise<Buffer> {
  return gzipSync(await makeTar(entries));
}

describe("scanTarGzStream + InventoryCollector", () => {
  it("builds the Lilly-case inventory from streamed layers (Alpine 3.21 + unmanaged nginx 1.27.4)", async () => {
    const layer1 = await makeLayer([
      { name: "etc/os-release", content: 'ID=alpine\nVERSION_ID=3.21.0\nPRETTY_NAME="Alpine Linux v3.21"\n' },
      { name: "etc/alpine-release", content: "3.21.0\n" },
      { name: "lib/apk/db/installed", content: readFileSync(join(fixturesDir, "apk-installed.txt")) },
    ]);
    const layer2 = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
      { name: "usr/share/doc/readme", content: "not interesting" },
    ]);

    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer1), "sha256:layer1", collector);
    await scanTarGzStream(Readable.from(layer2), "sha256:layer2", collector);

    const inventory = collector.build();
    expect(inventory.os.id).toBe("alpine");
    expect(inventory.os.versionId).toBe("3.21.0");
    expect(inventory.os.alpineRelease).toBe("3.21.0");
    expect(inventory.packages.map((p) => p.name)).toContain("nginx");
    expect(inventory.binaries).toHaveLength(1);
    expect(inventory.binaries[0]).toMatchObject({
      component: "nginx",
      version: "1.27.4",
      filePath: "usr/sbin/nginx",
      layerDigest: "sha256:layer2",
    });
    expect(inventory.rpmDbPresent).toBe(false);
  });

  it("applies last-writer-wins when a later layer overwrites a binary", async () => {
    const layer1 = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.25.0\0") },
    ]);
    const layer2 = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);

    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer1), "sha256:l1", collector);
    await scanTarGzStream(Readable.from(layer2), "sha256:l2", collector);

    const inventory = collector.build();
    expect(inventory.binaries).toHaveLength(1);
    expect(inventory.binaries[0].version).toBe("1.27.4");
    expect(inventory.binaries[0].layerDigest).toBe("sha256:l2");
  });

  it("flags rpmdb presence for the unsupported-v1 note", async () => {
    const layer = await makeLayer([
      { name: "var/lib/rpm/rpmdb.sqlite", content: Buffer.alloc(16) },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    expect(collector.build().rpmDbPresent).toBe(true);
  });

  it("drops candidate binaries whose declared size exceeds the binary scan cap (large-entry guard)", async () => {
    const layer = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0".padEnd(4096, "\0")) },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector, { maxBinaryScanBytes: 64 });
    expect(collector.build().binaries).toEqual([]);
  });

  it("clears an earlier layer's binary record when a later layer replaces it with an over-cap entry (last-writer-wins)", async () => {
    const layer1 = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.25.0\0") },
    ]);
    const layer2 = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0".padEnd(4096, "\0")) },
    ]);

    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer1), "sha256:l1", collector, { maxBinaryScanBytes: 256 });
    await scanTarGzStream(Readable.from(layer2), "sha256:l2", collector, { maxBinaryScanBytes: 256 });

    // The 1.25.0 record from layer1 must not survive: the binary was replaced,
    // we just could not fingerprint the replacement.
    expect(collector.build().binaries).toEqual([]);
  });

  it("clears an earlier layer's metadata file when a later layer replaces it with an over-cap entry", async () => {
    const layer1 = await makeLayer([
      { name: "lib/apk/db/installed", content: "P:nginx\nV:1.26.3-r0\no:nginx\n" },
    ]);
    const layer2 = await makeLayer([
      { name: "lib/apk/db/installed", content: "P:nginx\nV:1.27.0-r0\no:nginx\n".padEnd(4096, "\n") },
    ]);

    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer1), "sha256:l1", collector, { maxEntryBytes: 256 });
    await scanTarGzStream(Readable.from(layer2), "sha256:l2", collector, { maxEntryBytes: 256 });

    expect(collector.build().packages).toEqual([]);
  });

  it("drops metadata files whose declared size exceeds the entry cap (gzip-bomb guard)", async () => {
    const layer = await makeLayer([
      { name: "lib/apk/db/installed", content: "P:nginx\nV:1.26.3-r0\no:nginx\n".padEnd(4096, "\n") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector, { maxEntryBytes: 64 });
    expect(collector.build().packages).toEqual([]);
  });

  it("still scans a small binary alongside an over-cap hostile entry in the same layer", async () => {
    const layer = await makeLayer([
      { name: "usr/bin/curl", content: fakeElf("x".repeat(8192)) }, // over cap, drained
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector, { maxBinaryScanBytes: 256 });
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0].component).toBe("nginx");
  });

  it("does not report a plain text file named like a server binary (non-ELF false positive)", async () => {
    const layer = await makeLayer([
      { name: "usr/sbin/nginx", content: "just a shell script mentioning nginx/1.27.4\n" },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    expect(collector.build().binaries).toEqual([]);
  });

  it("still reports the Java text `release` metadata file (allowTextFile signature)", async () => {
    const layer = await makeLayer([
      { name: "opt/java/openjdk/release", content: 'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="17.0.11"\n' },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "java", version: "17.0.11" });
  });

  it("detects a versioned python interpreter reached via its symlink (finding 1)", async () => {
    // /usr/bin/python3 → python3.11 ; the versioned ELF is also directly a candidate.
    const layer = await makeLayer([
      { name: "usr/bin/python3", type: "symlink", linkname: "python3.11" },
      { name: "usr/bin/python3.11", content: fakeElf("Python 3.11.9\0") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "python3", version: "3.11.9" });
  });

  it("scans a symlink target whose own basename is not a candidate (points detection at the target)", async () => {
    // usr/bin/php → ../lib/php-runtime : target basename is not a candidate, but
    // the symlink's basename (php) is, so the target must be scanned.
    const layer = await makeLayer([
      { name: "usr/bin/php", type: "symlink", linkname: "../lib/php-runtime" },
      { name: "usr/lib/php-runtime", content: fakeElf("X-Powered-By: PHP/8.2.10\0") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "php", version: "8.2.10", filePath: "usr/lib/php-runtime" });
  });

  it("resolves a hardlink's linkname relative to the archive root, not the link's directory (finding N2)", async () => {
    // A hardlink's linkname names another archive member from the archive root.
    // Resolved (wrongly) like a symlink it would become usr/bin/opt/php/bin/php-runtime
    // and detection would miss the target entirely.
    const layer = await makeLayer([
      { name: "usr/bin/php", type: "link", linkname: "opt/php/bin/php-runtime" },
      { name: "opt/php/bin/php-runtime", content: fakeElf("X-Powered-By: PHP/8.2.10\0") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "php", version: "8.2.10", filePath: "opt/php/bin/php-runtime" });
  });

  it("propagates candidate signatures through an intermediate non-candidate symlink in a chain (finding N2)", async () => {
    // python3 → runtime-alias → cpython-runtime : neither the intermediate nor
    // the final basename is a candidate, but the chain starts at one, so the
    // final ELF must still be scanned with the python3 signatures.
    const layer = await makeLayer([
      { name: "usr/bin/python3", type: "symlink", linkname: "runtime-alias" },
      { name: "usr/bin/runtime-alias", type: "symlink", linkname: "../lib/cpython-runtime" },
      { name: "usr/lib/cpython-runtime", content: fakeElf("Python 3.12.4\0") },
    ]);
    const collector = new InventoryCollector();
    await scanTarGzStream(Readable.from(layer), "sha256:l", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "python3", version: "3.12.4", filePath: "usr/lib/cpython-runtime" });
  });
});

describe("resolveLinkTarget", () => {
  it("resolves relative link targets against the link's directory", () => {
    expect(resolveLinkTarget("usr/bin/python3", "python3.11")).toBe("usr/bin/python3.11");
    expect(resolveLinkTarget("usr/bin/php", "../lib/php-runtime")).toBe("usr/lib/php-runtime");
  });

  it("resolves absolute link targets from the image root", () => {
    expect(resolveLinkTarget("usr/bin/python", "/usr/bin/python3.12")).toBe("usr/bin/python3.12");
  });

  it("returns undefined for empty links or links that escape the root", () => {
    expect(resolveLinkTarget("usr/bin/python3", "")).toBeUndefined();
    expect(resolveLinkTarget("bin/x", "../../../../etc/passwd")).toBeUndefined();
  });
});

describe("resolveHardlinkTarget (finding N2)", () => {
  it("resolves the linkname from the archive root regardless of the link's location", () => {
    expect(resolveHardlinkTarget("usr/lib/php-runtime")).toBe("usr/lib/php-runtime");
    expect(resolveHardlinkTarget("./usr/lib/php-runtime")).toBe("usr/lib/php-runtime");
    expect(resolveHardlinkTarget("/usr/lib/php-runtime")).toBe("usr/lib/php-runtime");
  });

  it("returns undefined for empty linknames or targets escaping the root", () => {
    expect(resolveHardlinkTarget("")).toBeUndefined();
    expect(resolveHardlinkTarget("../etc/passwd")).toBeUndefined();
  });
});

describe("layerCompression + scanLayerStream mediaType handling (finding 2)", () => {
  it("classifies media types", () => {
    expect(layerCompression("application/vnd.docker.image.rootfs.diff.tar.gzip")).toBe("gzip");
    expect(layerCompression("application/vnd.oci.image.layer.v1.tar+gzip")).toBe("gzip");
    expect(layerCompression("application/vnd.oci.image.layer.v1.tar")).toBe("tar");
    expect(layerCompression("application/vnd.oci.image.layer.v1.tar+zstd")).toBe("zstd");
    expect(layerCompression(undefined)).toBe("unknown");
  });

  it("streams a plain (uncompressed) tar layer directly without gunzip", async () => {
    const tar = await makeTar([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);
    const collector = new InventoryCollector();
    await scanLayerStream(Readable.from(tar), "sha256:l", "application/vnd.oci.image.layer.v1.tar", collector);
    const binaries = collector.build().binaries;
    expect(binaries).toHaveLength(1);
    expect(binaries[0]).toMatchObject({ component: "nginx", version: "1.27.4" });
  });

  it("gunzips a gzip layer via scanLayerStream", async () => {
    const layer = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);
    const collector = new InventoryCollector();
    await scanLayerStream(Readable.from(layer), "sha256:l", "application/vnd.docker.image.rootfs.diff.tar.gzip", collector);
    expect(collector.build().binaries).toHaveLength(1);
  });

  it("throws UnsupportedLayerCompressionError for a zstd layer (not a cryptic zlib error)", async () => {
    const collector = new InventoryCollector();
    await expect(
      scanLayerStream(Readable.from(Buffer.from("whatever")), "sha256:l", "application/vnd.oci.image.layer.v1.tar+zstd", collector),
    ).rejects.toBeInstanceOf(UnsupportedLayerCompressionError);
  });
});

describe("corrupted layer graceful skip (finding: missing test)", () => {
  it("rejects on a corrupted gzip layer so the caller can skip the image", async () => {
    const notGzip = Buffer.from("this is not gzip data at all, no magic header");
    const collector = new InventoryCollector();
    await expect(
      scanTarGzStream(Readable.from(notGzip), "sha256:l", collector),
    ).rejects.toBeTruthy();
  });

  it("rejects on a truncated gzip stream (incomplete layer)", async () => {
    const layer = await makeLayer([
      { name: "usr/sbin/nginx", content: fakeElf("nginx version: nginx/1.27.4\0") },
    ]);
    const truncated = layer.subarray(0, Math.floor(layer.length / 2));
    const collector = new InventoryCollector();
    await expect(
      scanTarGzStream(Readable.from(truncated), "sha256:l", collector),
    ).rejects.toBeTruthy();
  });

  it("rejects on a corrupted plain tar stream", async () => {
    // Random bytes that are not a valid tar; the extractor should error out.
    const garbage = Buffer.alloc(2048, 0x7f);
    const collector = new InventoryCollector();
    await expect(
      scanLayerStream(Readable.from(garbage), "sha256:l", "application/vnd.oci.image.layer.v1.tar", collector),
    ).rejects.toBeTruthy();
  });

  it("destroys the source stream when a plain tar layer fails to scan (finding N3)", async () => {
    const garbage = Buffer.alloc(2048, 0x7f);
    const source = Readable.from(garbage);
    const collector = new InventoryCollector();
    await expect(
      scanLayerStream(source, "sha256:l", "application/vnd.oci.image.layer.v1.tar", collector),
    ).rejects.toBeTruthy();
    // Same guarantee as the gzip path: a failed layer must not leak the HTTP body.
    expect(source.destroyed).toBe(true);
  });

  it("destroys the source stream when a gzip layer fails to scan", async () => {
    const notGzip = Buffer.from("this is not gzip data at all, no magic header");
    const source = Readable.from(notGzip);
    const collector = new InventoryCollector();
    await expect(scanTarGzStream(source, "sha256:l", collector)).rejects.toBeTruthy();
    expect(source.destroyed).toBe(true);
  });
});

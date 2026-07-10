import { describe, it, expect } from "vitest";
import {
  extractBinaryVersions,
  candidateSignatures,
  isElf,
  SignatureStreamScanner,
} from "../../../src/scanners/ecr-image-cve/binary-signatures.js";

/** Synthetic ELF-like buffer embedding a version string (no real binaries in the repo). */
function fakeElf(embedded: string): Buffer {
  return Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
    Buffer.alloc(64, 0),
    Buffer.from(embedded, "latin1"),
    Buffer.alloc(32, 0),
  ]);
}

describe("isElf", () => {
  it("recognizes the ELF magic", () => {
    expect(isElf(fakeElf("x"))).toBe(true);
    expect(isElf(Buffer.from("#!/bin/sh\n"))).toBe(false);
    expect(isElf(Buffer.alloc(2))).toBe(false);
  });
});

describe("candidateSignatures", () => {
  it("matches by basename regardless of directory", () => {
    expect(candidateSignatures("usr/sbin/nginx").length).toBeGreaterThan(0);
    expect(candidateSignatures("opt/custom/bin/redis-server").length).toBeGreaterThan(0);
    expect(candidateSignatures("usr/bin/vim")).toEqual([]);
  });

  it("matches versioned shared library names by prefix", () => {
    const sigs = candidateSignatures("usr/lib/libssl.so.3");
    expect(sigs.some((s) => s.component === "openssl")).toBe(true);
  });

  it("matches versioned python interpreter basenames (python3.11, python3.12)", () => {
    expect(candidateSignatures("usr/bin/python3.11").some((s) => s.component === "python3")).toBe(true);
    expect(candidateSignatures("usr/local/bin/python3.12").some((s) => s.component === "python3")).toBe(true);
    // bare python3 still matches
    expect(candidateSignatures("usr/bin/python3").some((s) => s.component === "python3")).toBe(true);
    // but an unrelated python-ish name does not
    expect(candidateSignatures("usr/bin/python3-config")).toEqual([]);
  });

  it("matches versioned php interpreter basenames (Debian php8.2, Alpine php82, php-fpm variants)", () => {
    expect(candidateSignatures("usr/bin/php8.2").some((s) => s.component === "php")).toBe(true);
    expect(candidateSignatures("usr/sbin/php-fpm8.2").some((s) => s.component === "php")).toBe(true);
    expect(candidateSignatures("usr/bin/php82").some((s) => s.component === "php")).toBe(true);
    expect(candidateSignatures("usr/sbin/php-fpm82").some((s) => s.component === "php")).toBe(true);
    // bare php still matches
    expect(candidateSignatures("usr/bin/php").some((s) => s.component === "php")).toBe(true);
  });
});

describe("extractBinaryVersions for versioned interpreters", () => {
  it("extracts a Python version from a versioned python3.11 ELF (finding 1 regression)", () => {
    const records = extractBinaryVersions(
      "usr/bin/python3.11",
      fakeElf("Python 3.11.9\0built with gcc"),
      "sha256:l",
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ component: "python3", version: "3.11.9" });
  });

  it("extracts a PHP version from a versioned php8.2 ELF (finding 1 regression)", () => {
    const records = extractBinaryVersions(
      "usr/bin/php8.2",
      fakeElf("X-Powered-By: PHP/8.2.10\0"),
      "sha256:l",
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ component: "php", version: "8.2.10" });
  });
});

describe("extractBinaryVersions", () => {
  it("extracts nginx version from 'nginx version: nginx/x.y.z' signature", () => {
    const records = extractBinaryVersions(
      "usr/sbin/nginx",
      fakeElf("nginx version: nginx/1.27.4\0built with OpenSSL"),
      "sha256:layer1",
    );
    expect(records).toHaveLength(1);
    expect(records[0].component).toBe("nginx");
    expect(records[0].version).toBe("1.27.4");
    expect(records[0].signatureId).toBe("nginx-version-string");
    expect(records[0].filePath).toBe("usr/sbin/nginx");
    expect(records[0].layerDigest).toBe("sha256:layer1");
  });

  it("falls back to the 'nginx/x.y.z' server-string signature", () => {
    const records = extractBinaryVersions("usr/sbin/nginx", fakeElf("Server: nginx/1.25.3\0"), "sha256:l");
    expect(records).toHaveLength(1);
    expect(records[0].version).toBe("1.25.3");
    expect(records[0].signatureId).toBe("nginx-server-string");
  });

  it("extracts OpenSSL versions including letter suffixes", () => {
    const records = extractBinaryVersions("usr/bin/openssl", fakeElf("OpenSSL 1.0.2k  26 Jan 2017\0"), "sha256:l");
    expect(records).toHaveLength(1);
    expect(records[0].component).toBe("openssl");
    expect(records[0].version).toBe("1.0.2k");
  });

  it("extracts Redis server version", () => {
    const records = extractBinaryVersions("usr/local/bin/redis-server", fakeElf("Redis server v=6.2.5 sha=0\0"), "sha256:l");
    expect(records).toHaveLength(1);
    expect(records[0].component).toBe("redis");
    expect(records[0].version).toBe("6.2.5");
  });

  it("returns nothing for a matching filename without a version signature", () => {
    const records = extractBinaryVersions("usr/sbin/nginx", fakeElf("no version markers here"), "sha256:l");
    expect(records).toEqual([]);
  });

  it("returns nothing for non-candidate paths even with a signature inside", () => {
    const records = extractBinaryVersions("usr/bin/other-tool", fakeElf("nginx version: nginx/1.27.4"), "sha256:l");
    expect(records).toEqual([]);
  });

  it("dedupes identical component@version across multiple signatures", () => {
    const records = extractBinaryVersions(
      "usr/sbin/nginx",
      fakeElf("nginx version: nginx/1.27.4\0nginx/1.27.4"),
      "sha256:l",
    );
    expect(records).toHaveLength(1);
  });

  it("rejects a non-ELF text file with a server-binary basename (false-positive guard)", () => {
    const records = extractBinaryVersions(
      "usr/sbin/nginx",
      Buffer.from("#!/bin/sh\necho nginx version: nginx/1.27.4\n"),
      "sha256:l",
    );
    expect(records).toEqual([]);
  });

  it("rejects non-ELF files for every signature without allowTextFile", () => {
    expect(extractBinaryVersions("usr/bin/openssl", Buffer.from("OpenSSL 1.0.2k"), "sha256:l")).toEqual([]);
    expect(extractBinaryVersions("usr/bin/redis-server", Buffer.from("Redis server v=6.2.5"), "sha256:l")).toEqual([]);
  });

  it("accepts the Java `release` text file via its allowTextFile signature", () => {
    const records = extractBinaryVersions(
      "opt/java/openjdk/release",
      Buffer.from('JAVA_VERSION="17.0.11"\nOS_NAME="Linux"\n'),
      "sha256:l",
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ component: "java", version: "17.0.11", signatureId: "java-release-string" });
  });

  it("requires ELF magic for the `java` binary itself", () => {
    expect(extractBinaryVersions("usr/bin/java", Buffer.from('JAVA_VERSION="17.0.11"'), "sha256:l")).toEqual([]);
    const elf = extractBinaryVersions("usr/bin/java", fakeElf('JAVA_VERSION="17.0.11"'), "sha256:l");
    expect(elf).toHaveLength(1);
    expect(elf[0].component).toBe("java");
  });
});

describe("SignatureStreamScanner", () => {
  it("finds a signature split across chunk boundaries via the sliding window", () => {
    const bytes = fakeElf("nginx version: nginx/1.27.4\0");
    const scanner = new SignatureStreamScanner("usr/sbin/nginx", "sha256:l");
    // Feed one byte at a time — worst-case chunking
    for (let i = 0; i < bytes.length; i++) scanner.update(bytes.subarray(i, i + 1));
    const records = scanner.finish();
    expect(records.some((r) => r.component === "nginx" && r.version === "1.27.4")).toBe(true);
  });

  it("does not truncate a version that ends exactly at a chunk edge", () => {
    const scanner = new SignatureStreamScanner("usr/sbin/nginx", "sha256:l");
    scanner.update(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("nginx version: nginx/1.27.1")]));
    scanner.update(Buffer.from("0\0trailer"));
    const records = scanner.finish();
    expect(records).toHaveLength(1);
    expect(records[0].version).toBe("1.27.10");
  });

  it("keeps bounded memory while scanning a large stream", () => {
    const scanner = new SignatureStreamScanner("usr/sbin/nginx", "sha256:l");
    scanner.update(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    const filler = Buffer.alloc(64 * 1024, 0x41);
    for (let i = 0; i < 64; i++) scanner.update(filler); // 4 MiB of filler
    scanner.update(Buffer.from("nginx version: nginx/1.27.4\0"));
    const records = scanner.finish();
    expect(records).toHaveLength(1);
    expect(records[0].version).toBe("1.27.4");
  });
});

import type { OsInfo, PackageRecord } from "./types.js";

/** Parse Alpine's /lib/apk/db/installed (blank-line-separated stanzas, one-letter keys). */
export function parseApkInstalled(content: string): PackageRecord[] {
  const packages: PackageRecord[] = [];
  for (const stanza of content.split(/\n\s*\n/)) {
    let name: string | undefined;
    let version: string | undefined;
    let origin: string | undefined;
    for (const line of stanza.split("\n")) {
      if (line.startsWith("P:")) name = line.slice(2).trim();
      else if (line.startsWith("V:")) version = line.slice(2).trim();
      else if (line.startsWith("o:")) origin = line.slice(2).trim();
    }
    if (name && version) {
      packages.push({ name, version, sourcePackage: origin, manager: "apk" });
    }
  }
  return packages;
}

/** Parse Debian/Ubuntu /var/lib/dpkg/status. Only `install ok installed` packages are returned. */
export function parseDpkgStatus(content: string): PackageRecord[] {
  const packages: PackageRecord[] = [];
  for (const stanza of content.split(/\n\s*\n/)) {
    let name: string | undefined;
    let version: string | undefined;
    let source: string | undefined;
    let installed = false;
    for (const line of stanza.split("\n")) {
      if (line.startsWith("Package:")) name = line.slice(8).trim();
      else if (line.startsWith("Version:")) version = line.slice(8).trim();
      else if (line.startsWith("Status:")) installed = line.includes("install ok installed");
      else if (line.startsWith("Source:")) source = line.slice(7).trim().split(" ")[0];
    }
    if (name && version && installed) {
      packages.push({ name, version, sourcePackage: source, manager: "dpkg" });
    }
  }
  return packages;
}

/** Parse /etc/os-release (KEY=value, possibly quoted). */
export function parseOsRelease(content: string): Pick<OsInfo, "id" | "versionId" | "prettyName"> {
  const values: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return {
    id: values["ID"],
    versionId: values["VERSION_ID"],
    prettyName: values["PRETTY_NAME"],
  };
}

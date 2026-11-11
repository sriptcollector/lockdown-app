// Open-source scanners Lockdown runs under the hood. Pinned versions, verified by SHA-256
// before first use. Credits: gitleaks (MIT), OSV-Scanner (Apache-2.0), Opengrep (LGPL-2.1),
// Trivy (Apache-2.0).
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { dataDir, IS_WIN, run } from "../util";

type Asset = { url: string; sha256: string; archive?: "zip" | "tar.gz"; bin: string };
type Tool = { name: string; version: string; license: string; home: string; assets: Record<string, Asset> };

const gl = (n: string) => `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/${n}`;
const osv = (n: string) => `https://github.com/google/osv-scanner/releases/download/v2.7.1/${n}`;
const og = (n: string) => `https://github.com/opengrep/opengrep/releases/download/v1.33.1/${n}`;
const tv = (n: string) => `https://github.com/aquasecurity/trivy/releases/download/v0.76.2/${n}`;

export const TOOLS: Record<"gitleaks" | "osv-scanner" | "opengrep" | "trivy", Tool> = {
  gitleaks: {
    name: "gitleaks",
    version: "8.30.1",
    license: "MIT",
    home: "https://github.com/gitleaks/gitleaks",
    assets: {
      "win32-x64": { url: gl("gitleaks_8.30.1_windows_x64.zip"), sha256: "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e", archive: "zip", bin: "gitleaks.exe" },
      "darwin-arm64": { url: gl("gitleaks_8.30.1_darwin_arm64.tar.gz"), sha256: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5", archive: "tar.gz", bin: "gitleaks" },
      "darwin-x64": { url: gl("gitleaks_8.30.1_darwin_x64.tar.gz"), sha256: "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709", archive: "tar.gz", bin: "gitleaks" },
      "linux-x64": { url: gl("gitleaks_8.30.1_linux_x64.tar.gz"), sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", archive: "tar.gz", bin: "gitleaks" },
    },
  },
  "osv-scanner": {
    name: "OSV-Scanner",
    version: "2.7.1",
    license: "Apache-2.0",
    home: "https://github.com/google/osv-scanner",
    assets: {
      "win32-x64": { url: osv("osv-scanner_windows_amd64.exe"), sha256: "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800", bin: "osv-scanner.exe" },
      "darwin-arm64": { url: osv("osv-scanner_darwin_arm64"), sha256: "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3", bin: "osv-scanner" },
      "darwin-x64": { url: osv("osv-scanner_darwin_amd64"), sha256: "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b", bin: "osv-scanner" },
      "linux-x64": { url: osv("osv-scanner_linux_amd64"), sha256: "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8", bin: "osv-scanner" },
    },
  },
  opengrep: {
    name: "Opengrep",
    version: "1.33.1",
    license: "LGPL-2.1",
    home: "https://github.com/opengrep/opengrep",
    assets: {
      "win32-x64": { url: og("opengrep_windows_x86.exe"), sha256: "132e606e071bdd3928286fddc893198a6106a90820d46e21197e0ace1a23e0c1", bin: "opengrep.exe" },
      "darwin-arm64": { url: og("opengrep_osx_arm64"), sha256: "a17c1881bb40e3214266a7a291cf4f2ae3bc56c1715628b5712d2ec816bc3e2d", bin: "opengrep" },
      "darwin-x64": { url: og("opengrep_osx_x86"), sha256: "c3bd18e0d898d44e28419d95dad57c8928bb46ab32889a0ee1f72a87ad9627af", bin: "opengrep" },
      "linux-x64": { url: og("opengrep_manylinux_x86"), sha256: "46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808", bin: "opengrep" },
    },
  },
  trivy: {
    name: "Trivy",
    version: "0.76.2",
    license: "Apache-2.0",
    home: "https://github.com/aquasecurity/trivy",
    assets: {
      "win32-x64": { url: tv("trivy_0.76.2_windows-64bit.zip"), sha256: "691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6", archive: "zip", bin: "trivy.exe" },
      "darwin-arm64": { url: tv("trivy_0.76.2_macOS-ARM64.tar.gz"), sha256: "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8", archive: "tar.gz", bin: "trivy" },
      "darwin-x64": { url: tv("trivy_0.76.2_macOS-64bit.tar.gz"), sha256: "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b", archive: "tar.gz", bin: "trivy" },
      "linux-x64": { url: tv("trivy_0.76.2_Linux-64bit.tar.gz"), sha256: "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf", archive: "tar.gz", bin: "trivy" },
    },
  },
};

export type ToolId = keyof typeof TOOLS;

const inflight = new Map<ToolId, Promise<string | null>>();

/** Path to a verified scanner binary, downloading it once. Null when this platform has no build. */
export function ensureTool(id: ToolId): Promise<string | null> {
  if (!inflight.has(id)) inflight.set(id, fetchTool(id));
  return inflight.get(id)!;
}

async function fetchTool(id: ToolId): Promise<string | null> {
  const tool = TOOLS[id];
  const key = `${platform()}-${arch() === "arm64" && platform() === "win32" ? "x64" : arch()}`;
  const asset = tool.assets[key];
  if (!asset) return null;
  const dir = dataDir("tools", id, tool.version);
  const binPath = join(dir, asset.bin);
  if (existsSync(binPath) && statSync(binPath).size > 0) return binPath;

  const res = await fetch(asset.url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download ${tool.name} failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = createHash("sha256").update(buf).digest("hex");
  if (got !== asset.sha256) throw new Error(`${tool.name} checksum mismatch; refusing to run it`);

  if (!asset.archive) {
    writeFileSync(binPath, buf);
  } else {
    const tmp = join(dir, "_extract");
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true });
    const archivePath = join(tmp, asset.archive === "zip" ? "a.zip" : "a.tar.gz");
    writeFileSync(archivePath, buf);
    // tar ships with Windows 10+ and macOS and handles both zip and tar.gz.
    const r = await run(IS_WIN ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar", ["-xf", archivePath, "-C", tmp]);
    if (r.code !== 0) throw new Error(`unpack ${tool.name} failed: ${r.stderr.slice(0, 200)}`);
    const found = findFile(tmp, asset.bin);
    if (!found) throw new Error(`${asset.bin} missing from ${tool.name} archive`);
    renameSync(found, binPath);
    rmSync(tmp, { recursive: true, force: true });
  }
  if (!IS_WIN) chmodSync(binPath, 0o755);
  return binPath;
}

function findFile(dir: string, name: string): string | null {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isFile() && e.name === name) return p;
    if (e.isDirectory()) {
      const f = findFile(p, name);
      if (f) return f;
    }
  }
  return null;
}

export function credits() {
  return Object.values(TOOLS).map((t) => ({ name: t.name, version: t.version, license: t.license, home: t.home }));
}

export function readJsonFile<T>(p: string): T | null {
  try {
    return JSON.parse(readFileSync(p, "utf8")) as T;
  } catch {
    return null;
  }
}

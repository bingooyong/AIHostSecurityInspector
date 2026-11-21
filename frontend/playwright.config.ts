import { defineConfig } from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(frontendRoot, "..");
const hostsec = path.join(repoRoot, "build", "hostsec");
const fixtureRoot = path.join(repoRoot, "backend", "internal", "collector", "linux", "testdata", "host");
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "hostsec-e2e-"));

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "off"
  },
  webServer: [
    {
      command: [
        hostsec,
        "api",
        "--listen",
        "127.0.0.1:18080",
        "--file",
        path.join(repoRoot, "examples", "hosts.yaml"),
        "--identities",
        path.join(repoRoot, "examples", "identities.json"),
        "--root",
        fixtureRoot,
        "--out",
        outDir
      ]
        .map(shellQuote)
        .join(" "),
      url: "http://127.0.0.1:18080/healthz",
      reuseExistingServer: false,
      timeout: 30_000
    },
    {
      command: "npx vite preview --host 127.0.0.1 --port 4173 --strictPort",
      url: "http://127.0.0.1:4173",
      reuseExistingServer: false,
      timeout: 30_000
    }
  ]
});

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

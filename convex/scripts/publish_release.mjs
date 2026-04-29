#!/usr/bin/env node
/**
 * publish_release.mjs
 *
 * Uploads pre-compiled Sicario binaries to Convex File Storage and
 * records them in the `releases` table via the `publishRelease` mutation.
 *
 * Usage:
 *   node scripts/publish_release.mjs --version v0.1.9 [--dry-run]
 *
 * Environment variables:
 *   CONVEX_URL          — Convex deployment URL (e.g. https://flexible-terrier-680.convex.cloud)
 *   CONVEX_DEPLOY_KEY   — Convex deploy key (from `npx convex dashboard`)
 *
 * Binary layout expected (relative to repo root):
 *   target/x86_64-unknown-linux-musl/release/sicario          → linux-x64-musl
 *   target/x86_64-unknown-linux-gnu/release/sicario            → linux-x64
 *   target/aarch64-apple-darwin/release/sicario                → macos-aarch64
 *   target/x86_64-apple-darwin/release/sicario                 → macos-x64
 *   target/x86_64-pc-windows-msvc/release/sicario.exe          → windows-x64
 *
 * The script also accepts pre-built tarballs from GitHub Releases via
 * the --github-release flag (downloads from the GH release assets).
 */

import { createReadStream, existsSync, statSync } from "fs";
import { readFile } from "fs/promises";
import { createHash } from "crypto";
import { resolve, join } from "path";
import { parseArgs } from "util";

// ── CLI args ──────────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
  options: {
    version: { type: "string" },
    "dry-run": { type: "boolean", default: false },
    "repo-root": { type: "string", default: resolve(process.cwd(), "..") },
  },
  strict: false,
});

const VERSION = args.version;
const DRY_RUN = args["dry-run"];
const REPO_ROOT = args["repo-root"];

if (!VERSION) {
  console.error("Error: --version is required (e.g. --version v0.1.9)");
  process.exit(1);
}

const CONVEX_URL = process.env.CONVEX_URL || "https://flexible-terrier-680.convex.cloud";
const CONVEX_DEPLOY_KEY = process.env.CONVEX_DEPLOY_KEY;

if (!CONVEX_DEPLOY_KEY && !DRY_RUN) {
  console.error("Error: CONVEX_DEPLOY_KEY environment variable is required");
  console.error("Get it from: npx convex dashboard → Settings → Deploy Key");
  process.exit(1);
}

// ── Platform → binary path mapping ───────────────────────────────────────────

const PLATFORMS = [
  {
    platform: "linux-x64-musl",
    path: join(REPO_ROOT, "target/x86_64-unknown-linux-musl/release/sicario"),
    contentType: "application/octet-stream",
  },
  {
    platform: "linux-x64",
    path: join(REPO_ROOT, "target/x86_64-unknown-linux-gnu/release/sicario"),
    contentType: "application/octet-stream",
  },
  {
    platform: "macos-aarch64",
    path: join(REPO_ROOT, "target/aarch64-apple-darwin/release/sicario"),
    contentType: "application/octet-stream",
  },
  {
    platform: "macos-x64",
    path: join(REPO_ROOT, "target/x86_64-apple-darwin/release/sicario"),
    contentType: "application/octet-stream",
  },
  {
    platform: "windows-x64",
    path: join(REPO_ROOT, "target/x86_64-pc-windows-msvc/release/sicario.exe"),
    contentType: "application/octet-stream",
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

async function sha256File(filePath) {
  const data = await readFile(filePath);
  return createHash("sha256").update(data).digest("hex");
}

async function convexMutation(mutationName, args) {
  const resp = await fetch(`${CONVEX_URL}/api/mutation`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Convex ${CONVEX_DEPLOY_KEY}`,
    },
    body: JSON.stringify({ path: mutationName, args }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Convex mutation ${mutationName} failed (${resp.status}): ${text}`);
  }
  return resp.json();
}

async function uploadToStorage(uploadUrl, filePath, contentType) {
  const data = await readFile(filePath);
  const resp = await fetch(uploadUrl, {
    method: "POST",
    headers: { "Content-Type": contentType },
    body: data,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Storage upload failed (${resp.status}): ${text}`);
  }
  const json = await resp.json();
  return json.storageId;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n🔫 Sicario Release Publisher`);
  console.log(`   Version : ${VERSION}`);
  console.log(`   Convex  : ${CONVEX_URL}`);
  console.log(`   Dry run : ${DRY_RUN}\n`);

  const available = PLATFORMS.filter(({ path }) => existsSync(path));
  const missing = PLATFORMS.filter(({ path }) => !existsSync(path));

  if (missing.length > 0) {
    console.warn("⚠️  Missing binaries (will be skipped):");
    for (const { platform, path } of missing) {
      console.warn(`   ${platform}: ${path}`);
    }
    console.warn("");
  }

  if (available.length === 0) {
    console.error("❌ No binaries found. Build the project first.");
    process.exit(1);
  }

  console.log(`📦 Publishing ${available.length} platform(s):\n`);

  for (const { platform, path, contentType } of available) {
    const size = statSync(path).size;
    const checksum = await sha256File(path);

    console.log(`  → ${platform}`);
    console.log(`     File    : ${path}`);
    console.log(`     Size    : ${(size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`     SHA-256 : ${checksum}`);

    if (DRY_RUN) {
      console.log(`     [DRY RUN] Skipping upload\n`);
      continue;
    }

    // 1. Get upload URL
    const { value: uploadUrl } = await convexMutation("releases:generateUploadUrl", {});

    // 2. Upload binary
    const storageId = await uploadToStorage(uploadUrl, path, contentType);
    console.log(`     Storage : ${storageId}`);

    // 3. Record in database (deactivates old, inserts new)
    await convexMutation("releases:publishRelease", {
      version: VERSION,
      platform,
      storageId,
      checksum,
      fileSize: size,
    });

    console.log(`     ✅ Published\n`);
  }

  console.log(`✅ Release ${VERSION} published successfully.`);
  console.log(`   Download page: https://usesicario.xyz/download\n`);
}

main().catch((err) => {
  console.error("❌ Fatal error:", err.message);
  process.exit(1);
});

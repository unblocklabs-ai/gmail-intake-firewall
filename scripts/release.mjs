#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const PLUGIN_ID = "gmail-intake-firewall";
const PACKAGE_JSON_PATH = path.join(ROOT, "package.json");
const PACKAGE_LOCK_PATH = path.join(ROOT, "package-lock.json");
const OPENCLAW_PLUGIN_PATH = path.join(ROOT, "openclaw.plugin.json");
const MARKETPLACE_PATH = path.join(ROOT, ".claude-plugin", "marketplace.json");
const RELEASED_BRANCH = "main";
const RELEASE_STAGE_PATHS = [
  "package.json",
  "package-lock.json",
  "openclaw.plugin.json",
  ".claude-plugin/marketplace.json",
  `marketplace/${PLUGIN_ID}`,
];

function fail(message) {
  console.error(message);
  process.exit(1);
}

function run(cmd, args, options = {}) {
  const rendered = [cmd, ...args].join(" ");
  if (options.dryRun) {
    console.log(`[dry-run] ${rendered}`);
    return "";
  }
  return execFileSync(cmd, args, {
    cwd: ROOT,
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
    encoding: "utf8",
  })?.trim() ?? "";
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function parseArgs(argv) {
  const result = {
    bump: undefined,
    dryRun: false,
    message: undefined,
    skipChecks: false,
    skipGithubRelease: false,
    skipNpmPublish: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") {
      result.dryRun = true;
    } else if (arg === "--skip-checks") {
      result.skipChecks = true;
    } else if (arg === "--no-github-release") {
      result.skipGithubRelease = true;
    } else if (arg === "--no-npm") {
      result.skipNpmPublish = true;
    } else if (arg === "--message" || arg === "-m") {
      const value = argv[index + 1];
      if (!value) {
        fail("Missing value for --message.");
      }
      result.message = value;
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else if (!result.bump) {
      result.bump = arg;
    } else {
      fail(`Unexpected argument: ${arg}`);
    }
  }
  if (!result.bump) {
    fail("Usage: node scripts/release.mjs <patch|minor|major|x.y.z> [--dry-run] [--skip-checks] [--no-npm] [--no-github-release]");
  }
  return result;
}

function printHelp() {
  console.log(`Usage:
  node scripts/release.mjs <patch|minor|major|x.y.z> [--dry-run] [--message "..."] [--skip-checks] [--no-npm] [--no-github-release]`);
}

function parseSemver(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) {
    fail(`Invalid semver version: ${version}`);
  }
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

function bumpVersion(currentVersion, bump) {
  if (/^\d+\.\d+\.\d+$/.test(bump)) {
    return bump;
  }
  const current = parseSemver(currentVersion);
  if (bump === "patch") {
    return `${current.major}.${current.minor}.${current.patch + 1}`;
  }
  if (bump === "minor") {
    return `${current.major}.${current.minor + 1}.0`;
  }
  if (bump === "major") {
    return `${current.major + 1}.0.0`;
  }
  fail(`Unsupported bump target: ${bump}`);
}

function ensureBranch(dryRun) {
  const branch = run("git", ["branch", "--show-current"], { capture: true, dryRun });
  if (!dryRun && branch !== RELEASED_BRANCH) {
    fail(`Releases must be cut from "${RELEASED_BRANCH}". Current branch: "${branch}".`);
  }
}

function ensureCleanWorkingTree(dryRun) {
  const status = run("git", ["status", "--porcelain"], { capture: true, dryRun });
  if (!dryRun && status.trim()) {
    fail("Working tree must be clean before release.");
  }
}

function ensureTagDoesNotExist(tagName, dryRun) {
  const existingTag = run("git", ["tag", "--list", tagName], { capture: true, dryRun });
  if (!dryRun && existingTag.trim()) {
    fail(`Git tag already exists: ${tagName}`);
  }
}

function ensureNpmVersionDoesNotExist(packageName, version, dryRun) {
  if (dryRun) {
    run("npm", ["view", `${packageName}@${version}`, "version"], { dryRun });
    return;
  }
  try {
    const publishedVersion = run("npm", ["view", `${packageName}@${version}`, "version"], { capture: true });
    if (publishedVersion === version) {
      fail(`npm version already exists: ${packageName}@${version}`);
    }
  } catch (error) {
    const stderr = String(error.stderr ?? error.message ?? "");
    if (!stderr.includes("E404") && !stderr.includes("404 Not Found")) {
      fail(`Unable to check npm version ${packageName}@${version}.\n${stderr}`);
    }
  }
}

function ensureReleasePublishers({ packageName, version, publishToNpm, createGithubRelease, dryRun }) {
  if (publishToNpm) {
    run("npm", ["whoami"], { dryRun });
    ensureNpmVersionDoesNotExist(packageName, version, dryRun);
  }
  if (createGithubRelease) {
    run("gh", ["auth", "status"], { dryRun });
  }
}

function syncVersions(currentVersion, nextVersion, dryRun) {
  const packageJson = readJson(PACKAGE_JSON_PATH);
  const packageLock = readJson(PACKAGE_LOCK_PATH);
  const pluginManifest = readJson(OPENCLAW_PLUGIN_PATH);
  const marketplace = readJson(MARKETPLACE_PATH);
  packageJson.version = nextVersion;
  packageLock.version = nextVersion;
  if (packageLock.packages?.[""]) {
    packageLock.packages[""].version = nextVersion;
  }
  pluginManifest.version = nextVersion;
  marketplace.version = nextVersion;
  if (Array.isArray(marketplace.plugins)) {
    for (const plugin of marketplace.plugins) {
      if (plugin?.name === PLUGIN_ID) {
        plugin.version = nextVersion;
      }
    }
  }
  if (dryRun) {
    console.log(`[dry-run] would set version ${currentVersion} -> ${nextVersion} in release metadata files`);
    return;
  }
  writeJson(PACKAGE_JSON_PATH, packageJson);
  writeJson(PACKAGE_LOCK_PATH, packageLock);
  writeJson(OPENCLAW_PLUGIN_PATH, pluginManifest);
  writeJson(MARKETPLACE_PATH, marketplace);
}

function commitRelease(commitMessage, dryRun) {
  run("git", ["add", ...RELEASE_STAGE_PATHS], { dryRun });
  if (dryRun) {
    run("git", ["commit", "-m", commitMessage], { dryRun });
    return;
  }
  const stagedPaths = run("git", ["diff", "--cached", "--name-only"], { capture: true });
  if (stagedPaths.trim()) {
    run("git", ["commit", "-m", commitMessage]);
  } else {
    console.log("No release metadata changes to commit; tagging current HEAD.");
  }
}

const args = parseArgs(process.argv.slice(2));
const packageJson = readJson(PACKAGE_JSON_PATH);
const currentVersion = packageJson.version;
const packageName = packageJson.name;
const nextVersion = bumpVersion(currentVersion, args.bump);
const tagName = `v${nextVersion}`;
const commitMessage = args.message ?? `release: v${nextVersion}`;
const publishToNpm = packageJson.openclaw?.release?.publishToNpm === true && !args.skipNpmPublish;
const createGithubRelease = !args.skipGithubRelease;

ensureBranch(args.dryRun);
ensureCleanWorkingTree(args.dryRun);
ensureTagDoesNotExist(tagName, args.dryRun);
ensureReleasePublishers({ packageName, version: nextVersion, publishToNpm, createGithubRelease, dryRun: args.dryRun });
syncVersions(currentVersion, nextVersion, args.dryRun);
run("npm", ["run", args.skipChecks ? "build" : "preflight"], { dryRun: args.dryRun });
run("npm", ["run", "marketplace:sync"], { dryRun: args.dryRun });
commitRelease(commitMessage, args.dryRun);
run("git", ["tag", "-a", tagName, "-m", tagName], { dryRun: args.dryRun });
run("git", ["push", "origin", "HEAD"], { dryRun: args.dryRun });
run("git", ["push", "origin", tagName], { dryRun: args.dryRun });
if (publishToNpm) {
  run("npm", ["publish", "--access", "public"], { dryRun: args.dryRun });
} else {
  console.log("Skipping npm publish.");
}
if (createGithubRelease) {
  run("gh", ["release", "create", tagName, "--title", tagName, "--generate-notes", "--verify-tag"], { dryRun: args.dryRun });
} else {
  console.log("Skipping GitHub release.");
}
console.log(`Released ${nextVersion}${args.dryRun ? " (dry run)" : ""}.`);

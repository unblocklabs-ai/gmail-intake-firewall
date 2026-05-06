#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const PLUGIN_ID = "gmail-intake-firewall";
const MARKETPLACE_SOURCE = `marketplace/${PLUGIN_ID}`;

function fail(message) {
  console.error(message);
  process.exit(1);
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function assertFile(relativePath) {
  const absolutePath = path.join(ROOT, relativePath);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    fail(`Missing expected file: ${relativePath}`);
  }
}

const packageJson = readJson("package.json");
const pluginManifest = readJson("openclaw.plugin.json");
const marketplace = readJson(".claude-plugin/marketplace.json");

if (!Array.isArray(packageJson.openclaw?.extensions) || packageJson.openclaw.extensions.length === 0) {
  fail("package.json missing openclaw.extensions");
}
for (const extension of packageJson.openclaw.extensions) {
  if (typeof extension !== "string" || !extension.trim()) {
    fail("package.json openclaw.extensions contains an invalid entry");
  }
  assertFile(extension.replace(/^\.\//, ""));
}
if (!Array.isArray(packageJson.openclaw.runtimeExtensions) || packageJson.openclaw.runtimeExtensions.length !== packageJson.openclaw.extensions.length) {
  fail("package.json openclaw.runtimeExtensions must mirror openclaw.extensions");
}
for (const [index, extension] of packageJson.openclaw.runtimeExtensions.entries()) {
  if (extension !== packageJson.openclaw.extensions[index]) {
    fail("package.json openclaw.runtimeExtensions must mirror openclaw.extensions");
  }
}
if (packageJson.main !== packageJson.openclaw.extensions[0]) {
  fail(`package.json main must match OpenClaw extension entry: ${packageJson.openclaw.extensions[0]}`);
}
if (pluginManifest.id !== PLUGIN_ID) {
  fail(`Unexpected openclaw.plugin.json id: ${pluginManifest.id}`);
}
if (pluginManifest.version !== packageJson.version) {
  fail(`Version mismatch: openclaw.plugin.json=${pluginManifest.version} package.json=${packageJson.version}`);
}
if (marketplace.version !== packageJson.version) {
  fail(`Version mismatch: marketplace=${marketplace.version} package.json=${packageJson.version}`);
}
const marketplacePlugin = Array.isArray(marketplace.plugins)
  ? marketplace.plugins.find((entry) => entry?.name === PLUGIN_ID)
  : undefined;
if (!marketplacePlugin) {
  fail(`Marketplace manifest missing ${PLUGIN_ID} plugin entry`);
}
if (marketplacePlugin.version !== packageJson.version) {
  fail(`Version mismatch: marketplace plugin=${marketplacePlugin.version} package.json=${packageJson.version}`);
}
if (marketplacePlugin.source !== MARKETPLACE_SOURCE) {
  fail(`Unexpected marketplace source: ${marketplacePlugin.source}`);
}

const marketplacePackage = readJson(path.join(MARKETPLACE_SOURCE, "package.json"));
const marketplacePluginManifest = readJson(path.join(MARKETPLACE_SOURCE, "openclaw.plugin.json"));
if (marketplacePackage.version !== packageJson.version) {
  fail(`Version mismatch: marketplace package=${marketplacePackage.version} package.json=${packageJson.version}`);
}
if (!Array.isArray(marketplacePackage.openclaw?.runtimeExtensions) || marketplacePackage.openclaw.runtimeExtensions.length !== marketplacePackage.openclaw.extensions?.length) {
  fail("Marketplace package openclaw.runtimeExtensions must mirror openclaw.extensions");
}
for (const [index, extension] of marketplacePackage.openclaw.runtimeExtensions.entries()) {
  if (extension !== marketplacePackage.openclaw.extensions[index]) {
    fail("Marketplace package openclaw.runtimeExtensions must mirror openclaw.extensions");
  }
}
if (marketplacePackage.scripts || marketplacePackage.devDependencies) {
  fail("Marketplace package must not include development scripts or devDependencies");
}
for (const dep of ["googleapis", "@slack/web-api"]) {
  if (!marketplacePackage.dependencies?.[dep]) {
    fail(`Marketplace package missing runtime dependency: ${dep}`);
  }
}
if (!marketplacePackage.optionalDependencies?.["better-sqlite3"]) {
  fail("Marketplace package missing optionalDependency: better-sqlite3");
}
if (marketplacePluginManifest.version !== pluginManifest.version) {
  fail(`Version mismatch: marketplace manifest=${marketplacePluginManifest.version} root manifest=${pluginManifest.version}`);
}
assertFile(path.join(MARKETPLACE_SOURCE, "dist", "index.js"));

const importedEntry = await import(pathToFileURL(path.join(ROOT, "dist", "index.js")).href);
if (importedEntry.default?.id !== PLUGIN_ID || typeof importedEntry.default?.register !== "function") {
  fail(`dist/index.js default export is not the expected ${PLUGIN_ID} plugin entry`);
}

console.log("Install shape check passed.");

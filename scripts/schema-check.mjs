#!/usr/bin/env node
// Drift detection: regenerate every generated artifact, then fail (and restore the
// originals) if anything differs from what is on disk / committed.
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const GENERATED = [
  "packages/schema/json",
  "packages/schema/src/generated",
  "packages/client/openapi.json",
  "packages/client/src/generated",
  "packages/world/fixtures/streams",
  "packages/world/fixtures/commands",
];

const STEPS = [
  ["uv", ["run", "--no-sync", "python", "packages/core/scripts/export_schema.py"]],
  ["pnpm", ["--filter", "@notary/schema", "run", "schema:generate"]],
  ["uv", ["run", "--no-sync", "python", "apps/server/scripts/export_openapi.py"]],
  ["pnpm", ["--filter", "@notary/client", "run", "api:generate"]],
  ["uv", ["run", "--no-sync", "python", "packages/world/scripts/export_event_fixtures.py"]],
];

function walk(path, out) {
  if (!existsSync(path)) return;
  if (statSync(path).isDirectory()) {
    for (const entry of readdirSync(path).sort()) walk(join(path, entry), out);
  } else {
    out.set(relative(root, path), readFileSync(path));
  }
}

function snapshot() {
  const files = new Map();
  for (const entry of GENERATED) walk(join(root, entry), files);
  return files;
}

function restore(before, after) {
  for (const file of after.keys()) if (!before.has(file)) rmSync(join(root, file), { force: true });
  for (const [file, content] of before) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), content);
  }
}

const before = snapshot();
try {
  for (const [cmd, args] of STEPS) {
    execFileSync(cmd, args, { cwd: root, stdio: ["ignore", "ignore", "inherit"] });
  }
} catch (error) {
  restore(before, snapshot());
  console.error(
    "schema:check could not regenerate (a model change probably broke a generator or fixture).",
  );
  throw error;
}
const after = snapshot();

const problems = [];
for (const [file, content] of after) {
  const old = before.get(file);
  if (old === undefined) problems.push(`+ ${file} (not committed)`);
  else if (!old.equals(content)) problems.push(`~ ${file} (stale)`);
}
for (const file of before.keys())
  if (!after.has(file)) problems.push(`- ${file} (no longer generated)`);

if (problems.length > 0) {
  // Restore the previous state so re-running the check keeps failing until regenerated.
  restore(before, after);
  console.error("schema drift detected. Run `pnpm schema:generate` and commit the result:");
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}
console.log("schema:check ok: generated files are up to date");

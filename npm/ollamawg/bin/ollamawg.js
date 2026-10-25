#!/usr/bin/env node
// Runs the prebuilt ollamawg binary from the platform package npm installed
// alongside this one (see optionalDependencies).
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const pkg = `@ollamawg/${process.platform}-${process.arch}`;
const exe = process.platform === "win32" ? "ollamawg.exe" : "ollamawg";

let bin;
try {
  bin = require.resolve(`${pkg}/bin/${exe}`);
} catch {
  console.error(
    `ollamawg: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Expected the optional package ${pkg} to be installed. If you installed with\n` +
      `--no-optional or --omit=optional, reinstall without it. Otherwise build from source:\n` +
      `  go install github.com/himanshu-mamgain/ollamawg/cmd/ollamawg@latest`
  );
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`ollamawg: failed to run ${path.basename(bin)}: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 1);

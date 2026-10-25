// Assembles the npm packages into dist/npm from binaries in dist/bin.
//
//   node npm/build.mjs <version>
//
// Expects dist/bin/ollamawg-<goos>-<goarch>[.exe] for every target below.
// Writes dist/npm/<platform>/ (one package per binary) and dist/npm/ollamawg/
// (the launcher), all stamped with <version>.
import { chmodSync, copyFileSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = (process.argv[2] || "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("usage: node npm/build.mjs <semver>");
  process.exit(1);
}

// npm platform/arch -> Go GOOS/GOARCH
const targets = [
  { os: "darwin", cpu: "arm64", goos: "darwin", goarch: "arm64" },
  { os: "darwin", cpu: "x64", goos: "darwin", goarch: "amd64" },
  { os: "freebsd", cpu: "x64", goos: "freebsd", goarch: "amd64" },
  { os: "linux", cpu: "arm64", goos: "linux", goarch: "arm64" },
  { os: "linux", cpu: "x64", goos: "linux", goarch: "amd64" },
  { os: "win32", cpu: "x64", goos: "windows", goarch: "amd64" },
];

const out = join(root, "dist", "npm");
rmSync(out, { recursive: true, force: true });

const main = JSON.parse(readFileSync(join(root, "npm", "ollamawg", "package.json"), "utf8"));
main.version = version;
main.optionalDependencies = {};

for (const t of targets) {
  const name = `@ollamawg/${t.os}-${t.cpu}`;
  const exe = t.os === "win32" ? "ollamawg.exe" : "ollamawg";
  const src = join(root, "dist", "bin", `ollamawg-${t.goos}-${t.goarch}${t.os === "win32" ? ".exe" : ""}`);
  const dir = join(out, `${t.os}-${t.cpu}`);

  mkdirSync(join(dir, "bin"), { recursive: true });
  copyFileSync(src, join(dir, "bin", exe));
  chmodSync(join(dir, "bin", exe), 0o755);
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `The ${t.os}-${t.cpu} binary for ollamawg.`,
        repository: main.repository,
        license: main.license,
        os: [t.os],
        cpu: [t.cpu],
        files: ["bin"],
        preferUnplugged: true,
      },
      null,
      2
    ) + "\n"
  );
  copyFileSync(join(root, "LICENSE"), join(dir, "LICENSE"));
  writeFileSync(join(dir, "README.md"), `# ${name}\n\nThe ${t.os}-${t.cpu} binary for [ollamawg](https://www.npmjs.com/package/ollamawg). Install \`ollamawg\` instead.\n`);
  main.optionalDependencies[name] = version;
}

const mainDir = join(out, "ollamawg");
cpSync(join(root, "npm", "ollamawg"), mainDir, { recursive: true });
writeFileSync(join(mainDir, "package.json"), JSON.stringify(main, null, 2) + "\n");
copyFileSync(join(root, "README.md"), join(mainDir, "README.md"));
for (const f of ["LICENSE", "LICENSE.md"]) {
  try { copyFileSync(join(root, f), join(mainDir, f)); } catch {}
}

console.log(`built ${targets.length + 1} packages for ${version} in ${out}`);

// Assembles the npm packages into dist/npm from binaries in dist/bin.
//
//   node npm/build.mjs <version>
//
// Expects dist/bin/ollamawg-<goos>-<goarch>[.exe] for every target below.
// Writes dist/npm/<platform>/ (one package per binary) and dist/npm/cli/
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

const main = JSON.parse(readFileSync(join(root, "npm", "cli", "package.json"), "utf8"));
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
  writeFileSync(join(dir, "README.md"), `# ${name}\n\nThe ${t.os}-${t.cpu} binary for [ollamawg](https://www.npmjs.com/package/@ollamawg/cli). Install \`@ollamawg/cli\` instead.\n`);
  main.optionalDependencies[name] = version;
}

const mainDir = join(out, "cli");
cpSync(join(root, "npm", "cli"), mainDir, { recursive: true });
writeFileSync(join(mainDir, "package.json"), JSON.stringify(main, null, 2) + "\n");
writeFileSync(join(mainDir, "README.md"), npmReadme(readFileSync(join(root, "README.md"), "utf8")));
for (const f of ["LICENSE", "LICENSE.md"]) {
  try { copyFileSync(join(root, f), join(mainDir, f)); } catch {}
}

console.log(`built ${targets.length + 1} packages for ${version} in ${out}`);

// The README links to files in the repo (screenshots, docs) by relative path,
// which npmjs.com can't resolve because those files aren't in the package.
// Point them at GitHub, pinned to this release's tag so they match the code.
function npmReadme(md) {
  const repo = main.repository.url.replace(/^git\+/, "").replace(/\.git$/, "");
  const raw = repo.replace("https://github.com/", "https://raw.githubusercontent.com/") + `/v${version}/`;
  const blob = `${repo}/blob/v${version}/`;
  const abs = p => (/\.(png|jpe?g|gif|svg|webp)$/i.test(p.split("#")[0]) ? raw : blob) + p.replace(/^\.\//, "");
  const relative = p => !/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(p);
  return md
    .replace(/(!?\[[^\]]*\]\()([^)\s]+)(\))/g, (m, a, p, b) => (relative(p) ? a + abs(p) + b : m))
    .replace(/(<img\b[^>]*\bsrc=")([^"]+)(")/g, (m, a, p, b) => (relative(p) ? a + abs(p) + b : m));
}

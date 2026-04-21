#!/usr/bin/env node
/**
 * Generate platform-specific npm packages for httpcloak
 */

const fs = require("fs");
const path = require("path");

const VERSION = "1.4.0";

const PLATFORMS = [
  { name: "linux-x64", os: "linux", cpu: "x64", libName: "libhttpcloak-linux-amd64.so" },
  { name: "linux-arm64", os: "linux", cpu: "arm64", libName: "libhttpcloak-linux-arm64.so" },
  { name: "darwin-x64", os: "darwin", cpu: "x64", libName: "libhttpcloak-darwin-amd64.dylib" },
  { name: "darwin-arm64", os: "darwin", cpu: "arm64", libName: "libhttpcloak-darwin-arm64.dylib" },
  { name: "win32-x64", os: "win32", cpu: "x64", libName: "libhttpcloak-windows-amd64.dll" },
  { name: "win32-arm64", os: "win32", cpu: "arm64", libName: "libhttpcloak-windows-arm64.dll" },
];

const npmDir = path.join(__dirname, "..", "npm");

// Create each platform package
for (const platform of PLATFORMS) {
  const pkgDir = path.join(npmDir, platform.name);

  // Create directory
  fs.mkdirSync(pkgDir, { recursive: true });

  // Create package.json
  const packageJson = {
    name: `@httpcloak/${platform.name}`,
    version: VERSION,
    description: `HTTPCloak native binary for ${platform.os} ${platform.cpu}`,
    os: [platform.os],
    cpu: [platform.cpu],
    main: "lib.js",
    license: "MIT",
    repository: {
      type: "git",
      url: "https://github.com/sardanioss/httpcloak",
    },
    publishConfig: {
      access: "public",
    },
  };

  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(packageJson, null, 2) + "\n"
  );

  // Create lib.js that exports the library path
  const libJs = `// Auto-generated - exports path to native library
const path = require("path");
module.exports = path.join(__dirname, "${platform.libName}");
`;
  fs.writeFileSync(path.join(pkgDir, "lib.js"), libJs);

  console.log(`Created: @httpcloak/${platform.name}`);
}

// Create optionalDependencies for main package
const optionalDeps = {};
for (const platform of PLATFORMS) {
  optionalDeps[`@httpcloak/${platform.name}`] = VERSION;
}

console.log("\nAdd to main package.json optionalDependencies:");
console.log(JSON.stringify(optionalDeps, null, 2));

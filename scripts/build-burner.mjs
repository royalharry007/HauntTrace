// Builds HauntTrace's controlled test process and places it where Tauri
// expects sidecar binaries (src-tauri/binaries/<name>-<target-triple>.exe).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const release = process.argv.includes("--release");
const root = join(import.meta.dirname, "..", "src-tauri");
const triple = execFileSync("rustc", ["--print", "host-tuple"], { encoding: "utf8" }).trim();
execFileSync("cargo", ["build", "-p", "haunt-burner", ...(release ? ["--release"] : [])], { cwd: root, stdio: "inherit" });
mkdirSync(join(root, "binaries"), { recursive: true });
const src = join(root, "target", release ? "release" : "debug", "haunt-burner.exe");
const dst = join(root, "binaries", `haunt-burner-${triple}.exe`);
copyFileSync(src, dst);
console.log(`haunt-burner -> ${dst}`);

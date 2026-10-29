// Fails if anything that looks like a credential is present in the
// repository sources or in the built frontend bundle, or if the frontend
// bundle talks to ElevenLabs directly (it must only go through the backend).
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const root = join(import.meta.dirname, "..");
const skipDirs = new Set(["node_modules", "target", ".git", "gen", "icons", "binaries"]);
const patterns = [
  { name: "ElevenLabs-style key", re: /\bsk_[a-f0-9]{40,}\b/i },
  { name: "hard-coded api key assignment", re: /(api[_-]?key|xi-api-key|secret|token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{24,}["']/i },
  { name: "private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
];
const findings = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) {
      if (!skipDirs.has(name)) walk(p);
    } else if (s.size < 2_000_000 && !/\.(png|ico|icns|lock|db)$/i.test(name) && name !== "package-lock.json") {
      const text = readFileSync(p, "utf8");
      for (const { name: kind, re } of patterns) {
        if (re.test(text)) findings.push(`${relative(root, p)}: ${kind}`);
      }
    }
  }
}

walk(root);
const dist = join(root, "dist");
if (existsSync(dist)) {
  for (const f of readdirSync(join(dist, "assets"))) {
    const text = readFileSync(join(dist, "assets", f), "utf8");
    if (/api\.elevenlabs\.io/i.test(text)) findings.push(`dist/assets/${f}: frontend calls ElevenLabs directly`);
    if (/xi-api-key/i.test(text)) findings.push(`dist/assets/${f}: ElevenLabs header in frontend bundle`);
  }
}
if (findings.length) {
  console.error("Possible secrets found:\n" + findings.join("\n"));
  process.exit(1);
}
console.log(`No secrets found in repository sources${existsSync(dist) ? " or the frontend bundle" : ""}.`);

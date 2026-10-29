// Small, pure formatting helpers (unit-tested in format.test.ts).

export function formatBytes(b: number | null | undefined): string {
  if (b == null || !isFinite(b)) return "—";
  if (b < 1024 * 1024) return `${Math.round(b / 1024)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(b < 10 * 1024 ** 2 ? 1 : 0)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms == null || !isFinite(ms) || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function formatPercent(v: number | null | undefined, digits = 1): string {
  if (v == null || !isFinite(v)) return "—";
  return `${v.toFixed(digits)}%`;
}

export function timeAgo(ms: number, now = Date.now()): string {
  const d = Math.max(0, now - ms);
  if (d < 45_000) return "just now";
  if (d < 3_600_000) return `${Math.round(d / 60_000)} min ago`;
  if (d < 86_400_000) return `${Math.round(d / 3_600_000)} h ago`;
  return `${Math.round(d / 86_400_000)} d ago`;
}

export function clockTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTime(ms: number): string {
  return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export function minutesToHHMM(min: number): string {
  const h = Math.floor(min / 60) % 24;
  const m = min % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

export function hhmmToMinutes(s: string): number {
  const [h, m] = s.split(":").map((x) => parseInt(x, 10));
  if (!isFinite(h) || !isFinite(m)) return 0;
  return ((h % 24) * 60 + (m % 60) + 1440) % 1440;
}

/** Split text into plain segments and evidence references like "E3". */
export function splitEvidenceRefs(text: string): { text: string; ref?: string }[] {
  const out: { text: string; ref?: string }[] = [];
  const re = /\bE\d{1,3}\b/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index! > last) out.push({ text: text.slice(last, m.index) });
    out.push({ text: m[0], ref: m[0] });
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

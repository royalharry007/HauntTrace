import { useEffect, useState } from "react";
import { api, errorText, type SweepEntry } from "../lib/api";
import { formatBytes, formatPercent } from "../lib/format";
import { Sprite } from "../components/Sprite";
import { useApp } from "../components/ui";

/** "Why is my PC slow right now?" The busiest programs this moment, without
 * waiting for a rule. Tap one to deal with it like any other spirit. */
export function Sweep({ onClose }: { onClose: () => void }) {
  const { toast, openSpirit, status } = useApp();
  const [rows, setRows] = useState<SweepEntry[] | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  useEffect(() => {
    api.sweepHouse().then(setRows).catch((e) => toast(errorText(e), true));
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toast, onClose]);

  async function pick(r: SweepEntry) {
    setBusy(r.pid);
    try {
      openSpirit(await api.summonSpirit(r.pid, r.created));
    } catch (e) {
      toast(errorText(e), true);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="sheet-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="sheet" role="dialog" aria-modal="true" aria-label="Sweep the house">
        <button className="x" onClick={onClose} aria-label="Close">✕</button>
        <h2>Who's in the house right now</h2>
        <p className="dim">
          Your PC is using {formatPercent(status?.cpu_total, 0)} CPU
          {status?.memory_used_pct != null && <> and {Math.round(status.memory_used_pct)}% of its memory</>}. Tap one to see who it is and what to do.
        </p>
        {!rows ? (
          <p className="dim">Sweeping…</p>
        ) : rows.length === 0 ? (
          <p>Nothing busy at all. The house is quiet.</p>
        ) : (
          <ul className="sweep-list">
            {rows.map((r) => (
              <li key={`${r.pid}-${r.created}`}>
                <button className="ledger-row" disabled={busy !== null} onClick={() => pick(r)}>
                  <Sprite kind="shade" size={32} />
                  <span className="who">
                    <span className="proc">{r.name}</span>
                    <span className="habit">{r.why === "cpu" ? `${formatPercent(r.cpu)} CPU · ${formatBytes(r.private_bytes)}` : `${formatBytes(r.private_bytes)} memory · ${formatPercent(r.cpu)} CPU`}</span>
                  </span>
                  <span className={`meter-pill ${r.why}`}>{r.why === "cpu" ? "BUSY" : "BIG"}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="dim">Busy isn't bad: games, builds, video calls and browsers work hard on purpose.</p>
      </div>
    </div>
  );
}

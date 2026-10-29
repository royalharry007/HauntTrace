import { useMemo } from "react";
import { api, errorText, type Alert } from "../lib/api";
import { timeAgo } from "../lib/format";
import { Sprite, spiritFor } from "../components/Sprite";
import { useApp } from "../components/ui";

const ACTIVE = new Set(["new", "investigating", "investigated"]);
const MAX_AGE_MS = 12 * 3600_000;

export const spiritKey = (a: Alert) => `${a.process_name.toLowerCase()}|${a.rule}`;

/** Bad spirits currently in the house: recent, unresolved, one per process + habit. */
export function activeSpirits(alerts: Alert[]): Alert[] {
  const seen = new Set<string>();
  const out: Alert[] = [];
  for (const a of alerts) {
    if (!ACTIVE.has(a.status) || Date.now() - a.created_ms > MAX_AGE_MS || seen.has(spiritKey(a))) continue;
    seen.add(spiritKey(a));
    out.push(a);
  }
  return out.slice(0, 6);
}

// Where spirits float in the room (percent of the room box).
const SLOTS = [
  { left: 52, top: 10 },
  { left: 72, top: 30 },
  { left: 36, top: 40 },
  { left: 56, top: 50 },
  { left: 36, top: 4 },
  { left: 74, top: 2 },
];

export function House({ leaving }: { leaving: Record<string, string> }) {
  const { status, alerts, toast, refresh, openSpirit, openSweep, modelReady } = useApp();
  const spirits = useMemo(() => activeSpirits(alerts), [alerts]);
  const guarding = !!status?.monitoring;
  const hunting = !!status?.active_investigations.length;
  const level = guarding ? status?.haunt_level ?? 0 : 0;

  async function wake() {
    try {
      await api.setMonitoring(true);
      refresh();
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  async function summon() {
    try {
      await api.launchTestProcess("cpu", 240);
      toast("A practice Poltergeist is moving in. I'll spot it in about a minute.");
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  const headline = !guarding
    ? "The guardian is asleep"
    : spirits.length
      ? `${spirits.length} spirit${spirits.length > 1 ? "s" : ""} stirring`
      : ["The house is calm", "The house feels uneasy", "The house feels heavy"][level];
  const line = !guarding
    ? "Wake me and I'll watch for spirits that slow your PC down."
    : hunting
      ? "I'm out with my lantern, looking for clues…"
      : spirits.length
        ? "Tap a spirit and we'll deal with it together."
        : level > 0
          ? "Your PC is working hard. Sweep the house to see who's busy."
          : `Nothing's bothering your PC. I'm watching ${status?.process_count ?? "your"} programs.`;

  return (
    <div className="house">
      <div className={`room mood-${level}${spirits.length ? " haunted" : ""}`}>
        <div className="window" aria-hidden="true"><span className="moon" /></div>
        <div className="candle" aria-hidden="true"><span className="flame" /></div>
        <div className={`guardian${hunting ? " hunting" : ""}`}>
          <Sprite kind="guardian" size={88} sleepy={!guarding} lantern={hunting} title={guarding ? "Your guardian ghost" : "Your guardian ghost, asleep"} />
          {!guarding && <span className="zzz" aria-hidden="true">z z</span>}
        </div>
        {spirits.map((a, i) => {
          const s = spiritFor(a.rule);
          const slot = SLOTS[i % SLOTS.length];
          const big = (a.metrics.cpu_avg ?? 0) > 25 || a.priority === "warning";
          return (
            <button
              key={a.id}
              className={`spirit-float ${leaving[spiritKey(a)] ? `leave-${leaving[spiritKey(a)]}` : ""}`}
              style={{ left: `${slot.left}%`, top: `${slot.top}%`, animationDelay: `${i * 0.7}s` }}
              onClick={() => openSpirit(a.id)}
              title={`${s.name}: ${a.process_name}`}
            >
              <Sprite kind={s.kind} size={big ? 64 : 48} />
              <span className="tag">{a.process_name}</span>
            </button>
          );
        })}
        <div className="floor" aria-hidden="true" />
      </div>

      <section className="speech">
        <h1>{headline}</h1>
        <p>{line}</p>
        {guarding && status && <HauntMeter cpu={status.cpu_total} mem={status.memory_used_pct} level={level} />}
        {!guarding ? (
          <button className="px-btn primary" onClick={wake}>Wake up</button>
        ) : (
          <button className="px-btn" onClick={openSweep}>🧹 Sweep the house</button>
        )}
        {guarding && modelReady === false && <p className="hint">My lantern needs a local AI brain. See Options.</p>}
      </section>

      <section className="ledger">
        <h2>Spirits in the house</h2>
        {spirits.length === 0 ? (
          <div className="empty">
            <p>None right now.</p>
            {guarding && <button className="px-btn" onClick={summon}>Practice: summon a test spirit</button>}
          </div>
        ) : (
          <ul>
            {spirits.map((a) => {
              const s = spiritFor(a.rule);
              return (
                <li key={a.id}>
                  <button className="ledger-row" onClick={() => openSpirit(a.id)}>
                    <Sprite kind={s.kind} size={36} />
                    <span className="who">
                      <strong>{s.name}</strong> <span className="proc">{a.process_name}</span>
                      <span className="habit">{s.habit} · {timeAgo(a.created_ms)}</span>
                    </span>
                    <span className={`chip ${a.status}`}>{a.status === "new" ? "NEW" : a.status === "investigating" ? "LOOKING" : "SEEN"}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}

export function Welcome({ onStart }: { onStart: () => void }) {
  return (
    <div className="house">
      <div className="room">
        <div className="window" aria-hidden="true"><span className="moon" /></div>
        <div className="candle" aria-hidden="true"><span className="flame" /></div>
        <div className="guardian center"><Sprite kind="guardian" size={104} title="Your guardian ghost" /></div>
        <div className="floor" aria-hidden="true" />
      </div>
      <section className="speech">
        <h1>Hi. I'm your guardian ghost.</h1>
        <p>
          Sometimes bad spirits move into a PC: programs that hog the CPU, gobble memory or refuse to stay closed. I watch for them, tell you who they
          are, and help you chase them off. Everything stays on this computer.
        </p>
        <div className="bestiary" aria-label="The spirits I watch for">
          {(["sustained_cpu", "repeated_spikes", "memory_growth", "repeated_restarts", "lingering"] as const).map((r) => {
            const s = spiritFor(r);
            return (
              <div key={r} className="beast">
                <Sprite kind={s.kind} size={40} />
                <strong>{s.name}</strong>
                <span>{s.habit}</span>
              </div>
            );
          })}
        </div>
        <button className="px-btn primary big" onClick={onStart}>Start guarding</button>
      </section>
    </div>
  );
}

/** How haunted the house feels: real total CPU and memory pressure. */
function HauntMeter({ cpu, mem, level }: { cpu: number; mem: number | null; level: 0 | 1 | 2 }) {
  const bar = (label: string, v: number) => (
    <div className="meter" aria-label={`${label} ${Math.round(v)} percent`}>
      <span className="meter-label">{label}</span>
      <span className="meter-track">
        {Array.from({ length: 10 }, (_, i) => <span key={i} className={i < Math.round(v / 10) ? `on l${level}` : ""} />)}
      </span>
      <span className="meter-val">{Math.round(v)}%</span>
    </div>
  );
  return (
    <div className="meters">
      {bar("CPU", cpu)}
      {mem != null && bar("MEM", mem)}
    </div>
  );
}

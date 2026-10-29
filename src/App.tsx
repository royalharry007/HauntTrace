import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, errorText, type Alert, type Status } from "./lib/api";
import { playNarration, setNarrationMuted } from "./lib/audio";
import { spiritFor } from "./components/Sprite";
import { Ctx, type AppContext } from "./components/ui";
import { House, Welcome } from "./views/House";
import { SpiritCard, type Exit } from "./views/SpiritCard";
import { Options } from "./views/Options";
import { Sweep } from "./views/Sweep";

interface ToastMsg {
  id: number;
  msg: string;
  error?: boolean;
}

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [toasts, setToasts] = useState<ToastMsg[]>([]);
  const [pulse, setPulse] = useState(0);
  const [modelReady, setModelReady] = useState<boolean | null>(null);
  const [setupDone, setSetupDone] = useState<boolean | null>(null);
  const [spiritId, setSpiritId] = useState<string | null>(null);
  const [options, setOptions] = useState(false);
  const [sweep, setSweep] = useState(false);
  const [leaving, setLeaving] = useState<Record<string, Exit>>({});
  const [shake, setShake] = useState(false);
  const toastId = useRef(0);
  const statusRef = useRef<Status | null>(null);
  statusRef.current = status;

  const toast = useCallback((msg: string, error?: boolean) => {
    const id = ++toastId.current;
    setToasts((t) => [...t.slice(-2), { id, msg, error }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), error ? 7000 : 4000);
  }, []);

  const refresh = useCallback(() => {
    api.status().then((s) => {
      setStatus(s);
      setNarrationMuted(s.muted);
    }).catch(() => {});
    api.alerts(60).then(setAlerts).catch(() => {});
    setPulse((p) => p + 1);
  }, []);

  const checkModel = useCallback(() => {
    api.modelDiagnostics(false).then((d) => setModelReady(d.runtime_reachable && d.selected_model_available)).catch(() => setModelReady(false));
  }, []);

  const speak = useCallback((text: string) => {
    const s = statusRef.current;
    if (!s?.voice_enabled || s.muted || !text.trim()) return;
    api.speakText(text).then((b) => playNarration(b)).catch((e) => toast(`Voice: ${errorText(e)}`, true));
  }, [toast]);

  const openSpirit = useCallback((id: string) => {
    setOptions(false);
    setSweep(false);
    setSpiritId(id);
  }, []);
  const openOptions = useCallback(() => {
    setSpiritId(null);
    setSweep(false);
    setOptions(true);
  }, []);
  const openSweep = useCallback(() => {
    setSpiritId(null);
    setOptions(false);
    setSweep(true);
  }, []);

  // A spirit leaves with a little animation, then the house refreshes.
  const onExit = useCallback((key: string, how: Exit) => {
    setLeaving((l) => ({ ...l, [key]: how }));
    setTimeout(() => {
      refresh();
      setLeaving((l) => {
        const n = { ...l };
        delete n[key];
        return n;
      });
    }, 1100);
  }, [refresh]);

  useEffect(() => {
    // Notification buttons (or the tray) can ask to open a specific spirit.
    const goTo = async ({ view, id }: { view: string; id: string }) => {
      if (view === "haunting") return openSpirit(id);
      if (view === "investigation") {
        try {
          openSpirit((await api.investigation(id)).investigation.alert_id);
        } catch {}
      }
    };
    api.takePendingNavigation().then((p) => p && goTo(p)).catch(() => {});
    api.setupCompleted().then(setSetupDone).catch(() => setSetupDone(true));
    refresh();
    checkModel();
    const unsubs = [
      listen<Alert>("alert://new", (e) => {
        setAlerts((a) => [e.payload, ...a]);
        setShake(true);
        setTimeout(() => setShake(false), 700);
        speak(`A ${spiritFor(e.payload.rule).name} has moved in.`);
      }),
      listen("status://changed", () => refresh()),
      listen("settings://changed", () => { refresh(); checkModel(); }),
      listen("investigation://started", () => refresh()),
      listen("investigation://step", () => setPulse((p) => p + 1)),
      listen("investigation://evidence", () => setPulse((p) => p + 1)),
      listen("investigation://done", () => refresh()),
      listen<{ view: string; id: string }>("ui://navigate", (e) => {
        goTo(e.payload);
        api.takePendingNavigation().catch(() => {});
      }),
      listen<{ muted: boolean }>("audio://mute", (e) => {
        setNarrationMuted(e.payload.muted);
        setStatus((s) => (s ? { ...s, muted: e.payload.muted } : s));
      }),
      listen<{ investigation_id: string }>("narration://ready", async (e) => {
        try {
          await playNarration(await api.narrationAudio(e.payload.investigation_id), e.payload.investigation_id);
        } catch (err) {
          toast(`Voice: ${errorText(err)}`, true);
        }
      }),
    ];
    const timer = setInterval(() => api.status().then(setStatus).catch(() => {}), 5000);
    return () => {
      clearInterval(timer);
      unsubs.forEach((u) => u.then((f) => f()));
    };
  }, [refresh, checkModel, toast, speak, openSpirit]);

  const ctx: AppContext = useMemo(
    () => ({ status, alerts, toast, refresh, pulse, modelReady, openSpirit, openOptions, openSweep, speak }),
    [status, alerts, toast, refresh, pulse, modelReady, openSpirit, openOptions, openSweep, speak],
  );

  async function toggleMute() {
    try {
      await api.setMuted(!status?.muted);
      refresh();
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  async function start() {
    try {
      await api.setMonitoring(true);
      await api.setSetupCompleted(true);
      setSetupDone(true);
      refresh();
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  return (
    <Ctx.Provider value={ctx}>
      <div className={`app${shake ? " shake" : ""}`}>
        <header className="bar">
          <span className="logo">HauntTrace</span>
          <span className="spacer" />
          <button className="icon" onClick={toggleMute} aria-pressed={!!status?.muted} title={status?.muted ? "Unmute" : "Mute sound and voice"}>{status?.muted ? "🔇" : "🔊"}</button>
          <button className="icon" onClick={openOptions} title="Options" aria-label="Options">☰</button>
        </header>
        <main>{setupDone === false ? <Welcome onStart={start} /> : setupDone && <House leaving={leaving} />}</main>
      </div>
      {spiritId && <SpiritCard alertId={spiritId} onClose={() => setSpiritId(null)} onExit={onExit} />}
      {sweep && <Sweep onClose={() => setSweep(false)} />}
      {options && <Options onClose={() => { setOptions(false); checkModel(); }} />}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast${t.error ? " error" : ""}`}>{t.msg}</div>)}
      </div>
    </Ctx.Provider>
  );
}

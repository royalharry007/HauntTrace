import { useEffect, useState } from "react";
import { api, errorText, type ModelDiagnostics, type Settings, type VoiceMode } from "../lib/api";
import { playNarration } from "../lib/audio";
import { Switch, useApp } from "../components/ui";

const VOICES: { mode: VoiceMode; label: string; note: string }[] = [
  { mode: "off", label: "Silent", note: "Spooky sound and text only" },
  { mode: "windows", label: "Windows", note: "Built-in voice, works offline" },
  { mode: "elevenlabs", label: "ElevenLabs", note: "Natural voice, needs your API key" },
];

/** Everything a normal person needs to change, on one short page. */
export function Options({ onClose }: { onClose: () => void }) {
  const { toast, refresh } = useApp();
  const [s, setS] = useState<Settings | null>(null);
  const [brain, setBrain] = useState<ModelDiagnostics | null>(null);
  const [keySaved, setKeySaved] = useState(false);
  const [key, setKey] = useState("");
  const [winVoices, setWinVoices] = useState<string[]>([]);
  const [elVoices, setElVoices] = useState<{ voice_id: string; name: string }[]>([]);

  useEffect(() => {
    api.settings().then(setS);
    api.voiceStatus().then((v) => setKeySaved(v.key_saved)).catch(() => {});
    api.modelDiagnostics(false).then(setBrain).catch(() => {});
  }, []);
  useEffect(() => {
    if (s?.voice.mode === "windows" && !winVoices.length) api.windowsVoices().then(setWinVoices).catch(() => {});
    if (s?.voice.mode === "elevenlabs" && keySaved && !elVoices.length) api.elevenlabsVoices().then(setElVoices).catch((e) => toast(errorText(e), true));
  }, [s?.voice.mode, keySaved, winVoices.length, elVoices.length, toast]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!s) return null;

  async function change(f: (x: Settings) => void) {
    const next = structuredClone(s!);
    f(next);
    setS(next);
    try {
      setS(await api.saveSettings(next));
      refresh();
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  async function saveKey() {
    try {
      await api.saveVoiceKey(key);
      setKey("");
      setKeySaved(true);
      toast("Key saved in Windows Credential Manager.");
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  async function forgetKey() {
    try {
      await api.clearVoiceKey();
      setKeySaved(false);
      setElVoices([]);
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  async function testVoice() {
    try {
      await playNarration(await api.testVoice());
    } catch (e) {
      toast(errorText(e), true);
    }
  }

  const brainOk = brain?.runtime_reachable && brain.selected_model_available;

  return (
    <div className="sheet-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="sheet" role="dialog" aria-modal="true" aria-label="Options">
        <button className="x" onClick={onClose} aria-label="Close">✕</button>
        <h2>Options</h2>

        <section className="opt">
          <Switch on={s.monitoring.enabled} onChange={(v) => change((x) => (x.monitoring.enabled = v))} label="Guard my PC" />
          <Switch on={s.alerts.sound_enabled} onChange={(v) => change((x) => (x.alerts.sound_enabled = v))} label="Spooky alert sound" />
          <Switch on={s.alerts.notifications_enabled} onChange={(v) => change((x) => (x.alerts.notifications_enabled = v))} label="Windows notifications" />
        </section>

        <section className="opt">
          <h3>Guardian's voice</h3>
          <div className="voice-row">
            {VOICES.map((v) => (
              <button key={v.mode} className={`pick${s.voice.mode === v.mode ? " on" : ""}`} onClick={() => change((x) => (x.voice.mode = v.mode))} aria-pressed={s.voice.mode === v.mode}>
                <strong>{v.label}</strong>
                <span>{v.note}</span>
              </button>
            ))}
          </div>
          {s.voice.mode === "windows" && winVoices.length > 0 && (
            <select value={s.voice.windows_voice} onChange={(e) => change((x) => (x.voice.windows_voice = e.target.value))} aria-label="Windows voice">
              <option value="">System default</option>
              {winVoices.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          )}
          {s.voice.mode === "elevenlabs" && (
            <div className="stack">
              {keySaved ? (
                <p className="dim">API key saved in Windows Credential Manager. <button className="link" onClick={forgetKey}>Remove it</button></p>
              ) : (
                <form className="inline" onSubmit={(e) => { e.preventDefault(); saveKey(); }}>
                  <input type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder="Paste your ElevenLabs API key" autoComplete="off" aria-label="ElevenLabs API key" />
                  <button className="px-btn" disabled={key.trim().length < 10}>Save</button>
                </form>
              )}
              {keySaved && (
                <select value={s.voice.voice_id} onChange={(e) => change((x) => (x.voice.voice_id = e.target.value))} aria-label="ElevenLabs voice">
                  <option value="">Pick a voice…</option>
                  {elVoices.map((v) => <option key={v.voice_id} value={v.voice_id}>{v.name}</option>)}
                </select>
              )}
              <p className="dim">Only the short line the guardian says is sent to ElevenLabs. Never your process list.</p>
            </div>
          )}
          {s.voice.mode !== "off" && <button className="px-btn" onClick={testVoice}>Test voice</button>}
        </section>

        <section className="opt">
          <h3>Lantern (local AI)</h3>
          {!brain ? (
            <p className="dim">Checking…</p>
          ) : brainOk ? (
            <p>✓ {brain.selected_model} is ready on this PC. Investigations never leave your computer.</p>
          ) : (
            <>
              <p>The lantern needs Ollama with a Gemma model. Without it I still spot spirits and check who made them.</p>
              <p className="dim">1. Install Ollama from ollama.com · 2. Run <code>ollama pull {s.model.model}</code></p>
              <button className="px-btn" onClick={() => api.modelDiagnostics(false).then(setBrain)}>Check again</button>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

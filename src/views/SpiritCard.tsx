import { useCallback, useEffect, useState } from "react";
import { api, errorText, type AlertView, type ChatTurn, type Identity, type InvestigationDetail } from "../lib/api";
import { Sprite, spiritFor } from "../components/Sprite";
import { useApp } from "../components/ui";
import { spiritKey } from "./House";

export type Exit = "befriend" | "shoo" | "banish";

/** One bad spirit up close: who it really is, what the guardian found, and
 * the four things you can do about it. Nothing happens unless you choose it. */
export function SpiritCard({ alertId, onClose, onExit }: { alertId: string; onClose: () => void; onExit: (key: string, how: Exit) => void }) {
  const { status, alerts, toast, refresh, pulse, modelReady, speak } = useApp();
  const [view, setView] = useState<AlertView | null>(null);
  const [who, setWho] = useState<Identity | null>(null);
  const [whoErr, setWhoErr] = useState<string | null>(null);
  const [inv, setInv] = useState<InvestigationDetail | null>(null);
  const [proof, setProof] = useState(false);
  const [confirmBanish, setConfirmBanish] = useState(false);
  const [busy, setBusy] = useState(false);
  const [question, setQuestion] = useState("");
  const [talk, setTalk] = useState<ChatTurn[]>([]);
  const [asking, setAsking] = useState(false);

  const load = useCallback(() => {
    api.alert(alertId).then((v) => {
      setView(v);
      if (v.alert.investigation_id) api.investigation(v.alert.investigation_id).then(setInv).catch(() => {});
    }).catch((e) => toast(errorText(e), true));
  }, [alertId, toast]);
  useEffect(load, [load, pulse]);
  useEffect(() => {
    api.spiritIdentity(alertId).then(setWho).catch((e) => setWhoErr(errorText(e)));
  }, [alertId]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!view) return null;
  const a = view.alert;
  const s = spiritFor(a.rule);
  const alive = !!view.live?.alive;
  const running = status?.active_investigations.find((r) => r.alert_id === a.id);
  const report = inv?.investigation.status === "completed" ? inv.investigation.report : null;
  const lastStep = inv?.steps[inv.steps.length - 1];
  const evTitle = (id: string) => inv?.evidence.find((e) => e.evidence_id === id)?.title ?? id;

  /** Close this spirit everywhere it appears (all open alerts for the same process + habit). */
  async function resolve(how: Exit) {
    const key = spiritKey(a);
    await Promise.all(alerts.filter((x) => spiritKey(x) === key && x.status !== "dismissed").map((x) => api.dismissAlert(x.id).catch(() => {})));
    onClose();
    onExit(key, how);
  }

  async function act(fn: () => Promise<unknown>, how: Exit | null, ok: string) {
    setBusy(true);
    try {
      await fn();
      toast(ok);
      if (how) await resolve(how);
      else {
        load();
        refresh();
      }
    } catch (e) {
      toast(errorText(e), true);
    } finally {
      setBusy(false);
    }
  }

  async function ask() {
    const q = question.trim();
    if (!q || asking) return;
    const history = talk;
    setTalk([...history, { role: "you", text: q }]);
    setQuestion("");
    setAsking(true);
    try {
      const reply = await api.askGhost(q, a.id, history);
      setTalk((t) => [...t, { role: "ghost", text: reply }]);
      speak(reply);
    } catch (e) {
      setTalk((t) => [...t, { role: "ghost", text: `(My lantern flickered: ${errorText(e)})` }]);
    } finally {
      setAsking(false);
    }
  }

  return (
    <div className="sheet-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="sheet" role="dialog" aria-modal="true" aria-label={`${s.name}: ${a.process_name}`}>
        <button className="x" onClick={onClose} aria-label="Close">✕</button>

        <header className="card-head">
          <div className="portrait"><Sprite kind={s.kind} size={72} /></div>
          <div>
            <h2>{s.name}</h2>
            <p className="big-line"><span className="proc">{a.process_name}</span> {s.habit}.</p>
            <p className="dim">{a.reason}</p>
            {!alive && <p className="dim">It has already left the house.</p>}
          </div>
        </header>

        <section className={`who-box ${who ? (who.known ? "known" : "unknown") : ""}`}>
          {!who && !whoErr && <p className="dim">Checking who made it…</p>}
          {whoErr && <p className="dim">I couldn't check its file: {whoErr}</p>}
          {who && (
            <>
              <h3>{who.known ? "✓ Known spirit" : "? Unknown spirit"}</h3>
              <p>
                <strong>{who.title}</strong>
                {who.maker && <> by {who.maker}{!who.maker_verified && " (not verified)"}</>}
                {who.place !== "hidden" && <>, lives in {who.place}</>}.
              </p>
              <p className="dim">{who.note}</p>
            </>
          )}
        </section>

        {(running || report || inv?.investigation.status === "failed") && (
          <section className="lantern-box">
            {running ? (
              <div className="searching">
                <Sprite kind="guardian" size={40} lantern />
                <div>
                  <h3>Searching with my lantern…</h3>
                  <p className="dim">{lastStep ? lastStep.title : "Gathering the first clues"}</p>
                </div>
              </div>
            ) : report ? (
              <>
                <h3>What my lantern found</h3>
                <p className="finding">{report.narration || report.finding}</p>
                <p className="dim">How sure I am: {report.confidence}.</p>
                <button className="link" onClick={() => setProof(!proof)}>{proof ? "Hide the proof" : "Show the proof"}</button>
                {proof && (
                  <div className="proof">
                    <p>{report.finding}</p>
                    <ul>
                      {report.observed_facts.map((f, i) => (
                        <li key={i}>{f.statement} <span className="dim">({f.evidence_ids.map(evTitle).join(", ")})</span></li>
                      ))}
                    </ul>
                    {report.unknowns.length > 0 && <p className="dim">Still unknown: {report.unknowns.join(" · ")}</p>}
                    <p className="dim">Checked by {report.generated_by}. Unusual activity is never proof of anything malicious.</p>
                  </div>
                )}
              </>
            ) : (
              <p className="dim">My lantern went out: {inv?.investigation.error ?? "the search didn't finish"}.</p>
            )}
          </section>
        )}

        {confirmBanish ? (
          <section className="confirm">
            <p>Banish <strong>{a.process_name}</strong>? It closes right now, and anything unsaved in it is lost.</p>
            <div className="actions">
              <button className="px-btn danger" disabled={busy} onClick={() => act(() => api.terminate(a.id, a.process_name), "banish", `${a.process_name} has been banished.`)}>Yes, banish it</button>
              <button className="px-btn" onClick={() => setConfirmBanish(false)}>No</button>
            </div>
          </section>
        ) : (
          <div className="actions">
            {running ? (
              <button className="px-btn" disabled={busy} onClick={() => act(() => api.cancelInvestigation(running.investigation_id), null, "Lantern put away.")}>Stop looking</button>
            ) : (
              <button className="px-btn primary" disabled={busy} onClick={() => act(() => api.investigate(a.id), null, "Lighting my lantern…")} title="The guardian investigates with the local AI">🏮 {report ? "Look again" : "Lantern"}</button>
            )}
            <button className="px-btn" disabled={busy} onClick={() => act(() => api.exclude(a.id, false), "befriend", `${a.process_name} is a friend now. I won't bother you about it again.`)} title="Trust it: never flag this program again">Befriend</button>
            <button className="px-btn" disabled={busy} onClick={() => act(() => api.snooze(a.id, 60), "shoo", `Shooed ${a.process_name} for an hour.`)} title="Ignore it for one hour">Shoo 1h</button>
            {alive && <button className="px-btn danger" disabled={busy} onClick={() => setConfirmBanish(true)} title="End the process">Banish</button>}
          </div>
        )}

        {modelReady && (
          <section className="ask">
            {talk.map((t, i) => <p key={i} className={`say ${t.role}`}>{t.role === "ghost" ? "👻 " : "› "}{t.text}</p>)}
            {asking && <p className="say ghost dim">👻 hmm…</p>}
            <form onSubmit={(e) => { e.preventDefault(); ask(); }}>
              <input value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={500} placeholder="Ask the guardian about it…" aria-label="Ask the guardian" />
              <button className="px-btn" disabled={!question.trim() || asking}>Ask</button>
            </form>
          </section>
        )}
      </div>
    </div>
  );
}

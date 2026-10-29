import { createContext, useContext, type ReactNode } from "react";
import type { Alert, Status } from "../lib/api";

export interface AppContext {
  status: Status | null;
  alerts: Alert[];
  toast: (msg: string, error?: boolean) => void;
  refresh: () => void;
  /** Increments on every backend event, so views can re-fetch. */
  pulse: number;
  modelReady: boolean | null;
  openSpirit: (alertId: string) => void;
  openOptions: () => void;
  openSweep: () => void;
  /** Say a line in the guardian's voice when a voice is set up and sound is on. */
  speak: (text: string) => void;
}

export const Ctx = createContext<AppContext>(null!);
export const useApp = () => useContext(Ctx);

export function Switch({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: ReactNode }) {
  return (
    <button className={`switch${on ? " on" : ""}`} role="switch" aria-checked={on} onClick={() => onChange(!on)}>
      <span className="switch-label">{label}</span>
      <span className="switch-box">{on ? "ON" : "OFF"}</span>
    </button>
  );
}

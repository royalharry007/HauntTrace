// Typed wrappers around the Rust command surface. The UI never touches the
// system directly; every action goes through a validated backend command.
import { invoke } from "@tauri-apps/api/core";

export type GhostState = "quiet" | "watching" | "investigating";

export interface Status {
  ghost: GhostState;
  monitoring: boolean;
  muted: boolean;
  active_investigations: { investigation_id: string; alert_id: string }[];
  process_count: number;
  last_sample_ms: number;
  interval_secs: number;
  voice_enabled: boolean;
  cpu_total: number;
  memory_used_pct: number | null;
  /** 0 calm · 1 uneasy · 2 haunted */
  haunt_level: 0 | 1 | 2;
}

export interface SweepEntry {
  pid: number;
  created: string;
  name: string;
  exe_path: string | null;
  cpu: number;
  private_bytes: number;
  why: "cpu" | "memory";
}

export interface AlertMetrics {
  cpu_latest?: number | null;
  cpu_avg?: number | null;
  cpu_peak?: number | null;
  private_bytes?: number | null;
  working_set?: number | null;
  runtime_ms?: number | null;
  samples?: number;
  logical_cpus?: number;
}

export interface Alert {
  id: string;
  created_ms: number;
  rule: string;
  rule_label: string;
  priority: "info" | "warning";
  pid: number;
  process_created: string;
  process_name: string;
  exe_path: string | null;
  reason: string;
  metrics: AlertMetrics;
  details: Record<string, unknown> | null;
  delivery: { kind: "notify"; sound: boolean } | { kind: "silent"; reason: string } | null;
  status: "new" | "investigating" | "investigated" | "dismissed" | "cancelled";
  investigation_id: string | null;
  synthetic: boolean;
}

export interface LiveProcess {
  alive: boolean;
  exited_ms: number | null;
  runtime_ms: number | null;
  cpu_latest: number | null;
  cpu_avg_5min: number | null;
  private_bytes: number | null;
  working_set: number | null;
  logical_cpus: number;
  history: [number, number | null, number][];
}

export interface ActionRecord {
  created_ms: number;
  alert_id: string | null;
  investigation_id: string | null;
  action: string;
  detail: string;
  outcome: string;
}

export interface AlertView {
  alert: Alert;
  live: LiveProcess | null;
  actions: ActionRecord[];
  is_test_process: boolean;
  excluded: boolean;
}

export interface Step {
  seq: number;
  created_ms: number;
  kind: "packet" | "thinking" | "plan" | "tool" | "tool_rejected" | "report" | "note" | "error";
  title: string;
  payload: any;
}

export interface Evidence {
  evidence_id: string;
  created_ms: number;
  source: string;
  title: string;
  summary: string;
  data: unknown;
  synthetic: boolean;
}

export interface Linked {
  statement: string;
  evidence_ids: string[];
  linked: boolean;
}

export interface Report {
  finding: string;
  observed_facts: Linked[];
  unlinked_claims: Linked[];
  explanations: { explanation: string; likelihood: string; supporting: Linked[]; contradicting: Linked[] }[];
  unknowns: string[];
  confidence: "low" | "moderate" | "high";
  confidence_reason: string;
  next_steps: string[];
  narration: string;
  actions_performed: string[];
  generated_by: string;
  notes: string[];
}

export interface InvestigationRecord {
  id: string;
  alert_id: string;
  started_ms: number;
  finished_ms: number | null;
  status: "running" | "completed" | "cancelled" | "failed";
  model: string;
  deterministic: boolean;
  report: Report | null;
  error: string | null;
}

export interface InvestigationDetail {
  investigation: InvestigationRecord;
  alert: Alert | null;
  steps: Step[];
  evidence: Evidence[];
  actions: ActionRecord[];
}

export interface Settings {
  monitoring: { enabled: boolean; interval_secs: number };
  rules: {
    lingering: { enabled: boolean; runtime_minutes: number; min_avg_cpu: number; window_minutes: number };
    sustained_cpu: { enabled: boolean; cpu_percent: number; consecutive_samples: number; release_ratio: number };
    spikes: { enabled: boolean; spike_cpu_percent: number; min_spikes: number; window_minutes: number };
    memory_growth: { enabled: boolean; window_minutes: number; min_growth_percent: number; min_growth_mb: number };
    restarts: { enabled: boolean; min_restarts: number; window_minutes: number };
    cooldown_minutes: number;
  };
  alerts: {
    notifications_enabled: boolean;
    sound_enabled: boolean;
    volume: number;
    quiet_hours_enabled: boolean;
    quiet_start_min: number;
    quiet_end_min: number;
    min_interval_secs: number;
    max_per_hour: number;
  };
  exclusions: string[];
  model: { endpoint: string; model: string; max_steps: number; time_budget_secs: number; call_timeout_secs: number; keep_alive_minutes: number };
  voice: { mode: VoiceMode; windows_voice: string; voice_id: string; model_id: string; only_significant: boolean; cache_enabled: boolean };
  history: { retention_days: number; max_alerts: number };
}

export interface InstalledModel {
  name: string;
  size_bytes: number;
  parameter_size: string | null;
  quantization: string | null;
  family: string | null;
}

export interface ModelDiagnostics {
  endpoint: string;
  runtime_reachable: boolean;
  runtime_version: string | null;
  runtime_error: string | null;
  models: InstalledModel[];
  selected_model: string;
  selected_model_available: boolean;
  selected_model_loaded: boolean;
  test_ran: boolean;
  test_ok: boolean;
  test_latency_ms: number | null;
  test_error: string | null;
  total_ram_bytes: number | null;
  available_ram_bytes: number | null;
  resource_note: string | null;
}

export interface SuggestedModel {
  name: string;
  approx_download: string;
  note: string;
}

export type VoiceMode = "off" | "windows" | "elevenlabs";

export interface VoiceStatus {
  mode: VoiceMode;
  key_saved: boolean;
  voice_id_set: boolean;
}

export interface Diagnostics {
  version: string;
  monitor: {
    started_ms: number;
    samples: number;
    last_sample_ms: number;
    last_sample_duration_ms: number;
    avg_sample_duration_ms: number;
    process_count: number;
    last_error: string | null;
    alerts_raised: number;
    alerts_suppressed: number;
    self_cpu_percent: number | null;
    self_private_mb: number | null;
    self_working_set_mb: number | null;
  };
  store: { alerts: number; investigations: number; evidence: number; db_bytes: number };
  data_dir: string;
  log_path: string | null;
  logs: { t: number; level: string; event: string; data: unknown }[];
  logical_cpus: number;
  memory: { total_bytes: number; available_bytes: number } | null;
  is_elevated_hint: string;
}

export interface ChatTurn {
  role: "you" | "ghost";
  text: string;
}

export interface Identity {
  title: string;
  maker: string | null;
  maker_verified: boolean;
  place: string;
  known: boolean;
  note: string;
}

export const api = {
  status: () => invoke<Status>("get_status"),
  settings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),
  setMonitoring: (enabled: boolean) => invoke<void>("set_monitoring", { enabled }),
  setMuted: (muted: boolean) => invoke<void>("set_muted", { muted }),
  alerts: (limit = 100) => invoke<Alert[]>("list_alerts", { limit }),
  alert: (id: string) => invoke<AlertView>("get_alert", { id }),
  dismissAlert: (id: string) => invoke<void>("dismiss_alert", { id }),
  deleteAlert: (id: string) => invoke<void>("delete_alert", { id }),
  investigate: (alertId: string) => invoke<string>("start_investigation", { alertId }),
  cancelInvestigation: (id: string) => invoke<void>("cancel_investigation", { id }),
  investigation: (id: string) => invoke<InvestigationDetail>("get_investigation", { id }),
  investigations: (limit = 200) => invoke<InvestigationRecord[]>("list_investigations", { limit }),
  snooze: (alertId: string, minutes: number) => invoke<void>("snooze_process", { alertId, minutes }),
  snoozes: () => invoke<[string, number][]>("list_snoozes"),
  clearSnooze: (key: string) => invoke<void>("clear_snooze", { key }),
  exclude: (alertId: string, byPath: boolean) => invoke<Settings>("exclude_process", { alertId, byPath }),
  openLocation: (alertId: string) => invoke<void>("open_file_location", { alertId }),
  terminate: (alertId: string, confirmName: string) => invoke<string>("terminate_process", { alertId, confirmName }),
  testSound: (warning: boolean) => invoke<void>("test_sound", { warning }),
  modelDiagnostics: (runTest: boolean) => invoke<ModelDiagnostics>("model_diagnostics", { runTest }),
  suggestedModels: () => invoke<SuggestedModel[]>("suggested_models"),
  pullModel: (model: string) => invoke<void>("pull_model", { model }),
  cancelPull: () => invoke<void>("cancel_pull"),
  voiceStatus: () => invoke<VoiceStatus>("voice_status"),
  saveVoiceKey: (key: string) => invoke<void>("save_voice_key", { key }),
  clearVoiceKey: () => invoke<void>("clear_voice_key"),
  testVoice: () => invoke<ArrayBuffer>("test_voice"),
  narrationAudio: (investigationId: string) => invoke<ArrayBuffer>("narration_audio", { investigationId }),
  diagnostics: () => invoke<Diagnostics>("diagnostics"),
  deleteAllHistory: () => invoke<void>("delete_all_history"),
  launchTestProcess: (mode: string, seconds: number) => invoke<string>("launch_test_process", { mode, seconds }),
  windowsVoices: () => invoke<string[]>("windows_voices"),
  elevenlabsVoices: () => invoke<{ voice_id: string; name: string; category: string }[]>("elevenlabs_voices"),
  setupCompleted: () => invoke<boolean>("setup_completed"),
  setSetupCompleted: (done: boolean) => invoke<void>("set_setup_completed", { done }),
  askGhost: (question: string, alertId: string | null, history: ChatTurn[]) => invoke<string>("ask_ghost", { question, alertId, history }),
  speakText: (text: string) => invoke<ArrayBuffer>("speak_text", { text }),
  spiritIdentity: (alertId: string) => invoke<Identity>("spirit_identity", { alertId }),
  sweepHouse: () => invoke<SweepEntry[]>("sweep_house"),
  summonSpirit: (pid: number, created: string) => invoke<string>("summon_spirit", { pid, created }),
  takePendingNavigation: () => invoke<{ view: string; id: string } | null>("take_pending_navigation"),
};

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e);
}

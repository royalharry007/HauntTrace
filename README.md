# HauntTrace 👻

**A lightweight ghost in your system that spots lingering activity, warns you with a spooky alert, and shows you what's behind it.**

HauntTrace is a native Windows desktop app (Tauri 2 + Rust + React). Deterministic rules
watch process activity through Win32 APIs. When something lingers, a local alert and an
original spooky tone fire immediately. You can then press **Investigate**, and a **locally
running Gemma model** works through the evidence in a bounded, auditable loop. It requests
read-only checks, receives their real results, revises its hypotheses, and writes a report
in which every fact links back to collected evidence. ElevenLabs can optionally give the
ghost a voice.

Built for the Hacktoberfest Open-Source AI Challenge, Week 4: *Ghost in the Machine*.

> HauntTrace is an investigative assistant, **not antivirus software**. Unusual activity is not proof of anything malicious, and HauntTrace never says otherwise.

---

## Why open-weight AI matters here

- **Private by construction.** Process names, paths, parents and resource histories are sensitive. Gemma runs on your own hardware through Ollama. HauntTrace rejects any model address that is not loopback (`127.0.0.1`, `localhost`, `[::1]`), so evidence cannot be routed to a hosted LLM, even by misconfiguration.
- **Your hardware, your choice of model.** The model name is configurable: `gemma4:e2b-it-qat` by default, `gemma3:1b` for constrained laptops, or any compatible model your Ollama has.
- **Works offline.** Monitoring, alerts, the local sound, history, evidence collection and AI investigations all run without a network once the model is downloaded. Only the first model download and the optional ElevenLabs voice need connectivity.
- **Auditable.** Measurements come from deterministic code. The model can only *request* tools from a strict registry, and every request is validated, logged and shown in the trail, including the rejected ones.

## Features

| | |
| --- | --- |
| **Detection rules** | Sustained CPU, repeated spikes, memory growth, lingering activity (runtime **and** ongoing activity), and restart loops (a program running as a single copy that dies and respawns within 30 s; multi-process apps like browsers and on-demand shells and console hosts are ignored). Uses consecutive-sample requirements, hysteresis, per-process cooldowns, and configurable thresholds. |
| **Alerts** | Windows toast with **Investigate** / **Snooze 1 hour** buttons. An original synthesized tone (gentle for informational alerts, more pronounced for higher priority) with volume, mute, quiet hours, minimum interval, hourly cap, per-process snooze and trusted-app exclusions. |
| **Investigation engine** | Bounded loop (default 4 steps, 300 s budget, 15 s per tool, max 2 checks per step) with deduplication, rejection of invalid requests, cancellation at any time, and a deterministic fallback when the model is unavailable. |
| **Read-only tools** | `get_process_details`, `get_parent_process`, `get_resource_history`, `get_executable_metadata`, `get_digital_signature_status`, `get_related_processes`, `get_recent_process_events` |
| **Report** | Finding, evidence-linked facts, explanations with supporting and contradicting evidence, unknowns, calibrated confidence, safe next steps, and "actions performed" (set by the app, never the model). |
| **A guardian ghost vs. bad spirits** | Your PC is a small pixel-art haunted house with one guardian ghost in it. Each rule is a bad spirit whose name explains the behaviour: **Poltergeist** (won't stop rattling the CPU), **Banshee** (screams in CPU bursts), **Glutton** (keeps eating memory), **Revenant** (dies and keeps coming back), **Lingerer** (busy for hours, won't leave). Spirits float in the room; a list underneath says who they are. |
| **Sweep the house** | "Why is my PC slow *right now*?" One button lists the busiest programs this moment (top CPU, then top memory) without waiting for a rule. Tap one and it becomes a **Shade** you can inspect, light the lantern on, befriend, shoo or banish. |
| **Haunt meter** | The room follows real total CPU and memory pressure: calm, uneasy (faster candle flicker), or haunted (red, dim, flickering). Two pixel bars show the numbers. |
| **Who is this spirit?** | Tap a spirit to see who made it and where it lives, from the real file signature, version info and folder: *"✓ Known spirit · Google Chrome by Google LLC, lives in Program Files"* or *"? Unknown spirit … Unknown doesn't mean bad."* It never says "malware". |
| **Four moves** | **Lantern** (the guardian investigates with local Gemma and tells you what it found in plain words, with "Show the proof"), **Befriend** (trust it, never flag it again), **Shoo 1h** (snooze), **Banish** (end the process, after a second confirmation). Nothing happens unless you choose it. |
| **Ask the guardian** | A small box on each spirit card. Local Gemma answers **only from what HauntTrace recorded** about that spirit, says when it doesn't know, and cannot take actions. With a voice set up, it answers out loud. |
| **Voice modes** | **Silent**, **Windows** (built-in voices, offline, no key) or **ElevenLabs** (API key saved in Windows Credential Manager, voice list loaded from your account). Only the short spoken line is sent, sanitized. |
| **Options** | One short page: guard on/off, alert sound, notifications, voice, and whether the lantern (Ollama + Gemma) is ready. |

## Requirements

- Windows 10 or 11, x64. HauntTrace runs **without administrator rights**. Protected processes are reported as "access denied", never as suspicious.
- WebView2 runtime (preinstalled on Windows 11).
- For AI investigations: [Ollama](https://ollama.com/download) plus one model:

| Model | Download | Notes |
| --- | --- | --- |
| `gemma4:e2b-it-qat` (default) | ~4.3 GB | Good structured output. Comfortable with 8 GB+ RAM; uses a GPU if present. |
| `gemma3:1b` | ~0.8 GB | For constrained laptops. Faster, but weaker reasoning; invalid tool requests are rejected by the registry. |

Model size trades speed and memory for quality. HauntTrace never downloads a model by itself: Options → Lantern has an explicit **Download…** button with a confirmation. Without a model, alerts and evidence still work, and investigations run the standard checks and produce an evidence-only report.

## Install / run

**Downloads** (on the [Releases page](https://github.com/royalharry007/HauntTrace/releases), with `SHA256SUMS.txt`):

- `HauntTrace_0.1.0_x64-setup.exe`: per-user installer (no admin), Start-menu shortcut, uninstaller, registers the `haunttrace://` link used by notification buttons.
- `HauntTrace_0.1.0_x64-portable.zip`: unzip and run `HauntTrace.exe`; writes nothing to the registry.

**Installer:** run `HauntTrace_0.1.0_x64-setup.exe` (about 3.3 MB). Closing the window keeps the ghost watching from the tray; click the tray icon to reopen, or use its menu to pause monitoring, mute all sounds, or quit. Start with `--background` to launch straight to the tray.

**From source** (Node 20+, Rust stable with the MSVC toolchain, VS Build Tools with the C++ workload):

```powershell
npm install
npm run app:dev        # builds the test process, then runs the app in dev mode
npm run app:build      # release build + NSIS installer
```

Then, once only:

```powershell
ollama pull gemma4:e2b-it-qat     # or use the Download button in Options → Lantern
```

### Voice & API key (optional)

Options → *Guardian's voice* offers three modes. **Windows voice** needs no key and works offline. For **ElevenLabs**:

1. Choose *ElevenLabs*, paste your API key and press **Save**. It goes straight into **Windows Credential Manager** (`HauntTrace/ElevenLabs`). It is never written to files, never logged, and never sent back to the UI.
2. Pick a voice from the list loaded from your account.
3. Press **Test voice**.

Only the line the ghost is about to say (the narration sentence or a chat reply, clipped to 240 characters and sanitized to drop paths, `.exe` names, long numbers and alarmist claims) is sent to `api.elevenlabs.io`. No evidence, metrics or process lists are sent. If the key is missing, the network is down or the quota is hit, HauntTrace shows a short notice and carries on with the local sound and text.

## Architecture

```
            ┌───────────────────── Rust (src-tauri/src) ─────────────────────┐
 Win32 ───▶ │ collector/windows.rs   Toolhelp32, GetProcessTimes,            │
            │                        K32GetProcessMemoryInfo, image path     │
            │ collector/tracker.rs   identity = PID + creation time; CPU %   │
            │                        deltas; bounded history; start/exit     │
            │ detection.rs           5 rules, hysteresis, cooldowns          │
            │ alerts.rs              snooze, quiet hours, rate limits        │
            │ notify.rs, win/sound.rs  toast + synthesized tone (offline)    │
            │ investigation/         orchestrator ─ prompt ─ schema ─ tools  │
            │   tools.rs             strict registry + authorization         │
            │   provider.rs          live read-only evidence (tracker, Win32)│
            │ llm.rs                 Ollama adapter (loopback only)          │
            │ win/signature.rs       WinVerifyTrust (embedded + catalog)     │
            │ win/metadata.rs        version resource, file facts            │
            │ narration.rs           ElevenLabs adapter, cache               │
            │ store.rs               SQLite evidence store                   │
            │ app.rs / commands.rs   wiring + the UI's only command surface  │
            └──────────────────────────────▲──────────────────────────────────┘
                                           │ validated commands / events
            React + TypeScript (src/): House (pixel room + spirit list) · Spirit card · Options
            chat.rs: grounded "ask the guardian"   spirit.rs: who made it (signature, folder)
```

Every component sits behind a small interface (`ProcessSource`, `EvidenceProvider`, `ModelClient`, `Sink`) and is tested in isolation.

### The investigation loop

1. A rule produces a structured detection. It becomes an alert, and **E1** records exactly what the rule measured.
2. The engine adds **E2** (process details) and **E3** (recent resource history).
3. Gemma receives a compact, size-bounded evidence packet. It returns schema-constrained JSON: an assessment, hypotheses with evidence IDs, evidence gaps, up to 2 tool requests (`tool`, `pid`, optional `minutes`, `reason`), and `needs_more_investigation`.
4. **The registry validates each request.** The tool must be registered. The PID must already be authorized for this investigation: the subject, or a parent/child/sibling revealed by evidence, pinned to its creation time so a reused PID can never be inspected by mistake. Only `tool`, `pid`, `minutes` and `reason` are accepted, `minutes` must be in range, a reason is required, and duplicates are dropped. There is no tool that takes a path, URL, command or script; file checks run on the executable of the authorized process.
5. Valid checks run read-only with a timeout, and their results become new evidence. A failed check (e.g. access denied) is recorded as a limitation, not a red flag.
6. Gemma reassesses with the new evidence. Validated requests always run, and new evidence is always followed by a reassessment. The loop stops when the model requests no new permitted check, the step limit or time budget is reached, or you cancel.
7. Gemma writes the report. HauntTrace then validates it: facts must cite existing evidence IDs (others are demoted to **Unverified claims**), "high" confidence needs at least three linked facts, security-weakening steps are dropped, the narration is sanitized, and `actions_performed` is filled in by the app.

Malformed output is retried once with the parse error, then the engine falls back to an evidence-only report. Model text is never treated as authorization.

## Privacy & safety

- **Collected:** process name, PID, creation time, parent PID, session, image path, CPU time, memory counters; on investigation, the executable's version resource, size, dates and signature. **Not collected:** command lines, window titles, keystrokes, screenshots, browser data, documents.
- **Stored:** locally in `%APPDATA%\dev.haunttrace.app\haunttrace.db` (alerts, investigations, evidence, your actions). Raw samples are kept in memory only (30 min). Retention defaults to 30 days and 500 alerts.
- **Sent anywhere:** nothing, unless you enable voice; then only the narration sentence goes to ElevenLabs. Model prompts include `%USERPROFILE%`-redacted paths, even though they never leave the machine.
- **Logs:** JSON lines, size-capped, with user profile paths redacted and secrets never logged.
- **Actions:** HauntTrace never terminates, deletes, modifies services/startup/registry, or touches security software on its own. *End process* requires typing the process name, and re-verifies the PID's creation time immediately before terminating.
- **Frontend isolation:** a strict CSP, no Tauri plugins with filesystem or shell access, and every system action goes through a validated Rust command. `npm run check:secrets` verifies that the repo and built bundle contain no credentials and that the frontend never contacts ElevenLabs directly.

## Testing

```powershell
npm run test:rust        # 68 Rust tests
npm test                 # frontend unit tests (vitest)
npm run typecheck
npm run check:secrets    # after `npm run build`
cd src-tauri; cargo run --example live_demo   # real process + real Gemma, end to end
```

| Acceptance criterion | Covered by |
| --- | --- |
| Synthetic fixture triggers each rule | `detection::tests::*` (fixtures marked `synthetic`) |
| Thresholds behave predictably | `sustained_cpu_requires_consecutive_samples`, `..._dip_resets_the_count`, `stable_memory_does_not_trigger_growth`, `lingering_requires_runtime_and_activity` |
| PID reuse / exits keep identity | `tracker::pid_reuse_creates_a_distinct_instance`, `parent_is_not_assigned_from_a_reused_pid`, `detection::pid_reuse_does_not_carry_rule_state_to_new_process` |
| Cooldowns, snoozes, exclusions | `sustained_cpu_hysteresis_and_cooldown_prevent_spam`, `alerts::*`, `exclusions_suppress_detection` |
| Investigate gathers real evidence | `examples/live_demo.rs` (real burner, real Win32, real signature/metadata) |
| Gemma requests → receives → reassesses | `model_requests_a_check_receives_the_result_and_reassesses`, `requested_checks_run_and_are_reassessed_even_if_model_says_sufficient`, plus `live_demo` (passed 3/3 with `gemma4:e2b-it-qat` and 3/3 with `gemma3:1b` after the grammar caps) |
| Invalid tool requests rejected | `tools::tests::*`, `invalid_requests_are_rejected_and_never_executed`, `newly_discovered_parent_becomes_inspectable_but_others_do_not` |
| Malformed output is safe | `schema::malformed_output_is_an_error_not_a_panic`, `malformed_output_is_retried_then_falls_back_without_executing_anything` |
| Missing Gemma keeps monitoring/evidence | `unavailable_model_runs_standard_checks_and_deterministic_report`, `no_model_configured_still_produces_evidence_report` |
| Missing ElevenLabs credentials | `narration::missing_credentials_fail_gracefully_without_network` |
| Network failure | Detection, alerting, sound, store and model calls never use the internet; narration errors map to a notice (`NarrationError::Offline`) |
| No secrets in bundle/repo | `npm run check:secrets` |
| Cancellation | `cancellation_stops_the_investigation`, `time_budget_is_enforced`, `step_limit_is_enforced` |
| Findings traceable | `facts_without_valid_evidence_become_unlinked_claims`; the UI links every fact to its evidence |

See [docs/DEMO.md](docs/DEMO.md) for the reproducible demo, and [docs/settings.example.json](docs/settings.example.json) for every setting and its default.

## Measured overhead

Measured on an Intel i7-11700K (16 logical CPUs), 8 GB RAM, Windows 11, release build, default 5 s interval, about 300 processes, idle over 120 s after a 30 s warm-up (`TotalProcessorTime` and working set from Windows):

| State | CPU | Memory |
| --- | --- | --- |
| Monitoring from the tray (window closed) | **0.14% of one core** (0.009% of the machine) | 29 MB working set, 6 MB private; **0 WebView processes** |
| Window open | native process as above | plus ~330 MB across six `msedgewebview2.exe` processes |

That second row is why closing the window destroys the WebView instead of hiding it: the native monitor keeps running in the tray, and the window is recreated when you open it again.

- Each sampling pass (Toolhelp snapshot plus a limited-rights open of every process) is timed internally; the `diagnostics` backend command reports the last and average pass duration.
- Gemma is never running in the background. It is only called when you light the lantern, and Ollama unloads it after the configured keep-alive (5 min by default).
- Full investigations on a GTX 1660 Ti (6 GB), measured with `cargo run --example live_demo`: `gemma4:e2b-it-qat` took **69–97 s** (2–4 planning steps, 2–5 checks); `gemma3:1b` took **19–36 s**.
- Database writes happen only for alerts, investigation steps and actions; samples are never persisted.
- Numbers on your machine will differ.

## Limitations (honest list)

- **Short-lived processes** that start and exit between two samples (default 5 s) are invisible to the snapshot-based collector, so restart detection counts only instances that ran ≥ 10 s. ETW-based process tracing would close this gap but needs elevated rights.
- **Protected processes** (e.g. `System`, some anti-malware services) cannot be opened without elevation; their CPU, memory and path are reported as unavailable.
- **Signature checks** skip revocation (to stay offline), so a revoked-but-valid certificate shows as valid.
- **No per-process battery/energy figure.** Windows does not expose a reliable one to normal apps, so none is shown.
- **Model quality varies.** Small models can make weak or redundant requests (rejected by the registry) or over-confident claims (demoted, or confidence lowered). Before string-length caps were added to the decoding grammar, `gemma3:1b` sometimes looped inside a JSON string; HauntTrace then retried once and fell back to the evidence-only report. That fallback is still in place. The report is still an aid, not a verdict. `gemma3:1b` is noticeably weaker than the default.
- **Notification buttons.** In the installed build they use the installer-registered `haunttrace://` link, so they work from Notification Center, under Do Not Disturb, and even if HauntTrace was closed (verified on this machine). In the portable and dev builds HauntTrace never touches the registry, so the buttons work only while the banner is on screen; the spirit list in the app always works. With Windows Do Not Disturb on, banners and the alert banner sound stay hidden in Notification Center (HauntTrace's own tone still plays).
- **`haunttrace://` links are untrusted input.** They can only reference existing alerts, and can only start a read-only investigation, open the window, or snooze an alert raised in the last 2 hours.
- **Snoozes** are kept in memory and reset when HauntTrace restarts. Exclusions are persistent.
- **ElevenLabs narration was not verified end to end in this build environment** (no API key was available). The adapter, credential storage, voice listing, caching and error paths are implemented and unit-tested; the calls follow the documented `POST /v1/text-to-speech/{voice_id}` and `GET /v1/voices` APIs. The offline Windows voice was verified (it produces real WAV audio).
- The dev-dependency audit reports advisories in the Vite/esbuild dev server; runtime dependencies report 0 vulnerabilities (`npm audit --omit=dev`).

## Licenses

- HauntTrace: MIT (see [LICENSE](LICENSE)).
- Pixel fonts Silkscreen and VT323 (bundled via `@fontsource`): SIL Open Font License 1.1.
- The alert sound is synthesized by HauntTrace's own code at runtime (original audio, no samples).
- `gemma4:e2b-it-qat`: Apache 2.0. `gemma3:*`: Gemma Terms of Use. Check any model with `ollama show <model> --license`.
- ElevenLabs is a third-party service with its own terms; using it is optional.

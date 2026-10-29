# Reproducible demo

This walks through the guardian-vs-spirits loop on **real measurements** of a
**controlled test process** (`haunt-burner.exe`, shipped with HauntTrace). No
real problematic program is needed, and nothing in the flow is simulated.

## Before you start

1. Ollama is running and `gemma4:e2b-it-qat` is installed (Options → *Lantern* says it's ready).
2. Optional: Options → *Guardian's voice*: **Windows** (offline, no key) or **ElevenLabs** (save your key, pick a voice), then **Test voice**.
3. Sound is on (🔊 in the top bar).

## The sequence

1. **A calm house.** The guardian floats by the window; the headline says *The house is calm*.
2. **A spirit moves in.** With no spirits in the house, press **Practice: summon a test spirit**. The burner holds about 40% of total CPU.
3. **Alert.** After about 60 s the *Sustained CPU* rule fires: the room shakes, a red **Poltergeist** appears, the warning tone plays and a Windows notification shows. None of this depends on the model or the network.
4. **Who is it?** Tap the Poltergeist. The card shows who made the file, where it lives and whether its signature is valid ("? Unknown spirit … Unknown doesn't mean bad" for the unsigned test process).
5. **Lantern.** Press **🏮 Lantern**. The guardian picks up its lantern and the card shows each step live ("Searching with my lantern…"). Behind it, Gemma plans, requests read-only checks, gets their real results and reassesses.
6. **What it found.** A short plain-language finding with *How sure I am*, read aloud if a voice is set. **Show the proof** lists each fact with the evidence it came from, plus what is still unknown.
7. **Ask.** Type "Should I worry?". Gemma answers only from what was recorded.
8. **Chase it off.** **Banish** (confirm) ends the burner; the spirit bursts and leaves. **Befriend** and **Shoo 1h** are the gentler options.

## Headless verification of the same loop

```powershell
npm run build:burner
cd src-tauri
cargo run --example live_demo            # or: cargo run --example live_demo -- gemma3:1b
```

This prints the full transcript (rule → evidence → Gemma plan → executed checks →
reassessment → report). It exits non-zero unless Gemma requested at least one check,
received its real result, reassessed, and produced an AI report.

// Voice playback. One clip at a time; muting stops playback immediately.
// Audio bytes come from the backend (the ElevenLabs key never reaches here).

let current: HTMLAudioElement | null = null;
let currentUrl: string | null = null;
let muted = false;
const played = new Set<string>();
const listeners = new Set<(speaking: boolean) => void>();

function setSpeaking(v: boolean) {
  listeners.forEach((l) => l(v));
}

/** Subscribe to "the ghost is speaking" changes (drives the talking face). */
export function onSpeaking(cb: (speaking: boolean) => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function setNarrationMuted(m: boolean) {
  muted = m;
  if (m) stopNarration();
}

export function stopNarration() {
  if (current) {
    current.pause();
    current.src = "";
  }
  if (currentUrl) URL.revokeObjectURL(currentUrl);
  current = null;
  currentUrl = null;
  setSpeaking(false);
}

/** Play a voice clip (MP3 or WAV). `dedupeKey` prevents the same automatic line from
 * playing twice; manual replays pass no key. */
export async function playNarration(bytes: ArrayBuffer, dedupeKey?: string): Promise<void> {
  if (muted) return;
  if (dedupeKey) {
    if (played.has(dedupeKey)) return;
    played.add(dedupeKey);
  }
  stopNarration();
  // Windows voice returns WAV ("RIFF" header); ElevenLabs returns MP3.
  const head = new Uint8Array(bytes.slice(0, 4));
  const isWav = String.fromCharCode(...head) === "RIFF";
  currentUrl = URL.createObjectURL(new Blob([bytes], { type: isWav ? "audio/wav" : "audio/mpeg" }));
  const audio = new Audio(currentUrl);
  current = audio;
  audio.volume = 0.9;
  audio.onplaying = () => setSpeaking(true);
  audio.onended = audio.onpause = audio.onerror = () => {
    if (current === audio) setSpeaking(false);
  };
  await audio.play();
}

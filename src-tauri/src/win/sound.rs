//! The ghost's alert sound. Synthesized at runtime (an eerie theremin-like
//! glide with a soft echo), so it is original audio with no licensing
//! concerns and no bundled file. Played asynchronously from memory through
//! the Win32 PlaySound API, independent of the model and of the network.

use std::f32::consts::PI;
use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Media::Audio::{PlaySoundW, SND_ASYNC, SND_MEMORY, SND_NODEFAULT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Informational alerts: one gentle falling glide.
    Soft,
    /// Higher-priority alerts: a rising then falling "woo-ooo" over a low drone.
    Warning,
}

const SR: u32 = 22_050;
/// Peak amplitude at 100% volume. Kept well below full scale so the sound
/// is never startling.
const MAX_PEAK: f32 = 0.6;

static PLAYING: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn glide(out: &mut [f32], start: usize, dur: f32, f0: f32, f1: f32, amp: f32) {
    let n = (dur * SR as f32) as usize;
    let mut phase = 0.0f32;
    for i in 0..n {
        let t = i as f32 / SR as f32;
        let x = t / dur;
        // Ease the glide, add a slow vibrato.
        let f = f0 + (f1 - f0) * (x * x * (3.0 - 2.0 * x));
        let f = f * (1.0 + 0.015 * (2.0 * PI * 5.5 * t).sin());
        phase += 2.0 * PI * f / SR as f32;
        let attack = (t / 0.22).min(1.0);
        let release = ((dur - t) / 0.5).clamp(0.0, 1.0);
        let env = attack * release;
        let v = phase.sin() + 0.18 * (2.0 * phase).sin() + 0.06 * (3.0 * phase).sin();
        if let Some(s) = out.get_mut(start + i) {
            *s += v * env * amp;
        }
    }
}

pub fn synthesize(tone: Tone, volume: u8) -> Vec<u8> {
    let total = match tone {
        Tone::Soft => 2.2,
        Tone::Warning => 2.9,
    };
    let len = (total * SR as f32) as usize;
    let mut s = vec![0.0f32; len];
    match tone {
        Tone::Soft => glide(&mut s, 0, 1.5, 523.0, 392.0, 1.0),
        Tone::Warning => {
            glide(&mut s, 0, 0.9, 392.0, 587.0, 1.0);
            glide(&mut s, (0.75 * SR as f32) as usize, 1.3, 587.0, 440.0, 1.0);
            // Low drone underneath.
            let n = (2.0 * SR as f32) as usize;
            for (i, v) in s.iter_mut().take(n).enumerate() {
                let t = i as f32 / SR as f32;
                let env = (t / 0.4).min(1.0) * ((2.0 - t) / 0.8).clamp(0.0, 1.0);
                *v += 0.25 * env * (2.0 * PI * 98.0 * t).sin();
            }
        }
    }
    // Two-tap echo for a hollow, haunted room feel.
    let dry = s.clone();
    for (delay, gain) in [(0.19f32, 0.35f32), (0.38, 0.16)] {
        let d = (delay * SR as f32) as usize;
        for i in d..len {
            s[i] += dry[i - d] * gain;
        }
    }
    let peak = s.iter().fold(0.0f32, |m, v| m.max(v.abs())).max(1e-6);
    let gain = MAX_PEAK * (volume.min(100) as f32 / 100.0).powf(1.5) / peak;
    let pcm: Vec<i16> = s.iter().map(|v| (v * gain * i16::MAX as f32) as i16).collect();
    wav_bytes(&pcm)
}

fn wav_bytes(pcm: &[i16]) -> Vec<u8> {
    let data_len = (pcm.len() * 2) as u32;
    let mut b = Vec::with_capacity(44 + data_len as usize);
    b.extend_from_slice(b"RIFF");
    b.extend_from_slice(&(36 + data_len).to_le_bytes());
    b.extend_from_slice(b"WAVEfmt ");
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // PCM
    b.extend_from_slice(&1u16.to_le_bytes()); // mono
    b.extend_from_slice(&SR.to_le_bytes());
    b.extend_from_slice(&(SR * 2).to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(b"data");
    b.extend_from_slice(&data_len.to_le_bytes());
    for v in pcm {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

/// Play the tone asynchronously. The buffer is kept alive in a static until
/// the next play/stop call, as SND_MEMORY | SND_ASYNC requires.
pub fn play(tone: Tone, volume: u8) {
    if volume == 0 {
        return;
    }
    let wav = synthesize(tone, volume);
    let mut guard = PLAYING.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // Stop any current sound before releasing its buffer.
        let _ = PlaySoundW(PCWSTR::null(), None, SND_NODEFAULT);
    }
    *guard = Some(wav);
    let ptr = guard.as_ref().unwrap().as_ptr();
    unsafe {
        let _ = PlaySoundW(PCWSTR(ptr as *const u16), None, SND_MEMORY | SND_ASYNC | SND_NODEFAULT);
    }
}

pub fn stop() {
    let mut guard = PLAYING.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let _ = PlaySoundW(PCWSTR::null(), None, SND_NODEFAULT);
    }
    *guard = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wav_is_well_formed_and_volume_scaled() {
        let loud = synthesize(Tone::Warning, 100);
        let quiet = synthesize(Tone::Warning, 20);
        assert_eq!(&loud[0..4], b"RIFF");
        assert_eq!(&loud[8..12], b"WAVE");
        let peak = |w: &[u8]| w[44..].chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]]).unsigned_abs()).max().unwrap();
        assert!(peak(&loud) <= (MAX_PEAK * i16::MAX as f32) as u16 + 1);
        assert!(peak(&quiet) < peak(&loud) / 5);
    }
}

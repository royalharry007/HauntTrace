//! Offline narration with the voices built into Windows (WinRT
//! SpeechSynthesizer). No network and no API key; returns WAV bytes.

use windows::core::HSTRING;
use windows::Media::SpeechSynthesis::SpeechSynthesizer;
use windows::Storage::Streams::DataReader;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

fn com() {
    // Safe to call repeatedly; WinRT needs COM on the calling thread.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
}

/// Display names of the installed Windows voices. Blocking.
pub fn voices() -> Result<Vec<String>, String> {
    com();
    let all = SpeechSynthesizer::AllVoices().map_err(|e| e.to_string())?;
    let n = all.Size().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for i in 0..n {
        if let Ok(v) = all.GetAt(i) {
            if let Ok(name) = v.DisplayName() {
                out.push(name.to_string());
            }
        }
    }
    Ok(out)
}

/// Speak `text` into a WAV buffer with the named voice (or the default).
/// Blocking; run off the async runtime.
pub fn speak_to_wav(text: &str, voice: Option<&str>) -> Result<Vec<u8>, String> {
    com();
    let synth = SpeechSynthesizer::new().map_err(|e| format!("Windows speech is unavailable: {e}"))?;
    if let Some(want) = voice.filter(|v| !v.is_empty()) {
        let all = SpeechSynthesizer::AllVoices().map_err(|e| e.to_string())?;
        for i in 0..all.Size().unwrap_or(0) {
            if let Ok(v) = all.GetAt(i) {
                if v.DisplayName().map(|n| n.to_string() == want).unwrap_or(false) {
                    synth.SetVoice(&v).map_err(|e| e.to_string())?;
                    break;
                }
            }
        }
    }
    let stream = synth
        .SynthesizeTextToStreamAsync(&HSTRING::from(text))
        .and_then(|op| op.get())
        .map_err(|e| format!("Windows speech failed: {e}"))?;
    let size = stream.Size().map_err(|e| e.to_string())? as u32;
    let input = stream.GetInputStreamAt(0).map_err(|e| e.to_string())?;
    let reader = DataReader::CreateDataReader(&input).map_err(|e| e.to_string())?;
    reader.LoadAsync(size).and_then(|op| op.get()).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; size as usize];
    reader.ReadBytes(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_voice_produces_wav() {
        // Every Windows 10/11 install ships at least one voice.
        let v = voices().unwrap();
        assert!(!v.is_empty());
        let wav = speak_to_wav("Something has been lingering.", Some(&v[0])).unwrap();
        assert_eq!(&wav[0..4], b"RIFF");
        assert!(wav.len() > 10_000);
    }
}

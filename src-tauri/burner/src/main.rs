//! haunt-burner: HauntTrace's controlled test process.
//!
//! Produces a deliberate, bounded load so detection and investigation can be
//! demonstrated on REAL measurements without a real problematic program.
//! It never touches files, the network or other processes, and always exits
//! on its own after at most 15 minutes.
//!
//!   haunt-burner --mode cpu     --seconds 120 [--threads N]
//!   haunt-burner --mode spikes  --seconds 180     (7 s bursts every 25 s)
//!   haunt-burner --mode memory  --seconds 900     (+10 MB every 2 s, cap 600 MB)
//!   haunt-burner --mode restart --seconds 240     (runs 15 s, starts a successor, exits)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn burn_until(stop: Arc<AtomicBool>, until: Instant) {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    while Instant::now() < until && !stop.load(Ordering::Relaxed) {
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
        }
        std::hint::black_box(x);
    }
}

fn burn_threads(n: usize, dur: Duration) {
    let stop = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + dur;
    let handles: Vec<_> = (0..n).map(|_| {
        let s = stop.clone();
        std::thread::spawn(move || burn_until(s, until))
    }).collect();
    for h in handles {
        let _ = h.join();
    }
}

fn main() {
    let mode = arg("--mode").unwrap_or_else(|| "cpu".into());
    let seconds: u64 = arg("--seconds").and_then(|s| s.parse().ok()).unwrap_or(120).clamp(10, 900);
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    // Enough threads to exceed the default 25% sustained-CPU threshold.
    let default_threads = ((cpus as f64 * 0.4).ceil() as usize).max(1);
    let threads: usize = arg("--threads").and_then(|s| s.parse().ok()).unwrap_or(default_threads).clamp(1, cpus);
    let deadline = Instant::now() + Duration::from_secs(seconds);

    match mode.as_str() {
        "cpu" => burn_threads(threads, Duration::from_secs(seconds)),
        "spikes" => {
            let burst = ((cpus as f64 * 0.6).ceil() as usize).max(1);
            while Instant::now() < deadline {
                // 7 s bursts so at least one full 5 s sample lands inside each burst.
                burn_threads(burst, Duration::from_secs(7));
                std::thread::sleep(Duration::from_secs(18).min(deadline.saturating_duration_since(Instant::now())));
            }
        }
        "memory" => {
            let mut hoard: Vec<Vec<u8>> = Vec::new();
            while Instant::now() < deadline {
                if hoard.len() < 60 {
                    // Touch every page so the memory is really committed.
                    hoard.push(vec![0xA5u8; 10 * 1024 * 1024]);
                }
                std::hint::black_box(&hoard);
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        "restart" => {
            // Each generation lives ~15 s with light load, then hands over to
            // a successor, until the total budget is used up.
            let life = Duration::from_secs(15).min(Duration::from_secs(seconds));
            burn_threads(1, life);
            let remaining = seconds.saturating_sub(life.as_secs() + 1);
            if remaining >= 10 {
                if let Ok(exe) = std::env::current_exe() {
                    let mut cmd = std::process::Command::new(exe);
                    cmd.args(["--mode", "restart", "--seconds", &remaining.to_string()]);
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        cmd.creation_flags(0x0800_0000);
                    }
                    let _ = cmd.spawn();
                }
            }
        }
        _ => {
            eprintln!("unknown mode; use cpu | spikes | memory | restart");
            std::process::exit(2);
        }
    }
}

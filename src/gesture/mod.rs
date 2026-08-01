pub mod buffer;
pub mod config;
pub mod dataset;
pub mod features;
pub mod inject;
pub mod model;
pub mod serial;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{info, warn};

use self::config::GestureConfig;
use self::serial::Sample;

/// Record N seconds of raw samples for a gesture label.
/// The captured stream is segmented into `WINDOW_MS` windows, so each
/// recorded burst produces multiple training windows matching inference length.
pub fn record(label: &str, seconds: u64) -> Result<()> {
    let cfg = GestureConfig::default();
    let (tx, rx) = crossbeam_channel::unbounded::<Sample>();
    serial::spawn_reader(&cfg.serial_port, cfg.baud, tx)
        .context("failed to start serial reader")?;

    info!("recording '{}' for {}s — perform the gesture now", label, seconds);

    // Drain any stale samples from a previous session so they don't skew t0.
    let flush_start = Instant::now();
    while flush_start.elapsed() < Duration::from_millis(300) {
        while rx.try_recv().is_ok() {}
        std::thread::sleep(Duration::from_millis(20));
    }

    let start = Instant::now();
    let deadline = Duration::from_secs(seconds);
    let mut by_ap: HashMap<String, Vec<(u64, f64)>> = HashMap::new();

    while start.elapsed() < deadline {
        let remaining = (deadline - start.elapsed()).as_secs();
        eprint!(
            "\r[{:>3}s left] samples: {:>6}      ",
            remaining,
            total_samples(&by_ap)
        );
        while let Ok(s) = rx.try_recv() {
            by_ap
                .entry(s.mac)
                .or_default()
                .push((s.ts_us, s.rssi as f64));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("\n[record] collected {} unique APs", by_ap.len());

    if by_ap.is_empty() {
        return Err(anyhow::anyhow!(
            "no samples captured — is the ESP32 streaming? (SERIAL_PORT={})",
            cfg.serial_port
        ));
    }

    let windows = segment_windows(by_ap, cfg.window_ms);
    if windows.is_empty() {
        return Err(anyhow::anyhow!(
            "captured samples but no full {}-ms window completed",
            cfg.window_ms
        ));
    }

    for win in windows.iter() {
        let w = dataset::LabeledWindow {
            label: label.to_string(),
            streams: win.clone(),
        };
        dataset::append_window(&w)?;
    }
    info!(
        "appended {} windows for '{}' ({} ms each)",
        windows.len(),
        label,
        cfg.window_ms
    );
    Ok(())
}

/// Segment per-AP (ts, rssi) streams into fixed-duration windows.
fn segment_windows(
    by_ap: HashMap<String, Vec<(u64, f64)>>,
    window_ms: u64,
) -> Vec<HashMap<String, Vec<f64>>> {
    let win_us = window_ms * 1000;
    // Determine the time range spanned by the samples.
    let mut t0 = u64::MAX;
    let mut t1 = 0u64;
    for v in by_ap.values() {
        for &(ts, _) in v.iter() {
            t0 = t0.min(ts);
            t1 = t1.max(ts);
        }
    }
    if t0 == u64::MAX || t1 - t0 < win_us {
        return Vec::new();
    }

    let n_windows = ((t1 - t0) / win_us) as usize;
    let mut out: Vec<HashMap<String, Vec<f64>>> = vec![HashMap::new(); n_windows];

    for (mac, samples) in &by_ap {
        for &(ts, rssi) in samples {
            if ts < t0 {
                continue;
            }
            let idx = ((ts - t0) / win_us) as usize;
            if idx < n_windows {
                out[idx].entry(mac.clone()).or_default().push(rssi);
            }
        }
    }

    // Drop empty windows (start/end partials).
    out.retain(|w| !w.is_empty());
    out
}

fn total_samples(by_ap: &HashMap<String, Vec<(u64, f64)>>) -> usize {
    by_ap.values().map(|v| v.len()).sum()
}

/// Train the model from recorded data.
pub fn train() -> Result<()> {
    let labels = dataset::list_labels()?;
    if labels.is_empty() {
        return Err(anyhow::anyhow!(
            "no recorded gestures — run `gesture-record <name>` first"
        ));
    }

    let windows = dataset::load_all(&labels)?;
    if windows.is_empty() {
        return Err(anyhow::anyhow!("no labeled windows found on disk"));
    }
    info!("loaded {} windows for labels {:?}", windows.len(), labels);

    let mut rows: Vec<Vec<f64>> = Vec::new();
    let mut y: Vec<u32> = Vec::new();
    let label_map: HashMap<String, u32> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| (l.clone(), i as u32))
        .collect();

    let ap_order: Vec<String> = {
        let mut seen: Vec<String> = Vec::new();
        for w in &windows {
            for mac in w.streams.keys() {
                if !seen.contains(mac) {
                    seen.push(mac.clone());
                }
            }
        }
        // top-N by aggregate count across windows
        let mut counts: HashMap<&String, usize> = HashMap::new();
        for w in &windows {
            for (mac, v) in &w.streams {
                *counts.entry(mac).or_default() += v.len();
            }
        }
        seen.sort_by(|a, b| counts.get(b).unwrap_or(&0).cmp(counts.get(a).unwrap_or(&0)));
        seen.truncate(config::GestureConfig::default().ap_count);
        seen
    };

    let feature_dim = features::features_for_stream_present(&[], true).len() * ap_order.len();

    for w in &windows {
        let label_idx = *label_map.get(&w.label).context("missing label mapping")?;

        // Build exactly `ap_order.len()` stream feature blocks (pad missing APs).
        let mut stream_features: Vec<f64> = Vec::with_capacity(feature_dim);
        for mac in &ap_order {
            if let Some(v) = w.streams.get(mac) {
                stream_features.extend(features::features_for_stream_present(v, true));
            } else {
                stream_features.extend(features::features_for_stream_present(&[], false));
            }
        }
        rows.push(stream_features);
        y.push(label_idx);
    }

    let model = model::train(&rows, &y, &labels, &ap_order)?;
    model::TrainedModel::save(&model, model::MODEL_PATH)?;
    info!("saved model to {}", model::MODEL_PATH);
    Ok(())
}

/// Run the live classification + injection loop.
pub fn run() -> Result<()> {
    let model = model::TrainedModel::load(model::MODEL_PATH)
        .context("load model — run `gesture-train` first")?;

    let cfg = GestureConfig::default();
    let (tx, rx) = crossbeam_channel::unbounded::<Sample>();
    serial::spawn_reader(&cfg.serial_port, cfg.baud, tx)
        .context("failed to start serial reader")?;

    let (term_tx, term_rx) = crossbeam_channel::bounded::<()>(1);
    ctrlc::set_handler(move || {
        let _ = term_tx.send(());
    })
    .context("failed to install Ctrl-C handler")?;

    let mut win = buffer::WindowBuffer::new(cfg.window_ms);
    let mut last_emit = Instant::now() - Duration::from_secs(60);
    let mut pending: Vec<Option<(String, f64)>> = Vec::new();

    info!("gesture-run active — Ctrl-C to stop");

    loop {
        // Check for Ctrl-C
        if term_rx.try_recv().is_ok() {
            info!("shutting down");
            break;
        }

        while let Ok(s) = rx.try_recv() {
            if let Some(raw) = win.push(s) {
                let by_ap = buffer::WindowBuffer::to_f64_map(&raw);

                // Build features using the model's fixed AP order so feature
                // positions match training exactly.
                let mut feat = Vec::with_capacity(model.feature_dim);
                for mac in &model.ap_order {
                    if let Some(v) = by_ap.get(mac) {
                        feat.extend(features::features_for_stream_present(v, true));
                    } else {
                        feat.extend(features::features_for_stream_present(&[], false));
                    }
                }

                if feat.len() != model.feature_dim {
                    warn!(
                        "window feature dim {} != model {} — skipping",
                        feat.len(),
                        model.feature_dim
                    );
                    continue;
                }

                if let Ok(Some((label, prob))) = model.predict(&feat) {
                    pending.push(Some((label, prob)));
                } else {
                    pending.push(None);
                }
                if pending.len() > cfg.debounce_k {
                    pending.remove(0);
                }

                let decision = decide(&pending, &model.labels, cfg.ratio);
                if let Some(label) = decision {
                    let now = Instant::now();
                    if now.duration_since(last_emit) >= Duration::from_millis(cfg.cooldown_ms) {
                        if let Some(key) = inject::key_for_gesture(&label) {
                            match inject::emit_key(key) {
                                Ok(()) => {
                                    last_emit = now;
                                    pending.clear(); // reset debounce after a real emit
                                    let ts = crate::gesture::now_rfc3339();
                                    let line = format!(
                                        "{} gesture={} key={}",
                                        ts, label, key
                                    );
                                    println!("[KEY] {}", line);
                                    append_event_log(&line);
                                }
                                Err(e) => warn!("key emission failed: {}", e),
                            }
                        }
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

/// Append an emitted-command record to the persistent event log.
fn append_event_log(line: &str) {
    let path = "gesture_events.log";
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    } else {
        warn!("could not open {} for append", path);
    }
}

/// RFC 3339 timestamp for the current time.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Given the last K predictions (with margin), decide a gesture using
/// majority vote plus a minimum-margin requirement. Returns Some(label)
/// if a confident majority emerged.
fn decide(
    pending: &[Option<(String, f64)>],
    labels: &[String],
    min_margin: f64,
) -> Option<String> {
    if pending.len() < 2 {
        return None;
    }

    let mut counts: HashMap<&String, (usize, f64)> = HashMap::new();
    for p in pending.iter().flatten() {
        let e = counts.entry(&p.0).or_insert((0, 0.0));
        e.0 += 1;
        e.1 += p.1;
    }
    let (best_label, (best_count, margin_sum)) = counts
        .iter()
        .max_by_key(|(_, (c, _))| *c)
        .map(|(k, v)| (k, *v))?;
    let total = pending.len();
    if best_count * 2 <= total {
        return None; // no majority
    }
    if !labels.contains(best_label) {
        return None;
    }
    // average margin of the winning class must exceed the ratio gate
    let avg_margin = margin_sum / best_count as f64;
    if avg_margin < min_margin {
        return None;
    }
    Some((*best_label).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decides_majority() {
        let labels = vec!["a".to_string(), "b".to_string()];
        let p = vec![
            Some(("a".to_string(), 0.9)),
            Some(("a".to_string(), 0.8)),
            Some(("b".to_string(), 0.7)),
            Some(("a".to_string(), 0.9)),
        ];
        assert_eq!(decide(&p, &labels, 0.2), Some("a".to_string()));
    }

    #[test]
    fn low_margin_rejected() {
        let labels = vec!["a".to_string(), "b".to_string()];
        let p = vec![
            Some(("a".to_string(), 0.05)),
            Some(("a".to_string(), 0.05)),
            Some(("a".to_string(), 0.05)),
        ];
        assert_eq!(decide(&p, &labels, 0.2), None);
    }

    #[test]
    fn no_decision_on_split() {
        let labels = vec!["a".to_string(), "b".to_string()];
        let p = vec![
            Some(("a".to_string(), 0.9)),
            Some(("b".to_string(), 0.9)),
        ];
        assert_eq!(decide(&p, &labels, 0.2), None);
    }

    #[test]
    fn segment_windows_splits_by_duration() {
        // 2 APs, samples spanning 3.5 windows of 1000ms each.
        let mut by_ap: HashMap<String, Vec<(u64, f64)>> = HashMap::new();
        by_ap.insert(
            "A".into(),
            (0..4000).step_by(1000).map(|ts| (ts as u64 * 1000, -50.0)).collect(),
        );
        by_ap.insert(
            "B".into(),
            (0..4000).step_by(1000).map(|ts| (ts as u64 * 1000, -60.0)).collect(),
        );

        let wins = segment_windows(by_ap, 1000);
        // t0=0, t1=3_000_000 -> 3 full windows
        assert_eq!(wins.len(), 3);
        for w in &wins {
            assert_eq!(w.len(), 2); // both APs present
            assert_eq!(w["A"].len(), 1); // one sample per AP per window
        }
    }

    #[test]
    fn segment_windows_drops_partial_edges() {
        let mut by_ap: HashMap<String, Vec<(u64, f64)>> = HashMap::new();
        by_ap.insert("A".into(), vec![(0, -50.0), (500_000, -51.0)]);
        let wins = segment_windows(by_ap, 1000);
        assert_eq!(wins.len(), 0); // total span < 1 window
    }
}

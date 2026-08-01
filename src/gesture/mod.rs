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
pub fn record(label: &str, seconds: u64) -> Result<()> {
    let cfg = GestureConfig::default();
    let (tx, rx) = crossbeam_channel::unbounded::<Sample>();
    serial::spawn_reader(&cfg.serial_port, cfg.baud, tx)
        .context("failed to start serial reader")?;

    info!("recording '{}' for {}s — perform the gesture now", label, seconds);

    let start = Instant::now();
    let deadline = Duration::from_secs(seconds);
    let mut by_ap: HashMap<String, Vec<f64>> = HashMap::new();

    while start.elapsed() < deadline {
        let remaining = (deadline - start.elapsed()).as_secs();
        eprint!("\r[{:>3}s left] samples: {:>6}      ", remaining, total_samples(&by_ap));
        while let Ok(s) = rx.try_recv() {
            by_ap
                .entry(s.mac)
                .or_default()
                .push(s.rssi as f64);
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

    let window = dataset::LabeledWindow {
        label: label.to_string(),
        streams: by_ap,
    };
    dataset::append_window(&window)?;
    info!("appended one window for '{}'", label);
    Ok(())
}

fn total_samples(by_ap: &HashMap<String, Vec<f64>>) -> usize {
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
        seen
    };

    let feature_dim = features::features_for_stream(&[0.0], 4).len() * config::GestureConfig::default().ap_count;

    for w in &windows {
        let label_idx = *label_map.get(&w.label).context("missing label mapping")?;

        // Build exactly `ap_count` stream feature blocks (pad missing APs).
        let mut stream_features: Vec<f64> = Vec::with_capacity(feature_dim);
        for i in 0..config::GestureConfig::default().ap_count {
            if let Some(mac) = ap_order.get(i) {
                if let Some(v) = w.streams.get(mac) {
                    stream_features.extend(features::features_for_stream(v, 4));
                    continue;
                }
            }
            stream_features.extend(features::features_for_stream(&[], 4));
        }
        rows.push(stream_features);
        y.push(label_idx);
    }

    let model = model::train(&rows, &y, &labels)?;
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
                let top = features::top_aps(&by_ap, cfg.ap_count);

                let mut feat = Vec::with_capacity(model.feature_dim);
                for i in 0..cfg.ap_count {
                    if let Some(mac) = top.get(i) {
                        if let Some(v) = by_ap.get(mac) {
                            feat.extend(features::features_for_stream(v, 4));
                            continue;
                        }
                    }
                    feat.extend(features::features_for_stream(&[], 4));
                }

                if feat.len() != model.feature_dim {
                    warn!("window feature dim {} != model {} — skipping", feat.len(), model.feature_dim);
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
                                    info!("EMIT {} -> key {}", label, key);
                                    last_emit = now;
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
}

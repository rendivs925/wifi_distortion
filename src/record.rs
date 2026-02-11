use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};

const INTERFACE_NAME: &str = "wlp3s0";
const SAMPLE_DURATION_MS: u64 = 5000;
const TOP_N: usize = 10;

pub fn record_fingerprint(label: &str) -> Result<IndexMap<String, i8>, String> {
    println!("[RECORD] Starting 5-second sampling for '{}'...", label);
    println!("[RECORD] Please stand still at the location...");

    let mut capture = pcap::Capture::from_device(INTERFACE_NAME)
        .map_err(|e| format!("Failed to open interface: {}", e))?
        .timeout(100)
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;

    let progress_bar = ProgressBar::new(SAMPLE_DURATION_MS);
    progress_bar.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {wide_bar} {percent}%")
            .unwrap()
            .progress_chars("█▉▉"),
    );

    let mut bssid_readings: HashMap<String, Vec<i8>> = HashMap::new();
    let start_time = Instant::now();
    let mut packet_count = 0;

    println!("[RECORD] Listening for packets...");

    loop {
        let elapsed = start_time.elapsed().as_millis() as u64;

        if elapsed >= SAMPLE_DURATION_MS {
            break;
        }

        match capture.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                if let Some((bssid, rssi)) = super::utils::extract_rssi_from_radiotap(&packet.data)
                {
                    bssid_readings
                        .entry(bssid)
                        .or_insert_with(Vec::new)
                        .push(rssi);
                }
            }
            Err(_) => {}
        }

        progress_bar.set_position(elapsed);
    }

    progress_bar.finish_with_message("done!");

    println!(
        "[RECORD] Captured {} packets, {} unique BSSIDs",
        packet_count,
        bssid_readings.len()
    );

    if bssid_readings.is_empty() {
        return Err("No packets captured. Check interface and permissions.".to_string());
    }

    let mut averaged_signals: Vec<(String, i8)> = bssid_readings
        .into_iter()
        .map(|(bssid, readings)| {
            let avg_rssi = readings.iter().sum::<i8>() / readings.len() as i8;
            (bssid, avg_rssi)
        })
        .collect();

    averaged_signals.sort_by(|a, b| b.1.cmp(&a.1));

    let top_signals: IndexMap<String, i8> = averaged_signals.into_iter().take(TOP_N).collect();

    let count = top_signals.len();
    println!("[RECORD] Kept top {} BSSIDs", count);

    Ok(top_signals)
}

pub fn save_fingerprint(
    label: String,
    signals: IndexMap<String, i8>,
    map_path: &str,
) -> Result<(), String> {
    let mut radio_map = match super::fingerprint::RadioMap::load_from_file(map_path) {
        Ok(map) => map,
        Err(_) => super::fingerprint::RadioMap::new(),
    };

    radio_map.add_fingerprint(label, signals);
    radio_map
        .save_to_file(map_path)
        .map_err(|e| format!("Failed to save: {}", e))?;

    println!("[RECORD] Saved fingerprint to {}", map_path);
    Ok(())
}

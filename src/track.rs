use indexmap::IndexMap;
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

const INTERFACE_NAME: &str = "wlp3s0";
const SAMPLE_DURATION_MS: u64 = 3000;
const TOP_N: usize = 10;

pub fn track_location(map_path: &str) -> Result<(), String> {
    println!("[TRACK] Scanning for 3 seconds...");

    let mut capture = pcap::Capture::from_device(INTERFACE_NAME)
        .map_err(|e| format!("Failed to open interface: {}", e))?
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;

    let radio_map = super::fingerprint::RadioMap::load_from_file(map_path)
        .map_err(|e| format!("Failed to load radio map: {}", e))?;

    if radio_map.fingerprints.is_empty() {
        return Err("No fingerprints in map. Run 'record' first.".to_string());
    }

    let mut bssid_readings: HashMap<String, Vec<i8>> = HashMap::new();
    let start_time = std::time::Instant::now();

    print!("[TRACK] Sampling");
    std::io::stdout().flush().unwrap();

    loop {
        if start_time.elapsed() >= Duration::from_millis(SAMPLE_DURATION_MS) {
            println!(" done!");
            break;
        }

        match capture.next_packet() {
            Ok(packet) => {
                if let Some((bssid, rssi)) = super::utils::extract_rssi_from_radiotap(&packet.data)
                {
                    bssid_readings
                        .entry(bssid)
                        .or_insert_with(Vec::new)
                        .push(rssi);
                }
            }
            Err(_) => continue,
        }

        print!(".");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }

    if bssid_readings.is_empty() {
        return Err("No packets captured.".to_string());
    }

    let mut averaged_signals: Vec<(String, i8)> = bssid_readings
        .into_iter()
        .map(|(bssid, readings)| {
            let avg_rssi = readings.iter().sum::<i8>() / readings.len() as i8;
            (bssid, avg_rssi)
        })
        .collect();

    averaged_signals.sort_by(|a, b| b.1.cmp(&a.1));

    let current_signals: IndexMap<String, i8> = averaged_signals.into_iter().take(TOP_N).collect();

    let current_features = super::utils::extract_top10_features(&current_signals);

    if let Some((best_label, distance)) =
        super::utils::find_nearest_match(&current_features, &radio_map)
    {
        println!(
            "\n[TRACK] Best match: '{}' (distance: {:.2})",
            best_label, distance
        );

        let confidence = if distance < 10.0 {
            "HIGH"
        } else if distance < 30.0 {
            "MEDIUM"
        } else {
            "LOW"
        };
        println!("[TRACK] Confidence: {}", confidence);
    } else {
        println!("[TRACK] Could not determine location.");
    }

    Ok(())
}

pub fn list_fingerprints(map_path: &str) -> Result<(), String> {
    let radio_map = super::fingerprint::RadioMap::load_from_file(map_path)
        .map_err(|e| format!("Failed to load radio map: {}", e))?;

    if radio_map.fingerprints.is_empty() {
        println!("No fingerprints recorded yet.");
        return Ok(());
    }

    println!("\n=== Radio Map ===");
    println!("Created: {}\n", radio_map.created);

    for (i, fp) in radio_map.fingerprints.iter().enumerate() {
        println!("{}. {} ({} BSSIDs)", i + 1, fp.label, fp.signals.len());
        for (bssid, rssi) in fp.signals.iter().take(5) {
            println!("   {}: {} dBm", bssid, rssi);
        }
        if fp.signals.len() > 5 {
            println!("   ... and {} more", fp.signals.len() - 5);
        }
        println!();
    }

    Ok(())
}

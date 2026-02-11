use pcap::Capture;
use radiotap::Radiotap;
use std::collections::VecDeque;
use std::io::{stdout, Write};

// --- CONFIGURATION ---
const INTERFACE_NAME: &str = "wlp3s0";
const TARGET_ROUTER_MAC: &str = "80:F7:A6:D5:F7:AC";
const WINDOW_SIZE: usize = 25; // Small window for faster reaction
const VARIANCE_THRESHOLD: f64 = 3.5; // High sensitivity for testing
                                     // ---------------------

fn calculate_variance(window: &VecDeque<i8>) -> f64 {
    let n = window.len() as f64;
    let sum: f64 = window.iter().map(|&x| x as f64).sum();
    let mean = sum / n;
    window
        .iter()
        .map(|&x| {
            let diff = (x as f64) - mean;
            diff * diff
        })
        .sum::<f64>()
        / n
}

fn main() {
    println!("=== Wi-Fi Distortion: High-Sensitivity Mode ===");

    let mut cap = Capture::from_device(INTERFACE_NAME)
        .unwrap()
        .immediate_mode(true)
        .open()
        .expect("Check monitor mode and root permissions");

    // Convert MAC string to raw bytes for the BPF filter
    let mac_clean = TARGET_ROUTER_MAC.replace(':', "");
    let mac_bytes = hex::decode(mac_clean).expect("Invalid MAC address format");

    // Low-level BPF: Checks for MAC at standard 802.11 offsets
    // This bypasses the 'ta'/'addr2' keyword limitations
    let bpf_filter = format!(
        "link[10:4] = 0x{:02x}{:02x}{:02x}{:02x} and link[14:2] = 0x{:02x}{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    cap.filter(&bpf_filter, true).expect("BPF Filter Error");
    println!("Target locked via raw BPF: {}", TARGET_ROUTER_MAC);

    let mut rssi_window: VecDeque<i8> = VecDeque::with_capacity(WINDOW_SIZE);

    loop {
        if let Ok(packet) = cap.next_packet() {
            if let Ok(rt) = Radiotap::from_bytes(&packet.data) {
                if let Some(dbm) = rt.antenna_signal {
                    rssi_window.push_back(dbm.value);

                    if rssi_window.len() > WINDOW_SIZE {
                        rssi_window.pop_front();
                    }

                    if rssi_window.len() == WINDOW_SIZE {
                        let var = calculate_variance(&rssi_window);

                        print!("\rVariance: {:.2} | RSSI: {} dBm    ", var, dbm.value);
                        stdout().flush().unwrap();

                        if var > VARIANCE_THRESHOLD {
                            println!("\nMOTION DETECTED");
                            rssi_window.clear(); // Cooldown to prevent spam
                        }
                    }
                }
            }
        }
    }
}

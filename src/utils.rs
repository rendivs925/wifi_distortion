use indexmap::IndexMap;

pub fn extract_rssi_from_radiotap(packet: &[u8]) -> Option<(String, i8)> {
    if packet.len() < 36 {
        return None;
    }

    let radiotap = match radiotap::Radiotap::from_bytes(packet) {
        Ok(r) => r,
        Err(_) => return None,
    };

    let rssi = match radiotap.antenna_signal {
        Some(signal) => signal.value,
        None => return None,
    };

    if !(-127..=0).contains(&rssi) {
        return None;
    }

    let frame_start = radiotap.header.length as usize;

    if packet.len() < frame_start + 24 {
        return None;
    }

    let frame_control = u16::from_le_bytes([packet[frame_start], packet[frame_start + 1]]);
    let frame_type = (frame_control >> 2) & 0x3;
    let to_ds = ((frame_control >> 8) & 0x1) == 1;
    let from_ds = ((frame_control >> 9) & 0x1) == 1;

    let bssid_offset = match (frame_type, to_ds, from_ds) {
        // Management frames always carry BSSID in Address 3.
        (0, _, _) => frame_start + 16,
        // Data frames: BSSID address position depends on DS direction bits.
        (2, false, false) => frame_start + 16, // Address 3
        (2, true, false) => frame_start + 4,   // Address 1
        (2, false, true) => frame_start + 10,  // Address 2
        // WDS (ToDS=FromDS=1) has four-address format; no direct BSSID field.
        (2, true, true) => return None,
        // Control/other frame types do not expose a stable BSSID.
        _ => return None,
    };

    if packet.len() < bssid_offset + 6 {
        return None;
    }

    let bssid_bytes = &packet[bssid_offset..bssid_offset + 6];
    if bssid_bytes.iter().all(|&b| b == 0) {
        return None;
    }

    let bssid = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bssid_bytes[0], bssid_bytes[1], bssid_bytes[2], bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
    );

    Some((bssid, rssi))
}

pub fn extract_top10_features(signals: &IndexMap<String, i8>) -> Vec<f64> {
    signals.values().take(10).map(|&rssi| rssi as f64).collect()
}

pub fn pad_to_10(values: &[f64]) -> Vec<f64> {
    let mut padded = values.to_vec();
    while padded.len() < 10 {
        padded.push(-100.0);
    }
    padded
}

pub fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

pub fn find_nearest_match(
    current_features: &[f64],
    radio_map: &super::fingerprint::RadioMap,
) -> Option<(String, f64)> {
    let mut best_match = None;
    let mut best_distance = f64::MAX;

    for fp in &radio_map.fingerprints {
        let features = extract_top10_features(&fp.signals);
        let padded_current = pad_to_10(current_features);
        let padded_saved = pad_to_10(&features);

        let distance = euclidean_distance(&padded_current, &padded_saved);

        if distance < best_distance {
            best_distance = distance;
            best_match = Some(fp.label.clone());
        }
    }

    best_match.map(|label| (label, best_distance))
}

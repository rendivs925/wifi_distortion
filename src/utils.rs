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

    if rssi > 0 || rssi < -100 {
        return None;
    }

    let frame_start = radiotap.header.length as usize;

    if packet.len() < frame_start + 24 {
        return None;
    }

    let frame_control = u16::from_le_bytes([packet[frame_start], packet[frame_start + 1]]);
    let frame_type = (frame_control >> 2) & 0x3;

    let bssid_offset = match frame_type {
        0 => frame_start + 16,
        2 => frame_start + 4,
        _ => frame_start + 4,
    };

    if packet.len() < bssid_offset + 6 {
        return None;
    }

    let bssid = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        packet[bssid_offset],
        packet[bssid_offset + 1],
        packet[bssid_offset + 2],
        packet[bssid_offset + 3],
        packet[bssid_offset + 4],
        packet[bssid_offset + 5]
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

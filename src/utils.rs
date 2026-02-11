use indexmap::IndexMap;

pub fn extract_rssi_from_radiotap(packet: &[u8]) -> Option<(String, i8)> {
    if packet.len() < 36 {
        return None;
    }

    let radiotap_len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < radiotap_len + 24 {
        return None;
    }

    let mut rssi: Option<i8> = None;
    let mut offset = 8;

    while offset + 1 < radiotap_len && offset + 1 < packet.len() {
        let itype = packet[offset];
        let ilen = packet[offset + 1] as usize;

        if offset + 2 + ilen > radiotap_len {
            break;
        }

        if itype == 0 && ilen >= 1 {
            if offset + 2 < packet.len() {
                rssi = Some(packet[offset + 2] as i8);
            }
        }

        offset += 2 + ilen;
    }

    let rssi_val = rssi?;
    if rssi_val > 0 || rssi_val < -100 {
        return None;
    }

    let frame_control = u16::from_le_bytes([packet[radiotap_len], packet[radiotap_len + 1]]);

    let frame_type = (frame_control >> 2) & 0x3;
    let frame_subtype = (frame_control >> 4) & 0xF;

    let bssid_offset = if frame_type == 0 {
        match frame_subtype {
            0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 => {
                radiotap_len + 16
            }
            _ => radiotap_len + 4,
        }
    } else if frame_type == 2 {
        radiotap_len + 4
    } else {
        radiotap_len + 4
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

    Some((bssid, rssi_val))
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

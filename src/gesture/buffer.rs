use std::collections::HashMap;

use crate::gesture::serial::Sample;

/// Accumulates samples grouped by AP and forms time-aligned windows.
pub struct WindowBuffer {
    window_us: u64,
    by_ap: HashMap<String, Vec<(u64, i8)>>,
    window_start_us: Option<u64>,
}

impl WindowBuffer {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_us: window_ms * 1000,
            by_ap: HashMap::new(),
            window_start_us: None,
        }
    }

    /// Ingest one sample. Returns `Some(by_ap)` when a full window has elapsed.
    pub fn push(&mut self, s: Sample) -> Option<HashMap<String, Vec<i8>>> {
        let start = *self.window_start_us.get_or_insert(s.ts_us);

        let mac = s.mac.clone();
        self.by_ap
            .entry(mac)
            .or_default()
            .push((s.ts_us, s.rssi));

        if s.ts_us.saturating_sub(start) >= self.window_us {
            let out: HashMap<String, Vec<i8>> = self
                .by_ap
                .iter()
                .map(|(mac, v)| (mac.clone(), v.iter().map(|&(_, rssi)| rssi).collect()))
                .collect();
            self.by_ap.clear();
            self.window_start_us = Some(s.ts_us);
            Some(out)
        } else {
            None
        }
    }

    /// Convert raw windows to f64 vectors per AP (values only, in order).
    pub fn to_f64_map(raw: &HashMap<String, Vec<i8>>) -> HashMap<String, Vec<f64>> {
        raw.iter()
            .map(|(mac, v)| {
                (
                    mac.clone(),
                    v.iter().map(|&x| x as f64).collect::<Vec<f64>>(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: u64, rssi: i8) -> Sample {
        Sample {
            ts_us: ts,
            mac: "AA:BB:CC:DD:EE:FF".into(),
            rssi,
        }
    }

    #[test]
    fn emits_after_window() {
        let mut b = WindowBuffer::new(10);
        let mut emitted = false;
        for i in 0..100 {
            let r = b.push(sample(i * 1000, -50));
            if r.is_some() {
                emitted = true;
                let map = r.unwrap();
                assert!(!map.is_empty());
                break;
            }
        }
        assert!(emitted);
    }

    #[test]
    fn groups_by_ap() {
        let mut b = WindowBuffer::new(1);
        let mut emitted = None;
        b.push(Sample {
            ts_us: 0,
            mac: "A".into(),
            rssi: -1,
        });
        if let Some(m) = b.push(Sample {
            ts_us: 2000,
            mac: "B".into(),
            rssi: -2,
        }) {
            emitted = Some(m);
        }
        let map = emitted.expect("window should have emitted");
        assert!(map.contains_key("A"));
        assert!(map.contains_key("B"));
    }
}

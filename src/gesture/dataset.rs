use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const GESTURES_DIR: &str = "gestures";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledWindow {
    pub label: String,
    /// Map of AP MAC -> raw RSSI series (f64) for this window.
    pub streams: HashMap<String, Vec<f64>>,
}

/// Save a labeled window to `gestures/<label>.jsonl` (append).
pub fn append_window(window: &LabeledWindow) -> Result<()> {
    std::fs::create_dir_all(GESTURES_DIR)?;
    let path = Path::new(GESTURES_DIR).join(format!("{}.jsonl", window.label));
    let line = serde_json::to_string(window)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    writeln!(f, "{}", line)?;
    Ok(())
}

/// Load all labeled windows for the given labels.
pub fn load_all(labels: &[String]) -> Result<Vec<LabeledWindow>> {
    let mut out = Vec::new();
    for label in labels {
        let path = Path::new(GESTURES_DIR).join(format!("{}.jsonl", label));
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        for line in content.lines() {
            let w: LabeledWindow = serde_json::from_str(line)?;
            out.push(w);
        }
    }
    Ok(out)
}

/// List existing gesture labels on disk.
pub fn list_labels() -> Result<Vec<String>> {
    if !Path::new(GESTURES_DIR).exists() {
        return Ok(Vec::new());
    }
    let mut labels = Vec::new();
    for entry in std::fs::read_dir(GESTURES_DIR)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(stripped) = name.strip_suffix(".jsonl") {
            labels.push(stripped.to_string());
        }
    }
    labels.sort();
    Ok(labels)
}

/// Remove all recorded data for a label.
pub fn delete_label(label: &str) -> Result<()> {
    let path = Path::new(GESTURES_DIR).join(format!("{}.jsonl", label));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Count windows recorded for a label.
pub fn count_for(label: &str) -> Result<usize> {
    let windows = load_all(&[label.to_string()])?;
    Ok(windows.len())
}

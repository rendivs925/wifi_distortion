use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioFingerprint {
    pub label: String,
    pub timestamp: i64,
    pub signals: IndexMap<String, i8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RadioMap {
    pub version: u32,
    pub created: String,
    pub fingerprints: Vec<RadioFingerprint>,
}

impl RadioMap {
    pub fn new() -> Self {
        Self {
            version: 1,
            created: chrono::Utc::now().to_rfc3339(),
            fingerprints: Vec::new(),
        }
    }

    pub fn add_fingerprint(&mut self, label: String, signals: IndexMap<String, i8>) {
        self.fingerprints.push(RadioFingerprint {
            label,
            timestamp: chrono::Utc::now().timestamp(),
            signals,
        });
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Self, std::io::Error> {
        let json = std::fs::read_to_string(path)?;
        let map: RadioMap = serde_json::from_str(&json)?;
        Ok(map)
    }
}

impl Default for RadioMap {
    fn default() -> Self {
        Self::new()
    }
}

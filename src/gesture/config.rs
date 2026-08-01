use std::env;

#[derive(Debug, Clone)]
pub struct GestureConfig {
    pub serial_port: String,
    pub baud: u32,
    pub window_ms: u64,
    pub ap_count: usize,
    pub ratio: f64,
    pub debounce_k: usize,
    pub cooldown_ms: u64,
}

impl Default for GestureConfig {
    fn default() -> Self {
        Self {
            serial_port: env::var("SERIAL_PORT").unwrap_or_else(|_| "/dev/ttyUSB0".into()),
            baud: env::var("SERIAL_BAUD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(115_200),
            window_ms: env::var("WINDOW_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            ap_count: env::var("AP_COUNT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            ratio: env::var("RATIO")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.3),
            debounce_k: env::var("DEBOUNCE_K")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            cooldown_ms: env::var("COOLDOWN_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(400),
        }
    }
}

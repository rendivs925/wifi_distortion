use std::io::BufRead;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use tracing::{debug, error, info};

pub struct Sample {
    pub ts_us: u64,
    pub mac: String,
    pub rssi: i8,
}

pub fn spawn_reader(port: &str, baud: u32, tx: Sender<Sample>) -> Result<()> {
    info!("opening serial port {} @ {}", port, baud);
    let serial = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open()
        .with_context(|| format!("failed to open serial port {}", port))?;

    let reader = serial.try_clone().context("failed to clone serial reader")?;
    let mut lines = std::io::BufReader::new(reader).lines();

    thread::Builder::new()
        .name("esp-serial-reader".into())
        .spawn(move || loop {
            match lines.next() {
                Some(Ok(line)) => {
                    if let Some(sample) = parse_line(&line) {
                        if tx.send(sample).is_err() {
                            error!("sample channel closed, stopping reader");
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    debug!("serial read error: {}", e);
                }
                None => {
                    debug!("serial EOF, retrying");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .context("failed to spawn serial reader thread")?;

    Ok(())
}

fn parse_line(line: &str) -> Option<Sample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split(',');
    let ts_us = parts.next()?.trim().parse().ok()?;
    let mac = parts.next()?.trim().to_string();
    let rssi = parts.next()?.trim().parse().ok()?;

    if mac.len() != 17 || !(-100..=0).contains(&rssi) {
        return None;
    }

    Some(Sample { ts_us, mac, rssi })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_line() {
        let s = parse_line("1234567,AA:BB:CC:DD:EE:FF,-45").unwrap();
        assert_eq!(s.ts_us, 1234567);
        assert_eq!(s.mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(s.rssi, -45);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_line("#comment").is_none());
        assert!(parse_line("garbage").is_none());
        assert!(parse_line("1,AA:BB,5").is_none());
        assert!(parse_line("1,AA:BB:CC:DD:EE:FF,-101").is_none());
    }
}

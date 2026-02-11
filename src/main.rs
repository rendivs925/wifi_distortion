mod fingerprint;
mod record;
mod track;
mod utils;

use clap::{Parser, Subcommand};

const INTERFACE_NAME: &str = "wlp3s0";
const RADIO_MAP_PATH: &str = "radio_map.json";

#[derive(Parser, Debug)]
#[command(name = "wifi_distortion")]
#[command(author = "vibe_cli")]
#[command(version = "0.2.0")]
#[command(about = "Wi-Fi Fingerprinting Map Builder for vibe_cli", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "map", alias = "record")]
    Map { label: String },
    #[command(name = "track")]
    Track,
    #[command(name = "list")]
    List,
    #[command(name = "clear")]
    Clear,
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Map { label } => match record::record_fingerprint(&label) {
            Ok(signals) => {
                if let Err(e) = record::save_fingerprint(label, signals, RADIO_MAP_PATH) {
                    eprintln!("[ERROR] Failed to save: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Recording failed: {}", e);
            }
        },
        Commands::Track => {
            if let Err(e) = track::track_location(RADIO_MAP_PATH) {
                eprintln!("[ERROR] Tracking failed: {}", e);
            }
        }
        Commands::List => {
            if let Err(e) = track::list_fingerprints(RADIO_MAP_PATH) {
                eprintln!("[ERROR] Listing failed: {}", e);
            }
        }
        Commands::Clear => match std::fs::remove_file(RADIO_MAP_PATH) {
            Ok(()) => println!("[OK] Cleared radio map."),
            Err(_) => println!("[OK] No radio map to clear."),
        },
    }
}

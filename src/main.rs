mod fingerprint;
mod gesture;
mod record;
mod track;
mod utils;

use clap::{Parser, Subcommand};

const RADIO_MAP_PATH: &str = "radio_map.json";

#[derive(Parser, Debug)]
#[command(name = "wifi_distortion")]
#[command(author = "vibe_cli")]
#[command(version = "0.1.0")]
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
    #[command(name = "gesture-record", alias = "grec")]
    GestureRecord {
        label: String,
        #[arg(long, default_value_t = 3)]
        seconds: u64,
    },
    #[command(name = "gesture-train", alias = "gtrain")]
    GestureTrain,
    #[command(name = "gesture-run", alias = "grun")]
    GestureRun,
    #[command(name = "gesture-list", alias = "glist")]
    GestureList,
    #[command(name = "gesture-clear", alias = "gclear")]
    GestureClear { label: String },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wifi_distortion=info".into()),
        )
        .init();

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
        Commands::GestureRecord { label, seconds } => {
            if let Err(e) = gesture::record(&label, seconds) {
                eprintln!("[ERROR] Gesture record failed: {}", e);
            }
        }
        Commands::GestureTrain => {
            if let Err(e) = gesture::train() {
                eprintln!("[ERROR] Gesture train failed: {}", e);
            }
        }
        Commands::GestureRun => {
            if let Err(e) = gesture::run() {
                eprintln!("[ERROR] Gesture run failed: {}", e);
            }
        }
        Commands::GestureList => match gesture::dataset::list_labels() {
            Ok(labels) => {
                if labels.is_empty() {
                    println!("[OK] No gestures recorded.");
                } else {
                    println!("[OK] Recorded gestures:");
                    for l in labels {
                        match gesture::dataset::count_for(&l) {
                            Ok(n) => println!("  {} ({} windows)", l, n),
                            Err(_) => println!("  {}", l),
                        }
                    }
                }
            }
            Err(e) => eprintln!("[ERROR] Gesture list failed: {}", e),
        },
        Commands::GestureClear { label } => {
            if let Err(e) = gesture::dataset::delete_label(&label) {
                eprintln!("[ERROR] Gesture clear failed: {}", e);
            } else {
                println!("[OK] Cleared gesture '{}'.", label);
            }
        }
    }
}


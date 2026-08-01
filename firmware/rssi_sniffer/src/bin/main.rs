#![no_std]
#![no_main]

use core::cell::RefCell;
use core::fmt::Write as FmtWrite;

use critical_section::Mutex;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_hal::time::{Duration, Instant};
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, Uart};
use esp_radio::wifi::sniffer::PromiscuousPkt;
use esp_radio::wifi::{SecondaryChannel, WifiController, Interfaces};

// === CONFIGURATION ===
const SNIFFER_CHANNEL: u8 = 10; // Router channel (from `iw dev`)
const SAMPLE_CAPACITY: usize = 256; // ring buffer depth
// =====================

#[derive(Clone, Copy)]
struct Sample {
    ts_us: u64,
    mac: [u8; 6],
    rssi: i32,
}

struct SampleRing {
    buf: [Sample; SAMPLE_CAPACITY],
    head: usize,
    len: usize,
}

impl SampleRing {
    const fn new() -> Self {
        Self {
            buf: [Sample {
                ts_us: 0,
                mac: [0; 6],
                rssi: 0,
            }; SAMPLE_CAPACITY],
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, s: Sample) {
        if self.len < SAMPLE_CAPACITY {
            let idx = (self.head + self.len) % SAMPLE_CAPACITY;
            self.buf[idx] = s;
            self.len += 1;
        } else {
            // buffer full: overwrite oldest
            self.buf[self.head] = s;
            self.head = (self.head + 1) % SAMPLE_CAPACITY;
        }
    }

    fn pop(&mut self) -> Option<Sample> {
        if self.len == 0 {
            None
        } else {
            let s = self.buf[self.head];
            self.head = (self.head + 1) % SAMPLE_CAPACITY;
            self.len -= 1;
            Some(s)
        }
    }
}

static RING: Mutex<RefCell<SampleRing>> = Mutex::new(RefCell::new(SampleRing::new()));

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

extern crate alloc;

esp_bootloader_esp_idf::esp_app_desc!();

fn on_sniff(pkt: PromiscuousPkt<'_>) {
    if pkt.rx_cntl.rx_state != 0 {
        return; // drop corrupted frames
    }
    if pkt.data.len() < 24 {
        return;
    }

    // Only management (00) and data (10) frames carry a usable addr2 (transmitter).
    // Control frames (01: ACK/CTS/RTS) have no addr2 at offset 10 and would
    // produce garbage MACs that pollute the dataset.
    let fc = u16::from_le_bytes([pkt.data[0], pkt.data[1]]);
    let frame_type = (fc >> 2) & 0x3;
    if frame_type != 0 && frame_type != 2 {
        return;
    }

    let mac: [u8; 6] = pkt.data[10..16].try_into().unwrap(); // addr2 = transmitter
    let ts_us = pkt.rx_cntl.timestamp.duration_since_epoch().as_micros();
    let sample = Sample {
        ts_us,
        mac,
        rssi: pkt.rx_cntl.rssi,
    };

    critical_section::with(|cs| {
        RING.borrow_ref_mut(cs).push(sample);
    });
}

#[allow(clippy::large_stack_frames)]
#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98768);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    let mut uart = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_tx(peripherals.GPIO1)
        .with_rx(peripherals.GPIO3);

    let (mut controller, interfaces): (WifiController, Interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, Default::default())
            .expect("Failed to initialize Wi-Fi controller");

    let mut sniffer = interfaces.sniffer;
    sniffer.set_receive_cb(on_sniff);
    sniffer
        .set_promiscuous_mode(true)
        .expect("Failed to enable promiscuous mode");

    controller
        .set_channel(SNIFFER_CHANNEL, SecondaryChannel::None)
        .expect("Failed to set channel");

    writeln!(uart, "#rssi_sniffer ready channel={}", SNIFFER_CHANNEL).ok();

    loop {
        let mut out = [Sample {
            ts_us: 0,
            mac: [0; 6],
            rssi: 0,
        }; 64];
        critical_section::with(|cs| {
            let mut ring = RING.borrow_ref_mut(cs);
            for i in 0..out.len() {
                match ring.pop() {
                    Some(s) => out[i] = s,
                    None => break,
                }
            }
        });

        for s in out.iter() {
            if s.ts_us == 0 {
                break;
            }
            writeln!(
                uart,
                "{},{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X},{}",
                s.ts_us,
                s.mac[0],
                s.mac[1],
                s.mac[2],
                s.mac[3],
                s.mac[4],
                s.mac[5],
                s.rssi
            )
            .ok();
        }

        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(5) {}
    }
}

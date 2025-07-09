mod airmon_ng;
mod capture;
mod tagged_params;
mod types;
mod gps;

//use tagged_params::tagged_params;
use gps::start_gps;
use tagged_params::tagged_params_ws;
use airmon_ng::{start_monitor_mode, stop_monitor_mode, set_channel};

use std::{
    thread,
    time::Duration,
    sync::{Arc, atomic::{AtomicU64, Ordering::Acquire}}
};
// do channels 1, 6 and 11
// Sometimes fails to start?
// Figure out how to make passing gps data not so round about

fn getLocation(atomic_coords: [Arc<AtomicU64>; 3]) -> [f64; 3] {
    let time = f64::from_bits(atomic_coords[0].load(Acquire));
    let lat = f64::from_bits(atomic_coords[1].load(Acquire));
    let lon = f64::from_bits(atomic_coords[2].load(Acquire));

    return [time, lat, lon];
}

fn packet_found_callback(broadcast: capture::Broadcast, gps_data: Option<[Arc<AtomicU64>; 3]>) {
    if let Some(ssid) = broadcast.found_tags.get(&0x00) {
        if !ssid.is_empty() {

            if let Some(gps_data) = gps_data {
                dbg!(getLocation(gps_data));
            }
            
            println!("{}", capture::mac_address_to_string(&broadcast.transmitter_mac_address));
            println!("{}", value_to_type!(broadcast.packet_type));

            println!("{}\n\n", &String::from_utf8_lossy(&ssid))
        }
    }
}

fn main() {
    let time_a_u64 = Arc::new(AtomicU64::new(0));
    let lat_a_u64 = Arc::new(AtomicU64::new(0));
    let lon_a_u64 = Arc::new(AtomicU64::new(0));

    let interface: String;
    let mut attempts_to_start = 0;

    loop {
        if attempts_to_start >= 1 {
            println!("Attempted to start {} times.", attempts_to_start);

            if attempts_to_start >= 5 {
                println!("Exiting.");

                return;
            }

            thread::sleep(Duration::from_secs(5));

            match stop_monitor_mode("wlan1") {
                Ok(_) => {},
                Err(e) => { println!("{}", e); continue; }
            };
        }

        attempts_to_start += 1;

        // Determine which interface to use based of which one changed. Hacky method....
        // Could also just predict that the name would be wlan1"mon"
        let original_interfaces = match capture::get_interfaces() {
            Ok(interfaces) => interfaces,
            Err(e) => { println!("Error {}", e); continue; }
        };

        match start_monitor_mode("wlan1") {
            Ok(_) => {},
            Err(e) => { println!("Error {}", e); continue; }
        };

        let possible_changed_interfaces = match capture::get_interfaces() {
            Ok(interfaces) => interfaces,
            Err(e) => { println!("Error {}", e); continue; }
        };

        let changed_interfaces = capture::get_changed_interfaces(original_interfaces, possible_changed_interfaces);

        if changed_interfaces.len() < 1 {
            println!("No interface found.");

            continue;
        }

        interface = changed_interfaces[0].name.clone();
        break;
    }

    println!("Starting capture using interface: {}", &interface);

    // Start GPS in a different thread
    println!("Starting GPS...");

    // Clone Arc AtomicU64s
    let time_a_u64_clone = Arc::clone(&time_a_u64);
    let lat_a_u64_clone = Arc::clone(&lat_a_u64);
    let lon_a_u64_clone = Arc::clone(&lon_a_u64);

    thread::spawn(move || {
        start_gps("/dev/serial0", 9_600, [time_a_u64_clone, lat_a_u64_clone, lon_a_u64_clone]);
    });

    set_channel(&interface, 1).unwrap();

    let mut tagged_params_filter: Vec<u8> = Vec::new();
    tagged_params_filter.push(tagged_params_ws::SSID);

    let (tx, rx) = mpsc::channel();
    let sender = tx.clone();
    capture::start(&interface, &tagged_params_filter, packet_found_callback).unwrap();
}

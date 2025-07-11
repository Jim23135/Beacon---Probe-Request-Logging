mod airmon_ng;
mod capture;
mod tagged_params;
mod types;
mod gps;

use gps::start_gps;
use tagged_params::tagged_params_ws;
use airmon_ng::{start_monitor_mode, stop_monitor_mode, set_channel};

use std::{
    thread,
    time::Duration,
    fs::OpenOptions,
    io::{Write, BufWriter},
    sync::{Arc, mpsc, Mutex, atomic::{AtomicU64}}
};

// do channels 1, 6 and 11
// There seems to be an issue where sometimes stuff is not being printed to console. cant actually figure out why this is. Assuming it wont be a problem when i start writing to file...
// create better error handling so that the system doesnt halt for one malformated packet
// Add actual error handling for functions and threads in main

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

    println!("\nUsing interface: {}", &interface);

    // Clone Arc AtomicU64s
    let time_a_u64_clone = Arc::clone(&time_a_u64);
    let lat_a_u64_clone = Arc::clone(&lat_a_u64);
    let lon_a_u64_clone = Arc::clone(&lon_a_u64);

    // Start gps receving
    thread::spawn(move || {
        match start_gps("/dev/serial0", 9_600, [time_a_u64_clone, lat_a_u64_clone, lon_a_u64_clone]) {
            Ok(_) => {},
            Err(e) => eprintln!("Error starting GPS: {}", e)
        };
    });

    // Set channel
    match set_channel(&interface, 1) {
        Ok(_) => println!("Successfully switched channel to channel 1"),
        Err(e) => eprintln!("Unable to set channel: {}", e)
    }

    let mut tagged_params_filter: Vec<u8> = Vec::new();
    tagged_params_filter.push(tagged_params_ws::SSID);

    let (capture_thread_tx, capture_thread_rx): (mpsc::Sender<(capture::Broadcast, capture::GpsDataDecoded)>, mpsc::Receiver<(capture::Broadcast, capture::GpsDataDecoded)>) = mpsc::channel();
    let capture_thread_tx_clone = capture_thread_tx.clone();

    // Clone Arc AtomicU64s
    let time_a_u64_clone = Arc::clone(&time_a_u64);
    let lat_a_u64_clone = Arc::clone(&lat_a_u64);
    let lon_a_u64_clone = Arc::clone(&lon_a_u64);

    thread::spawn(move || {
        match capture::start(&interface, &tagged_params_filter, capture_thread_tx_clone, Some([time_a_u64_clone, lat_a_u64_clone, lon_a_u64_clone])) {
            Ok(_) => println!("Successfully started capture thread"),
            Err(e) => eprintln!("Unable to start capture thread: {}", e)
        };
    });


    // Setup a thread to take items out of the rx.
    // Not using rx as a buffer since I don't think there is a way to tell how many items in it unless I kept track of that through another shared variable

    let logged_packet_dump = Arc::new(Mutex::new(Vec::<(capture::Broadcast, capture::GpsDataDecoded)>::new()));

    let logged_packet_dump_clone = Arc::clone(&logged_packet_dump);

    thread::spawn(move || {
        // Probably want to switch to sqlite3 at some point
        let output_logged_packets_file = OpenOptions::new().write(true).append(true).create(true).open("logged_packets.txt").unwrap();

        loop {
            /*
                TODO: do some math so that the dump at number changes based on how many are being dumpped per. dump start at 20

                The reason that I create a separate mpsc channel is because to keep track of how many items are in the original could possibly be
                troublesome or at least I assume so. It feels like there could be too much complexity there and spots for failure but I don't actually know. 
            */

            thread::sleep(Duration::from_secs(1));

            let mut logged_packet_dump_locked = logged_packet_dump_clone.lock().unwrap();

            if logged_packet_dump_locked.len() >= 20 {
                let to_dump_packets = std::mem::take(&mut *logged_packet_dump_locked);
                drop(logged_packet_dump_locked);

                let mut output_logged_packets_file_writer = BufWriter::new(&output_logged_packets_file);

                for packet in to_dump_packets {
                    let (broadcast, gps_data) = packet;

                    let ssid = broadcast.found_tags.get(&0x00).unwrap();

                    writeln!(
                        output_logged_packets_file_writer,
                        "{} packet recvd for {} from {} at {:.6}, {:.6}, {}",
                        value_to_type!(broadcast.packet_type),
                        &String::from_utf8_lossy(&ssid),
                        capture::mac_address_to_string(&broadcast.transmitter_mac_address),
                        gps_data.lat,
                        gps_data.lon,
                        gps_data.time
                    ).unwrap();
                }
            }
        }
    });


    // Not the most proud of this soultion. Might switch to a different method later if i give it some more though.
    let mut temp_logged_packet_holder: Vec<(capture::Broadcast, capture::GpsDataDecoded)> = Vec::new();
    
    loop {
        thread::sleep(Duration::from_micros(500));
        let (broadcast, gps_data) = capture_thread_rx.recv().unwrap();

        if let Some(ssid) = broadcast.found_tags.get(&0x00) {
            if !ssid.is_empty() && !ssid.iter().all(|&x| x == 0) {
                temp_logged_packet_holder.push((broadcast, gps_data));
                
                //println!("", value_to_type!(broadcast.packet_type), &String::from_utf8_lossy(&ssid), capture::mac_address_to_string(&broadcast.transmitter_mac_address), gps_data.lat, gps_data.lon);

                if temp_logged_packet_holder.len() >= 20 {
                    logged_packet_dump.lock().unwrap().append(&mut temp_logged_packet_holder);
                }
            }
        }
    }
}

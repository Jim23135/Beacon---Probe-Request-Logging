use pcap::{Device, Capture, Error as pcap_error};
use std::{
    collections::HashMap, io::Error as io_error, sync::{atomic::{AtomicU64, Ordering::Acquire}, mpsc, Arc, RwLock}, thread, time::Duration
};
use crate::types::packet_types;

pub struct Broadcast {
    pub packet_type: u8, // First byte in ieee 802.11 header
    pub transmitter_mac_address: [u8; 6],
    pub found_tags: HashMap<u8, Vec<u8>>
}

#[derive(Clone, Debug)]
pub struct GpsDataDecoded {
    pub time: f64,
    pub lat: f64,
    pub lon: f64
}

fn get_location(atomic_coords: &[Arc<AtomicU64>; 3]) -> GpsDataDecoded {
    let time = f64::from_bits(atomic_coords[0].load(Acquire));
    let lat = f64::from_bits(atomic_coords[1].load(Acquire));
    let lon = f64::from_bits(atomic_coords[2].load(Acquire));

    return GpsDataDecoded {time: time, lat: lat, lon: lon};
}

fn search_tagged_params(data: &[u8], target_tag_numbers: &Vec<u8>) -> HashMap<u8, Vec<u8>> {
    let mut tags: HashMap<u8, Vec<u8>> = HashMap::new();
    let mut position = 0;

    while position < data.len() {
        let tag_number = data[position];
        let tag_length = data[position + 1] as usize;

        if target_tag_numbers.contains(&tag_number) {
            tags.insert(tag_number, data[position + 2..position + 2 + tag_length].to_owned());  
        }

        // Increment position forward tag_length and then +2 to account for the original tag number and length
        position += tag_length + 2;
    }

    return tags;
}

pub fn mac_address_to_string(mac_address: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]
    )
}

pub fn get_interfaces() -> Result<Vec<Device>, pcap_error> {
    Device::list()
}

pub fn get_changed_interfaces(original_devices: Vec<Device>, changed_devices: Vec<Device>) -> Vec<Device> {
    let mut new_or_changed_devices: Vec<Device> = Vec::new();

    for changed_device in &changed_devices {
        if original_devices.iter().any(|d| d.name == changed_device.name) {
            continue;
        }
        new_or_changed_devices.push(changed_device.clone());
    }

    return new_or_changed_devices;
}

pub fn start(interface_name: &str, tag_numbers: &Vec<u8>, mpsc_sender: mpsc::Sender<(Broadcast, GpsDataDecoded)>, gps_data_arc: Option<[Arc<AtomicU64>; 3]>) -> Result<(), std::io::Error> {
    let global_gps_data = Arc::new(RwLock::new(GpsDataDecoded {time: 0.0, lat: 0.0, lon: 0.0}));

    // If the caller has passed gps_data then assume to use gps
    if let Some(gps_data) = gps_data_arc {
        let global_gps_data_handle = Arc::clone(&global_gps_data);

        thread::spawn(move || { 
            loop {
                let current_global_gps_data = global_gps_data_handle.read().unwrap();

                // Get GPS data
                let current_gps_data = get_location(&gps_data);

                // If the GPS data is not different then do not change the global gps data
                // If the GPS data is 0 for both lat and lon then dont change the global gps data
                if (current_global_gps_data.lat == current_gps_data.lat && current_global_gps_data.lon == current_gps_data.lon) || (current_gps_data.lat == 0.0 || current_gps_data.lon == 0.0) {
                    // Drop early
                    drop(current_global_gps_data);

                    thread::sleep(Duration::from_millis(400));

                    continue;
                }
            
                // Drop the last read to prevent a deadlock
                drop(current_global_gps_data);

                //println!("Updated GPS");
                let mut current_global_gps_data = global_gps_data_handle.write().unwrap();
                *current_global_gps_data = current_gps_data;
            }       
        });
    }

    // immediate_mode(false) - Packets do not come through when
    // promisc() - Promiscuous mode (true - captures all packets even if they werent addressed to us)
    let mut capture = Capture::from_device(interface_name)
        .map_err(|e| io_error::new(std::io::ErrorKind::Other, e))?
        .immediate_mode(true).promisc(true).open()
        .map_err(|e| io_error::new(std::io::ErrorKind::Other, e))?;

    // Berkeley packet filter syntax
    capture.filter("type mgt subtype probe-req or subtype beacon", true)
        .map_err(|e| io_error::new(std::io::ErrorKind::Other, e))?;

    while let Ok(packet) = capture.next_packet() {
        let packet = packet.data;
        

        // https://howiwifi.com/2020/07/13/802-11-frame-types-and-formats/
        let mut ieee_802_11_frame_start: usize = 0;
        let first_byte = packet[0];

        // First byte of packet - meaning
        // 0x00 - A radiotap header will be present
        // Anything else - A radiotap header will NOT be present. Instead it is the immediate start of the 802.11 frame
        if first_byte == 0x00 {
            // https://www.radiotap.org/
            // "Data is specified in little endian byte-order"
            ieee_802_11_frame_start = u16::from_le_bytes([packet[2], packet[3]]) as usize; // u_int16_t
        }

        let ieee_80211_frame = &packet[ieee_802_11_frame_start..];

        //let _frame_control_first_4 = ieee80211_frame[0];
        //let _frame_control_last_4 = ieee80211_frame[1];

        // Dont have to check for To/From DS because of the filter we applies earlier.

        let transmitter_mac_address: &[u8] = &ieee_80211_frame[10..16];
        let mut offset = 24;

        // Skip fixed parameters
        if ieee_80211_frame[0] == packet_types::BEACON {
            offset += 12
        }

        let data: &[u8] = &ieee_80211_frame[offset..];

        let found_tags = search_tagged_params(data, &tag_numbers);

        if found_tags.len() > 0 {
            let broadcast: Broadcast = Broadcast {
                packet_type: ieee_80211_frame[0],
                transmitter_mac_address: transmitter_mac_address.try_into().map_err(|e| io_error::new(std::io::ErrorKind::Other, e))?,
                found_tags: found_tags
            };

            let gps_data = global_gps_data.read().unwrap();
            mpsc_sender.send((broadcast, (*gps_data).clone())).unwrap();
        }
    }

    return Ok(());
}

// [1..2] - start is inclusive, end is non inclusive
use pcap::{Device, Capture, Error as pcap_error};
use std::{
    io::Error as io_error,
    collections::HashMap,
    sync::{Arc, atomic::{AtomicU64}}
};
use crate::types::packet_types;

pub struct Broadcast {
    pub packet_type: u8, // First byte in ieee 802.11 header
    pub transmitter_mac_address: [u8; 6],
    pub found_tags: HashMap<u8, Vec<u8>>
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

pub fn start<F>(interface_name: &str, tag_numbers: &Vec<u8>, callback: F, gps_data: Option<[Arc<AtomicU64>; 3]>) -> Result<(), std::io::Error> where F: Fn(Broadcast, Option<[Arc<AtomicU64>; 3]>), {
    // Lots of error mapping here. Theres probably a better way to do the error handling...

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
        
        //
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

            //callback(broadcast, gps_data);
        }
        
    }

    return Ok(());
}

// [1..2] - start is inclusive, end is non inclusive
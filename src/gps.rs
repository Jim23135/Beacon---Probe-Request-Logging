use serialport;
use std::{
    time::Duration,
    collections::HashMap,
    io::{BufReader, BufRead},
    sync::{Arc, atomic::{AtomicU64, Ordering::Release}}
};

fn nema_coords_to_regular_coords(degree: &str, direction: &str) -> f64 {
    let degree = match degree.parse::<f64>() {
        Ok(degree) => degree,
        Err(_e) => { return 0.0 }
    };

    let degrees = (degree / 100.0).floor();
    let minutes = degree - degrees * 100.0;
    let mut decimal = degrees + minutes / 60.0;

    if direction.contains("S") || direction.contains("W") {
        decimal = -decimal;
    }

    return decimal
}

fn parse_nema(nema_string: &str) -> HashMap<&str, f64> {
    let nema_parts: Vec<&str> = nema_string.split(",").collect();

    let mut nema_parsed: HashMap<&str, f64> = HashMap::new();

    if nema_parts[0] == "$GNGGA" {
        nema_parsed.insert("time", nema_parts[1].parse().unwrap_or(0.0));
        nema_parsed.insert("lat", nema_coords_to_regular_coords(nema_parts[2], nema_parts[3]));
        nema_parsed.insert("lon", nema_coords_to_regular_coords(nema_parts[4], nema_parts[5]));
    } else if nema_parts[0] == "$GNRMC" {
        nema_parsed.insert("time", nema_parts[1].parse().unwrap_or(0.0));
        nema_parsed.insert("lat", nema_coords_to_regular_coords(nema_parts[3], nema_parts[4]));
        nema_parsed.insert("lon", nema_coords_to_regular_coords(nema_parts[5], nema_parts[6]));
    }

    return nema_parsed
}

pub fn start_gps(serial_device: &str, baud_rate: u32, atomic_coords: [Arc<AtomicU64>; 3]) {
    let serial = match serialport::new(serial_device, baud_rate).timeout(Duration::from_millis(10)).open() {
        Ok(serial) => serial,
        Err(e) => panic!("{}", e)
    };
    //let a = Arc::new(AtomicU64::new(v));

    let serial_reader = BufReader::new(serial);

    for line in serial_reader.lines() {
        match line {
            Ok(line) => {
                // line.starts_with("$GNGGA") || (Not parsing for this one because the coords are the same for each pair of gngga and gnrmc)
                
                if line.starts_with("$GNRMC") {
                    let parsed_nema = parse_nema(&line);

                    atomic_coords[0].store(parsed_nema.get("time").unwrap_or(&0.0).to_bits(), Release);
                    atomic_coords[1].store(parsed_nema.get("lat").unwrap_or(&0.0).to_bits(), Release);
                    atomic_coords[2].store(parsed_nema.get("lon").unwrap_or(&0.0).to_bits(), Release);
                }
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            },
            Err(e) => {println!("Error getting serial: {}", e)}
        }
    }
}


// https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-ieee80211.h
pub mod packet_types {
    pub const BEACON: u8 = 0x80;
    pub const PROBE_REQUEST: u8 = 0x40;
}

#[macro_export]
macro_rules! value_to_type {
    ($val:expr) => {
        match $val {
            types::packet_types::BEACON => "BEACON",
            types::packet_types::PROBE_REQUEST => "PROBE_REQUEST",
            _ => "UNKNOWN",
        }
    };
}
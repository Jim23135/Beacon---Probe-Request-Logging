use std::process::{Command, Stdio};

pub fn start_monitor_mode(interface_name: &str) -> Result<(), String> {
    match Command::new("airmon-ng").arg("start").arg(interface_name).stdout(Stdio::null()).stderr(Stdio::null()).status() { //
        Ok(status) if status.success() => {
            return Ok(());
        }
        Ok(status) => {
            return Err(status.to_string());
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }
}

pub fn stop_monitor_mode(interface_name: &str) -> Result<(), String> {
    let interface_name_mon = interface_name.to_owned() + "mon";

    match Command::new("airmon-ng").arg("stop").arg(interface_name_mon).stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) if status.success() => {
            return Ok(());
        }
        Ok(status) => {
            return Err(status.to_string());
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }
}

pub fn set_channel(interface: &str, channel: u8) -> Result<(), String> {
    match Command::new("iwconfig").arg(interface).arg("channel").arg(channel.to_string()).stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) if status.success() => {
            return Ok(());
        }
        Ok(status) => {
            return Err(status.to_string());
        }
        Err(e) => {
            return Err(e.to_string());
        }
    }
}
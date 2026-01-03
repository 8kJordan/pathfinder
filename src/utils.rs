use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use pcap::{Capture, Device};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err("MAC address must have 6 octets".to_string());
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| format!("Invalid MAC octet: {}", part))?;
        }

        Ok(MacAddr(bytes))
    }
}

pub fn resolve_interface(interface: &str) -> Result<Device, Box<dyn Error>> {
    let devices = Device::list()?;

    if interface != "auto" {
        if let Some(device) = devices.into_iter().find(|d| d.name == interface) {
            return Ok(device);
        }
        return Err(format!("Interface {} not found", interface).into());
    }

    Device::list()?
        .into_iter()
        .find(|d| d.name != "lo")
        .or_else(|| devices.into_iter().next())
        .ok_or_else(|| "No network interfaces available".into())
}

pub fn open_capture(device: &Device) -> Result<Capture<pcap::Active>, Box<dyn Error>> {
    let capture = Capture::from_device(device.name.as_str())?
        .immediate_mode(true)
        .promisc(true)
        .open()?;
    let capture = capture.setnonblock()?;
    Ok(capture)
}

pub fn send_packet(device: &Device, packet: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut cap = open_capture(device)?;
    cap.sendpacket(packet)?;
    Ok(())
}

pub fn ipv4_to_bytes(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

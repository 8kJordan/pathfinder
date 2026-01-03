use pcap::{Capture, Device};
use std::net::Ipv4Addr;

pub fn default_interface_or(choice: Option<String>) -> String {
    choice.unwrap_or_else(|| default_interface().unwrap_or_else(|_| "".to_string()))
}

pub fn default_interface() -> Result<String, String> {
    Device::lookup()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no default interface available".to_string())
        .map(|d| d.name)
}

pub fn open_capture(interface: &str) -> Result<Capture<pcap::Active>, String> {
    Capture::from_device(interface)
        .map_err(|e| e.to_string())?
        .promisc(true)
        .open()
        .map_err(|e| format!("failed to open {interface}: {e}"))
}

pub fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let bytes: Vec<u8> = mac
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid mac format".to_string())?;

    if bytes.len() != 6 {
        return Err("mac must have 6 octets".into());
    }

    let mut arr = [0u8; 6];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn parse_ipv4(ip: &str) -> Result<[u8; 4], String> {
    ip.parse::<Ipv4Addr>()
        .map(|addr| addr.octets())
        .map_err(|_| "invalid IPv4".to_string())
}

pub fn parse_domain_labels(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut idx = offset;
    let mut labels = Vec::new();
    while idx < data.len() {
        let len = data[idx] as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        idx += 1;
        if idx + len > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[idx..idx + len]).into_owned());
        idx += len;
    }
    Some((labels.join("."), idx))
}

pub fn compute_ipv4_checksum(data: &[u8]) -> [u8; 2] {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

pub trait ChecksumExt {}

pub fn host_mac_on(interface: &str) -> Result<[u8; 6], String> {
    // basic helper: best effort with pcap Device listing
    let devices = Device::list().map_err(|e| e.to_string())?;
    for dev in devices {
        if dev.name == interface {
            if let Some(addresses) = dev.addresses.first() {
                if let Some(mac) = addresses.addr.mac {
                    return Ok(mac.octets());
                }
            }
        }
    }
    Err("could not determine MAC for interface".into())
}

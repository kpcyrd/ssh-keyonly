use clap::ArgAction;
use std::net::SocketAddr;

#[derive(Debug, clap::Parser)]
pub struct Args {
    /// Increase logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub verbose: u8,
    /// Reduce logging output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub quiet: u8,
    /// The user to try to authenticate with
    #[arg(short, long, default_value = "root")]
    pub user: String,
    /// The ssh server to try to connect to (including port)
    pub addr: SocketAddr,
}

mod detection;
pub mod error;
mod error_msg;
mod handle_wrapper;
pub mod winapi;

use clap::{Parser, Subcommand};
use std::{env, ffi::OsString};

#[derive(Subcommand)]
enum Commands {
    All,
    Registry,
    Modules,
    Files,
    Processes,
    Threads,
}

#[derive(Parser)]
#[command(author, about)]
pub struct Cli {
    /// Increase log message verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    log_level: u8,
    #[arg(short = 'V', long)]
    /// Print version information
    version: bool,
    #[command(subcommand)]
    commands: Commands,
}

pub fn main() -> anyhow::Result<()> {
    let mut args = env::args_os().collect::<Vec<_>>();
    if args.len() == 1 {
        args.push(OsString::from("--help"));
    }
    let args = Cli::parse_from(args);
    let _ = ansi_term::enable_ansi_support();
    let log_level = match args.log_level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new().filter_level(log_level).init();

    // let filter = match args.commands {
    //     Commands::StartDetection { sig_store_path } => {
    //         detection::start_detection()
    //     },
    // };
    detection::start_detection();

    Ok(())
}

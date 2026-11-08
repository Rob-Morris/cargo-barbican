// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This CLI tool is experimental, and exposes some functionality that's not available in rsop yet.
//!
//! Its functionality may be considered complementary to rsop, but with a less stable CLI API.
//! Hopefully, some of it will get refined and eventually upstreamed into SOP (and rsop).

use std::{error::Error, fs::File, path::PathBuf};

use clap::Parser;
use rpgpie::{
    certificate::{Certificate, Checked},
    model::status_summary,
    util::print_cert,
};

#[derive(Parser, Debug)]
#[command(about = "An experimental OpenPGP CLI tool", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Print a high-level summary of a certificate's status.
    ///
    /// This shows interpreted data and validity information about the certificate's contents.
    /// It filters out invalid signature packets, and shows just one active signature per component.
    ///
    /// This view is useful to inspect which components are valid.
    Status(StatusCommand),

    /// Print the raw internals of a certificate.
    ///
    /// This prints a detailed representation of a certificate's contents, without filtering out
    /// invalid elements.
    ///
    /// (This view is intended for lower level debugging, and inspecting the changes in a
    /// certificate over time.)
    Show(ShowCommand),
}

#[derive(Parser, Debug)]
pub struct ShowCommand {
    #[arg(help = "An OpenPGP file")]
    pub file: Option<PathBuf>,

    #[arg(short, long)]
    pub verbose: bool,

    /// Print objects in the order that they are stored in wire format
    #[arg(short, long)]
    pub unordered: bool,
}

#[derive(Parser, Debug)]
pub struct StatusCommand {
    #[arg(help = "An OpenPGP file")]
    pub file: Option<PathBuf>,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(long)]
    pub json: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Show(show) => {
            let certs = if let Some(file) = show.file {
                Certificate::load(&mut File::open(&file)?)
            } else {
                Certificate::load(&mut std::io::stdin())
            }
            .map_err(|e| format!("Failed to load certificates: {}", e))?;

            for (i, cert) in certs.iter().enumerate() {
                if i != 0 {
                    println!();
                }

                print_cert(cert, show.verbose, !show.unordered);
            }
        }
        Command::Status(status) => {
            let certs = if let Some(file) = status.file {
                Certificate::load(&mut File::open(&file)?)
            } else {
                Certificate::load(&mut std::io::stdin())
            }
            .map_err(|e| format!("Failed to load certificates: {}", e))?;

            let summaries: Vec<_> = certs
                .into_iter()
                .map(Checked::from)
                .map(|c| status_summary(&c))
                .collect();

            if !status.json {
                for (i, summary) in summaries.iter().enumerate() {
                    if i != 0 {
                        println!();
                    }

                    print!("{}", summary)
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&summaries)?);
            }
        }
    }

    Ok(())
}

// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The command line: one binary, one subcommand per job.
//!
//! `serve` runs the server, `config check` reads and resolves the
//! configuration the way `serve` would and exits, `healthcheck` asks the
//! server on this host for its readiness, `client hash-secret` turns a
//! confidential symmetric client's secret into the hash its
//! `secret_hash_file` holds, `subject` prints a person's pairwise subject,
//! and `upstream registration` prints what a provider must be configured
//! with. No specification governs the command line: our own design, the
//! family's.

use clap::{Parser, Subcommand};
use ferrohealth_server::cli::{Common, ConfigArgs};

/// The `ferrosmart` command line.
#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "ferrosmart",
    version,
    about = "FerroSMART, the SMART App Launch authorization server"
)]
pub struct Cli {
    /// `--config`, the file to read in place of the one `FERROSMART_CONFIG`
    /// names, and the `--set key=value` pairs applied last.
    #[command(flatten)]
    pub config: ConfigArgs,
    /// The job to run.
    #[command(subcommand)]
    pub command: Command,
}

/// What the binary does.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// `serve`, `config check` and `healthcheck`.
    #[command(flatten)]
    Common(Common),
    /// Works on the registered clients.
    Client {
        /// The job to run.
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Prints the FerroSMART `sub` of the person `--sub` names at the
    /// provider `--upstream` names, which a resource server binds them by.
    Subject {
        /// The `[[ferrosmart.upstream]]` entry's name.
        #[arg(long)]
        upstream: String,
        /// The person's subject at that provider.
        #[arg(long)]
        sub: String,
    },
    /// Works on the upstream providers.
    Upstream {
        /// The job to run.
        #[command(subcommand)]
        command: UpstreamCommand,
    },
}

/// The `upstream` jobs.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum UpstreamCommand {
    /// Prints what the provider `name` must be configured with.
    Registration {
        /// The `[[ferrosmart.upstream]]` entry's name.
        name: String,
    },
}

/// The `client` jobs.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ClientCommand {
    /// Reads a client secret from standard input and prints its Argon2id PHC
    /// hash, for a confidential symmetric client's `secret_hash_file`.
    HashSecret,
}

#[cfg(test)]
mod tests {
    use super::{Cli, ClientCommand, Command, UpstreamCommand};
    use clap::{CommandFactory, Parser};
    use ferrohealth_server::cli::{Common, ConfigCommand};

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_job_parses() {
        for (args, command) in [
            (vec!["ferrosmart", "serve"], Command::Common(Common::Serve)),
            (
                vec!["ferrosmart", "config", "check"],
                Command::Common(Common::Config {
                    command: ConfigCommand::Check,
                }),
            ),
            (
                vec!["ferrosmart", "healthcheck"],
                Command::Common(Common::Healthcheck),
            ),
            (
                vec!["ferrosmart", "client", "hash-secret"],
                Command::Client {
                    command: ClientCommand::HashSecret,
                },
            ),
            (
                vec![
                    "ferrosmart",
                    "subject",
                    "--upstream",
                    "idp",
                    "--sub",
                    "248289761001",
                ],
                Command::Subject {
                    upstream: String::from("idp"),
                    sub: String::from("248289761001"),
                },
            ),
            (
                vec!["ferrosmart", "upstream", "registration", "idp"],
                Command::Upstream {
                    command: UpstreamCommand::Registration {
                        name: String::from("idp"),
                    },
                },
            ),
        ] {
            let parsed = Cli::try_parse_from(&args).expect("the job parses");
            assert_eq!(command, parsed.command, "{args:?}");
        }
        let parsed = Cli::try_parse_from(["ferrosmart", "serve", "--config", "smart.toml"])
            .expect("the job parses");
        assert_eq!(Some("smart.toml".into()), parsed.config.config);
    }
}

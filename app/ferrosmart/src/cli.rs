// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The command line: one binary, one subcommand per job.
//!
//! `serve` runs the server, `config check` reads and resolves the
//! configuration the way `serve` would and exits, and `healthcheck` asks the
//! server on this host for its readiness. No specification governs the
//! command line: our own design, the family's.

use clap::Parser;
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
    /// The job to run: `serve`, `config check` or `healthcheck`.
    #[command(subcommand)]
    pub command: Common,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{CommandFactory, Parser};
    use ferrohealth_server::cli::{Common, ConfigCommand};

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_job_parses() {
        for (args, command) in [
            (vec!["ferrosmart", "serve"], Common::Serve),
            (
                vec!["ferrosmart", "config", "check"],
                Common::Config {
                    command: ConfigCommand::Check,
                },
            ),
            (vec!["ferrosmart", "healthcheck"], Common::Healthcheck),
        ] {
            let parsed = Cli::try_parse_from(&args).expect("the job parses");
            assert_eq!(command, parsed.command, "{args:?}");
        }
        let parsed = Cli::try_parse_from(["ferrosmart", "serve", "--config", "smart.toml"])
            .expect("the job parses");
        assert_eq!(Some("smart.toml".into()), parsed.config.config);
    }
}

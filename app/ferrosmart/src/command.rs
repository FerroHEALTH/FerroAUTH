// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The run path of the `ferrosmart` binary: the command line parsed, the
//! configuration read, and each job run to its exit code.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_config::loader::Loaded;
use ferrohealth_server::cli::{Common, ConfigCommand};
use ferrohealth_server::run::{Failure, Run, chain};
use ferrohealth_telemetry::section::TelemetrySection;
use ferrohealth_telemetry::telemetry::{Console, InitError, Service, Telemetry};

use crate::cli::Cli;
use crate::config::Config;
use crate::config::settings::Settings;
use crate::server::AppState;
use crate::store::Store;

/// How long `healthcheck` waits for the readiness answer, shorter than the
/// five seconds a container `HEALTHCHECK` commonly allows.
pub const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// The run path of the `ferrosmart` binary, which names it in every line it
/// writes.
pub const RUN: Run = Run::new("ferrosmart");

/// Runs the job `cli` names and returns its exit code.
///
/// # Errors
///
/// Returns the [`Failure`] of a configuration that does not resolve and of
/// a job that fails.
pub async fn dispatch(cli: Cli) -> Result<ExitCode, Failure> {
    let loaded = Config::load(&cli.config).and_then(|loaded| {
        loaded
            .settings()
            .resolve()
            .map(|settings| (loaded, settings))
    });
    let (loaded, settings) = loaded.map_err(|error| cli.command.refused(error))?;
    match cli.command {
        Common::Healthcheck => healthcheck(&settings).await,
        Common::Config {
            command: ConfigCommand::Check,
        } => config_check(&loaded),
        Common::Serve => {
            let telemetry = loaded.settings().telemetry.clone();
            Box::pin(serve(settings, telemetry)).await
        }
    }
}

/// Runs `config check`: every key printed with where it came from and every
/// secret masked, after the settings resolved, keys read included.
#[expect(
    clippy::print_stdout,
    reason = "the job's one answer goes to standard output"
)]
fn config_check(loaded: &Loaded<Config>) -> Result<ExitCode, Failure> {
    ferrohealth_server::run::config_check(loaded)?;
    println!("ferrosmart: the configuration is valid");
    Ok(ExitCode::SUCCESS)
}

/// Runs `healthcheck` against the server this configuration describes.
#[expect(
    clippy::print_stdout,
    reason = "the job's one-line answer goes to standard output"
)]
async fn healthcheck(settings: &Settings) -> Result<ExitCode, Failure> {
    let target = ferrohealth_server::healthcheck::target(settings.server.listen);
    let base = settings.server.base_path.as_str();
    let outcome = match &settings.server.tls {
        Some(tls) => {
            let pinned = ferrohealth_server::tls::HealthcheckTls::read_of(
                tls,
                ferrohealth_server::tls::TlsKeys::SERVER,
            )
            .map_err(Failure::refused_configuration)?;
            ferrohealth_server::healthcheck::check_tls(target, base, HEALTHCHECK_TIMEOUT, &pinned)
                .await
        }
        None => ferrohealth_server::healthcheck::check(target, base, HEALTHCHECK_TIMEOUT).await,
    };
    if outcome.exit_code() == 0 {
        println!("ferrosmart: {outcome}");
        Ok(ExitCode::SUCCESS)
    } else {
        Err(Failure::boxed(outcome.to_string()))
    }
}

/// Runs `serve`: the subscriber, the state, and the server until `SIGTERM`
/// or `SIGINT`.
async fn serve(settings: Settings, section: TelemetrySection) -> Result<ExitCode, Failure> {
    let service = Service::new("ferrosmart", env!("CARGO_PKG_VERSION")).export_crate("ferrosmart");
    let log = |error: InitError| Failure::from(error).with_context("cannot start the log");
    let telemetry = Telemetry::new(&section, service).map_err(log)?;
    telemetry
        .install(&section, &Console::detect())
        .map_err(log)?;
    ferrohealth_telemetry::panic::install_hook();
    let served = listen_and_serve(settings).await;
    if let Err(error) = telemetry.shutdown() {
        tracing::warn!(error = %chain(&error), "the telemetry did not flush");
    }
    served
}

/// Serves the state `settings` describe until `SIGTERM` or `SIGINT`.
async fn listen_and_serve(settings: Settings) -> Result<ExitCode, Failure> {
    let listen = settings.server.listen;
    let section = settings.server.clone();
    let store = Store::connect(&settings.database_url, settings.max_connections)
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot reach the database"))?;
    store
        .migrate()
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot migrate the database"))?;
    store
        .register(&settings.clients)
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot register the clients"))?;
    let sweeper = tokio::spawn(sweep(store.clone()));
    let state = Arc::new(AppState::new(settings, store));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| Failure::from(error).with_context("cannot bind the listen address"))?;
    tracing::info!(%listen, "ferrosmart is listening");
    let lifecycle = state.lifecycle().clone();
    let app = crate::server::router(state);
    let stop = ferrohealth_server::serve::shutdown_signal();
    let served = ferrohealth_server::serve::run(listener, app, &section, lifecycle, stop).await;
    sweeper.abort();
    match served {
        Ok(_drained) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            tracing::error!(error = %chain(&error), "the listener failed");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// How often a replica deletes the expired assertion ids and token records.
/// No specification governs the value: our own design.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Deletes the expired rows every [`SWEEP_INTERVAL`]; a failed sweep is
/// logged and the next one tries again.
async fn sweep(store: Store) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        if let Err(error) = store.sweep().await {
            tracing::warn!(error = %chain(&error), "the expired rows were not swept");
        }
    }
}

use std::time::Duration;

use cja::{
    jobs::{DEFAULT_MAX_RETRIES, JobWorkerConfig, worker::job_worker},
    server::run_server_until,
    setup::TracingConfig,
    tasks::{ShutdownBudget, Supervisor},
};

mod cron;
mod crypto;
mod discovery;
mod email;
mod github;
mod jobs;
mod routes;
mod session;
mod state;

use state::AppState;

/// Shutdown budget, sized for fly.toml's `kill_signal = "SIGTERM"` +
/// `kill_timeout = "10s"`: 6s for tasks, leaving up to ~3s for telemetry.
///
/// An in-flight job gets 5s to finish. `SyncUser` and `SendReminder` are a
/// handful of GitHub/MailPace round trips, so that lets nearly all of them
/// complete instead of being re-run (a `SendReminder` dropped between the
/// send and the `notified_at` stamp re-sends the email on retry). Whatever is
/// still running after 5s is dropped with its lock released, so the next
/// boot claims it at once rather than waiting for lock reclamation. The
/// remaining 1s covers lock release, cron, and HTTP shutdown.
const SHUTDOWN_BUDGET: ShutdownBudget = ShutdownBudget {
    job_drain: Duration::from_secs(5),
    exit_grace: Duration::from_secs(1),
};

fn main() -> cja::Result<()> {
    color_eyre::install()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> cja::Result<()> {
    let telemetry_handle = TracingConfig::new("prn")
        .version(env!("CARGO_PKG_VERSION"))
        .init()?;

    let result = run_tasks().await;
    if let Err(error) = &result {
        tracing::error!(error = %format_args!("{error:#}"), "application tasks failed");
    }
    let flush = telemetry_handle.shutdown().await;
    if result.is_ok() {
        flush?;
    }
    result
}

async fn run_tasks() -> cja::Result<()> {
    let app_state = AppState::from_env().await?;

    // Build the cron registry once so it can seed the Eyes boot manifest
    // before being handed off to the cron worker.
    let cron_registry = cron::registry();

    // The existing public health endpoint also gives Eyes an external check
    // of this always-on service. Keep Eyes transport best effort.
    let manifest = cja::eyes_manifest::build_boot_manifest_from_state::<jobs::Jobs, AppState>(
        &app_state,
        Some(env!("CARGO_PKG_VERSION")),
        None,
        Some(&cron_registry),
    )?;
    cja::eyes_manifest::send_manifest(manifest);

    cja::posthog_manifest::emit_boot_manifest::<jobs::Jobs, AppState>(
        &app_state,
        &cja::posthog_manifest::BootManifest::new("prn", &cron_registry, &cron::TIMEZONE, &[], &[]),
    )?;

    // The supervisor registers SIGTERM + SIGINT, owns the shutdown token the
    // server, job worker and cron all watch, and runs the drain.
    let mut supervisor = Supervisor::new(SHUTDOWN_BUDGET)?;
    let shutdown = supervisor.shutdown_token();

    tracing::info!("Spawning tasks");
    supervisor.spawn(
        "server",
        run_server_until(
            routes::routes().with_state(app_state.clone()),
            shutdown.clone().cancelled_owned(),
        ),
    );
    supervisor.spawn(
        "job_worker",
        job_worker(
            app_state.clone(),
            jobs::Jobs,
            Duration::from_secs(5),
            DEFAULT_MAX_RETRIES,
            shutdown.clone(),
            JobWorkerConfig {
                shutdown_drain_timeout: supervisor.budget().job_drain,
                ..JobWorkerConfig::default()
            },
        ),
    );
    supervisor.spawn(
        "cron_worker",
        cron::run_cron(app_state, cron_registry, shutdown),
    );

    supervisor.run().await
}
